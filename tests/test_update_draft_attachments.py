"""``update_draft`` must preserve attachments when the caller doesn't pass them.

Bug #2: ``update_draft(uid=N, cc=[...])`` used to silently drop every
attachment from the original draft. Root cause: ``build_message`` was
called without an ``attachments`` argument and no carry-over logic
existed. The fix mirrors the implicit-preserve semantics that
``preserve_message_id`` / ``in_reply_to`` already use for header-bound
fields:

  * ``attachments`` omitted (``None``) — preserve original attachments.
  * ``attachments=[]`` — explicitly clear all.
  * ``attachments=[spec, ...]`` — replace with the new set.
"""

from __future__ import annotations

import email
import email.policy
import tempfile
from email.message import EmailMessage
from pathlib import Path
from unittest.mock import MagicMock, patch

from mail_mcp import imap_client, smtp_client
from mail_mcp.config import AccountModel, Config, ConfigModel
from mail_mcp.credentials import AuthCredential
from mail_mcp.safety.attachments import ResolvedAttachment
from mail_mcp.tools.drafts import update_draft
from mail_mcp.tools.schemas import AttachmentSpec, UpdateDraftInput


def _account() -> AccountModel:
    return AccountModel(
        alias="t",
        email="me@example.com",
        imap_host="imap.example.com",
        smtp_host="smtp.example.com",
        drafts_mailbox="Drafts",
        trash_mailbox="Trash",
    )


def _build_draft_with_eml_attachment() -> bytes:
    """Build the wire bytes of a draft that has one .eml attached."""
    inner = EmailMessage(policy=email.policy.default)
    inner["From"] = "a@example.com"
    inner["To"] = "b@example.com"
    inner["Subject"] = "evidence"
    inner.set_content("preserved body content")
    fh = tempfile.NamedTemporaryFile(suffix=".eml", delete=False)
    fh.write(inner.as_bytes())
    fh.close()
    src = Path(fh.name)
    try:
        resolved = ResolvedAttachment(
            path=src, filename="evidence.eml", content_type="message/rfc822", size=src.stat().st_size,
        )
        draft = smtp_client.build_message(
            from_addr="me@example.com",
            to=["recipient@example.com"],
            subject="Original subject",
            body_text="Original body.",
            attachments=[resolved],
        )
        return bytes(draft)
    finally:
        src.unlink(missing_ok=True)


def _run_update_draft(params: UpdateDraftInput, original_wire: bytes) -> bytes:
    """Drive ``update_draft`` against mocked IMAP, return the new wire bytes."""
    cfg = Config(path=Path("/tmp/x"), model=ConfigModel(accounts=[_account()]))
    captured: dict[str, bytes] = {}

    @contextmanager_factory
    def fake_connect(account, creds):
        client = MagicMock()
        yield client

    def fake_fetch_raw(c, *, mailbox, uid):
        return original_wire, {}

    def fake_save_draft(c, *, account, message_bytes):
        captured["wire"] = message_bytes
        return 999

    def fake_delete(c, **kw):
        return 1

    with patch.object(imap_client, "connect", fake_connect), \
         patch.object(imap_client, "fetch_raw_message", fake_fetch_raw), \
         patch.object(imap_client, "save_draft", fake_save_draft), \
         patch.object(imap_client, "delete_uids", fake_delete), \
         patch.object(imap_client, "resolve_drafts_mailbox", lambda c, a, **kw: "Drafts"), \
         patch("mail_mcp.tools.drafts.resolve_auth", lambda a: AuthCredential(
             kind="password", username=a.email, secret="x"
         )):
        update_draft(cfg, params)
    return captured["wire"]


def contextmanager_factory(fn):
    """Tiny @contextmanager-style decorator for the fake connect()."""
    from contextlib import contextmanager
    return contextmanager(fn)


def _list_attachments(wire: bytes) -> list:
    parsed = email.message_from_bytes(wire, policy=email.policy.default)
    _t, _h, atts = imap_client._extract_parts(parsed)
    return atts


def test_update_draft_preserves_attachments_when_not_specified():
    """The headline regression: ``update_draft(cc=...)`` keeps attachments."""
    original = _build_draft_with_eml_attachment()
    new_wire = _run_update_draft(
        UpdateDraftInput(uid=1, cc=["new@example.com"]),
        original,
    )
    atts = _list_attachments(new_wire)
    assert len(atts) == 1
    assert atts[0].filename == "evidence.eml"
    assert atts[0].content_type == "message/rfc822"
    assert atts[0].size > 100  # body survived


def test_update_draft_clears_attachments_when_explicit_empty_list():
    """Passing ``attachments=[]`` is the opt-in to drop all attachments."""
    original = _build_draft_with_eml_attachment()
    new_wire = _run_update_draft(
        UpdateDraftInput(uid=1, cc=["new@example.com"], attachments=[]),
        original,
    )
    atts = _list_attachments(new_wire)
    assert atts == []


def test_update_draft_replaces_attachments_when_new_list_supplied():
    """A non-empty list replaces the original attachments."""
    fh = tempfile.NamedTemporaryFile(
        prefix="update_draft_test_",
        suffix=".pdf",
        dir=Path.home() / "Downloads",
        delete=False,
    )
    fh.write(b"%PDF-1.4 fake content" * 50)
    fh.close()
    pdf_path = Path(fh.name)
    try:
        original = _build_draft_with_eml_attachment()
        new_wire = _run_update_draft(
            UpdateDraftInput(
                uid=1,
                attachments=[
                    AttachmentSpec(path=str(pdf_path), filename="report.pdf")
                ],
            ),
            original,
        )
        atts = _list_attachments(new_wire)
        # Only the new PDF — the original .eml is gone because the caller
        # opted in to replacement.
        assert len(atts) == 1
        assert atts[0].filename == "report.pdf"
        assert atts[0].content_type == "application/pdf"
    finally:
        pdf_path.unlink(missing_ok=True)
