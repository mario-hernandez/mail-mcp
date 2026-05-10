"""``update_draft`` / ``send_draft`` must refuse non-drafts mailboxes.

Codex adversarial review (high) flagged that the ``mailbox`` parameter
on these tools was caller-controlled and reached an unconditional
permanent-delete of the source UID. A prompt-injected LLM on the
default-visible ``update_draft`` tool could have used it as a
permanent-delete primitive against any UID/mailbox: append a copy to
Drafts, then ``uid_expunge`` the original from INBOX, all without
``MAIL_MCP_WRITE_ENABLED`` / ``MAIL_MCP_ALLOW_PERMANENT_DELETE`` /
``confirm=true``.

Fix: validate that an explicit ``mailbox=`` matches the resolved drafts
mailbox before any fetch/append/delete. These tests pin the new
contract: explicit non-drafts → ``ValidationError`` with no IMAP
mutation, explicit-but-correct works, ``mailbox=None`` still resolves.
"""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from mail_mcp import imap_client
from mail_mcp.config import AccountModel, Config, ConfigModel
from mail_mcp.credentials import AuthCredential
from mail_mcp.safety.validation import ValidationError
from mail_mcp.tools.drafts import update_draft
from mail_mcp.tools.schemas import UpdateDraftInput


def _account() -> AccountModel:
    return AccountModel(
        alias="t",
        email="me@example.com",
        imap_host="imap.example.com",
        smtp_host="smtp.example.com",
        drafts_mailbox="Drafts",
        trash_mailbox="Trash",
    )


def _localised_folders() -> list[tuple[list[bytes], str, str]]:
    """A typical localised setup: residual 'Drafts' + SPECIAL-USE 'Borradores'."""
    return [
        ([b"\\HasNoChildren"], "/", "INBOX"),
        ([b"\\HasNoChildren", b"\\Drafts"], "/", "Borradores"),
        ([b"\\HasNoChildren"], "/", "Drafts"),  # residual / migration leftover
    ]


def _run_update_draft(params: UpdateDraftInput, *, capture: dict) -> None:
    """Drive ``update_draft`` with mocks; let the test inspect what was called."""
    cfg = Config(path=Path("/tmp/x"), model=ConfigModel(accounts=[_account()]))

    @contextmanager
    def fake_connect(account, creds):
        client = MagicMock()
        client.list_folders.return_value = _localised_folders()

        def fake_append(*a, **kw):
            capture["append"] = (a, kw)
            return b"[APPENDUID 1 999] APPEND completed."
        client.append = fake_append

        capture["client"] = client
        yield client

    def fake_fetch_raw(c, *, mailbox, uid):
        capture["fetched"] = (mailbox, uid)
        # Return a minimal valid RFC822
        return b"From: a@example.com\r\nTo: b@example.com\r\nSubject: x\r\n\r\nbody\r\n", {
            "Subject": "x",
            "From": "a@example.com",
        }

    def fake_delete(c, *, mailbox, uids, trash_mailbox, permanent):
        capture["deleted"] = (mailbox, uids, permanent)
        return len(uids)

    with patch.object(imap_client, "connect", fake_connect), \
         patch.object(imap_client, "fetch_raw_message", fake_fetch_raw), \
         patch.object(imap_client, "delete_uids", fake_delete), \
         patch("mail_mcp.tools.drafts.resolve_auth",
               lambda a: AuthCredential(kind="password", username=a.email, secret="x")):
        update_draft(cfg, params)


def test_update_draft_refuses_explicit_non_drafts_mailbox():
    """Pin the exact bypass: ``mailbox="INBOX"`` must be rejected pre-flight."""
    capture: dict = {}
    with pytest.raises(ValidationError) as ei:
        _run_update_draft(
            UpdateDraftInput(account="t", mailbox="INBOX", uid=42),
            capture=capture,
        )
    msg = str(ei.value)
    assert "update_draft" in msg
    assert "Borradores" in msg  # the resolved name is surfaced
    assert "INBOX" in msg       # the rejected name is surfaced
    # Critically: NO IMAP mutation occurred. Pre-fix, the handler would
    # have fetched INBOX/42, APPENDed to Drafts, and deleted INBOX/42.
    assert "fetched" not in capture
    assert "deleted" not in capture
    assert "append" not in capture


def test_update_draft_refuses_residual_drafts_when_special_use_points_elsewhere():
    """Even ``mailbox="Drafts"`` is wrong if SPECIAL-USE points to ``Borradores``.

    The residual plain ``Drafts`` exists on the server (migration leftover)
    but is NOT the user's mail-client drafts folder. The strict resolver
    must reject it just like any other non-drafts override.
    """
    capture: dict = {}
    with pytest.raises(ValidationError) as ei:
        _run_update_draft(
            UpdateDraftInput(account="t", mailbox="Drafts", uid=1),
            capture=capture,
        )
    assert "Borradores" in str(ei.value)
    assert "fetched" not in capture


def test_update_draft_accepts_explicit_correct_drafts_mailbox():
    """If the caller passes the actual resolved name, the call proceeds."""
    capture: dict = {}
    _run_update_draft(
        UpdateDraftInput(account="t", mailbox="Borradores", uid=1, body="new body"),
        capture=capture,
    )
    # Fetch hits the resolved name
    assert capture["fetched"] == ("Borradores", 1)
    # Old UID is deleted from the resolved name (not from any caller-supplied mailbox)
    assert capture["deleted"][0] == "Borradores"


def test_update_draft_resolves_when_mailbox_omitted():
    """``mailbox=None`` (the default) still works through the resolver."""
    capture: dict = {}
    _run_update_draft(
        UpdateDraftInput(account="t", uid=1, body="new body"),
        capture=capture,
    )
    assert capture["fetched"] == ("Borradores", 1)
    assert capture["deleted"][0] == "Borradores"


def test_send_draft_refuses_explicit_non_drafts_mailbox(monkeypatch):
    """Same gate applies to ``send_draft`` — same primitive."""
    monkeypatch.setenv("MAIL_MCP_WRITE_ENABLED", "true")
    monkeypatch.setenv("MAIL_MCP_SEND_ENABLED", "true")
    from mail_mcp.tools.drafts import send_draft
    from mail_mcp.tools.schemas import SendDraftInput

    cfg = Config(path=Path("/tmp/x"), model=ConfigModel(accounts=[_account()]))
    capture: dict = {}

    @contextmanager
    def fake_connect(account, creds):
        client = MagicMock()
        client.list_folders.return_value = _localised_folders()
        capture["client"] = client
        yield client

    def fake_fetch_raw(c, *, mailbox, uid):
        capture["fetched"] = (mailbox, uid)
        return b"From: x@example.com\r\nSubject: y\r\n\r\n", {}

    with patch.object(imap_client, "connect", fake_connect), \
         patch.object(imap_client, "fetch_raw_message", fake_fetch_raw), \
         patch("mail_mcp.tools.drafts.resolve_auth",
               lambda a: AuthCredential(kind="password", username=a.email, secret="x")):
        with pytest.raises(ValidationError) as ei:
            send_draft(
                cfg,
                SendDraftInput(
                    account="t", mailbox="INBOX", uid=42, confirm=True,
                ),
            )
    assert "send_draft" in str(ei.value)
    assert "INBOX" in str(ei.value)
    # No fetch happened — the gate is pre-flight.
    assert "fetched" not in capture
