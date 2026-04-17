"""Integration tests for the drafts + send path.

Exercises the full MCP-tool surface that mutates the user's mailbox via
drafts or the gated ``send_email`` / ``send_draft`` tools. All tests run
against GreenMail (see ``tests/integration/conftest.py``) using a
session-scoped container plus a per-test unique account.

These tests own the behaviour documented in ``SECURITY.md`` around the
send gating chain (env vars + ``confirm=true`` + per-account rate limit).
"""

from __future__ import annotations

import email as _email
import email.policy as _policy
import ssl
import uuid
from pathlib import Path

import pytest
from imapclient import IMAPClient

from mail_mcp.config import AccountModel, Config
from mail_mcp.safety.validation import ValidationError
from mail_mcp.tools import drafts, organize, read, send
from mail_mcp.tools.schemas import (
    CreateFolderInput,
    ForwardDraftInput,
    GetEmailInput,
    ListDraftsInput,
    ReplyDraftInput,
    SaveDraftInput,
    SearchInput,
    SendDraftInput,
    SendEmailInput,
    UpdateDraftInput,
)
from mail_mcp.tools.send import RateLimited, SendDisabled, _reset_for_tests

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Local fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _write_and_send_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    """Flip both env gates on for the whole module.

    Individual tests that need to observe the *disabled* state override
    these with ``monkeypatch.delenv`` after the autouse fixture has run.
    """
    monkeypatch.setenv("MAIL_MCP_WRITE_ENABLED", "true")
    monkeypatch.setenv("MAIL_MCP_SEND_ENABLED", "true")


@pytest.fixture(autouse=True)
def _patch_tool_keyring_bindings(
    test_account: AccountModel, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Patch ``get_password`` at every tool-module binding site.

    Each tool module does ``from ..keyring_store import get_password`` at
    import time, which binds the name in the tool module's own namespace.
    The shared ``patched_keyring`` fixture only replaces the attribute on
    :mod:`mail_mcp.keyring_store`, which is invisible to tool code that has
    already imported the symbol. We repatch each binding here.
    """

    def _fake(alias: str, email: str) -> str:
        if alias == test_account.alias or email == test_account.email:
            return "greenmail"
        raise RuntimeError(f"no password stub for {alias!r}/{email!r}")

    for module in ("mail_mcp.tools.drafts", "mail_mcp.tools.read",
                   "mail_mcp.tools.send", "mail_mcp.tools.organize"):
        monkeypatch.setattr(f"{module}.get_password", _fake)


@pytest.fixture(autouse=True)
def _reset_send_bucket() -> None:
    """Clear the process-local rate-limit deque between tests."""
    _reset_for_tests()
    yield
    _reset_for_tests()


@pytest.fixture
def ensure_drafts(cfg: Config) -> None:
    """Pre-create the Drafts mailbox so save_draft can APPEND.

    GreenMail does not auto-create SPECIAL-USE folders. The first real test
    would otherwise fail at APPEND time because the target mailbox doesn't
    exist yet — which has nothing to do with what we are testing.
    """
    organize.create_folder(cfg, CreateFolderInput(mailbox="Drafts"))


@pytest.fixture
def ensure_trash(cfg: Config) -> None:
    """Pre-create Trash so update_draft's APPEND-then-DELETE can run."""
    organize.create_folder(cfg, CreateFolderInput(mailbox="Trash"))


@pytest.fixture
def recipient_account(
    greenmail: dict,
    test_account: AccountModel,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[AccountModel, str]:
    """A second GreenMail account + password, used for end-to-end send tests.

    Kept local to this file so the shared ``conftest.py`` stays lean. The
    keyring stub is expanded to know about *both* accounts so
    ``smtp_client.send`` + ``imap_client.connect`` resolve credentials for
    either account without colliding.
    """
    sender = test_account
    alias = f"recipient-{uuid.uuid4().hex[:8]}"
    email = f"test-{uuid.uuid4().hex[:8]}@localhost.local"
    password = "greenmail"
    acct = AccountModel(
        alias=alias,
        email=email,
        imap_host=greenmail["imap_host"],
        imap_port=greenmail["imap_port"],
        smtp_host=greenmail["smtp_host"],
        smtp_port=greenmail["smtp_port"],
        imap_use_ssl=True,
        smtp_starttls=False,
        drafts_mailbox="Drafts",
        trash_mailbox="Trash",
    )
    # Provision the recipient on the GreenMail server just like the primary
    # test account; without this step IMAP LOGIN fails with "Invalid login".
    from tests.integration.conftest import create_greenmail_user

    create_greenmail_user(greenmail["admin_url"], email, password)

    # Wrap the existing keyring stub so both the sender and the recipient
    # resolve to "greenmail". monkeypatch re-entry *replaces* the prior stub
    # rather than stacking, so the autouse ``_patch_tool_keyring_bindings``
    # from this module is overridden cleanly by this more permissive version.
    def _get_password(alias_in: str, email_in: str) -> str:
        if alias_in == sender.alias or email_in == sender.email:
            return "greenmail"
        if alias_in == acct.alias or email_in == acct.email:
            return password
        raise RuntimeError(f"no password stub for {alias_in!r}/{email_in!r}")

    monkeypatch.setattr("mail_mcp.keyring_store.get_password", _get_password)
    # Each tool module rebinds `get_password` at import time via
    # `from ..keyring_store import get_password`; repatch every site.
    for module in ("mail_mcp.tools.drafts", "mail_mcp.tools.read",
                   "mail_mcp.tools.send", "mail_mcp.tools.organize"):
        monkeypatch.setattr(f"{module}.get_password", _get_password)
    return acct, password


def _imap_ssl_context() -> ssl.SSLContext:
    """Unverified TLS context for raw IMAPClient calls against GreenMail."""
    return ssl._create_unverified_context()  # noqa: S323 — test-only GreenMail cert


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_save_draft_appends_to_drafts(cfg: Config, ensure_drafts: None) -> None:
    """``save_draft`` writes an APPENDable draft that shows up in listings."""
    result = drafts.save_draft(
        cfg,
        SaveDraftInput(to=["bob@example.com"], subject="hi", body="hola"),
    )
    assert result["mailbox"] == "Drafts"
    assert result["uid"] >= 1
    assert result["message_id"]

    listing = read.list_drafts(cfg, ListDraftsInput())
    subjects = [row["subject"] for row in listing["results"]]
    uids = [row["uid"] for row in listing["results"]]
    assert "hi" in subjects
    assert result["uid"] in uids


def test_save_draft_with_attachment_from_disk(
    cfg: Config, ensure_drafts: None, tmp_path: Path
) -> None:
    """File attachments sourced from the on-disk allowlist round-trip."""
    outbox = Path.home() / "Downloads" / "mail-mcp-outbox"
    outbox.mkdir(parents=True, exist_ok=True)
    attach_path = outbox / f"mailmcp-{uuid.uuid4().hex[:8]}.txt"
    attach_path.write_text("hello from disk\n", encoding="utf-8")
    try:
        result = drafts.save_draft(
            cfg,
            SaveDraftInput(
                to=["bob@example.com"],
                subject="with attachment",
                body="see attached",
                attachments=[{"path": str(attach_path)}],
            ),
        )
        got = read.get_email(
            cfg, GetEmailInput(mailbox="Drafts", uid=result["uid"])
        )
        assert len(got["attachments"]) == 1
        assert got["attachments"][0]["filename"] == attach_path.name
    finally:
        if attach_path.exists():
            attach_path.unlink()


def test_save_draft_attachment_outside_allowlist_rejected(
    cfg: Config, ensure_drafts: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Paths outside the configured allowlist raise ``ValidationError``."""
    # Pin the allowlist to a non-existent directory so whatever path the test
    # supplies is guaranteed to fall outside. This sidesteps the platform-
    # dependent $TMPDIR entry in the default allowlist (e.g. macOS puts
    # pytest's tmp_path under /var/folders, which *is* allowed normally).
    monkeypatch.setenv("MAIL_MCP_ATTACHMENT_DIR", "/nonexistent")
    monkeypatch.setattr(
        "mail_mcp.safety.attachments._allowed_roots",
        lambda: [Path("/nonexistent")],
    )

    external = tmp_path / "evil.txt"
    external.write_text("payload", encoding="utf-8")

    with pytest.raises(ValidationError):
        drafts.save_draft(
            cfg,
            SaveDraftInput(
                to=["bob@example.com"],
                subject="nope",
                body="nope",
                attachments=[{"path": str(external)}],
            ),
        )


def test_reply_draft_sets_threading_headers(
    cfg: Config,
    ensure_drafts: None,
    populated_inbox: list[tuple[int, str, str]],
) -> None:
    """Reply drafts carry ``In-Reply-To`` + ``References`` + ``Re:`` subject."""
    # Target the Stripe invoice root (subject begins with "Your Stripe invoice").
    target = next(
        (uid, mid, subj) for uid, mid, subj in populated_inbox
        if subj.startswith("Your Stripe invoice")
    )
    uid, orig_mid, _subj = target

    result = drafts.reply_draft(
        cfg,
        ReplyDraftInput(mailbox="INBOX", uid=uid, body="thanks"),
    )

    # Refetch the draft and inspect its headers on the wire.
    acct = cfg.account(None)
    with IMAPClient(
        acct.imap_host, port=acct.imap_port, ssl=True, ssl_context=_imap_ssl_context()
    ) as c:
        c.login(acct.email, "greenmail")
        c.select_folder("Drafts", readonly=True)
        fetched = c.fetch([result["uid"]], ["RFC822"])
        raw = fetched[result["uid"]][b"RFC822"]

    draft_msg = _email.message_from_bytes(raw, policy=_policy.default)

    assert draft_msg["In-Reply-To"] == orig_mid
    references = (draft_msg.get("References") or "").split()
    assert orig_mid in references
    subject = draft_msg.get("Subject", "")
    assert subject.lower().startswith("re:")


def test_reply_draft_reply_all_dedupes_self(
    cfg: Config, ensure_drafts: None, test_account: AccountModel
) -> None:
    """``reply_all`` excludes the test account and keeps third-party Cc."""
    # ``deliver`` from the shared conftest doesn't take ``cc``, so drop into
    # smtplib directly to craft a multi-recipient seed message.
    import smtplib
    from email.message import EmailMessage
    from email.utils import formatdate, make_msgid

    acct = test_account
    seed = EmailMessage()
    seed["From"] = "sender@example.com"
    seed["To"] = ", ".join([acct.email, "other@example.com"])
    seed["Cc"] = "third@example.com"
    seed["Subject"] = "reply all please"
    seed["Date"] = formatdate(localtime=False, usegmt=True)
    seed["Message-ID"] = make_msgid(domain="example.com")
    seed.set_content("hi team")
    with smtplib.SMTP_SSL(
        acct.smtp_host, acct.smtp_port, context=_imap_ssl_context(), timeout=15
    ) as server:
        try:
            server.login("admin", "admin")
        except smtplib.SMTPException:
            pass
        server.send_message(
            seed,
            from_addr="sender@example.com",
            to_addrs=[acct.email, "other@example.com", "third@example.com"],
        )
    # Find the message we just delivered so we have its UID.
    search_res = read.search(
        cfg,
        SearchInput(mailbox="INBOX", subject="reply all please"),
    )
    uid = search_res["results"][0]["uid"]

    result = drafts.reply_draft(
        cfg,
        ReplyDraftInput(mailbox="INBOX", uid=uid, body="thanks all", reply_all=True),
    )

    with IMAPClient(
        acct.imap_host, port=acct.imap_port, ssl=True, ssl_context=_imap_ssl_context()
    ) as c:
        c.login(acct.email, "greenmail")
        c.select_folder("Drafts", readonly=True)
        fetched = c.fetch([result["uid"]], ["RFC822"])
        raw = fetched[result["uid"]][b"RFC822"]
    draft_msg = _email.message_from_bytes(raw, policy=_policy.default)
    to_hdr = draft_msg.get("To", "")
    cc_hdr = draft_msg.get("Cc", "")

    assert acct.email not in to_hdr, f"self-address leaked into To: {to_hdr!r}"
    assert "third@example.com" in cc_hdr


def test_forward_draft_attaches_rfc822(
    cfg: Config, ensure_drafts: None, test_account: AccountModel, deliver
) -> None:
    """Forward drafts attach the original as message/rfc822, not inline text."""
    marker = "ORIGINAL_CONTENT_MARKER"
    deliver(
        from_="someone@example.com",
        to=[test_account.email],
        subject="forward me",
        body=f"line one\n{marker}\nline three",
    )
    search_res = read.search(cfg, SearchInput(mailbox="INBOX", subject="forward me"))
    uid = search_res["results"][0]["uid"]

    result = drafts.forward_draft(
        cfg,
        ForwardDraftInput(
            mailbox="INBOX", uid=uid, to=["mgr@example.com"], comment="FYI"
        ),
    )

    listing = read.list_drafts(cfg, ListDraftsInput())
    assert result["uid"] in {row["uid"] for row in listing["results"]}

    got = read.get_email(cfg, GetEmailInput(mailbox="Drafts", uid=result["uid"]))
    # The original email body must not leak into the forward's body verbatim:
    # build_forward_message attaches the original as a message/rfc822 part.
    assert marker not in got["body"]

    # Re-parse the raw message to confirm an rfc822 part exists. get_email's
    # ``attachments`` list filters by Content-Disposition, which EmailMessage
    # does not automatically set for inline message/rfc822 parts.
    acct = cfg.account(None)
    with IMAPClient(
        acct.imap_host, port=acct.imap_port, ssl=True, ssl_context=_imap_ssl_context()
    ) as c:
        c.login(acct.email, "greenmail")
        c.select_folder("Drafts", readonly=True)
        raw = c.fetch([result["uid"]], ["RFC822"])[result["uid"]][b"RFC822"]
    draft_msg = _email.message_from_bytes(raw, policy=_policy.default)
    types = {part.get_content_type() for part in draft_msg.walk()}
    assert "message/rfc822" in types


def test_update_draft_replaces_in_place(
    cfg: Config, ensure_drafts: None, ensure_trash: None
) -> None:
    """``update_draft`` appends v2 and deletes v1, preserving Message-ID."""
    first = drafts.save_draft(
        cfg, SaveDraftInput(to=["x@example.com"], subject="draft", body="v1")
    )
    old_uid = first["uid"]
    old_mid = first["message_id"]

    updated = drafts.update_draft(
        cfg,
        UpdateDraftInput(mailbox="Drafts", uid=old_uid, body="v2", preserve_message_id=True),
    )

    assert updated["new_uid"] != old_uid
    # Old UID must be gone from Drafts.
    listing = read.list_drafts(cfg, ListDraftsInput())
    uids = {row["uid"] for row in listing["results"]}
    assert old_uid not in uids
    assert updated["new_uid"] in uids

    body = read.get_email(cfg, GetEmailInput(mailbox="Drafts", uid=updated["new_uid"]))
    assert "v2" in body["body"]
    assert updated["message_id"] == old_mid


def test_update_draft_without_message_id_preservation(
    cfg: Config, ensure_drafts: None, ensure_trash: None
) -> None:
    """``preserve_message_id=False`` mints a brand-new Message-ID."""
    first = drafts.save_draft(
        cfg, SaveDraftInput(to=["x@example.com"], subject="draft", body="v1")
    )
    updated = drafts.update_draft(
        cfg,
        UpdateDraftInput(
            mailbox="Drafts", uid=first["uid"], body="v2", preserve_message_id=False
        ),
    )
    assert updated["message_id"] != first["message_id"]


def test_send_draft_requires_env_and_confirm(
    cfg: Config,
    ensure_drafts: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``send_draft`` refuses without both env gates + confirm=true."""
    first = drafts.save_draft(
        cfg, SaveDraftInput(to=["x@example.com"], subject="gate", body="body")
    )
    uid = first["uid"]

    # 1. Env disabled: SendDisabled even with confirm=True.
    monkeypatch.delenv("MAIL_MCP_SEND_ENABLED", raising=False)
    with pytest.raises(SendDisabled):
        drafts.send_draft(
            cfg, SendDraftInput(mailbox="Drafts", uid=uid, confirm=True)
        )

    # 2. Env re-enabled but confirm missing → SendDisabled.
    monkeypatch.setenv("MAIL_MCP_SEND_ENABLED", "true")
    with pytest.raises(SendDisabled):
        drafts.send_draft(
            cfg, SendDraftInput(mailbox="Drafts", uid=uid, confirm=False)
        )


def test_send_draft_happy_path(
    cfg: Config,
    ensure_drafts: None,
    ensure_trash: None,
    recipient_account: tuple[AccountModel, str],
) -> None:
    """A draft sent with confirm=true is SMTP-delivered and removed from Drafts."""
    recipient, recipient_password = recipient_account
    first = drafts.save_draft(
        cfg,
        SaveDraftInput(
            to=[recipient.email], subject="send-happy", body="hi there"
        ),
    )
    uid = first["uid"]

    result = drafts.send_draft(
        cfg, SendDraftInput(mailbox="Drafts", uid=uid, confirm=True)
    )
    assert result["status"] == "sent"

    # Draft is gone from Drafts.
    listing = read.list_drafts(cfg, ListDraftsInput())
    assert uid not in {row["uid"] for row in listing["results"]}

    # Message arrived on the recipient's INBOX. Log in as the recipient via
    # raw IMAPClient — bypassing the tools layer keeps this assertion
    # independent of whatever the SUT does with credentials.
    with IMAPClient(
        recipient.imap_host,
        port=recipient.imap_port,
        ssl=True,
        ssl_context=_imap_ssl_context(),
    ) as c:
        c.login(recipient.email, recipient_password)
        c.select_folder("INBOX", readonly=True)
        matches = c.search(["SUBJECT", "send-happy"])
        assert matches, "message never arrived on recipient INBOX"


def test_send_email_rate_limit_enforced(
    cfg: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Exceeding ``MAIL_MCP_SEND_HOURLY_LIMIT`` raises ``RateLimited``."""
    monkeypatch.setenv("MAIL_MCP_SEND_HOURLY_LIMIT", "2")
    _reset_for_tests()

    def _call():
        return send.send_email(
            cfg,
            SendEmailInput(
                to=[f"ratelimit-{uuid.uuid4().hex[:6]}@localhost.local"],
                subject="t",
                body="b",
                confirm=True,
            ),
        )

    _call()
    _call()
    with pytest.raises(RateLimited):
        _call()


def test_send_email_respects_from_header(
    cfg: Config,
    recipient_account: tuple[AccountModel, str],
    test_account: AccountModel,
) -> None:
    """Delivered mail carries From: == the configured test account."""
    recipient, recipient_password = recipient_account
    sender = test_account

    subject = f"from-check-{uuid.uuid4().hex[:6]}"
    send.send_email(
        cfg,
        SendEmailInput(
            to=[recipient.email], subject=subject, body="hi", confirm=True
        ),
    )

    with IMAPClient(
        recipient.imap_host,
        port=recipient.imap_port,
        ssl=True,
        ssl_context=_imap_ssl_context(),
    ) as c:
        c.login(recipient.email, recipient_password)
        c.select_folder("INBOX", readonly=True)
        matches = c.search(["SUBJECT", subject])
        assert matches, "message never arrived"
        raw = c.fetch(matches, ["RFC822"])[matches[0]][b"RFC822"]

    msg = _email.message_from_bytes(raw, policy=_policy.default)
    from_hdr = msg.get("From", "")
    assert sender.email in from_hdr, (
        f"expected sender {sender.email!r} in From header, got {from_hdr!r}"
    )
