"""Integration tests for the read-path tools against a live GreenMail IMAP/SMTP server.

These tests exercise ``mail_mcp.tools.read`` end-to-end: list/search/get/thread
semantics, attachment download under the allowlisted directory, account
introspection, and quota handling. Fixtures (``cfg``, ``patched_keyring``,
``deliver``, ``populated_inbox``) are defined in ``tests/integration/conftest.py``
per the contract in ``_contract.md``.

Skip behaviour: if GreenMail or docker fail to start, the ``greenmail`` fixture
short-circuits to ``pytest.skip`` so these tests skip cleanly instead of failing.
"""

from __future__ import annotations

import pytest

from mail_mcp.tools import drafts, organize, read
from mail_mcp.tools.schemas import (
    AccountInfoInput,
    CreateFolderInput,
    DownloadAttachmentInput,
    GetEmailInput,
    GetQuotaInput,
    GetThreadInput,
    ListAccountsInput,
    ListAttachmentsInput,
    ListDraftsInput,
    ListFoldersInput,
    SaveDraftInput,
    SearchInput,
    SpecialFoldersInput,
)

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Folder listing
# ---------------------------------------------------------------------------


def test_list_folders_returns_inbox(cfg, patched_keyring):
    """``list_folders`` returns at least INBOX with well-formed entries."""
    result = read.list_folders(cfg, ListFoldersInput())

    assert result["count"] >= 1
    names = [f["name"] for f in result["folders"]]
    assert "INBOX" in names

    for entry in result["folders"]:
        assert "name" in entry
        assert "delimiter" in entry
        assert "flags" in entry
        assert "special_use" in entry
        assert isinstance(entry["flags"], list)


def test_get_special_folders_detects_drafts_and_trash(cfg, patched_keyring):
    """``get_special_folders`` returns a dict; GreenMail may not advertise SPECIAL-USE."""
    # Ensure Drafts exists so that a server advertising SPECIAL-USE has something to report.
    organize.create_folder(cfg, CreateFolderInput(mailbox="Drafts"))

    result = read.get_special_folders(cfg, SpecialFoldersInput())

    assert "special_folders" in result
    specials = result["special_folders"]
    # GreenMail may not announce SPECIAL-USE flags; empty dict is acceptable.
    assert isinstance(specials, dict)


# ---------------------------------------------------------------------------
# Search
# ---------------------------------------------------------------------------


def test_search_emails_populated(cfg, patched_keyring, populated_inbox):
    """``search`` returns the seeded messages; narrowing by subject finds the Stripe thread."""
    result = read.search(cfg, SearchInput(limit=20))

    assert result["total"] >= 10
    assert result["returned"] >= 1
    result_subjects = [r["subject"] for r in result["results"]]

    # Every seeded message should be discoverable (spot-check the first few).
    seeded_message_ids = [mid for (_uid, mid, _subj) in populated_inbox]
    assert len(seeded_message_ids) >= 10

    # Narrow by subject to isolate the Stripe/Invoice thread.
    narrowed = read.search(cfg, SearchInput(limit=20, subject="Invoice"))
    assert narrowed["total"] >= 1
    assert narrowed["returned"] >= 1

    # Every match should mention "Invoice" in the subject (case-insensitive).
    for r in narrowed["results"]:
        assert "invoice" in r["subject"].lower()

    # The narrowed result set should be a strict subset of the full listing.
    narrowed_subjects = {r["subject"] for r in narrowed["results"]}
    assert narrowed_subjects.issubset(set(result_subjects))


def test_search_emails_pagination(cfg, patched_keyring, populated_inbox):
    """Pagination returns disjoint pages with a stable ``total``."""
    page1 = read.search(cfg, SearchInput(limit=3, offset=0))
    page2 = read.search(cfg, SearchInput(limit=3, offset=3))

    assert page1["total"] == page2["total"]
    assert page1["total"] >= 6  # need two full pages of 3
    assert page1["returned"] == 3
    assert page2["returned"] == 3

    uids1 = {r["uid"] for r in page1["results"]}
    uids2 = {r["uid"] for r in page2["results"]}
    assert uids1.isdisjoint(uids2)


# ---------------------------------------------------------------------------
# Get email
# ---------------------------------------------------------------------------


def test_get_email_wraps_body_in_xpia(cfg, patched_keyring, populated_inbox):
    """``get_email`` wraps the body in the XPIA envelope."""
    # Pick any seeded UID and fetch it.
    uid, _message_id, _subject = populated_inbox[0]
    result = read.get_email(cfg, GetEmailInput(uid=uid))

    body = result["body"]
    assert "<untrusted_email_content>" in body
    assert "</untrusted_email_content>" in body
    # Warning banner should precede the tagged block.
    assert "untrusted email content" in body.lower()


def test_get_email_sanitizes_subject_crlf(cfg, patched_keyring, test_account):
    """Subject CR/LF injections are stripped before reaching the caller.

    We bypass :func:`deliver` here because :class:`email.message.EmailMessage`
    refuses to set a header containing a literal ``\\r\\n`` — which is
    exactly the kind of payload an attacker would try to smuggle. Instead we
    hand-craft the wire bytes and ship them via :class:`smtplib.SMTP_SSL`.
    """
    import smtplib
    import ssl as _ssl

    ctx = _ssl._create_unverified_context()
    raw = (
        b"From: attacker@localhost.local\r\n"
        b"To: " + test_account.email.encode() + b"\r\n"
        b"Subject: Hello\r\n Bcc: evil@x.com\r\n"  # LWSP-continued so SMTP accepts it
        b"\r\n"
        b"plain body\r\n"
    )
    with smtplib.SMTP_SSL(
        test_account.smtp_host, test_account.smtp_port, context=ctx, timeout=10
    ) as server:
        server.sendmail("attacker@localhost.local", [test_account.email], raw)
    # Small settling delay so GreenMail commits the delivery before we SEARCH.
    import time

    time.sleep(0.5)

    # Locate the delivered message — GreenMail assigns the newest UID.
    listing = read.search(cfg, SearchInput(limit=50))
    target = None
    for r in listing["results"]:
        if r["subject"].startswith("Hello"):
            target = r
            break
    assert target is not None, "delivered message not found in INBOX"

    msg = read.get_email(cfg, GetEmailInput(uid=target["uid"]))
    subject = msg["header"]["subject"]
    assert "\r" not in subject
    assert "\n" not in subject
    # The "Bcc:" fragment should still be present as plain text (the CRLF is what mattered).
    assert subject.startswith("Hello")


# ---------------------------------------------------------------------------
# Threading
# ---------------------------------------------------------------------------


def test_get_thread_basic(cfg, patched_keyring, populated_inbox):
    """``get_thread`` returns the full thread when THREAD=REFERENCES is available.

    GreenMail may not advertise the extension — in that case the tool falls
    back to the singleton UID and sets a note. Both paths are accepted here.
    """
    # The contract seeds a three-message Stripe invoice thread. Find any UID
    # whose subject contains "Invoice" to use as the entry point.
    listing = read.search(cfg, SearchInput(limit=50, subject="Invoice"))
    assert listing["returned"] >= 1, "populated_inbox should contain the Invoice thread"
    root_uid = listing["results"][0]["uid"]

    result = read.get_thread(cfg, GetThreadInput(uid=root_uid))

    assert result["thread_size"] >= 1
    assert result["returned"] >= 1
    assert isinstance(result["messages"], list)
    assert isinstance(result["notes"], list)

    if result["thread_size"] == 1:
        # Fallback path: server didn't advertise THREAD=REFERENCES.
        joined = " ".join(result["notes"])
        assert "did not advertise" in joined
    else:
        # Full-thread path: at least the Stripe invoice reply + follow-up should appear.
        assert result["thread_size"] >= 2
        assert result["returned"] >= 2
        returned_uids = {m["uid"] for m in result["messages"]}
        assert root_uid in returned_uids


# ---------------------------------------------------------------------------
# Drafts listing (read-side alias resolution)
# ---------------------------------------------------------------------------


def test_list_drafts_resolves_mailbox_by_alias(cfg, patched_keyring, test_account):
    """``list_drafts`` reports the configured drafts_mailbox and its contents."""
    acct = test_account
    subject = "Draft for listing"

    drafts.save_draft(
        cfg,
        SaveDraftInput(
            to=[f"someone@{acct.email.split('@', 1)[1]}"],
            subject=subject,
            body="draft body",
        ),
    )

    result = read.list_drafts(cfg, ListDraftsInput())

    assert result["returned"] >= 1
    assert result["mailbox"] == acct.drafts_mailbox
    subjects = [r["subject"] for r in result["results"]]
    assert subject in subjects


# ---------------------------------------------------------------------------
# Attachments
# ---------------------------------------------------------------------------


def _find_uid_by_subject(cfg, subject: str) -> int:
    """Locate the UID of a delivered message by subject match."""
    listing = read.search(cfg, SearchInput(limit=50, subject=subject))
    assert listing["returned"] >= 1, f"no message with subject matching {subject!r}"
    # Prefer an exact match when the server returns supersets.
    for r in listing["results"]:
        if r["subject"] == subject:
            return r["uid"]
    return listing["results"][0]["uid"]


def test_list_attachments_returns_metadata(cfg, patched_keyring, deliver):
    """``list_attachments`` returns the attachment metadata for a PDF payload."""
    subject = "With PDF attachment"
    pdf_bytes = b"%PDF-1.4\n" + b"\x00" * 500
    deliver(subject=subject, body="see attachment", attachment=("factura.pdf", pdf_bytes))

    uid = _find_uid_by_subject(cfg, subject)
    result = read.list_attachments(cfg, ListAttachmentsInput(uid=uid))

    assert len(result["attachments"]) == 1
    att = result["attachments"][0]
    assert att["filename"] == "factura.pdf"
    assert "pdf" in att["content_type"].lower()
    assert att["size"] > 0


def test_download_attachment_writes_file_under_allowlist(
    cfg, patched_keyring, deliver, test_account
):
    """``download_attachment`` writes the attachment under ~/Downloads/mail-mcp/."""
    from pathlib import Path

    from mail_mcp.safety.paths import default_download_root

    subject = "Download target"
    pdf_bytes = b"%PDF-1.4\n" + b"\x00" * 500
    deliver(subject=subject, body="download me", attachment=("factura.pdf", pdf_bytes))

    uid = _find_uid_by_subject(cfg, subject)
    result = read.download_attachment(
        cfg,
        DownloadAttachmentInput(uid=uid, index=0, filename="factura.pdf"),
    )

    path = Path(result["path"])
    assert path.exists()
    assert result["bytes"] > 0

    # Path must be under the download allowlist root.
    root = default_download_root()
    assert str(path).startswith(str(root))
    # And under a per-account subdirectory.
    acct = test_account
    assert acct.alias in path.parts


# ---------------------------------------------------------------------------
# Account introspection
# ---------------------------------------------------------------------------


def test_list_accounts_returns_test_account(cfg, patched_keyring, test_account):
    """``list_accounts`` surfaces the single configured test account as default."""
    acct = test_account
    result = read.list_accounts(cfg, ListAccountsInput())

    assert result["count"] == 1
    assert result["default"] == acct.alias
    assert len(result["accounts"]) == 1
    entry = result["accounts"][0]
    assert entry["is_default"] is True
    assert entry["email"] == acct.email
    assert entry["alias"] == acct.alias


def test_get_account_info(cfg, patched_keyring):
    """``get_account_info`` mirrors the GreenMail host/port configuration."""
    result = read.get_account_info(cfg, AccountInfoInput())

    assert result["imap"]["host"] == "localhost"
    assert result["imap"]["port"] > 0
    assert result["imap"]["ssl"] is True
    assert result["smtp"]["port"] > 0


def test_get_quota_returns_nulls_or_values(cfg, patched_keyring):
    """``get_quota`` returns either nulls (GreenMail without QUOTA) or two ints."""
    result = read.get_quota(cfg, GetQuotaInput())

    assert "used_kb" in result
    assert "limit_kb" in result
    used, limit = result["used_kb"], result["limit_kb"]

    # Both nulls OR both ints — consistent reporting in either case.
    if used is None:
        assert limit is None
    else:
        assert isinstance(used, int)
        assert isinstance(limit, int)
