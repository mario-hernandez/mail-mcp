"""Drafts mailbox resolution — fixes ``[TRYCREATE] folder does not exist``.

External user reported that ``save_draft`` against an Outlook account in
Spanish (drafts mailbox named ``Borradores``) failed with
``append failed: [TRYCREATE] folder does not exist``. Root cause: the
account's ``drafts_mailbox`` field was the literal default ``"Drafts"``
(either because the wizard's SPECIAL-USE detection failed at setup time
or because the account predates that logic), and ``save_draft`` was
trusting it blindly.

The fix adds :func:`imap_client.resolve_drafts_mailbox`, which queries
the server at call time and picks, in order:

1. The optional ``hint`` argument if present and existing.
2. ``account.drafts_mailbox`` if it exists on the server.
3. Whichever folder advertises the RFC 6154 ``\\Drafts`` SPECIAL-USE flag.
4. The first match from a curated list of localised names commonly used
   by Outlook / Exchange / IONOS / GMX / Cyrus / Gmail.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from mail_mcp import imap_client
from mail_mcp.config import AccountModel


def _account(drafts: str = "Drafts") -> AccountModel:
    return AccountModel(
        alias="t",
        email="me@example.com",
        imap_host="imap.example.com",
        smtp_host="smtp.example.com",
        drafts_mailbox=drafts,
        trash_mailbox="Trash",
    )


def _fake_client_with_folders(*folders: tuple[list[bytes], str, str]) -> MagicMock:
    """Build a MagicMock IMAPClient whose ``list_folders`` returns the given folders.

    Each folder is a triple ``(flags, delimiter, name)`` matching the
    shape ``imapclient`` itself yields. Pass ``[b"\\Drafts"]`` in the
    flags to mark a folder as RFC 6154 SPECIAL-USE drafts.
    """
    client = MagicMock()
    client.list_folders.return_value = list(folders)
    return client


def test_resolve_uses_special_use_drafts_flag_over_configured_name():
    """The headline regression: configured 'Drafts' is wrong, server has 'Borradores'."""
    client = _fake_client_with_folders(
        ([b"\\HasNoChildren"], "/", "INBOX"),
        ([b"\\HasNoChildren", b"\\Drafts"], "/", "Borradores"),
        ([b"\\HasNoChildren", b"\\Sent"], "/", "Elementos enviados"),
        ([b"\\HasNoChildren", b"\\Trash"], "/", "Papelera"),
    )
    acct = _account(drafts="Drafts")  # stale default — no 'Drafts' folder exists
    assert imap_client.resolve_drafts_mailbox(client, acct) == "Borradores"


def test_resolve_uses_configured_name_when_it_exists_on_server():
    """English account with the wizard-detected name: keep using it, no detection cost."""
    client = _fake_client_with_folders(
        ([b"\\HasNoChildren"], "/", "INBOX"),
        ([b"\\HasNoChildren", b"\\Drafts"], "/", "Drafts"),
    )
    acct = _account(drafts="Drafts")
    assert imap_client.resolve_drafts_mailbox(client, acct) == "Drafts"


def test_resolve_falls_back_to_localised_name_when_special_use_missing():
    """Some IMAP servers don't advertise SPECIAL-USE — try common names."""
    client = _fake_client_with_folders(
        ([b"\\HasNoChildren"], "/", "INBOX"),
        ([b"\\HasNoChildren"], "/", "Borradores"),  # no \\Drafts flag
        ([b"\\HasNoChildren"], "/", "Papelera"),
    )
    acct = _account(drafts="Drafts")
    assert imap_client.resolve_drafts_mailbox(client, acct) == "Borradores"


def test_resolve_raises_clear_error_when_nothing_matches():
    """No configured, no SPECIAL-USE, no localised name → clear remediation hint."""
    client = _fake_client_with_folders(
        ([b"\\HasNoChildren"], "/", "INBOX"),
        ([b"\\HasNoChildren"], "/", "Sent"),
    )
    acct = _account(drafts="Drafts")
    with pytest.raises(RuntimeError, match="no drafts mailbox found"):
        imap_client.resolve_drafts_mailbox(client, acct)


def test_resolve_honours_explicit_hint_over_configured_and_special_use():
    """An explicit hint from the caller (e.g. UpdateDraftInput.mailbox) wins."""
    client = _fake_client_with_folders(
        ([b"\\HasNoChildren", b"\\Drafts"], "/", "Borradores"),
        ([b"\\HasNoChildren"], "/", "Concepts"),
    )
    acct = _account(drafts="Drafts")
    # User explicitly named "Concepts" — respect it even though SPECIAL-USE
    # would have picked Borradores.
    assert imap_client.resolve_drafts_mailbox(client, acct, hint="Concepts") == "Concepts"


def test_resolve_recognises_gmail_style_drafts_folder():
    """Gmail's ``[Gmail]/Drafts`` quirk is in the localised fallback list."""
    client = _fake_client_with_folders(
        ([b"\\HasNoChildren"], "/", "INBOX"),
        ([b"\\HasNoChildren"], "/", "[Gmail]/Drafts"),
    )
    acct = _account(drafts="Drafts")
    assert imap_client.resolve_drafts_mailbox(client, acct) == "[Gmail]/Drafts"


def test_save_draft_uses_resolved_mailbox_for_append():
    """End-to-end: ``save_draft`` calls APPEND against the resolved name, not the literal config."""
    client = _fake_client_with_folders(
        ([b"\\HasNoChildren"], "/", "INBOX"),
        ([b"\\HasNoChildren", b"\\Drafts"], "/", "Borradores"),
    )
    client.append.return_value = b"[APPENDUID 1 42] APPEND completed."
    acct = _account(drafts="Drafts")
    uid = imap_client.save_draft(client, account=acct, message_bytes=b"Subject: t\r\n\r\nbody")
    assert uid == 42
    # The APPEND must have been issued against ``Borradores``, NOT ``Drafts``.
    append_calls = client.append.call_args_list
    assert len(append_calls) == 1
    assert append_calls[0].args[0] == "Borradores"
