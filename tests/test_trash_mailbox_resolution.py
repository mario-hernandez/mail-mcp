"""Trash mailbox resolution — symmetric to drafts.

Codex flagged that ``delete_email(permanent=false)`` was passing
``acct.trash_mailbox`` straight through, which on a stale-config
localised account means the move-to-trash either lands in the wrong
folder or fails. The fix mirrors the drafts resolver: hint →
SPECIAL-USE ``\\Trash`` → configured name → localised fallback list.

Critically, when a server has BOTH a residual plain ``Trash`` folder
(migration leftover) AND the real localised mailbox flagged ``\\Trash``
(``Papelera`` / ``Elementos eliminados`` / ``Corbeille`` / ``Papierkorb``),
the SPECIAL-USE-flagged one wins. Picking the residual ``Trash`` would
silently send "deleted" mail to a folder the user's mail client does
not treat as trash.
"""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from unittest.mock import MagicMock, patch

from mail_mcp import imap_client
from mail_mcp.config import AccountModel, Config, ConfigModel
from mail_mcp.credentials import AuthCredential


def _account(trash: str = "Trash") -> AccountModel:
    return AccountModel(
        alias="t",
        email="me@example.com",
        imap_host="imap.example.com",
        smtp_host="smtp.example.com",
        drafts_mailbox="Drafts",
        trash_mailbox=trash,
    )


def _fake_client_with_folders(*folders: tuple[list[bytes], str, str]) -> MagicMock:
    client = MagicMock()
    client.list_folders.return_value = list(folders)
    return client


def test_resolve_trash_uses_special_use_over_configured_name():
    """Localised Outlook account: config says 'Trash', server has 'Papelera' \\Trash."""
    client = _fake_client_with_folders(
        ([b"\\HasNoChildren"], "/", "INBOX"),
        ([b"\\HasNoChildren", b"\\Drafts"], "/", "Borradores"),
        ([b"\\HasNoChildren", b"\\Trash"], "/", "Papelera"),
    )
    acct = _account(trash="Trash")
    assert imap_client.resolve_trash_mailbox(client, acct) == "Papelera"


def test_resolve_trash_prefers_special_use_over_residual_plain_trash_folder():
    """Both residual 'Trash' (no flag) AND real \\Trash 'Papelera' coexist —
    SPECIAL-USE wins so deleted mail does not vanish into a residual folder."""
    client = _fake_client_with_folders(
        ([b"\\HasNoChildren"], "/", "INBOX"),
        ([b"\\HasNoChildren"], "/", "Trash"),  # migration leftover
        ([b"\\HasNoChildren", b"\\Trash"], "/", "Papelera"),  # real one
    )
    acct = _account(trash="Trash")
    assert imap_client.resolve_trash_mailbox(client, acct) == "Papelera"


def test_resolve_trash_uses_configured_name_when_it_exists():
    """English account, server has only 'Trash': use it without extra detection cost."""
    client = _fake_client_with_folders(
        ([b"\\HasNoChildren"], "/", "INBOX"),
        ([b"\\HasNoChildren", b"\\Trash"], "/", "Trash"),
    )
    acct = _account(trash="Trash")
    assert imap_client.resolve_trash_mailbox(client, acct) == "Trash"


def test_resolve_trash_falls_back_to_outlook_localised_name_without_special_use():
    """Some IMAP servers do not advertise SPECIAL-USE — try Outlook variants."""
    client = _fake_client_with_folders(
        ([b"\\HasNoChildren"], "/", "INBOX"),
        ([b"\\HasNoChildren"], "/", "Elementos eliminados"),
    )
    acct = _account(trash="Trash")
    assert imap_client.resolve_trash_mailbox(client, acct) == "Elementos eliminados"


def test_resolve_trash_honours_explicit_hint():
    """Caller hint overrides everything when the named folder exists."""
    client = _fake_client_with_folders(
        ([b"\\HasNoChildren", b"\\Trash"], "/", "Papelera"),
        ([b"\\HasNoChildren"], "/", "MyCustomBin"),
    )
    acct = _account(trash="Trash")
    assert imap_client.resolve_trash_mailbox(
        client, acct, hint="MyCustomBin",
    ) == "MyCustomBin"


def test_resolve_trash_raises_clear_error_when_nothing_matches():
    client = _fake_client_with_folders(
        ([b"\\HasNoChildren"], "/", "INBOX"),
        ([b"\\HasNoChildren"], "/", "Sent"),
    )
    acct = _account(trash="Trash")
    import pytest
    with pytest.raises(RuntimeError, match="no trash mailbox found"):
        imap_client.resolve_trash_mailbox(client, acct)


def test_delete_email_tool_moves_to_resolved_trash_on_localised_account():
    """End-to-end: ``delete_email(permanent=false)`` lands in the SPECIAL-USE folder."""
    from mail_mcp.tools.organize import delete_email
    from mail_mcp.tools.schemas import DeleteEmailInput

    cfg = Config(path=Path("/tmp/x"), model=ConfigModel(accounts=[_account("Trash")]))
    moves: list = []

    @contextmanager
    def fake_connect(account, creds):
        client = MagicMock()
        client.list_folders.return_value = [
            ([b"\\HasNoChildren"], "/", "INBOX"),
            ([b"\\HasNoChildren", b"\\Trash"], "/", "Papelera"),
        ]
        # Capture move target without involving move_uids' validation.
        def fake_move(uids, destination):
            moves.append((list(uids), destination))
        client.move = fake_move
        yield client

    with patch.object(imap_client, "connect", fake_connect), \
         patch("mail_mcp.tools.organize._auth",
               lambda cfg, alias: (cfg.account(alias),
                                   AuthCredential(kind="password", username="x@e.com", secret="x"))):
        result = delete_email(
            cfg,
            DeleteEmailInput(
                account="t", mailbox="INBOX", uids=[5, 6], permanent=False,
            ),
        )

    assert result["mode"] == "trash"
    assert result["trash_mailbox"] == "Papelera"
    assert moves == [([5, 6], "Papelera")]
