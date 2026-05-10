"""``EXPUNGE`` must be UID-scoped — bare ``EXPUNGE`` deletes other people's mail.

Adversarial review (Codex) flagged that ``imap_client.delete_uids`` was
calling ``client.expunge()`` with no UID argument after marking the
target UIDs ``\\Deleted``. RFC 3501's bare ``EXPUNGE`` removes *every*
message in the selected mailbox already flagged ``\\Deleted``, including
messages another mail client (Outlook, a phone app, an earlier failed
operation) had flagged. That turns a "delete this one draft" into
silent collateral damage on the user's inbox.

The fix uses RFC 4315 ``UID EXPUNGE`` (UIDPLUS) via
``client.uid_expunge``. Servers that do not advertise UIDPLUS get a
typed :class:`UIDPlusRequired` error rather than the unsafe fallback.
The ``update_draft`` / ``send_draft`` callers catch that error and
fall back to mark-deleted-without-expunge so they don't expose users
to the unsafe expunge either.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from mail_mcp import imap_client


def _client_with_caps(*caps: bytes) -> MagicMock:
    c = MagicMock()
    c.capabilities.return_value = list(caps)
    return c


def test_safe_uid_expunge_uses_uidplus_when_available():
    """RFC 4315 UID EXPUNGE — the only safe per-UID variant."""
    client = _client_with_caps(b"IMAP4rev1", b"UIDPLUS")
    imap_client.safe_uid_expunge(client, uids=[1, 2, 3])
    client.uid_expunge.assert_called_once_with([1, 2, 3])
    # Bare EXPUNGE must never be issued — that's the bug we are fixing.
    assert not client.expunge.called


def test_safe_uid_expunge_refuses_without_uidplus():
    """No silent fallback to bare EXPUNGE — that would re-introduce the bug."""
    client = _client_with_caps(b"IMAP4rev1")  # no UIDPLUS
    with pytest.raises(imap_client.UIDPlusRequired) as ei:
        imap_client.safe_uid_expunge(client, uids=[42])
    assert ei.value.code == "UIDPLUS_REQUIRED_FOR_SAFE_EXPUNGE"
    assert not client.expunge.called
    assert not client.uid_expunge.called


def test_delete_uids_permanent_uses_uid_expunge_under_uidplus():
    """End-to-end: ``delete_emails(permanent=true)`` issues UID EXPUNGE only."""
    client = _client_with_caps(b"IMAP4rev1", b"UIDPLUS")
    imap_client.delete_uids(
        client,
        mailbox="INBOX",
        uids=[7],
        trash_mailbox="Trash",
        permanent=True,
    )
    client.add_flags.assert_called_once_with([7], [b"\\Deleted"])
    client.uid_expunge.assert_called_once_with([7])
    assert not client.expunge.called


def test_delete_uids_permanent_raises_without_mutation_when_uidplus_missing():
    """No-UIDPLUS must fail BEFORE any \\Deleted flagging.

    Pin Codex finding (medium): until v0.3.8 the handler set ``\\Deleted``
    first and only then probed UIDPLUS, so a legacy server's failure path
    still tombstoned the target UIDs. Some clients hide
    ``\\Deleted``-flagged messages and a later EXPUNGE from any source
    would finish the deletion. The probe is now BEFORE the flag — the
    server state must be untouched on this failure.
    """
    client = _client_with_caps(b"IMAP4rev1")  # no UIDPLUS
    with pytest.raises(imap_client.UIDPlusRequired):
        imap_client.delete_uids(
            client,
            mailbox="INBOX",
            uids=[7],
            trash_mailbox="Trash",
            permanent=True,
        )
    # The crucial assertion: NO mutation occurred. Pre-fix this assertion
    # failed because the handler had already flagged the UID \Deleted.
    assert not client.add_flags.called
    assert not client.expunge.called
    assert not client.uid_expunge.called


def test_update_draft_helper_falls_back_to_mark_deleted_without_uidplus():
    """``update_draft`` / ``send_draft`` recover from no-UIDPLUS with a warning."""
    from mail_mcp.tools.drafts import _delete_old_draft_uid_safely

    client = _client_with_caps(b"IMAP4rev1")  # no UIDPLUS
    warning = _delete_old_draft_uid_safely(
        client, mailbox="Drafts", uid=99, trash_mailbox="Trash",
    )
    assert warning is not None
    assert "UIDPLUS" in warning
    assert "uid=99" in warning
    # The fallback path: re-select the source mailbox writeable, mark the
    # UID \Deleted, and stop. No expunge — bare or otherwise.
    client.select_folder.assert_called_with("Drafts", readonly=False)
    client.add_flags.assert_called_with([99], [b"\\Deleted"])
    assert not client.expunge.called
    assert not client.uid_expunge.called


def test_update_draft_helper_no_warning_when_uidplus_available():
    """The happy path returns ``None`` — no warning leaks into the response."""
    from mail_mcp.tools.drafts import _delete_old_draft_uid_safely

    client = _client_with_caps(b"IMAP4rev1", b"UIDPLUS")
    warning = _delete_old_draft_uid_safely(
        client, mailbox="Drafts", uid=99, trash_mailbox="Trash",
    )
    assert warning is None
    client.uid_expunge.assert_called_once_with([99])
