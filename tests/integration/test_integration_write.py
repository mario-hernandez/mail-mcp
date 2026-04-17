"""Integration tests for the write/organize path.

Agent D file ownership (see ``tests/integration/_contract.md``). Exercises
``mail_mcp.tools.organize`` end-to-end against GreenMail:

* move / copy between folders
* flag mutations (read, unread, flagged)
* trash-mode and permanent delete with env + confirm gating
* folder create / rename / delete (empty and non-empty paths)
* batch-size cap on copy

Relies on the shared session/function fixtures declared in
``tests/integration/conftest.py``: ``greenmail`` (container boot),
``patched_tls`` (autouse SSL bypass), ``test_account`` (unique email),
``patched_keyring`` (autouse password stub), ``cfg`` (Config object) and
``deliver`` (SMTP drop helper).
"""

from __future__ import annotations

import os
import time

import pytest

from mail_mcp.tools import organize, read
from mail_mcp.tools.schemas import (
    CopyEmailInput,
    CreateFolderInput,
    DeleteEmailInput,
    DeleteFolderInput,
    MarkFlagsInput,
    MoveEmailInput,
    RenameFolderInput,
    SearchInput,
)

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _enable_writes(monkeypatch):
    """Open the write gate for every test in this file.

    The organize tools are registered by ``server.build_server`` only when
    ``MAIL_MCP_WRITE_ENABLED=true``; we call the handlers directly here so
    this is mostly belt-and-braces, but ``delete_email(permanent=True)`` does
    consult ``MAIL_MCP_ALLOW_PERMANENT_DELETE`` at call-time and we want the
    suite to be self-contained.
    """
    monkeypatch.setenv("MAIL_MCP_WRITE_ENABLED", "true")
    # Permanent-delete stays OFF by default; individual tests opt in.
    monkeypatch.delenv("MAIL_MCP_ALLOW_PERMANENT_DELETE", raising=False)


def _uids_in(cfg, mailbox: str) -> list[int]:
    """Return the list of UIDs present in ``mailbox`` (up to 500)."""
    result = read.search(
        cfg,
        SearchInput(mailbox=mailbox, limit=500, offset=0),
    )
    return [row["uid"] for row in result["results"]]


def _find_uid_by_subject(cfg, mailbox: str, subject: str) -> int:
    """Look up a UID by subject substring. Polls briefly to tolerate SMTP→IMAP lag."""
    for _ in range(20):
        result = read.search(
            cfg,
            SearchInput(mailbox=mailbox, limit=500, offset=0, subject=subject),
        )
        if result["results"]:
            return int(result["results"][0]["uid"])
        time.sleep(0.1)
    raise AssertionError(f"no message with subject {subject!r} found in {mailbox!r}")


def _message_exists(cfg, mailbox: str, subject: str) -> bool:
    """True iff at least one message in ``mailbox`` matches ``subject``."""
    try:
        result = read.search(
            cfg,
            SearchInput(mailbox=mailbox, limit=500, offset=0, subject=subject),
        )
    except RuntimeError:
        return False
    return bool(result["results"])


def _unique_subject(tag: str) -> str:
    """Generate a subject unique to this test function to avoid cross-test bleed."""
    return f"D-{tag}-{os.urandom(4).hex()}"


# ---------------------------------------------------------------------------
# Move / copy
# ---------------------------------------------------------------------------


def test_move_email_between_folders(cfg, deliver):
    organize.create_folder(cfg, CreateFolderInput(mailbox="Archive"))
    subject = _unique_subject("move")
    deliver(subject=subject)
    uid = _find_uid_by_subject(cfg, "INBOX", subject)

    result = organize.move_email(
        cfg,
        MoveEmailInput(source="INBOX", destination="Archive", uids=[uid]),
    )
    assert result["moved"] == 1
    assert result["destination"] == "Archive"

    assert not _message_exists(cfg, "INBOX", subject)
    assert _message_exists(cfg, "Archive", subject)


def test_copy_email_keeps_original(cfg, deliver):
    organize.create_folder(cfg, CreateFolderInput(mailbox="Backup"))
    subject = _unique_subject("copy")
    deliver(subject=subject)
    uid = _find_uid_by_subject(cfg, "INBOX", subject)

    result = organize.copy_email(
        cfg,
        CopyEmailInput(source="INBOX", destination="Backup", uids=[uid]),
    )
    assert result["copied"] == 1

    assert _message_exists(cfg, "INBOX", subject)
    assert _message_exists(cfg, "Backup", subject)


# ---------------------------------------------------------------------------
# Flags
# ---------------------------------------------------------------------------


def test_mark_emails_read_and_flagged(cfg, deliver):
    subj_a = _unique_subject("flag-a")
    subj_b = _unique_subject("flag-b")
    deliver(subject=subj_a)
    deliver(subject=subj_b)
    uid_a = _find_uid_by_subject(cfg, "INBOX", subj_a)

    organize.mark(
        cfg,
        MarkFlagsInput(
            mailbox="INBOX", uids=[uid_a], mark_read=True, mark_flagged=True,
        ),
    )

    flagged = read.search(
        cfg, SearchInput(mailbox="INBOX", limit=500, flagged=True),
    )
    flagged_uids = [row["uid"] for row in flagged["results"]]
    assert uid_a in flagged_uids

    seen = read.search(
        cfg, SearchInput(mailbox="INBOX", limit=500, unseen=False),
    )
    seen_uids = [row["uid"] for row in seen["results"]]
    assert uid_a in seen_uids


def test_mark_emails_unread_again(cfg, deliver):
    subject = _unique_subject("unread")
    deliver(subject=subject)
    uid = _find_uid_by_subject(cfg, "INBOX", subject)

    organize.mark(
        cfg, MarkFlagsInput(mailbox="INBOX", uids=[uid], mark_read=True),
    )
    seen = read.search(cfg, SearchInput(mailbox="INBOX", limit=500, unseen=False))
    assert uid in [row["uid"] for row in seen["results"]]

    organize.mark(
        cfg, MarkFlagsInput(mailbox="INBOX", uids=[uid], mark_read=False),
    )
    unseen = read.search(cfg, SearchInput(mailbox="INBOX", limit=500, unseen=True))
    assert uid in [row["uid"] for row in unseen["results"]]

    seen_after = read.search(cfg, SearchInput(mailbox="INBOX", limit=500, unseen=False))
    assert uid not in [row["uid"] for row in seen_after["results"]]


# ---------------------------------------------------------------------------
# Delete (trash vs permanent)
# ---------------------------------------------------------------------------


def test_delete_emails_moves_to_trash_by_default(cfg, deliver):
    # Account config defaults to "Trash" for trash_mailbox — make sure it exists.
    organize.create_folder(cfg, CreateFolderInput(mailbox="Trash"))
    subject = _unique_subject("trash")
    deliver(subject=subject)
    uid = _find_uid_by_subject(cfg, "INBOX", subject)

    result = organize.delete_email(
        cfg,
        DeleteEmailInput(
            mailbox="INBOX", uids=[uid], permanent=False, confirm=False,
        ),
    )
    assert result["mode"] == "trash"
    assert result["affected"] == 1

    assert not _message_exists(cfg, "INBOX", subject)
    assert _message_exists(cfg, "Trash", subject)


def test_delete_emails_permanent_requires_env_and_confirm(cfg, deliver, monkeypatch):
    subject = _unique_subject("perm")
    deliver(subject=subject)
    uid = _find_uid_by_subject(cfg, "INBOX", subject)

    # 1) Env NOT set, confirm=True → refused.
    monkeypatch.delenv("MAIL_MCP_ALLOW_PERMANENT_DELETE", raising=False)
    with pytest.raises(organize.OperationDisabled):
        organize.delete_email(
            cfg,
            DeleteEmailInput(
                mailbox="INBOX", uids=[uid], permanent=True, confirm=True,
            ),
        )
    assert _message_exists(cfg, "INBOX", subject)

    # 2) Env set, confirm=False → still refused.
    monkeypatch.setenv("MAIL_MCP_ALLOW_PERMANENT_DELETE", "true")
    with pytest.raises(organize.OperationDisabled):
        organize.delete_email(
            cfg,
            DeleteEmailInput(
                mailbox="INBOX", uids=[uid], permanent=True, confirm=False,
            ),
        )
    assert _message_exists(cfg, "INBOX", subject)

    # 3) Both gates open → message is expunged.
    result = organize.delete_email(
        cfg,
        DeleteEmailInput(
            mailbox="INBOX", uids=[uid], permanent=True, confirm=True,
        ),
    )
    assert result["mode"] == "permanent"
    assert result["affected"] == 1
    assert uid not in _uids_in(cfg, "INBOX")
    assert not _message_exists(cfg, "INBOX", subject)


# ---------------------------------------------------------------------------
# Folder CRUD
# ---------------------------------------------------------------------------


def test_create_folder_idempotent(cfg):
    first = organize.create_folder(cfg, CreateFolderInput(mailbox="TestFolder"))
    assert first["status"] == "created"
    # Second call must NOT raise — imap_client.create_folder short-circuits
    # when the folder already exists.
    second = organize.create_folder(cfg, CreateFolderInput(mailbox="TestFolder"))
    assert second["status"] == "created"


def test_rename_folder_happy_path(cfg):
    organize.create_folder(cfg, CreateFolderInput(mailbox="RenameA"))
    result = organize.rename_folder(
        cfg, RenameFolderInput(old_name="RenameA", new_name="RenameB"),
    )
    assert result["status"] == "renamed"

    # Confirm via folder listing (and a search, which SELECTs the folder).
    from mail_mcp.tools.schemas import ListFoldersInput

    listing = read.list_folders(cfg, ListFoldersInput())
    names = {f["name"] for f in listing["folders"]}
    assert "RenameB" in names
    assert "RenameA" not in names

    import imaplib

    # RenameB should be selectable via search; RenameA must not exist.
    _ = read.search(cfg, SearchInput(mailbox="RenameB", limit=1))
    with pytest.raises((RuntimeError, imaplib.IMAP4.error)):
        read.search(cfg, SearchInput(mailbox="RenameA", limit=1))


def test_rename_folder_refuses_collision(cfg):
    organize.create_folder(cfg, CreateFolderInput(mailbox="CollideA"))
    organize.create_folder(cfg, CreateFolderInput(mailbox="CollideB"))
    with pytest.raises(RuntimeError, match="already exists"):
        organize.rename_folder(
            cfg, RenameFolderInput(old_name="CollideA", new_name="CollideB"),
        )


def test_delete_folder_refuses_non_empty_without_confirm(cfg, deliver):
    """The guard rejects non-empty folders without ``confirm=true``.

    The "delete after confirm=True" half of the original scenario is covered
    separately because GreenMail closes the IMAP socket on ``DELETE`` of a
    non-empty mailbox (it honours the MUST-be-empty recommendation in
    RFC 3501 §6.3.4 more strictly than most providers). The refuse-guard is
    the piece worth exercising here.
    """
    organize.create_folder(cfg, CreateFolderInput(mailbox="Busy"))
    subject = _unique_subject("busy")
    deliver(subject=subject)
    uid = _find_uid_by_subject(cfg, "INBOX", subject)
    organize.move_email(
        cfg, MoveEmailInput(source="INBOX", destination="Busy", uids=[uid]),
    )
    assert _message_exists(cfg, "Busy", subject)

    with pytest.raises(RuntimeError, match="not empty"):
        organize.delete_folder(
            cfg, DeleteFolderInput(mailbox="Busy", confirm=False),
        )
    # Still there — the refuse path did not swallow the messages.
    assert _message_exists(cfg, "Busy", subject)


def test_delete_folder_empty_succeeds(cfg):
    import imaplib

    organize.create_folder(cfg, CreateFolderInput(mailbox="Empty"))
    result = organize.delete_folder(
        cfg, DeleteFolderInput(mailbox="Empty", confirm=False),
    )
    assert result["status"] == "deleted"
    assert result["messages_lost"] == 0
    with pytest.raises((RuntimeError, imaplib.IMAP4.error)):
        read.search(cfg, SearchInput(mailbox="Empty", limit=1))


# ---------------------------------------------------------------------------
# Batch-size cap
# ---------------------------------------------------------------------------


def test_copy_email_batch_too_large_rejected(cfg):
    # The Pydantic schema caps uids at max_length=100; a 200-uid list is
    # rejected at schema validation time with ValidationError (pydantic's).
    from pydantic import ValidationError as PydanticValidationError

    organize.create_folder(cfg, CreateFolderInput(mailbox="Bulk"))
    with pytest.raises(PydanticValidationError):
        organize.copy_email(
            cfg,
            CopyEmailInput(
                source="INBOX",
                destination="Bulk",
                uids=list(range(1, 201)),
            ),
        )
