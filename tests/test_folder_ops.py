"""Unit tests for folder management helpers.

The IMAP client is mocked; we care about the decision logic (empty-folder
refusal, idempotency, validation wiring), not about the wire behaviour of
any particular server.
"""

from unittest.mock import MagicMock

import pytest

from mail_mcp import imap_client
from mail_mcp.safety.validation import ValidationError


def _fake_client(*, exists: bool = True, message_count: int = 0) -> MagicMock:
    c = MagicMock()
    c.folder_exists.return_value = exists
    c.folder_status.return_value = {b"MESSAGES": message_count}
    return c


def test_create_folder_idempotent_when_present():
    c = _fake_client(exists=True)
    imap_client.create_folder(c, mailbox="Archive/2026")
    c.create_folder.assert_not_called()


def test_create_folder_creates_when_absent():
    c = _fake_client(exists=False)
    imap_client.create_folder(c, mailbox="Archive/2026")
    c.create_folder.assert_called_once_with("Archive/2026")


def test_create_folder_rejects_wildcard():
    c = _fake_client()
    with pytest.raises(ValidationError):
        imap_client.create_folder(c, mailbox="Archive/*")


def test_rename_folder_ok():
    c = _fake_client(exists=True)
    c.folder_exists.side_effect = [True, False]
    imap_client.rename_folder(c, old_name="Archivo", new_name="Archive")
    c.rename_folder.assert_called_once_with("Archivo", "Archive")


def test_rename_folder_refuses_when_destination_exists():
    c = _fake_client()
    c.folder_exists.side_effect = [True, True]
    with pytest.raises(RuntimeError, match="already exists"):
        imap_client.rename_folder(c, old_name="A", new_name="B")
    c.rename_folder.assert_not_called()


def test_rename_folder_refuses_when_source_missing():
    c = _fake_client()
    c.folder_exists.side_effect = [False, False]
    with pytest.raises(RuntimeError, match="does not exist"):
        imap_client.rename_folder(c, old_name="Ghost", new_name="Whatever")


def test_delete_folder_refuses_non_empty_without_confirm():
    c = _fake_client(exists=True, message_count=42)
    with pytest.raises(RuntimeError, match="not empty"):
        imap_client.delete_folder(c, mailbox="Archivo", allow_non_empty=False)
    c.delete_folder.assert_not_called()


def test_delete_folder_allows_non_empty_with_confirm():
    c = _fake_client(exists=True, message_count=42)
    removed = imap_client.delete_folder(c, mailbox="Archivo", allow_non_empty=True)
    assert removed == 42
    c.delete_folder.assert_called_once_with("Archivo")


def test_delete_folder_empty_without_confirm():
    c = _fake_client(exists=True, message_count=0)
    removed = imap_client.delete_folder(c, mailbox="Archivo", allow_non_empty=False)
    assert removed == 0
    c.delete_folder.assert_called_once_with("Archivo")


def test_delete_folder_refuses_missing():
    c = _fake_client(exists=False)
    with pytest.raises(RuntimeError, match="does not exist"):
        imap_client.delete_folder(c, mailbox="Ghost", allow_non_empty=False)
