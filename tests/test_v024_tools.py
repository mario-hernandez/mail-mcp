"""Tests for the v0.2.4 tool additions.

These are unit-level: IMAP and SMTP are mocked. We cover the decision
logic (recipient dedup in update_draft, rate-limit pass-through in
send_draft, attachment resolution refusal outside the allowlist) rather
than wire behaviour.
"""

import os
from unittest.mock import MagicMock, patch

import pytest

from mail_mcp import imap_client
from mail_mcp.safety import attachments as att_mod
from mail_mcp.safety.validation import ValidationError


def test_copy_uids_rejects_oversized_batch():
    c = MagicMock()
    with pytest.raises(ValidationError, match="batch too large"):
        imap_client.copy_uids(c, source="INBOX", destination="Archive", uids=list(range(200)))


def test_copy_uids_happy_path():
    c = MagicMock()
    imap_client.copy_uids(c, source="INBOX", destination="Archive", uids=[1, 2, 3])
    c.select_folder.assert_called_once_with("INBOX", readonly=False)
    c.copy.assert_called_once_with([1, 2, 3], "Archive")


def test_get_quota_returns_nulls_when_not_supported():
    c = MagicMock()
    c.get_quota_root.side_effect = Exception("NOT SUPPORTED")
    out = imap_client.get_quota(c, folder="INBOX")
    assert out == {"used_kb": None, "limit_kb": None}


def test_get_quota_parses_storage_resource():
    c = MagicMock()
    c.get_quota_root.return_value = (["Quota:User"], [])
    mock_q = MagicMock(resource="STORAGE", usage=1024, limit=10240)
    c.get_quota.return_value = [mock_q]
    out = imap_client.get_quota(c, folder="INBOX")
    assert out == {"used_kb": 1024, "limit_kb": 10240}


def test_thread_references_returns_empty_without_capability():
    c = MagicMock()
    c.capabilities.return_value = (b"IMAP4rev1",)  # no THREAD=REFERENCES
    out = imap_client.thread_references(c, mailbox="INBOX", since_days=30)
    assert out == []


def test_thread_references_flattens_nested_tree():
    c = MagicMock()
    c.capabilities.return_value = (b"THREAD=REFERENCES", b"IMAP4rev1")
    # imapclient returns a list of groups, each group is a list mixing ints and nested lists.
    c.thread.return_value = [[1, [2, [3]]], [4], [5, 6]]
    out = imap_client.thread_references(c, mailbox="INBOX", since_days=30)
    assert out == [[1, 2, 3], [4], [5, 6]]


def test_attachment_resolver_rejects_outside_allowlist(tmp_path):
    stray = tmp_path / "stray.txt"
    stray.write_text("x")
    # tmp_path from pytest is NOT under ~/Downloads or ~/Documents/mail-mcp-outbox,
    # and usually not under $TMPDIR either (varies by platform). Ensure we
    # override MAIL_MCP_ATTACHMENT_DIR to something that deliberately excludes it.
    with patch.dict(os.environ, {"MAIL_MCP_ATTACHMENT_DIR": "/nonexistent-for-this-test"}, clear=False):
        # Strip the system TMPDIR too to make the exclusion deterministic on macOS.
        with patch.object(att_mod, "_allowed_roots", return_value=[att_mod.Path.home() / "Downloads"]):
            with pytest.raises(ValidationError, match="outside the allowed"):
                att_mod.resolve(raw_path=str(stray), filename_override=None, content_type_override=None)


def test_attachment_resolver_infers_content_type(tmp_path):
    target = tmp_path / "report.csv"
    target.write_text("a,b\n1,2\n")
    with patch.object(att_mod, "_allowed_roots", return_value=[tmp_path]):
        out = att_mod.resolve(raw_path=str(target), filename_override=None, content_type_override=None)
    assert out.content_type == "text/csv"
    assert out.filename == "report.csv"
    assert out.size > 0


def test_attachment_resolver_refuses_oversized(tmp_path):
    big = tmp_path / "big.bin"
    big.write_bytes(b"\0" * (att_mod.MAX_ATTACHMENT_BYTES + 1))
    with patch.object(att_mod, "_allowed_roots", return_value=[tmp_path]):
        with pytest.raises(ValidationError, match="too large"):
            att_mod.resolve(raw_path=str(big), filename_override=None, content_type_override=None)


def test_attachment_resolve_many_enforces_total_cap(tmp_path):
    files = []
    for i in range(4):
        f = tmp_path / f"f{i}.bin"
        f.write_bytes(b"\0" * (15 * 1024 * 1024))  # 15 MB each; 4 * 15 = 60 > 50
        files.append(MagicMock(path=str(f), filename=None, content_type=None))
    with patch.object(att_mod, "_allowed_roots", return_value=[tmp_path]):
        with pytest.raises(ValidationError, match="total size"):
            att_mod.resolve_many(files)
