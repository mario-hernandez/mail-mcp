"""Regression tests for the three HIGH findings of the Opus line-by-line audit.

1. imap_client.thread_references called client.thread() with the wrong
   positional order ("REFERENCES", "UTF-8", criteria), putting "UTF-8" in
   the criteria slot — every server rejected it, so THREAD silently
   degraded to a singleton on all servers. The prior test used a Mock with
   a fixed return_value that ignored its arguments, so the bug was invisible.
2. update_draft flattened an HTML-only draft's body to an empty text/plain
   part when preserving the body (get_body(("plain",)) -> None -> "").
   Append-then-delete made the loss permanent.
3. list_folders fed the LLM-controlled `pattern` to the IMAP LIST command
   with no CR/LF / control-char guard — a CRLF IMAP-injection vector.
"""

from __future__ import annotations

import email
import email.policy
from email.message import EmailMessage
from unittest.mock import MagicMock

import pytest

from mail_mcp import imap_client
from mail_mcp.safety.validation import ValidationError


# ---------- HIGH #1: client.thread argument order ----------

def test_thread_references_passes_correct_arguments():
    """client.thread must receive algorithm/criteria/charset in the right slots.

    Asserts the actual call args (the old Mock-with-fixed-return test could
    not catch the swapped positional order).
    """
    client = MagicMock()
    client.capabilities.return_value = [b"IMAP4rev1", b"THREAD=REFERENCES"]
    client.thread.return_value = [[1, 2], [3]]

    groups = imap_client.thread_references(client, mailbox="INBOX", since_days=30)

    assert client.thread.call_count == 1
    _args, kwargs = client.thread.call_args
    # Must be keyword (or correctly-ordered) — algorithm REFERENCES, charset UTF-8,
    # criteria a list, NEVER charset="UTF-8" in the criteria slot.
    assert kwargs.get("algorithm") == "REFERENCES"
    assert kwargs.get("charset") == "UTF-8"
    assert isinstance(kwargs.get("criteria"), list)
    assert kwargs["criteria"][0] == "SINCE"
    # And the result is flattened into UID groups.
    assert groups == [[1, 2], [3]]


def test_thread_references_empty_without_capability():
    client = MagicMock()
    client.capabilities.return_value = [b"IMAP4rev1"]
    assert imap_client.thread_references(client, mailbox="INBOX") == []
    client.thread.assert_not_called()


# ---------- HIGH #2: HTML-only draft body preservation ----------

def _html_only_draft_bytes() -> bytes:
    m = EmailMessage(policy=email.policy.default)
    m["From"] = "me@example.com"
    m["To"] = "you@example.com"
    m["Subject"] = "Original subject"
    m["Message-ID"] = "<orig@example.com>"
    # HTML-only: set_content with subtype html, no text/plain alternative.
    m.set_content("<html><body><p>Important <b>HTML</b> body.</p></body></html>", subtype="html")
    return m.as_bytes()


def test_update_draft_preserves_html_only_body(monkeypatch):
    """Updating only the subject must keep the HTML body, not flatten it to ''."""
    from contextlib import contextmanager
    from pathlib import Path

    from mail_mcp.config import AccountModel, Config, ConfigModel
    from mail_mcp.credentials import AuthCredential
    from mail_mcp.tools.drafts import update_draft
    from mail_mcp.tools.schemas import UpdateDraftInput

    acct = AccountModel(
        alias="t", email="me@example.com",
        imap_host="imap.example.com", smtp_host="smtp.example.com",
        drafts_mailbox="Drafts", trash_mailbox="Trash",
    )
    cfg = Config(path=Path("/tmp/x"), model=ConfigModel(accounts=[acct]))
    captured = {}

    @contextmanager
    def fake_connect(account, creds):
        c = MagicMock()
        c.list_folders.return_value = [
            ([b"\\HasNoChildren"], "/", "INBOX"),
            ([b"\\HasNoChildren", b"\\Drafts"], "/", "Drafts"),
        ]
        yield c

    def fake_fetch_raw(c, *, mailbox, uid):
        return _html_only_draft_bytes(), {}

    def fake_save_draft(c, *, account, message_bytes):
        captured["bytes"] = message_bytes
        return "Drafts", 2

    monkeypatch.setattr(imap_client, "connect", fake_connect)
    monkeypatch.setattr(imap_client, "fetch_raw_message", fake_fetch_raw)
    monkeypatch.setattr(imap_client, "save_draft", fake_save_draft)
    monkeypatch.setattr(imap_client, "delete_uids", lambda *a, **k: 1)
    monkeypatch.setattr(
        "mail_mcp.tools.drafts.resolve_auth",
        lambda a: AuthCredential(kind="password", username=a.email, secret="x"),
    )

    update_draft(cfg, UpdateDraftInput(account="t", uid=1, subject="New subject"))

    rebuilt = email.message_from_bytes(captured["bytes"], policy=email.policy.default)
    body = rebuilt.get_body(preferencelist=("html", "plain"))
    assert body is not None
    assert body.get_content_subtype() == "html", "HTML body must be preserved, not flattened"
    assert "Important" in body.get_content()
    assert "<b>HTML</b>" in body.get_content()
    assert rebuilt["Subject"] == "New subject"


# ---------- HIGH #3: list_folders pattern CRLF guard ----------

@pytest.mark.parametrize("bad", ["INBOX\r\nA001 DELETE x", "x\ry", "x\ny", "x\x00y", "x\x01y"])
def test_list_folders_rejects_crlf_and_control_chars_in_pattern(bad):
    client = MagicMock()
    with pytest.raises(ValidationError):
        imap_client.list_folders(client, pattern=bad)
    client.list_folders.assert_not_called()


def test_list_folders_allows_legitimate_wildcards():
    """The guard must NOT reject the legitimate IMAP * and % wildcards."""
    client = MagicMock()
    client.list_folders.return_value = []
    for ok in ["*", "%", "INBOX/*", "INBOX.%"]:
        imap_client.list_folders(client, pattern=ok)
    assert client.list_folders.call_count == 4
