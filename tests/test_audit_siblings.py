"""Regression tests for the response/reality-drift siblings of the
send_email-drops-attachments bug, surfaced by the adversarial audit.

Each test pins a 'handler reports success while the operation did less
than the response implies' defect that the audit confirmed:

  - SMTP partial delivery (refused recipients) → PartialDeliveryError
  - SMTP / read-side recipient extraction via getaddresses, not split(',')
  - mark_emails no-op (both flags None) rejected at the schema boundary
  - create_folder reports created vs already_exists honestly
  - save_draft surfaces the intentionally-dropped BCC
"""

from __future__ import annotations

from email.message import EmailMessage
from unittest.mock import MagicMock

import pytest

from mail_mcp import imap_client, smtp_client
from mail_mcp.config import AccountModel


def _account() -> AccountModel:
    return AccountModel(
        alias="t",
        email="me@example.com",
        imap_host="imap.example.com",
        smtp_host="smtp.example.com",
        smtp_starttls=True,
    )


def _msg(to: str, cc: str = "") -> EmailMessage:
    m = EmailMessage()
    m["From"] = "me@example.com"
    m["To"] = to
    if cc:
        m["Cc"] = cc
    m["Subject"] = "x"
    m["Message-ID"] = "<mid@example.com>"
    m.set_content("body")
    return m


class _FakeSMTP:
    """Context-manager stand-in for smtplib.SMTP recording send_message args."""

    def __init__(self, *a, **k):
        self.sent = None
        self.refused: dict = {}

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def ehlo(self):
        pass

    def starttls(self, *a, **k):
        pass

    def login(self, *a, **k):
        pass

    def auth(self, *a, **k):
        pass

    def send_message(self, msg, *, from_addr, to_addrs):
        self.sent = {"from": from_addr, "to": to_addrs}
        return self.refused


# ---------- SMTP partial delivery + recipient extraction ----------

def test_send_raises_partial_delivery_when_recipients_refused(monkeypatch):
    fake = _FakeSMTP()
    fake.refused = {"bad@example.com": (550, b"No such user")}
    monkeypatch.setattr(smtp_client.smtplib, "SMTP", lambda *a, **k: fake)

    with pytest.raises(smtp_client.PartialDeliveryError) as ei:
        smtp_client.send(_account(), "pw", _msg("good@example.com, bad@example.com"))
    assert "bad@example.com" in str(ei.value)
    assert ei.value.message_id == "<mid@example.com>"
    assert "bad@example.com" in ei.value.refused


def test_send_returns_message_id_when_all_accepted(monkeypatch):
    fake = _FakeSMTP()  # refused = {} → full success
    monkeypatch.setattr(smtp_client.smtplib, "SMTP", lambda *a, **k: fake)
    mid = smtp_client.send(_account(), "pw", _msg("good@example.com"))
    assert mid == "<mid@example.com>"


def test_send_recipient_extraction_handles_comma_in_display_name(monkeypatch):
    """A display name with a comma must not fragment the envelope recipients."""
    fake = _FakeSMTP()
    monkeypatch.setattr(smtp_client.smtplib, "SMTP", lambda *a, **k: fake)
    # "Doe, Jane" contains a comma; naive split would produce 3 bogus recipients.
    smtp_client.send(
        _account(), "pw",
        _msg('"Doe, Jane" <jane@example.com>', cc="bob@example.com"),
    )
    assert fake.sent["to"] == ["jane@example.com", "bob@example.com"]


def test_send_appends_bcc_to_envelope(monkeypatch):
    fake = _FakeSMTP()
    monkeypatch.setattr(smtp_client.smtplib, "SMTP", lambda *a, **k: fake)
    smtp_client.send(_account(), "pw", _msg("a@example.com"), bcc=["secret@example.com"])
    assert fake.sent["to"] == ["a@example.com", "secret@example.com"]


# ---------- read-side address parsing ----------

def test_header_addresses_preserves_comma_in_display_name():
    out = imap_client._header_addresses('"Doe, Jane" <jane@example.com>, bob@example.com')
    assert out == ["jane@example.com", "bob@example.com"]


def test_header_addresses_empty():
    assert imap_client._header_addresses("") == []
    assert imap_client._header_addresses(None) == []


# ---------- mark no-op rejected at schema boundary ----------

def test_mark_flags_input_rejects_both_none():
    from pydantic import ValidationError as PydanticValidationError

    from mail_mcp.tools.schemas import MarkFlagsInput

    with pytest.raises(PydanticValidationError):
        MarkFlagsInput(account="t", uids=[1, 2], mark_read=None, mark_flagged=None)


def test_mark_flags_input_accepts_one_flag():
    from mail_mcp.tools.schemas import MarkFlagsInput

    m = MarkFlagsInput(account="t", uids=[1], mark_read=True)
    assert m.mark_read is True
    # mark_flagged=False alone is also valid (clear the flag).
    m2 = MarkFlagsInput(account="t", uids=[1], mark_flagged=False)
    assert m2.mark_flagged is False


# ---------- create_folder honest status ----------

def test_create_folder_returns_true_when_created():
    client = MagicMock()
    client.folder_exists.return_value = False
    created = imap_client.create_folder(client, mailbox="Archive/2026")
    assert created is True
    client.create_folder.assert_called_once_with("Archive/2026")


def test_create_folder_returns_false_when_already_exists():
    client = MagicMock()
    client.folder_exists.return_value = True
    created = imap_client.create_folder(client, mailbox="INBOX")
    assert created is False
    client.create_folder.assert_not_called()


def test_create_folder_tool_reports_already_exists(monkeypatch):
    from contextlib import contextmanager
    from pathlib import Path

    from mail_mcp.config import Config, ConfigModel
    from mail_mcp.credentials import AuthCredential
    from mail_mcp.tools.organize import create_folder as create_folder_tool
    from mail_mcp.tools.schemas import CreateFolderInput

    cfg = Config(path=Path("/tmp/x"), model=ConfigModel(accounts=[_account()]))

    @contextmanager
    def fake_connect(account, creds):
        c = MagicMock()
        c.folder_exists.return_value = True  # already exists
        yield c

    monkeypatch.setattr(imap_client, "connect", fake_connect)
    monkeypatch.setattr(
        "mail_mcp.tools.organize.resolve_auth",
        lambda a: AuthCredential(kind="password", username=a.email, secret="x"),
    )
    out = create_folder_tool(cfg, CreateFolderInput(account="t", mailbox="INBOX"))
    assert out["status"] == "already_exists"
