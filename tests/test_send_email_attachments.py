"""``send_email`` must actually attach the files it is given.

Regression for the production bug where ``send_email`` accepted
``attachments`` in its schema but never resolved them and never passed
them to the MIME builder — it returned a success dict with a
``message_id`` while delivering a single-part ``text/plain`` with no
attachment. An agent believed 17 invoices had been sent; they arrived
empty.

The fix gives ``send_email`` parity with ``save_draft``: resolve the
attachments after the gates, pass them to ``build_message_with_bcc``,
and surface the actually-attached files in the response. A bad path
must abort the whole send (``resolve_many`` raises) rather than
silently delivering an attachment-less message.
"""

from __future__ import annotations

import tempfile
from email.message import EmailMessage
from pathlib import Path

import pytest

from mail_mcp import smtp_client
from mail_mcp.config import AccountModel, Config, ConfigModel
from mail_mcp.credentials import AuthCredential
from mail_mcp.safety.validation import ValidationError
from mail_mcp.tools import send as send_mod
from mail_mcp.tools.schemas import SendEmailInput


def _account() -> AccountModel:
    return AccountModel(
        alias="t",
        email="me@example.com",
        imap_host="imap.example.com",
        smtp_host="smtp.example.com",
    )


def _cfg() -> Config:
    return Config(path=Path("/tmp/x"), model=ConfigModel(accounts=[_account()]))


def _pdf_under_downloads() -> Path:
    """Create a real PDF-ish file under ~/Downloads (an allowed attachment root)."""
    fh = tempfile.NamedTemporaryFile(
        prefix="send_email_test_",
        suffix=".pdf",
        dir=Path.home() / "Downloads",
        delete=False,
    )
    fh.write(b"%PDF-1.4\n" + b"invoice bytes " * 100)
    fh.close()
    return Path(fh.name)


@pytest.fixture(autouse=True)
def _enable_send(monkeypatch):
    monkeypatch.setenv("MAIL_MCP_WRITE_ENABLED", "true")
    monkeypatch.setenv("MAIL_MCP_SEND_ENABLED", "true")
    send_mod._reset_for_tests()
    yield
    send_mod._reset_for_tests()


@pytest.fixture(autouse=True)
def _no_real_auth(monkeypatch):
    monkeypatch.setattr(
        "mail_mcp.tools.send.resolve_auth",
        lambda a: AuthCredential(kind="password", username=a.email, secret="x"),
    )


def test_send_email_attaches_the_pdf_and_stays_multipart(monkeypatch):
    """The headline regression: the built message must be multipart with the PDF."""
    captured = {}

    def fake_send(account, creds, msg, *, bcc=None):
        captured["msg"] = msg
        captured["bcc"] = bcc
        return "<test-message-id@example.com>"

    monkeypatch.setattr(smtp_client, "send", fake_send)

    pdf = _pdf_under_downloads()
    try:
        result = send_mod.send_email(
            _cfg(),
            SendEmailInput(
                account="t",
                to=["recipient@example.com"],
                subject="Invoice",
                body="See attached invoice.",
                attachments=[{"path": str(pdf), "filename": "invoice.pdf"}],
                confirm=True,
            ),
        )
    finally:
        pdf.unlink(missing_ok=True)

    msg: EmailMessage = captured["msg"]
    assert msg.get_content_maintype() == "multipart", "message must be multipart"

    # There is a part with the PDF content type and the expected filename.
    pdf_parts = [
        p for p in msg.walk()
        if p.get_content_type() == "application/pdf"
    ]
    assert len(pdf_parts) == 1
    assert pdf_parts[0].get_filename() == "invoice.pdf"
    assert len(pdf_parts[0].get_payload(decode=True)) > 100

    # The text body survives.
    text_parts = [
        p for p in msg.walk()
        if p.get_content_type() == "text/plain"
    ]
    assert any("See attached invoice." in (p.get_content() or "") for p in text_parts)

    # The response reflects what actually shipped (derived from the resolved
    # attachments, not the raw input).
    assert len(result["attachments"]) == 1
    att = result["attachments"][0]
    assert att["filename"] == "invoice.pdf"
    assert att["content_type"] == "application/pdf"
    assert att["size"] > 100


def test_send_email_bad_path_aborts_without_sending(monkeypatch):
    """A non-existent / disallowed attachment path must raise and never send."""
    send_called = {"n": 0}

    def fake_send(*a, **k):
        send_called["n"] += 1
        return "<should-not-happen@example.com>"

    monkeypatch.setattr(smtp_client, "send", fake_send)

    # Path outside the allowlist AND non-existent.
    with pytest.raises(ValidationError):
        send_mod.send_email(
            _cfg(),
            SendEmailInput(
                account="t",
                to=["recipient@example.com"],
                subject="Invoice",
                body="See attached.",
                attachments=[{"path": "/etc/nonexistent-mail-mcp-xyz.pdf"}],
                confirm=True,
            ),
        )
    assert send_called["n"] == 0, "no email may be sent when an attachment fails to resolve"


def test_send_email_without_attachments_stays_single_part_text(monkeypatch):
    """No attachments → single-part text/plain (no regression to empty multipart)."""
    captured = {}

    def fake_send(account, creds, msg, *, bcc=None):
        captured["msg"] = msg
        return "<id@example.com>"

    monkeypatch.setattr(smtp_client, "send", fake_send)

    result = send_mod.send_email(
        _cfg(),
        SendEmailInput(
            account="t",
            to=["recipient@example.com"],
            subject="Plain note",
            body="Just text.",
            confirm=True,
        ),
    )
    msg: EmailMessage = captured["msg"]
    assert msg.get_content_maintype() == "text"
    assert msg.get_content_type() == "text/plain"
    assert result["attachments"] == []


def test_send_email_resolves_attachments_only_after_gates(monkeypatch):
    """A disabled send must reject BEFORE touching disk — no resolve on a bad path.

    If resolution happened before the enable gate, a disallowed path would
    raise ValidationError and mask the real reason (gate off). The gate must
    win.
    """
    monkeypatch.delenv("MAIL_MCP_SEND_ENABLED", raising=False)

    with pytest.raises(send_mod.SendDisabled) as ei:
        send_mod.send_email(
            _cfg(),
            SendEmailInput(
                account="t",
                to=["recipient@example.com"],
                subject="x",
                body="y",
                attachments=[{"path": "/etc/nonexistent-mail-mcp-xyz.pdf"}],
                confirm=True,
            ),
        )
    assert ei.value.code == send_mod.SendDisabled.NOT_ENABLED
