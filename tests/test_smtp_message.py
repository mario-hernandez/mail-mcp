import pytest

from mail_mcp.safety.validation import ValidationError
from mail_mcp.smtp_client import build_message


def test_build_message_basic():
    msg = build_message(
        from_addr="a@b.com",
        to=["c@d.com"],
        subject="hello",
        body_text="world",
    )
    assert msg["From"] == "a@b.com"
    assert msg["To"] == "c@d.com"
    assert msg["Subject"] == "hello"
    assert msg["Message-ID"] is not None


def test_build_message_rejects_header_injection_in_subject():
    with pytest.raises(ValidationError):
        build_message(
            from_addr="a@b.com",
            to=["c@d.com"],
            subject="hello\r\nBcc: attacker@evil.com",
            body_text="x",
        )


def test_build_message_rejects_header_injection_in_to():
    with pytest.raises(ValidationError):
        build_message(
            from_addr="a@b.com",
            to=["c@d.com\r\nBcc: attacker@evil.com"],
            subject="hello",
            body_text="x",
        )


def test_build_message_requires_recipients():
    with pytest.raises(ValidationError):
        build_message(
            from_addr="a@b.com",
            to=[],
            subject="hello",
            body_text="x",
        )
