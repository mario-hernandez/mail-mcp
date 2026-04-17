import pytest

from mail_mcp.safety.validation import (
    ValidationError,
    clamp_int,
    escape_imap_quoted,
    reject_control_chars,
    reject_crlf,
    strip_zero_width,
    validate_alias,
    validate_email_address,
    validate_header_value,
    validate_mailbox_name,
)


@pytest.mark.parametrize("value", ["a\r\nb", "a\nb", "a\rb"])
def test_reject_crlf(value):
    with pytest.raises(ValidationError):
        reject_crlf(value, field="subject")


def test_reject_control_chars():
    with pytest.raises(ValidationError):
        reject_control_chars("a\x00b", field="x")
    assert reject_control_chars("normal text", field="x") == "normal text"


def test_validate_header_value_rejects_long():
    with pytest.raises(ValidationError):
        validate_header_value("a" * 999, field="x")


def test_validate_email_address_ok():
    assert validate_email_address("a@b.com", field="to") == "a@b.com"


@pytest.mark.parametrize("addr", ["abc", "a@b", "a@@b.com", " a@b.com", "a b@c.com"])
def test_validate_email_address_rejects(addr):
    with pytest.raises(ValidationError):
        validate_email_address(addr, field="to")


def test_strip_zero_width():
    text = "a\u200bb\u200cc\ufeffd"
    assert strip_zero_width(text) == "abcd"


def test_escape_imap_quoted():
    assert escape_imap_quoted('he said "hi"') == 'he said \\"hi\\"'
    assert escape_imap_quoted("back\\slash") == "back\\\\slash"


@pytest.mark.parametrize("name", ["INBOX*", "bad%name", "x\x00y"])
def test_validate_mailbox_name_rejects(name):
    with pytest.raises(ValidationError):
        validate_mailbox_name(name)


def test_validate_mailbox_name_ok():
    assert validate_mailbox_name("INBOX/Archive") == "INBOX/Archive"


@pytest.mark.parametrize("alias", ["ok", "al_1-test.x", "A" * 64])
def test_validate_alias_ok(alias):
    assert validate_alias(alias) == alias


@pytest.mark.parametrize("alias", ["has space", "bad!", "A" * 65, ""])
def test_validate_alias_rejects(alias):
    with pytest.raises(ValidationError):
        validate_alias(alias)


def test_clamp_int():
    assert clamp_int(10, low=0, high=100, field="x") == 10
    with pytest.raises(ValidationError):
        clamp_int(200, low=0, high=100, field="x")
    with pytest.raises(ValidationError):
        clamp_int(True, low=0, high=100, field="x")
