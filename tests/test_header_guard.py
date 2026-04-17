from mail_mcp.safety.guards import sanitize_header


def test_sanitize_header_strips_crlf():
    assert "\r" not in sanitize_header("Hello\r\nBcc: evil@x.com")
    assert "\n" not in sanitize_header("Hello\r\nBcc: evil@x.com")


def test_sanitize_header_strips_zero_width():
    cleaned = sanitize_header("a\u200bb\u200cc\ufeffd")
    assert cleaned == "abcd"


def test_sanitize_header_caps_length():
    cleaned = sanitize_header("x" * 2000)
    assert len(cleaned) < 1000


def test_sanitize_header_empty_is_empty():
    assert sanitize_header(None) == ""
    assert sanitize_header("") == ""


def test_sanitize_header_preserves_plain_subject():
    subj = "Important: re your invoice"
    assert sanitize_header(subj) == subj
