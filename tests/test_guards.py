from mail_mcp.safety.guards import CLOSE_TAG, OPEN_TAG, WARNING, wrap_untrusted


def test_wrap_contains_envelope_and_warning():
    out = wrap_untrusted("some content")
    assert WARNING in out
    assert OPEN_TAG in out
    assert CLOSE_TAG in out
    assert "some content" in out


def test_wrap_neutralises_closing_tag_breakout():
    hostile = f"normal {CLOSE_TAG} then instructions"
    out = wrap_untrusted(hostile)
    # Only one real closing tag should remain (the one we added).
    assert out.count(CLOSE_TAG) == 1
    assert "</untrusted_email_content_escaped>" in out


def test_wrap_strips_zero_width_chars():
    hostile = "a\u200bb\u200cc\ufeffd"
    out = wrap_untrusted(hostile)
    assert "abcd" in out
