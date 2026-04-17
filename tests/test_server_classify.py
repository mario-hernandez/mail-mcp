from mail_mcp.server import _classify


def test_classify_validation_error():
    from mail_mcp.safety.validation import ValidationError

    out = _classify(ValidationError("bad input"))
    assert out["code"] == "VALIDATION_ERROR"
    assert out["retryable"] is False
    assert "schema" in out["hint"].lower()


def test_classify_auth_failed():
    out = _classify(RuntimeError("AUTHENTICATIONFAILED server said no"))
    assert out["code"] == "AUTH_FAILED"
    assert "app" in out["hint"].lower()


def test_classify_timeout_is_retryable():
    out = _classify(TimeoutError("operation timed out"))
    assert out["code"] == "TIMEOUT"
    assert out["retryable"] is True


def test_classify_permission_denied_from_send_disabled():
    from mail_mcp.tools.send import SendDisabled

    out = _classify(SendDisabled("gate off"))
    assert out["code"] == "PERMISSION_DENIED"
    assert "MAIL_MCP" in out["hint"]


def test_classify_unknown_falls_back():
    out = _classify(RuntimeError("something weird happened"))
    assert out["code"] == "INTERNAL_ERROR"
    assert out["retryable"] is False
