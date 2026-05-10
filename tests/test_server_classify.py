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


def test_classify_send_not_enabled_from_send_disabled():
    """Default code = SEND_NOT_ENABLED; hint carries the full env-var recipe."""
    from mail_mcp.tools.send import SendDisabled

    out = _classify(SendDisabled("gate off"))
    assert out["code"] == "SEND_NOT_ENABLED"
    assert "MAIL_MCP_WRITE_ENABLED" in out["hint"]
    assert "MAIL_MCP_SEND_ENABLED" in out["hint"]
    # Remediation must mention restart so the LLM doesn't expect immediate
    # availability after the env-var edit.
    assert "restart" in out["hint"].lower()


def test_classify_send_requires_confirm_uses_distinct_code():
    """Missing ``confirm=true`` is a per-call fix — distinct code from env-var gate."""
    from mail_mcp.tools.send import SendDisabled

    out = _classify(SendDisabled(
        "send_email requires confirm=true on the call.",
        code=SendDisabled.REQUIRES_CONFIRM,
    ))
    assert out["code"] == "SEND_REQUIRES_CONFIRM"
    assert "confirm=true" in out["hint"]
    # Critically, the recipe for env-var gate must NOT appear here — that
    # would mislead the LLM into telling the user to edit their config.
    assert "MAIL_MCP_WRITE_ENABLED" not in out["hint"]


def test_classify_unknown_falls_back():
    out = _classify(RuntimeError("something weird happened"))
    assert out["code"] == "INTERNAL_ERROR"
    assert out["retryable"] is False
