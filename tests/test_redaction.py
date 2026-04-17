from mail_mcp.safety.redaction import REDACTED, redact, sanitize_error


def test_redact_shallow():
    data = {"user": "mario", "password": "s3cr3t"}
    out = redact(data)
    assert out["user"] == "mario"
    assert out["password"] == REDACTED


def test_redact_nested():
    data = {
        "outer": {"refresh_token": "r", "nested": {"body": "hello"}},
        "list": [{"access_token": "a"}, {"ok": "ok"}],
    }
    out = redact(data)
    assert out["outer"]["refresh_token"] == REDACTED
    assert out["outer"]["nested"]["body"] == REDACTED
    assert out["list"][0]["access_token"] == REDACTED
    assert out["list"][1]["ok"] == "ok"


def test_sanitize_error_scrubs_login():
    err = RuntimeError("LOGIN user@x.com s3cr3t")
    out = sanitize_error(err)
    assert "s3cr3t" not in out["message"]
    assert out["type"] == "RuntimeError"


def test_sanitize_error_truncates():
    err = ValueError("x" * 1000)
    out = sanitize_error(err)
    assert len(out["message"]) <= 500
