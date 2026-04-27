from mail_mcp.safety.redaction import REDACTED, redact, redact_text, sanitize_error


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


def test_sanitize_error_scrubs_quoted_login_trace():
    # Only the quoted-arguments form (typical of debug dumps) is scrubbed —
    # the bare ``LOGIN user pass`` form from error text is ambiguous because
    # it collides with server messages like ``LOGIN failed``.
    err = RuntimeError('LOGIN "alice@example.com" "s3cr3t"')
    out = sanitize_error(err)
    assert "s3cr3t" not in out["message"]
    assert out["type"] == "RuntimeError"


def test_sanitize_error_scrubs_password_kv():
    err = RuntimeError("request failed password=hunter2")
    out = sanitize_error(err)
    assert "hunter2" not in out["message"]


def test_sanitize_error_keeps_authenticationfailed_code():
    """Regression: previous scrubber truncated any message containing 'LOGIN '."""
    err = RuntimeError("LOGIN failed: AUTHENTICATIONFAILED")
    out = sanitize_error(err)
    assert "AUTHENTICATIONFAILED" in out["message"]


def test_sanitize_error_keeps_badcredentials_code():
    err = RuntimeError("SMTPAuthenticationError 535 5.7.8 BADCREDENTIALS")
    out = sanitize_error(err)
    assert "BADCREDENTIALS" in out["message"]


def test_redact_text_masks_emails_and_hosts():
    out = redact_text("cannot resolve imap.example.com for alice@example.com")
    assert "alice@example.com" not in out
    assert "imap.example.com" not in out


def test_redact_text_does_not_mask_plain_words():
    out = redact_text("AUTHENTICATIONFAILED on server side")
    assert "AUTHENTICATIONFAILED" in out


def test_sanitize_error_truncates():
    err = ValueError("x" * 1000)
    out = sanitize_error(err)
    assert len(out["message"]) <= 500


def test_sanitize_error_scrubs_http_authorization_header():
    err = RuntimeError(
        "401 from Graph: Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.foo"
    )
    out = sanitize_error(err)
    assert "eyJ0eXAi" not in out["message"]
    assert "Bearer" not in out["message"]


def test_sanitize_error_scrubs_bare_bearer_token():
    err = RuntimeError("oauth2_login failed for Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")
    out = sanitize_error(err)
    assert "eyJhbGci" not in out["message"]


def test_sanitize_error_scrubs_xoauth2_sasl_payload():
    """The SASL XOAUTH2 string ``auth=Bearer <token>`` must never leak."""
    err = RuntimeError(
        "SMTP 535: rejected user=u@example.com\x01auth=Bearer ABCDEFGH12345.token\x01\x01"
    )
    out = sanitize_error(err)
    assert "ABCDEFGH12345" not in out["message"]


def test_redact_text_keeps_short_bearer_word():
    """The literal English word ``Bearer`` must not be over-eagerly redacted."""
    out = redact_text("Bearer of bad news arrived.")
    # Short word after ``Bearer`` is below the 8-char token threshold.
    assert "Bearer of bad news" in out
