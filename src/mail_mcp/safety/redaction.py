"""Redaction helpers for logs and error surfaces.

Log records and tool-result errors are the two most common places where secrets
and PII leak out of an email server. These helpers keep that surface clean.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

REDACTED = "[REDACTED]"

SECRET_KEYS = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "token",
        "access_token",
        "refresh_token",
        "client_secret",
        "authorization",
        "api_key",
        "credential",
        "credentials",
        "body",
        "body_html",
        "body_text",
        "content_base64",
    }
)


def redact(value: Any) -> Any:
    """Recursively redact sensitive keys in a JSON-like structure."""
    if isinstance(value, Mapping):
        return {
            k: (REDACTED if k.lower() in SECRET_KEYS else redact(v))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [redact(v) for v in value]
    if isinstance(value, tuple):
        return tuple(redact(v) for v in value)
    return value


def sanitize_error(exc: BaseException) -> dict[str, str]:
    """Return a structured summary of an exception safe to send to the LLM.

    Library error messages sometimes contain raw IMAP/SMTP command snippets
    that include usernames or authentication tokens. We surface only the
    exception class name plus a short, human-readable message with secret-like
    substrings redacted.
    """
    message = str(exc) or exc.__class__.__name__
    lowered = message.lower()
    for needle in ("login ", "auth=", "pass=", "password=", "xoauth2"):
        idx = lowered.find(needle)
        if idx != -1:
            message = message[:idx] + REDACTED
            break
    return {"type": exc.__class__.__name__, "message": message[:500]}
