"""Redaction helpers for logs and error surfaces.

Log records and tool-result errors are the two most common places where secrets
and PII leak out of an email server. These helpers keep that surface clean.
"""

from __future__ import annotations

import re
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

# Match ``user@host.tld`` (including IDN hosts and + aliases).
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")

# Match plausible hostnames (at least one dot, letters/digits/hyphen segments).
_HOST_RE = re.compile(r"(?<![@\w])(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.IGNORECASE)

# Patterns that identify runtime secrets in free-text error messages.
#
# Servers almost never echo credentials back in error strings — the common
# shapes we actually need to guard against come from app-level debug logging
# that leaked into an exception: ``XOAUTH2 <base64>``, ``AUTH PLAIN <b64>``,
# ``password=<value>``, etc. The previous scrubber over-matched on bare
# ``LOGIN `` and destroyed useful server error codes like
# ``AUTHENTICATIONFAILED`` / ``BADCREDENTIALS``.
_SECRET_SEQUENCES = re.compile(
    # XOAUTH2 / AUTH PLAIN / AUTH LOGIN followed by a base64 blob.
    r"\b(?:XOAUTH2|AUTH\s+PLAIN|AUTH\s+LOGIN)\s+[A-Za-z0-9+/=_\-]{8,}"
    # IMAP LOGIN protocol trace: LOGIN "user" "pass" — scrub the quoted pass.
    r'|\bLOGIN\s+"[^"]*"\s+"[^"]*"'
    # key=value / key: value forms where the key is a secret label.
    r"|\b(?:pass(?:word)?|secret|token|bearer|api[_-]?key)\s*[:=]\s*\S+",
    re.IGNORECASE,
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


def redact_text(message: str) -> str:
    """Redact email addresses, hostnames, and secret-like tokens in free text.

    Used for both log lines and tool error surfaces. Keeps server-provided
    failure codes (``AUTHENTICATIONFAILED``, ``NO``, ``BAD``, ...) legible
    because those are the actionable signal an LLM or the user needs.
    """
    cleaned = _SECRET_SEQUENCES.sub(REDACTED, message)
    cleaned = _EMAIL_RE.sub("[REDACTED_EMAIL]", cleaned)
    cleaned = _HOST_RE.sub("[REDACTED_HOST]", cleaned)
    return cleaned


def sanitize_error(exc: BaseException) -> dict[str, str]:
    """Return a structured summary of an exception safe to send to the LLM."""
    raw = str(exc) or exc.__class__.__name__
    return {"type": exc.__class__.__name__, "message": redact_text(raw)[:500]}
