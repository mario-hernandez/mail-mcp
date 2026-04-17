"""Input validation primitives.

Every helper here protects the boundary between untrusted input (LLM-controlled
tool arguments, email content received from the network) and trusted protocols
(IMAP, SMTP, filesystem). The rules are deliberately strict and fail closed.
"""

from __future__ import annotations

import re

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_CRLF = re.compile(r"[\r\n]")
_ZERO_WIDTH = re.compile(r"[\u200B\u200C\u200D\u2060\uFEFF\u00AD]")


class ValidationError(ValueError):
    """Raised when untrusted input fails validation at a safety boundary."""


def reject_crlf(value: str, *, field: str) -> str:
    """Reject carriage-return or line-feed in header-bound strings.

    Prevents SMTP header injection (e.g. ``To: a@x\\r\\nBcc: attacker@y``)
    and similar abuse across any field destined for an RFC 5322 header.
    """
    if _CRLF.search(value):
        raise ValidationError(f"{field!r} must not contain CR or LF characters")
    return value


def reject_control_chars(value: str, *, field: str) -> str:
    """Reject ASCII control characters in protocol-bound strings."""
    if _CONTROL_CHARS.search(value):
        raise ValidationError(f"{field!r} must not contain ASCII control characters")
    return value


def validate_header_value(value: str, *, field: str, max_length: int = 998) -> str:
    """Validate that a value is safe for use as an RFC 5322 header.

    Enforces: no CRLF, no NULs/controls, within RFC 5322 line length.
    """
    reject_crlf(value, field=field)
    reject_control_chars(value, field=field)
    if len(value) > max_length:
        raise ValidationError(f"{field!r} exceeds {max_length} chars (got {len(value)})")
    return value


def validate_email_address(value: str, *, field: str) -> str:
    """Minimal but strict email-address validation.

    Does not attempt to parse the full RFC 5321 grammar; instead enforces the
    invariants that matter for safety: single line, contains exactly one '@',
    no whitespace around it, no control characters.
    """
    validate_header_value(value, field=field, max_length=320)
    if any(c.isspace() for c in value):
        raise ValidationError(f"{field!r} must not contain whitespace")
    if value.count("@") != 1:
        raise ValidationError(f"{field!r} must contain exactly one '@'")
    local, _, domain = value.partition("@")
    if not local or not domain or "." not in domain:
        raise ValidationError(f"{field!r} is not a well-formed email address")
    return value


def strip_zero_width(value: str) -> str:
    """Remove invisible / zero-width characters used in homoglyph attacks."""
    return _ZERO_WIDTH.sub("", value)


def escape_imap_quoted(value: str) -> str:
    """Escape a value for inclusion in an IMAP quoted-string (RFC 3501).

    IMAP-quoted strings must not contain CR, LF or NUL. Backslash and
    double-quote must be escaped with a leading backslash.
    """
    reject_control_chars(value, field="imap-quoted-value")
    return value.replace("\\", "\\\\").replace('"', '\\"')


_MAILBOX_FORBIDDEN = re.compile(r"[\x00-\x1f\x7f*%]")


def validate_mailbox_name(value: str, *, field: str = "mailbox") -> str:
    """Reject IMAP wildcards and control characters in mailbox names.

    Wildcards (``*`` and ``%``) are meaningful in IMAP LIST/LSUB but have no
    place in a mailbox reference coming from an LLM tool call.
    """
    if not value:
        raise ValidationError(f"{field!r} must not be empty")
    if _MAILBOX_FORBIDDEN.search(value):
        raise ValidationError(f"{field!r} contains forbidden characters (control chars or wildcards)")
    if len(value) > 255:
        raise ValidationError(f"{field!r} exceeds 255 chars")
    return value


def validate_alias(value: str) -> str:
    """Validate a credential alias (used as a key in the OS keyring)."""
    if not re.fullmatch(r"[A-Za-z0-9_.\-]{1,64}", value):
        raise ValidationError(
            "account alias must match [A-Za-z0-9_.-]{1,64}"
        )
    return value


def clamp_int(value: int, *, low: int, high: int, field: str) -> int:
    """Clamp an integer to [low, high] or raise if it falls outside."""
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValidationError(f"{field!r} must be an integer")
    if value < low or value > high:
        raise ValidationError(f"{field!r} must be in [{low}, {high}] (got {value})")
    return value
