"""OS keyring access for IMAP/SMTP passwords.

Passwords live in the platform's native credential store
(macOS Keychain, Linux libsecret / KWallet, Windows Credential Manager) and
are accessed through the :mod:`keyring` library. The configuration file stores
only the *alias* that identifies a credential; the password itself never
touches the filesystem managed by this project.
"""

from __future__ import annotations

from dataclasses import dataclass

import keyring
from keyring.errors import KeyringError

from .safety.validation import ValidationError, validate_alias

SERVICE_PREFIX = "mail-mcp"
# Username used when storing an OAuth refresh token. The real mailbox address
# is stored by the password entry; the refresh-token entry is keyed by a
# sentinel ("oauth2") so the two never collide in the keyring.
REFRESH_TOKEN_USERNAME = "oauth2"  # noqa: S105 — sentinel keyring username, not a credential


@dataclass(frozen=True)
class KeyringRef:
    alias: str

    @property
    def service(self) -> str:
        return f"{SERVICE_PREFIX}:{self.alias}"

    @property
    def refresh_service(self) -> str:
        return f"{SERVICE_PREFIX}:{self.alias}:refresh_token"


def set_password(alias: str, username: str, password: str) -> None:
    """Store ``password`` in the OS keyring under ``alias``."""
    validate_alias(alias)
    if not username or not password:
        raise ValidationError("username and password must not be empty")
    ref = KeyringRef(alias)
    try:
        keyring.set_password(ref.service, username, password)
    except KeyringError as exc:
        raise RuntimeError(f"keyring write failed for alias {alias!r}") from exc


def get_password(alias: str, username: str) -> str:
    """Read the password stored for ``alias``/``username``.

    Raises ``RuntimeError`` if the entry does not exist; the exception does
    not include the alias or username in the rendered message destined to
    the LLM caller.
    """
    validate_alias(alias)
    ref = KeyringRef(alias)
    try:
        password = keyring.get_password(ref.service, username)
    except KeyringError as exc:
        raise RuntimeError("keyring read failed") from exc
    if password is None:
        raise RuntimeError("credential not found in keyring")
    return password


def delete_password(alias: str, username: str) -> None:
    """Remove a stored credential; silently tolerate missing entries."""
    validate_alias(alias)
    ref = KeyringRef(alias)
    try:
        keyring.delete_password(ref.service, username)
    except keyring.errors.PasswordDeleteError:
        return
    except KeyringError as exc:
        raise RuntimeError("keyring delete failed") from exc


def set_refresh_token(alias: str, token: str) -> None:
    """Store an OAuth refresh token for ``alias`` in the OS keyring.

    The refresh token lives under a separate service name
    (``mail-mcp:<alias>:refresh_token``) and a sentinel username so a single
    alias can hold both a password (rare) and a refresh token without one
    overwriting the other. Refresh tokens are long-lived secrets; callers
    must never log or print the returned value.
    """
    validate_alias(alias)
    if not token:
        raise ValidationError("refresh token must not be empty")
    ref = KeyringRef(alias)
    try:
        keyring.set_password(ref.refresh_service, REFRESH_TOKEN_USERNAME, token)
    except KeyringError as exc:
        raise RuntimeError(f"keyring write failed for alias {alias!r}") from exc


def get_refresh_token(alias: str) -> str:
    """Read the refresh token stored for ``alias``.

    Raises ``RuntimeError`` if no refresh token has been saved — typically
    because the account was configured with ``auth=password`` or the OAuth
    flow has not completed yet.
    """
    validate_alias(alias)
    ref = KeyringRef(alias)
    try:
        token = keyring.get_password(ref.refresh_service, REFRESH_TOKEN_USERNAME)
    except KeyringError as exc:
        raise RuntimeError("keyring read failed") from exc
    if token is None:
        raise RuntimeError("refresh token not found in keyring")
    return token


def delete_refresh_token(alias: str) -> None:
    """Remove a stored refresh token; tolerate missing entries."""
    validate_alias(alias)
    ref = KeyringRef(alias)
    try:
        keyring.delete_password(ref.refresh_service, REFRESH_TOKEN_USERNAME)
    except keyring.errors.PasswordDeleteError:
        return
    except KeyringError as exc:
        raise RuntimeError("keyring delete failed") from exc
