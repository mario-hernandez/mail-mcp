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


@dataclass(frozen=True)
class KeyringRef:
    alias: str

    @property
    def service(self) -> str:
        return f"{SERVICE_PREFIX}:{self.alias}"


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
