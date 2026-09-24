"""Account configuration loader.

Accounts live in ``~/.config/mail-mcp/config.json`` with 0600 permissions.
The file stores only non-secret settings — host, port, username, TLS flags —
plus the alias used to look the password up from the OS keyring. Passwords
are never written to disk by this project.
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from .safety.validation import ValidationError, validate_alias, validate_email_address

AuthKind = Literal["password", "oauth-microsoft"]


class AccountModel(BaseModel):
    alias: str
    email: str
    imap_host: str
    imap_port: int = 993
    smtp_host: str
    smtp_port: int = 587
    imap_use_ssl: bool = True
    smtp_starttls: bool = True
    drafts_mailbox: str = "Drafts"
    trash_mailbox: str = "Trash"
    # auth mechanism. Default keeps every pre-existing account on password auth
    # so upgrading mail-mcp never silently invalidates a saved config.
    auth: AuthKind = "password"
    # Microsoft OAuth-specific parameters. Non-empty only when auth == "oauth-microsoft".
    oauth_tenant: str | None = None
    oauth_client_id: str | None = None
    # Optional SMTP login identity when it differs from ``email``. Microsoft 365
    # only accepts SMTP AUTH as the signed-in user's UPN: a mailbox whose UPN is
    # ``x@tenant.onmicrosoft.com`` but whose address is ``x@company.com``, or a
    # shared mailbox sent through a delegate with Send As, fails with
    # ``535 5.7.3`` unless the SASL user is the UPN. IMAP keeps using ``email``
    # (that is how delegated/shared mailbox access is addressed). ``None`` keeps
    # the historical behaviour: SMTP logs in as ``email``.
    smtp_username: str | None = None
    # Optional signature files (see ``signatures.py``). ``None`` uses the
    # default ``<config dir>/signatures/<alias>/firma.html`` / ``firma.txt``
    # when present — no file, no signature, as before. ``""`` disables that
    # part. Every path must resolve inside ``<config dir>/signatures/``.
    signature_html_path: str | None = None
    signature_text_path: str | None = None

    @field_validator("alias")
    @classmethod
    def _check_alias(cls, v: str) -> str:
        return validate_alias(v)

    @field_validator("email")
    @classmethod
    def _check_email(cls, v: str) -> str:
        return validate_email_address(v, field="email")

    @field_validator("smtp_username")
    @classmethod
    def _check_smtp_username(cls, v: str | None) -> str | None:
        if v is None:
            return None
        return validate_email_address(v, field="smtp_username")

    @field_validator("signature_html_path", "signature_text_path")
    @classmethod
    def _check_signature_path(cls, v: str | None) -> str | None:
        # Containment and size are enforced when the file is read (the
        # signatures directory is relative to wherever the config lives);
        # here we only refuse values no real path contains.
        if v and any(ord(c) < 32 or ord(c) == 127 for c in v):
            raise ValidationError("signature path must not contain control characters")
        return v

    @field_validator("imap_host", "smtp_host")
    @classmethod
    def _check_host(cls, v: str) -> str:
        if not v or any(c.isspace() for c in v):
            raise ValidationError("host must be a non-empty token without whitespace")
        return v

    @field_validator("imap_port", "smtp_port")
    @classmethod
    def _check_port(cls, v: int) -> int:
        if not (1 <= v <= 65535):
            raise ValidationError("port must be in [1, 65535]")
        return v


class ConfigModel(BaseModel):
    default_alias: str | None = None
    accounts: list[AccountModel] = Field(default_factory=list)


@dataclass
class Config:
    path: Path
    model: ConfigModel

    def account(self, alias: str | None = None) -> AccountModel:
        if not self.model.accounts:
            raise RuntimeError("no accounts configured; run 'mail-mcp setup'")
        if alias is None:
            alias = self.model.default_alias or self.model.accounts[0].alias
        for acct in self.model.accounts:
            if acct.alias == alias:
                return acct
        raise RuntimeError(f"unknown account alias {alias!r}")


# Optional AccountModel fields a user sets by hand (config edit or CLI flag)
# that re-running ``init`` / ``add-account`` on the same alias must keep —
# dropping them silently turned a working account into a broken one.
PRESERVED_ACCOUNT_FIELDS = ("smtp_username", "signature_html_path", "signature_text_path")


def preserved_account_fields(cfg: Config, alias: str) -> dict[str, str]:
    """The hand-set optional fields of an existing ``alias`` (``{}`` if new)."""
    prev = next((a for a in cfg.model.accounts if a.alias == alias), None)
    if prev is None:
        return {}
    return {
        name: getattr(prev, name)
        for name in PRESERVED_ACCOUNT_FIELDS
        if getattr(prev, name) is not None
    }


def default_config_path() -> Path:
    return Path(os.path.expanduser("~/.config/mail-mcp/config.json"))


def load(path: Path | None = None) -> Config:
    target = path or default_config_path()
    if not target.exists():
        return Config(path=target, model=ConfigModel())
    raw = target.read_text(encoding="utf-8")
    data = json.loads(raw) if raw.strip() else {}
    return Config(path=target, model=ConfigModel.model_validate(data))


def save(cfg: Config) -> None:
    cfg.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    payload = json.dumps(cfg.model.model_dump(), indent=2) + "\n"
    tmp = cfg.path.with_suffix(cfg.path.suffix + ".tmp")
    tmp.write_text(payload, encoding="utf-8")
    os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
    os.replace(tmp, cfg.path)
    os.chmod(cfg.path, stat.S_IRUSR | stat.S_IWUSR)
