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

    @field_validator("alias")
    @classmethod
    def _check_alias(cls, v: str) -> str:
        return validate_alias(v)

    @field_validator("email")
    @classmethod
    def _check_email(cls, v: str) -> str:
        return validate_email_address(v, field="email")

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
