"""Tests for the optional ``AccountModel.smtp_username`` (SMTP login identity).

Microsoft 365 only accepts SMTP AUTH as the signed-in user's UPN, while IMAP
accepts the mailbox address (or a shared mailbox the user has Full Access to).
``smtp_username`` overrides the SMTP SASL/login user only; IMAP, the ``From``
header and the SMTP envelope sender keep using ``email``.
"""

from __future__ import annotations

import argparse
import json
from email.message import EmailMessage
from unittest.mock import MagicMock

import pydantic
import pytest

from mail_mcp import config as config_mod
from mail_mcp.config import AccountModel
from mail_mcp.credentials import AuthCredential
from mail_mcp.smtp_client import _smtp_authenticate

UPN = "admin@tenant.onmicrosoft.com"


def _acct(**kw) -> AccountModel:
    base = dict(alias="work", email="m@company.es", imap_host="outlook.office365.com",
                smtp_host="smtp.office365.com")
    base.update(kw)
    return AccountModel(**base)


def _sasl(acct, cred) -> str:
    captured: list = []
    server = MagicMock()
    server.auth = lambda mech, cb, *, initial_response_ok=True: captured.append(cb(b""))
    _smtp_authenticate(server, acct, cred)
    assert len(captured) == 1
    return captured[0]


# --- authentication -----------------------------------------------------------

def test_oauth_sasl_user_is_the_override() -> None:
    cred = AuthCredential(kind="oauth2", username="m@company.es", secret="TOK")
    assert _sasl(_acct(smtp_username=UPN), cred) == f"user={UPN}\x01auth=Bearer TOK\x01\x01"


def test_oauth_sasl_user_defaults_to_credential_username() -> None:
    cred = AuthCredential(kind="oauth2", username="m@company.es", secret="TOK")
    acct = _acct()
    assert acct.smtp_username is None
    assert _sasl(acct, cred) == "user=m@company.es\x01auth=Bearer TOK\x01\x01"


def test_password_credential_logs_in_with_override() -> None:
    server = MagicMock()
    _smtp_authenticate(server, _acct(smtp_username=UPN),
                       AuthCredential(kind="password", username="m@company.es", secret="S"))
    server.login.assert_called_once_with(UPN, "S")


@pytest.mark.parametrize("override, expected", [(UPN, UPN), (None, "m@company.es")])
def test_legacy_str_credential_path_honours_override(override, expected) -> None:
    """The wizard's pre-save check passes a bare password string."""
    server = MagicMock()
    _smtp_authenticate(server, _acct(smtp_username=override), "pw")
    server.login.assert_called_once_with(expected, "pw")


def test_send_keeps_email_as_envelope_sender(monkeypatch) -> None:
    """Only the login changes: MAIL FROM stays ``email`` (the server decides Send As)."""
    from mail_mcp import smtp_client

    server = MagicMock()
    server.send_message.return_value = {}
    smtp_cls = MagicMock()
    smtp_cls.return_value.__enter__.return_value = server
    monkeypatch.setattr(smtp_client.smtplib, "SMTP", smtp_cls)

    msg = EmailMessage()
    msg["From"] = "m@company.es"
    msg["To"] = "x@example.com"
    msg["Message-ID"] = "<id@company.es>"
    msg.set_content("hi")
    acct = _acct(smtp_username=UPN, smtp_port=587, smtp_starttls=True)
    smtp_client.send(acct, AuthCredential(kind="password", username="m@company.es", secret="S"), msg)

    server.login.assert_called_once_with(UPN, "S")
    _, kwargs = server.send_message.call_args
    assert kwargs["from_addr"] == "m@company.es"


# --- validation and config round-trip ------------------------------------------

@pytest.mark.parametrize("bad", ["", "no-at-sign", "a@b.com\r\nX-Injected: 1", "a b@c.com", "a@b.com\x01x"])
def test_invalid_values_are_rejected(bad: str) -> None:
    with pytest.raises(pydantic.ValidationError):
        _acct(smtp_username=bad)


def test_old_config_without_the_field_still_loads(tmp_path) -> None:
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"default_alias": "work", "accounts": [
        {"alias": "work", "email": "m@company.es", "imap_host": "i.example.com", "smtp_host": "s.example.com"}]}))
    cfg = config_mod.load(path)
    assert cfg.account("work").smtp_username is None


def test_field_survives_save_and_load(tmp_path) -> None:
    path = tmp_path / "config.json"
    cfg = config_mod.load(path)
    cfg.model = config_mod.ConfigModel(default_alias="work", accounts=[_acct(smtp_username=UPN)])
    config_mod.save(cfg)
    assert config_mod.load(path).account("work").smtp_username == UPN


# --- CLI and tools ---------------------------------------------------------------

def _add_account_args(**kw) -> argparse.Namespace:
    base = dict(alias="work", email="m@company.es", imap_host="outlook.office365.com", imap_port=993,
                smtp_host="smtp.office365.com", smtp_port=587, smtp_starttls=True,
                drafts_mailbox="Drafts", trash_mailbox="Trash", smtp_username=None)
    base.update(kw)
    return argparse.Namespace(**base)


@pytest.fixture
def isolated_cli(tmp_path, monkeypatch):
    """Run ``add-account`` against a temp config and a fake keyring."""
    from mail_mcp import __main__ as cli

    path = tmp_path / "config.json"
    monkeypatch.setattr(config_mod, "default_config_path", lambda: path)
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": "secret")
    store: dict = {}
    monkeypatch.setattr(cli, "set_password", lambda a, e, p: store.__setitem__((a, e), p))

    def _get(a, e):
        if (a, e) not in store:
            raise RuntimeError("missing")
        return store[(a, e)]

    monkeypatch.setattr(cli, "get_password", _get)
    return cli, path


def test_add_account_keeps_existing_override_when_flag_omitted(isolated_cli) -> None:
    cli, path = isolated_cli
    cfg = config_mod.load(path)
    cfg.model = config_mod.ConfigModel(default_alias="work", accounts=[_acct(smtp_username=UPN)])
    config_mod.save(cfg)

    assert cli._cmd_add_account(_add_account_args(smtp_port=25)) == 0
    acct = config_mod.load(path).account("work")
    assert acct.smtp_port == 25
    assert acct.smtp_username == UPN


def test_add_account_flag_sets_the_override(isolated_cli) -> None:
    cli, path = isolated_cli
    assert cli._cmd_add_account(_add_account_args(smtp_username=UPN)) == 0
    assert config_mod.load(path).account("work").smtp_username == UPN


def test_get_account_info_reports_the_smtp_user() -> None:
    from mail_mcp.tools.read import get_account_info
    from mail_mcp.tools.schemas import AccountInfoInput

    cfg = config_mod.Config(path=None, model=config_mod.ConfigModel(
        default_alias="work", accounts=[_acct(smtp_username=UPN)]))
    info = get_account_info(cfg, AccountInfoInput(account="work"))
    assert info["smtp"]["username"] == UPN
    assert info["email"] == "m@company.es"
