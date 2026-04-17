"""Entry point for the ``mail-mcp`` console script."""

from __future__ import annotations

import argparse
import asyncio
import getpass
import sys

from . import __version__
from .config import AccountModel, Config, ConfigModel, load, save
from .keyring_store import get_password, set_password
from .server import run_stdio


def _cmd_serve(_args: argparse.Namespace) -> int:
    asyncio.run(run_stdio())
    return 0


def _cmd_add_account(args: argparse.Namespace) -> int:
    cfg = load()
    password = getpass.getpass(prompt=f"Password for {args.email} (hidden): ")
    if not password:
        print("empty password; aborting.", file=sys.stderr)
        return 2
    set_password(args.alias, args.email, password)
    account = AccountModel(
        alias=args.alias,
        email=args.email,
        imap_host=args.imap_host,
        imap_port=args.imap_port,
        smtp_host=args.smtp_host,
        smtp_port=args.smtp_port,
        imap_use_ssl=True,
        smtp_starttls=args.smtp_starttls,
        drafts_mailbox=args.drafts_mailbox,
        trash_mailbox=args.trash_mailbox,
    )
    accounts = [a for a in cfg.model.accounts if a.alias != args.alias]
    accounts.append(account)
    cfg.model = ConfigModel(
        default_alias=cfg.model.default_alias or args.alias,
        accounts=accounts,
    )
    save(cfg)
    print(f"account {args.alias!r} saved to {cfg.path}")
    return 0


def _cmd_list_accounts(_args: argparse.Namespace) -> int:
    cfg = load()
    if not cfg.model.accounts:
        print("no accounts configured.")
        return 0
    print(f"config: {cfg.path}")
    for a in cfg.model.accounts:
        marker = "*" if a.alias == cfg.model.default_alias else " "
        print(f" {marker} {a.alias:<20} {a.email} (imap={a.imap_host}:{a.imap_port})")
    return 0


def _cmd_check(args: argparse.Namespace) -> int:
    cfg = load()
    account = cfg.account(args.alias)
    try:
        get_password(account.alias, account.email)
    except RuntimeError as exc:
        print(f"keyring check failed: {exc}", file=sys.stderr)
        return 3
    print(f"OK: credentials for {account.alias} are available in the keyring.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mail-mcp", description="mail-mcp CLI")
    parser.add_argument("--version", action="version", version=f"mail-mcp {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("serve", help="run the MCP server on stdio").set_defaults(func=_cmd_serve)

    add = sub.add_parser("add-account", help="add or update an account")
    add.add_argument("alias")
    add.add_argument("email")
    add.add_argument("--imap-host", required=True)
    add.add_argument("--imap-port", type=int, default=993)
    add.add_argument("--smtp-host", required=True)
    add.add_argument("--smtp-port", type=int, default=587)
    add.add_argument("--smtp-starttls", type=lambda v: v.lower() == "true", default=True)
    add.add_argument("--drafts-mailbox", default="Drafts")
    add.add_argument("--trash-mailbox", default="Trash")
    add.set_defaults(func=_cmd_add_account)

    sub.add_parser("list-accounts", help="list configured accounts").set_defaults(
        func=_cmd_list_accounts
    )

    check = sub.add_parser("check", help="verify keyring access for an account")
    check.add_argument("--alias", default=None)
    check.set_defaults(func=_cmd_check)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    raise SystemExit(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    main()
