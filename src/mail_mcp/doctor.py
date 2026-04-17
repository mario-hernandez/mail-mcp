"""``mail-mcp doctor`` — self-diagnostic report.

Run this first when anything looks wrong. It prints, with no network calls
unless ``--connect`` is passed:

* the mail-mcp version and interpreter it loaded from,
* the keyring backend in effect on this machine,
* the config file path, its permissions, and the accounts it contains,
* which MCP clients (Claude Desktop, Claude Code, Codex CLI) reference
  mail-mcp, and
* the state of the environment gates (``MAIL_MCP_WRITE_ENABLED``,
  ``MAIL_MCP_SEND_ENABLED``, ``MAIL_MCP_ALLOW_PERMANENT_DELETE``,
  ``MAIL_MCP_LOG_LEVEL``).

The report is designed to be pasted verbatim into a bug report; nothing
secret (passwords, message bodies, tokens) is emitted.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import stat
import sys
from pathlib import Path

from . import __version__
from .config import load
from .keyring_store import SERVICE_PREFIX


_ENV_FLAGS = (
    "MAIL_MCP_WRITE_ENABLED",
    "MAIL_MCP_SEND_ENABLED",
    "MAIL_MCP_ALLOW_PERMANENT_DELETE",
    "MAIL_MCP_ALLOW_INSECURE_TLS",
    "MAIL_MCP_LOG_LEVEL",
    "MAIL_MCP_IMAP_CONNECT_TIMEOUT",
    "MAIL_MCP_IMAP_READ_TIMEOUT",
)

_MCP_CLIENT_HINTS = {
    "Claude Desktop": Path.home() / "Library/Application Support/Claude/claude_desktop_config.json",
    "Claude Code": Path.home() / ".claude.json",
    "Codex CLI": Path.home() / ".codex/config.toml",
}


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mail-mcp doctor", description=__doc__)
    parser.add_argument(
        "--connect",
        action="store_true",
        help="Also attempt to authenticate against each account's IMAP/SMTP servers.",
    )
    args = parser.parse_args(argv)

    _section("runtime")
    print(f"  mail-mcp         : {__version__}")
    print(f"  python           : {sys.version.split()[0]} ({sys.executable})")
    print(f"  platform         : {platform.platform()}")
    print(f"  keyring backend  : {_keyring_backend()}")

    _section("config")
    cfg = load()
    print(f"  path             : {cfg.path}")
    if cfg.path.exists():
        mode = stat.S_IMODE(cfg.path.stat().st_mode)
        flag = "ok" if mode == 0o600 else f"warn ({mode:o} — should be 600)"
        print(f"  permissions      : {mode:o} [{flag}]")
    else:
        print("  permissions      : file does not exist")
    print(f"  accounts         : {len(cfg.model.accounts)}")
    print(f"  default          : {cfg.model.default_alias or '(none)'}")
    for acct in cfg.model.accounts:
        default_marker = "*" if acct.alias == cfg.model.default_alias else " "
        print(
            f"   {default_marker} {acct.alias:<20} {acct.email}  "
            f"imap={acct.imap_host}:{acct.imap_port}  "
            f"smtp={acct.smtp_host}:{acct.smtp_port}"
        )
        status = _keyring_status(acct.alias, acct.email)
        print(f"     keyring      : {status}")
        if args.connect:
            print(f"     imap+smtp    : {_live_check(acct)}")

    _section("environment gates")
    for name in _ENV_FLAGS:
        print(f"  {name:<35} = {os.environ.get(name, '(unset)')}")

    _section("mcp clients")
    for client, path in _MCP_CLIENT_HINTS.items():
        marker = _detect_mcp(client, path)
        print(f"  {client:<17} {path}  {marker}")

    print()
    print("Report generated with `mail-mcp doctor`. Share it verbatim when filing an issue.")
    return 0


def _section(title: str) -> None:
    print()
    print(f"== {title} ==")


def _keyring_backend() -> str:
    try:
        import keyring

        return type(keyring.get_keyring()).__module__ + "." + type(keyring.get_keyring()).__name__
    except Exception as exc:  # noqa: BLE001
        return f"unavailable ({exc.__class__.__name__})"


def _keyring_status(alias: str, email: str) -> str:
    try:
        import keyring

        value = keyring.get_password(f"{SERVICE_PREFIX}:{alias}", email)
    except Exception as exc:  # noqa: BLE001
        return f"error ({exc.__class__.__name__})"
    return "stored" if value else "missing"


def _live_check(acct) -> str:
    """Authenticate against IMAP+SMTP; does not transfer any messages."""
    from . import imap_client, smtp_client
    from .keyring_store import get_password

    try:
        password = get_password(acct.alias, acct.email)
    except Exception as exc:  # noqa: BLE001
        return f"keyring error ({exc.__class__.__name__})"
    try:
        with imap_client.connect(acct, password) as c:
            imap_client.list_folders(c, pattern="*")
    except Exception as exc:  # noqa: BLE001
        return f"IMAP error ({exc.__class__.__name__})"
    try:
        smtp_client.test_login(acct, password, timeout=15)
    except Exception as exc:  # noqa: BLE001
        return f"IMAP ok, SMTP error ({exc.__class__.__name__})"
    return "IMAP ok, SMTP ok"


def _detect_mcp(name: str, path: Path) -> str:
    if not path.exists():
        return "not found"
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return f"unreadable ({exc.errno})"
    if "mail-mcp" in text:
        return "mail-mcp registered"
    if name.startswith("Claude") and path.suffix == ".json":
        try:
            json.loads(text)
        except json.JSONDecodeError:
            return "present, invalid json"
    return "present, mail-mcp not registered"
