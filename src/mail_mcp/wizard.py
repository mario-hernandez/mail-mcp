"""Interactive onboarding wizard (``mail-mcp init``).

The wizard guides the user through a single account setup: it asks for an
email address, auto-detects the IMAP/SMTP endpoints, asks for the password,
verifies the login against both servers, and then persists the configuration.

The UX dependencies (:mod:`questionary`, :mod:`rich`, :mod:`dnspython`) are
pulled in through the ``mail-mcp[cli]`` install extra. Importing this module
without them raises :class:`WizardError` with a clear installation hint.
"""

from __future__ import annotations

import re
import sys
from typing import Any

from . import autoconfig, imap_client, smtp_client
from .autoconfig import Discovery, DiscoveryError, ServerSpec
from .config import AccountModel, ConfigModel, load, save
from .credentials import AuthCredential
from .keyring_store import set_password, set_refresh_token
from .safety.validation import validate_alias

# Hostnames that identify a Microsoft 365 IMAP endpoint — used to offer the
# OAuth browser flow instead of the password path (which Microsoft disabled
# by default for tenant-managed accounts in late 2022).
_M365_IMAP_HOSTS = ("outlook.office365.com",)


class WizardError(RuntimeError):
    pass


_INSTALL_HINT = (
    "mail-mcp init requires the interactive extras. Install them with:\n"
    "  pip install 'mail-mcp[cli]'"
)


def _require_cli_deps() -> tuple[Any, Any]:
    try:
        import questionary  # type: ignore[import-untyped]
    except ModuleNotFoundError as exc:
        raise WizardError(f"{_INSTALL_HINT}\nmissing: {exc.name}") from exc
    try:
        from rich.console import Console
    except ModuleNotFoundError as exc:
        raise WizardError(f"{_INSTALL_HINT}\nmissing: {exc.name}") from exc
    return questionary, Console()


def run() -> int:
    if not sys.stdin.isatty():
        print(
            "mail-mcp init is interactive. For scripted setup use "
            "`mail-mcp add-account` with flags.",
            file=sys.stderr,
        )
        return 2

    questionary, console = _require_cli_deps()
    from rich.panel import Panel
    from rich.table import Table

    console.print(
        Panel.fit(
            "[bold cyan]mail-mcp[/bold cyan]  "
            "[dim]privacy-first IMAP/SMTP for your AI assistant[/dim]",
            border_style="cyan",
        )
    )

    email = questionary.text(
        "What's the email address you want to connect?",
        validate=_email_validator,
    ).ask()
    if email is None:
        return _cancelled(console)
    email = email.strip()

    disc: Discovery | None
    with console.status("[cyan]Detecting provider…", spinner="dots"):
        try:
            disc = autoconfig.discover(email)
        except DiscoveryError as exc:
            console.print(f"[yellow]autoconfig: {exc}[/yellow]")
            disc = None
        except Exception as exc:  # noqa: BLE001
            console.print(f"[yellow]autoconfig failed: {exc}[/yellow]")
            disc = None

    if disc is not None:
        _print_discovery(console, Table, disc)
        if disc.needs_bridge:
            console.print(
                Panel(
                    "Proton Mail requires [bold]Proton Bridge[/bold] running "
                    "locally.\nInstall it from https://proton.me/mail/bridge "
                    "and use the IMAP password Bridge generates (not your "
                    "Proton login).",
                    title="heads up",
                    border_style="yellow",
                )
            )
        use = questionary.confirm("Use these settings?", default=True).ask()
        if use is None:
            return _cancelled(console)
    else:
        use = False

    if not use:
        disc = _prompt_manual(questionary, console)
        if disc is None:
            return _cancelled(console)

    if disc.imap.security != "ssl":
        console.print(
            f"[yellow]Note: IMAP security is {disc.imap.security!r}. "
            "mail-mcp only supports implicit TLS for IMAP in v0.1 — "
            "forcing port 993 with SSL.[/yellow]"
        )
        disc.imap = ServerSpec(disc.imap.host, 993, "ssl")

    # Microsoft 365 has basic-auth IMAP disabled by default for tenant-managed
    # mailboxes, so we detect that host and steer the user toward OAuth before
    # they type a password that won't work. Users can still decline if their
    # tenant has the legacy flag flipped.
    is_m365 = disc.imap.host in _M365_IMAP_HOSTS
    use_oauth = False
    if is_m365:
        use_oauth = _prompt_oauth_choice(questionary, console)

    default_alias = _default_alias(email)
    alias = questionary.text(
        "Short alias for this account:",
        default=default_alias,
        validate=_alias_validator,
    ).ask()
    if not alias:
        return _cancelled(console)

    cfg = load()
    if any(a.alias == alias for a in cfg.model.accounts):
        overwrite = questionary.confirm(
            f"Account '{alias}' already exists. Overwrite?", default=False,
        ).ask()
        if not overwrite:
            return _cancelled(console)

    if use_oauth:
        return _finish_oauth_microsoft(
            questionary=questionary,
            console=console,
            Panel=Panel,
            email=email,
            alias=alias,
            disc=disc,
            cfg=cfg,
        )

    password = questionary.password(
        "Password (stored in the OS keyring):",
    ).ask()
    if not password:
        return _cancelled(console)

    account = AccountModel(
        alias=alias,
        email=email,
        imap_host=disc.imap.host,
        imap_port=disc.imap.port,
        imap_use_ssl=True,
        smtp_host=disc.smtp.host,
        smtp_port=disc.smtp.port,
        smtp_starttls=(disc.smtp.security == "starttls"),
    )

    imap_ok, imap_err, specials = _test_imap(console, account, password)
    smtp_ok, smtp_err = _test_smtp(console, account, password)

    if specials:
        drafts = specials.get("\\Drafts")
        trash = specials.get("\\Trash")
        if drafts and drafts != account.drafts_mailbox:
            console.print(f"  [dim]detected Drafts mailbox: {drafts}[/dim]")
            account = account.model_copy(update={"drafts_mailbox": drafts})
        if trash and trash != account.trash_mailbox:
            console.print(f"  [dim]detected Trash mailbox: {trash}[/dim]")
            account = account.model_copy(update={"trash_mailbox": trash})

    if not (imap_ok and smtp_ok):
        if imap_err:
            console.print(f"   [dim]IMAP error: {imap_err}[/dim]")
        if smtp_err:
            console.print(f"   [dim]SMTP error: {smtp_err}[/dim]")
        save_anyway = questionary.confirm(
            "One or more checks failed. Save the account anyway?",
            default=False,
        ).ask()
        if not save_anyway:
            console.print("[yellow]discarded, nothing written.[/yellow]")
            return 1

    set_password(alias, email, password)
    accounts = [a for a in cfg.model.accounts if a.alias != alias]
    accounts.append(account)
    cfg.model = ConfigModel(
        default_alias=cfg.model.default_alias or alias,
        accounts=accounts,
    )
    save(cfg)

    console.print()
    console.print(
        Panel(
            (
                f"[green]✓[/green] Saved account [bold]{alias}[/bold]\n"
                f"  config  {cfg.path}\n"
                f"  secret  OS keyring (service = mail-mcp:{alias})\n\n"
                "Next: register mail-mcp with your AI client.\n\n"
                "  [cyan]Claude Code[/cyan]    "
                "claude mcp add mail-mcp \"$(which mail-mcp)\" serve\n"
                "  [cyan]Claude Desktop[/cyan] edit claude_desktop_config.json "
                "(docs/INTEGRATION.md)\n"
                "  [cyan]Codex CLI[/cyan]      edit ~/.codex/config.toml "
                "(docs/INTEGRATION.md)"
            ),
            title="all set",
            border_style="green",
        )
    )
    return 0


# --- helpers ----------------------------------------------------------------


def _cancelled(console: Any) -> int:
    console.print("[yellow]cancelled, nothing written.[/yellow]")
    return 130


def _email_validator(value: str) -> bool | str:
    value = (value or "").strip()
    if not value:
        return "please enter an email address"
    if value.count("@") != 1:
        return "must contain exactly one '@'"
    local, _, domain = value.partition("@")
    if not local or "." not in domain or any(c.isspace() for c in value):
        return "not a well-formed email address"
    return True


def _alias_validator(value: str) -> bool | str:
    if not re.fullmatch(r"[A-Za-z0-9_.\-]{1,64}", value or ""):
        return "alias must match [A-Za-z0-9_.-]{1,64}"
    return True


def _default_alias(email: str) -> str:
    local = email.split("@", 1)[0]
    cleaned = re.sub(r"[^A-Za-z0-9_.-]", "-", local)[:64]
    try:
        validate_alias(cleaned)
    except Exception:
        cleaned = "account"
    return cleaned or "account"


def _print_discovery(console: Any, Table: Any, disc: Discovery) -> None:
    label = {"ssl": "implicit TLS", "starttls": "STARTTLS", "plain": "PLAIN (insecure)"}
    tbl = Table(show_header=False, box=None, padding=(0, 1))
    tbl.add_column(style="dim")
    tbl.add_column()
    tbl.add_row(
        "IMAP",
        f"{disc.imap.host}:{disc.imap.port}  "
        f"[dim]({label[disc.imap.security]})[/dim]",
    )
    tbl.add_row(
        "SMTP",
        f"{disc.smtp.host}:{disc.smtp.port}  "
        f"[dim]({label[disc.smtp.security]})[/dim]",
    )
    tbl.add_row("source", f"[dim]{disc.source}[/dim]")
    console.print(tbl)
    for note in disc.notes:
        console.print(f"[yellow]! {note}[/yellow]")


def _prompt_manual(questionary: Any, console: Any) -> Discovery | None:
    console.print("[yellow]Filling in details manually.[/yellow]")
    imap_host = questionary.text("IMAP host:").ask()
    if not imap_host:
        return None
    imap_port_s = questionary.text("IMAP port:", default="993").ask()
    if not imap_port_s:
        return None
    smtp_host = questionary.text("SMTP host:").ask()
    if not smtp_host:
        return None
    smtp_port_s = questionary.text("SMTP port:", default="587").ask()
    if not smtp_port_s:
        return None
    smtp_sec = questionary.select(
        "SMTP security:",
        choices=["starttls", "ssl"],
        default="starttls",
    ).ask()
    if not smtp_sec:
        return None
    try:
        imap_port = int(imap_port_s)
        smtp_port = int(smtp_port_s)
    except ValueError:
        console.print("[red]ports must be integers[/red]")
        return None
    return Discovery(
        imap=ServerSpec(imap_host.strip(), imap_port, "ssl"),
        smtp=ServerSpec(smtp_host.strip(), smtp_port, smtp_sec),
        source="manual",
    )


def _test_imap(
    console: Any, account: AccountModel, credential: Any
) -> tuple[bool, str | None, dict[str, str]]:
    """``credential`` is a password string or an :class:`AuthCredential`."""
    with console.status("[cyan]Testing IMAP login…", spinner="dots"):
        try:
            with imap_client.connect(account, credential) as c:
                imap_client.list_folders(c)
                specials = imap_client.detect_special_mailboxes(c)
        except Exception as exc:  # noqa: BLE001
            console.print(
                f"  IMAP  : [red]✗[/red]  {account.imap_host}:{account.imap_port}"
            )
            return False, str(exc), {}
    console.print(
        f"  IMAP  : [green]✓[/green]  {account.imap_host}:{account.imap_port}"
    )
    return True, None, specials


def _test_smtp(console: Any, account: AccountModel, credential: Any) -> tuple[bool, str | None]:
    """``credential`` is a password string or an :class:`AuthCredential`."""
    with console.status("[cyan]Testing SMTP login…", spinner="dots"):
        try:
            smtp_client.test_login(account, credential)
        except Exception as exc:  # noqa: BLE001
            console.print(
                f"  SMTP  : [red]✗[/red]  {account.smtp_host}:{account.smtp_port}"
            )
            return False, str(exc)
    console.print(
        f"  SMTP  : [green]✓[/green]  {account.smtp_host}:{account.smtp_port}"
    )
    return True, None


# --- OAuth Microsoft 365 helpers -------------------------------------------


def _prompt_oauth_choice(questionary: Any, console: Any) -> bool:
    """Ask whether to sign in via browser (OAuth) or fall back to password.

    Returns True only when the user picks OAuth *and* MSAL is installed. If
    MSAL is missing we print a hint and fall back to the password branch
    silently — avoiding the foot-gun where the user picks OAuth, we crash,
    and they have to re-run ``init`` from scratch.
    """
    try:
        import msal  # type: ignore[import-untyped]  # noqa: F401
    except ModuleNotFoundError:
        console.print(
            "[yellow]Microsoft 365 detected but OAuth support not installed.\n"
            "To enable browser sign-in (recommended; Microsoft disabled basic-auth "
            "IMAP for most tenants):\n"
            "  pip install 'mail-mcp[oauth-microsoft]'[/yellow]"
        )
        return False

    choice = questionary.select(
        "Microsoft 365 detected. How do you want to sign in?",
        choices=[
            questionary.Choice(
                title="Sign in with Microsoft (browser — recommended)",
                value="oauth",
            ),
            questionary.Choice(
                title="Use a password / app password (legacy)",
                value="password",
            ),
        ],
        default="oauth",
    ).ask()
    return choice == "oauth"


def _finish_oauth_microsoft(
    *,
    questionary: Any,
    console: Any,
    Panel: Any,
    email: str,
    alias: str,
    disc: Discovery,
    cfg: Any,
) -> int:
    """Run the OAuth flow: prompt IDs, browser, verify, save.

    Reads the Azure app registration identifiers from env vars if present
    (``MAIL_MCP_M365_CLIENT_ID``, ``MAIL_MCP_M365_TENANT``); otherwise
    prompts the user. Tenant can be a GUID, a verified domain, or
    ``common``; the wizard does not try to guess it from the email domain
    because a verified domain and a tenant ID are not the same thing.
    """
    import os as _os

    from . import oauth

    client_id_default = _os.environ.get("MAIL_MCP_M365_CLIENT_ID", "")
    tenant_default = _os.environ.get("MAIL_MCP_M365_TENANT", "")

    console.print(
        Panel(
            (
                "You need an Azure AD app registration (public client) with:\n"
                "  • Redirect URI type: [bold]public client / native[/bold]\n"
                "  • Redirect URI value: [bold]http://localhost[/bold]\n"
                "  • API permissions (delegated): "
                "IMAP.AccessAsUser.All, SMTP.Send, offline_access\n"
                "  • 'Allow public client flows' = [bold]Yes[/bold]\n\n"
                "See docs/OAUTH_MICROSOFT.md for step-by-step screenshots."
            ),
            title="Azure AD app registration",
            border_style="cyan",
        )
    )

    client_id = questionary.text(
        "Azure application (client) ID:",
        default=client_id_default,
        validate=lambda v: bool((v or "").strip()) or "client ID is required",
    ).ask()
    if client_id is None:
        return _cancelled(console)
    client_id = client_id.strip()

    tenant = questionary.text(
        "Directory (tenant) ID, verified domain, or 'common':",
        default=tenant_default or "common",
        validate=lambda v: bool((v or "").strip()) or "tenant is required",
    ).ask()
    if tenant is None:
        return _cancelled(console)
    tenant = tenant.strip()

    console.print(
        "[cyan]A browser window will open. Complete the sign-in there; this "
        "process will continue once authentication succeeds.[/cyan]"
    )
    try:
        with console.status("[cyan]Waiting for browser sign-in…", spinner="dots"):
            bundle = oauth.acquire_token_interactive(
                email=email,
                client_id=client_id,
                tenant=tenant,
            )
    except oauth.OAuthError as exc:
        console.print(f"[red]OAuth sign-in failed: {exc}[/red]")
        return 1
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]OAuth sign-in failed: {exc}[/red]")
        return 1

    if not bundle.refresh_token:
        console.print(
            "[red]The token bundle is missing a refresh token. "
            "Make sure 'offline_access' is in the granted API permissions."
            "[/red]"
        )
        return 1

    account = AccountModel(
        alias=alias,
        email=email,
        imap_host=disc.imap.host,
        imap_port=disc.imap.port,
        imap_use_ssl=True,
        smtp_host=disc.smtp.host,
        smtp_port=disc.smtp.port,
        smtp_starttls=(disc.smtp.security == "starttls"),
        auth="oauth-microsoft",
        oauth_client_id=client_id,
        oauth_tenant=tenant,
    )

    # Verify the fresh access token actually works for IMAP and SMTP before
    # we write anything to disk or to the keyring.
    creds = AuthCredential(kind="oauth2", username=email, secret=bundle.access_token)
    imap_ok, imap_err, specials = _test_imap(console, account, creds)
    smtp_ok, smtp_err = _test_smtp(console, account, creds)
    if specials:
        drafts = specials.get("\\Drafts")
        trash = specials.get("\\Trash")
        if drafts and drafts != account.drafts_mailbox:
            console.print(f"  [dim]detected Drafts mailbox: {drafts}[/dim]")
            account = account.model_copy(update={"drafts_mailbox": drafts})
        if trash and trash != account.trash_mailbox:
            console.print(f"  [dim]detected Trash mailbox: {trash}[/dim]")
            account = account.model_copy(update={"trash_mailbox": trash})

    if not (imap_ok and smtp_ok):
        if imap_err:
            console.print(f"   [dim]IMAP error: {imap_err}[/dim]")
        if smtp_err:
            console.print(f"   [dim]SMTP error: {smtp_err}[/dim]")
        save_anyway = questionary.confirm(
            "One or more checks failed. Save the account anyway?",
            default=False,
        ).ask()
        if not save_anyway:
            console.print("[yellow]discarded, nothing written.[/yellow]")
            return 1

    # Persist refresh token first; if config write fails after this, a second
    # run of the wizard can reuse it silently (via acquire_token_by_refresh).
    set_refresh_token(alias, bundle.refresh_token)
    oauth.cache_access_token(alias, bundle)
    accounts = [a for a in cfg.model.accounts if a.alias != alias]
    accounts.append(account)
    cfg.model = ConfigModel(
        default_alias=cfg.model.default_alias or alias,
        accounts=accounts,
    )
    save(cfg)

    console.print()
    console.print(
        Panel(
            (
                f"[green]✓[/green] Saved account [bold]{alias}[/bold] (OAuth)\n"
                f"  config   {cfg.path}\n"
                f"  secret   OS keyring (service = mail-mcp:{alias}:refresh_token)\n"
                f"  tenant   {tenant}\n\n"
                "Next: register mail-mcp with your AI client.\n\n"
                "  [cyan]Claude Code[/cyan]    "
                "claude mcp add mail-mcp \"$(which mail-mcp)\" serve\n"
                "  [cyan]Claude Desktop[/cyan] edit claude_desktop_config.json "
                "(docs/INTEGRATION.md)\n"
                "  [cyan]Codex CLI[/cyan]      edit ~/.codex/config.toml "
                "(docs/INTEGRATION.md)"
            ),
            title="all set",
            border_style="green",
        )
    )
    return 0
