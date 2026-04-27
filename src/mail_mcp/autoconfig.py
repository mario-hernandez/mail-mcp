"""Mail-server autodiscovery for the interactive wizard.

Given an email address, resolve the IMAP and SMTP endpoints the user should
connect to. Resolution follows a tiered waterfall inspired by Thunderbird's
account-creation logic:

1. **Embedded provider table** — zero network, fastest, covers the ~25
   providers that account for the bulk of personal email traffic.
2. **Provider-hosted autoconfig XML** — HTTPS GET to
   ``autoconfig.<domain>/mail/config-v1.1.xml`` and the ``.well-known``
   variant.
3. **Mozilla ISPDB (online)** — HTTPS GET to
   ``autoconfig.thunderbird.net/v1.1/<domain>``. The **domain alone** is
   sent; the full email address never leaves the machine.
4. **MX-based presets** — one DNS query, maps common MX targets onto the
   embedded providers (Google Workspace, Microsoft 365, IONOS custom
   domains, Fastmail, etc.).
5. **DNS SRV (RFC 6186)** — ``_imaps._tcp`` + ``_submission._tcp``.
6. **Heuristic fallback** — ``imap.<domain>:993`` / ``smtp.<domain>:587``.

Privacy and safety:

- HTTPS is non-negotiable for every network tier. HTTP URLs are rejected.
- Each network call has a hard timeout (default 3 seconds).
- Failures are swallowed silently and the next tier is tried.
- ``dnspython`` is optional; the MX and SRV tiers degrade gracefully when
  the package is not installed.
"""

from __future__ import annotations

import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Literal
from xml.etree import ElementTree as ET  # noqa: S405 — Element type only; parsing uses defusedxml

import defusedxml.ElementTree as DET
from defusedxml import DefusedXmlException

from .safety.tls import create_tls_context
from .safety.validation import validate_email_address

Security = Literal["ssl", "starttls", "plain"]


@dataclass
class ServerSpec:
    host: str
    port: int
    security: Security


@dataclass
class Discovery:
    imap: ServerSpec
    smtp: ServerSpec
    source: str
    needs_bridge: bool = False
    notes: list[str] = field(default_factory=list)


class DiscoveryError(RuntimeError):
    """Raised when no tier can resolve the account's servers."""


# --- tier 1: embedded providers --------------------------------------------

PROVIDERS: dict[str, Discovery] = {}


def _register(
    domain: str,
    imap_h: str, imap_p: int, imap_s: Security,
    smtp_h: str, smtp_p: int, smtp_s: Security,
) -> None:
    PROVIDERS[domain] = Discovery(
        imap=ServerSpec(imap_h, imap_p, imap_s),
        smtp=ServerSpec(smtp_h, smtp_p, smtp_s),
        source="embedded",
    )


_register("gmail.com",       "imap.gmail.com",         993, "ssl",  "smtp.gmail.com",          587, "starttls")
_register("googlemail.com",  "imap.gmail.com",         993, "ssl",  "smtp.gmail.com",          587, "starttls")
_register("icloud.com",      "imap.mail.me.com",       993, "ssl",  "smtp.mail.me.com",        587, "starttls")
_register("me.com",          "imap.mail.me.com",       993, "ssl",  "smtp.mail.me.com",        587, "starttls")
_register("mac.com",         "imap.mail.me.com",       993, "ssl",  "smtp.mail.me.com",        587, "starttls")
_register("outlook.com",     "outlook.office365.com",  993, "ssl",  "smtp-mail.outlook.com",   587, "starttls")
_register("hotmail.com",     "outlook.office365.com",  993, "ssl",  "smtp-mail.outlook.com",   587, "starttls")
_register("live.com",        "outlook.office365.com",  993, "ssl",  "smtp-mail.outlook.com",   587, "starttls")
_register("msn.com",         "outlook.office365.com",  993, "ssl",  "smtp-mail.outlook.com",   587, "starttls")
_register("fastmail.com",    "imap.fastmail.com",      993, "ssl",  "smtp.fastmail.com",       465, "ssl")
_register("fastmail.fm",     "imap.fastmail.com",      993, "ssl",  "smtp.fastmail.com",       465, "ssl")
_register("yahoo.com",       "imap.mail.yahoo.com",    993, "ssl",  "smtp.mail.yahoo.com",     465, "ssl")
_register("yahoo.es",        "imap.mail.yahoo.com",    993, "ssl",  "smtp.mail.yahoo.com",     465, "ssl")
_register("aol.com",         "imap.aol.com",           993, "ssl",  "smtp.aol.com",            465, "ssl")
_register("ionos.es",        "imap.ionos.es",          993, "ssl",  "smtp.ionos.es",           587, "starttls")
_register("ionos.de",        "imap.ionos.de",          993, "ssl",  "smtp.ionos.de",           587, "starttls")
_register("1und1.de",        "imap.1und1.de",          993, "ssl",  "smtp.1und1.de",           587, "starttls")
_register("gmx.net",         "imap.gmx.net",           993, "ssl",  "mail.gmx.net",            587, "starttls")
_register("gmx.de",          "imap.gmx.net",           993, "ssl",  "mail.gmx.net",            587, "starttls")
_register("gmx.com",         "imap.gmx.com",           993, "ssl",  "mail.gmx.com",            587, "starttls")
_register("web.de",          "imap.web.de",            993, "ssl",  "smtp.web.de",             587, "starttls")
_register("zoho.com",        "imap.zoho.com",          993, "ssl",  "smtp.zoho.com",           465, "ssl")
_register("mailbox.org",     "imap.mailbox.org",       993, "ssl",  "smtp.mailbox.org",        465, "ssl")
_register("yandex.com",      "imap.yandex.com",        993, "ssl",  "smtp.yandex.com",         465, "ssl")
_register("yandex.ru",       "imap.yandex.ru",         993, "ssl",  "smtp.yandex.ru",          465, "ssl")


_PROTON_DOMAINS = {"proton.me", "protonmail.com", "protonmail.ch", "pm.me"}


# --- tier 4: MX-substring presets -------------------------------------------

_MX_PRESETS: list[tuple[str, str]] = [
    ("aspmx.l.google.com",          "gmail.com"),       # Google Workspace
    ("googlemail.com",              "gmail.com"),
    ("google.com",                  "gmail.com"),
    ("mail.protection.outlook.com", "outlook.com"),     # Microsoft 365
    ("outlook.com",                 "outlook.com"),
    ("messagingengine.com",         "fastmail.com"),
    ("yahoodns.net",                "yahoo.com"),
    ("icloud.com",                  "icloud.com"),
    ("zoho.com",                    "zoho.com"),
    ("mailbox.org",                 "mailbox.org"),
    ("gmx.net",                     "gmx.net"),
    ("kundenserver.de",             "ionos.de"),        # IONOS default MX (DE)
    ("perfora.net",                 "ionos.es"),        # IONOS default MX (ES)
    ("udag.de",                     "ionos.de"),
    ("1and1.com",                   "ionos.es"),
    ("1and1.es",                    "ionos.es"),
    ("ionos.es",                    "ionos.es"),        # IONOS custom-domain MX (mx00.ionos.es, ...)
    ("ionos.de",                    "ionos.de"),
    ("ionos.co.uk",                 "ionos.de"),
    ("ionos.com",                   "ionos.de"),
]


# --- public entry point ----------------------------------------------------


def discover(email: str, *, timeout: float = 3.0, offline: bool = False) -> Discovery:
    """Resolve IMAP/SMTP endpoints for ``email``.

    When ``offline`` is true, only the embedded providers table is consulted
    and no network calls are made.
    """
    validate_email_address(email, field="email")
    domain = email.split("@", 1)[1].lower()

    if domain in _PROTON_DOMAINS:
        return Discovery(
            imap=ServerSpec("127.0.0.1", 1143, "starttls"),
            smtp=ServerSpec("127.0.0.1", 1025, "starttls"),
            source="proton-bridge",
            needs_bridge=True,
            notes=[
                "Proton Mail requires Proton Bridge running locally. "
                "Use the IMAP password Bridge generates, not your Proton login."
            ],
        )

    if domain in PROVIDERS:
        base = PROVIDERS[domain]
        return Discovery(imap=base.imap, smtp=base.smtp, source="embedded")

    if offline:
        raise DiscoveryError(f"no embedded preset for {domain!r} and offline=True")

    for url in (
        f"https://autoconfig.{domain}/mail/config-v1.1.xml?emailaddress={email}",
        f"https://{domain}/.well-known/autoconfig/mail/config-v1.1.xml?emailaddress={email}",
    ):
        spec = _fetch_autoconfig(url, timeout=timeout)
        if spec is not None:
            spec.source = "provider-autoconfig"
            return spec

    spec = _fetch_autoconfig(
        f"https://autoconfig.thunderbird.net/v1.1/{domain}",
        timeout=timeout,
    )
    if spec is not None:
        spec.source = "ispdb"
        return spec

    mx_spec = _try_mx_preset(domain, timeout=timeout)
    if mx_spec is not None:
        return mx_spec

    srv_spec = _try_srv(domain, timeout=timeout)
    if srv_spec is not None:
        return srv_spec

    return Discovery(
        imap=ServerSpec(f"imap.{domain}", 993, "ssl"),
        smtp=ServerSpec(f"smtp.{domain}", 587, "starttls"),
        source="heuristic",
        notes=[
            "No autoconfig source matched. "
            f"Falling back to the common convention imap.{domain}:993 and "
            f"smtp.{domain}:587. Verify these before saving."
        ],
    )


# --- tier 2/3 helpers ------------------------------------------------------


def _fetch_autoconfig(url: str, *, timeout: float) -> Discovery | None:
    if not url.startswith("https://"):
        return None
    # S310: HTTPS-only enforced by the guard above; the schemes Bandit warns
    # about (file://, custom) cannot reach this point.
    req = urllib.request.Request(url, headers={"User-Agent": "mail-mcp autoconfig"})  # noqa: S310
    ctx = create_tls_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:  # noqa: S310
            if resp.status != 200:
                return None
            body = resp.read(256 * 1024)
    except (urllib.error.URLError, TimeoutError, ConnectionError, ssl.SSLError, OSError):
        return None
    return _parse_clientconfig_xml(body)


def _parse_clientconfig_xml(body: bytes) -> Discovery | None:
    try:
        # Parsing goes through ``defusedxml`` so a malicious ``autoconfig.xml``
        # cannot fire a billion-laughs / external-entity attack regardless of
        # what the size cap allows through. We keep stdlib ``ET`` only for the
        # ``Element`` type annotation in :func:`_pick_server`.
        root = DET.fromstring(body)
    except (ET.ParseError, DefusedXmlException):
        return None
    provider = root.find("emailProvider")
    if provider is None:
        return None
    imap = _pick_server(provider, "incomingServer", "imap")
    smtp = _pick_server(provider, "outgoingServer", "smtp")
    if imap is None or smtp is None:
        return None
    return Discovery(imap=imap, smtp=smtp, source="xml")


def _pick_server(provider: ET.Element, tag: str, kind: str) -> ServerSpec | None:
    for el in provider.findall(tag):
        if el.get("type") != kind:
            continue
        host = (el.findtext("hostname") or "").strip()
        port_text = (el.findtext("port") or "").strip()
        socket_type = (el.findtext("socketType") or "").strip().upper()
        if not host or not port_text.isdigit():
            continue
        port = int(port_text)
        if socket_type in ("SSL", "IMAPS", "SMTPS"):
            security: Security = "ssl"
        elif socket_type == "STARTTLS":
            security = "starttls"
        elif socket_type == "PLAIN":
            security = "plain"
        else:
            security = "ssl"
        return ServerSpec(host=host, port=port, security=security)
    return None


# --- tier 4: MX -------------------------------------------------------------


def _try_mx_preset(domain: str, *, timeout: float) -> Discovery | None:
    try:
        import dns.resolver  # type: ignore[import-not-found]
    except ModuleNotFoundError:
        return None
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout
        answers = resolver.resolve(domain, "MX")
    except Exception:
        return None
    sorted_records = sorted(answers, key=lambda r: getattr(r, "preference", 0))
    for record in sorted_records:
        target = str(getattr(record, "exchange", "")).rstrip(".").lower()
        if not target:
            continue
        for substring, provider_key in _MX_PRESETS:
            if substring in target:
                template = PROVIDERS.get(provider_key)
                if template is None:
                    continue
                return Discovery(
                    imap=template.imap,
                    smtp=template.smtp,
                    source=f"mx-preset:{provider_key}",
                    notes=[
                        f"MX record '{target}' matched provider '{provider_key}'."
                    ],
                )
    return None


# --- tier 5: DNS SRV --------------------------------------------------------


def _try_srv(domain: str, *, timeout: float) -> Discovery | None:
    try:
        import dns.resolver  # type: ignore[import-not-found]
    except ModuleNotFoundError:
        return None
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout
        imap_rr = resolver.resolve(f"_imaps._tcp.{domain}", "SRV")
        smtp_rr = resolver.resolve(f"_submission._tcp.{domain}", "SRV")
    except Exception:
        return None
    try:
        imap = min(imap_rr, key=lambda r: (r.priority, r.weight))
        smtp = min(smtp_rr, key=lambda r: (r.priority, r.weight))
    except ValueError:
        return None
    smtp_port = int(smtp.port)
    return Discovery(
        imap=ServerSpec(
            host=str(imap.target).rstrip("."),
            port=int(imap.port),
            security="ssl",
        ),
        smtp=ServerSpec(
            host=str(smtp.target).rstrip("."),
            port=smtp_port,
            security="starttls" if smtp_port == 587 else "ssl",
        ),
        source="dns-srv",
    )
