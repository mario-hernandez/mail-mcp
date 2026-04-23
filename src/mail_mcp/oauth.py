"""Microsoft 365 OAuth2 (IMAP + SMTP via XOAUTH2).

This module adds OAuth2 to ``mail-mcp`` *without touching the password path*.
The two authentication mechanisms live side by side; ``credentials.resolve_auth``
picks between them based on ``AccountModel.auth``.

Design choices
--------------
* **Public client, no ``client_secret``.** Microsoft permits this via PKCE;
  the ``client_id`` is expected to be embedded. No shared project-wide
  ``client_id`` is hardcoded here — the user supplies their own from their
  Azure AD tenant (see docs). That keeps us out of the Thunderbird-style
  legal-grey-zone where a leaked project ``client_id`` gets revoked for
  everyone.
* **Tenant-scoped by default.** ``AccountModel.oauth_tenant`` is the tenant ID
  (a GUID, or a verified domain). ``common`` works but we discourage it —
  tenant-scoped apps reject tokens from other tenants out of the box.
* **Scopes.** ``IMAP.AccessAsUser.All``, ``SMTP.Send``, ``offline_access``.
  ``offline_access`` is required to receive a refresh token; without it the
  user would be prompted to re-authenticate every hour.
* **In-memory access-token cache.** Refresh tokens persist in the OS keyring;
  access tokens live only in this process. On each ``resolve_auth`` call we
  silently refresh if the cached token is within 60 s of expiry.
* **XOAUTH2 SASL.** The format is ``user=<email>\\x01auth=Bearer <token>\\x01\\x01``,
  base64-encoded by the caller when needed (``imapclient`` does it internally;
  ``smtplib`` expects raw bytes via the auth callback).

MSAL is an optional dependency (``mail-mcp[oauth-microsoft]``). Importing this
module without MSAL installed raises a clear :class:`OAuthNotInstalled` on
first use, not at import time — so password-only users never trip over it.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

# Scopes required for full IMAP + SMTP access. ``offline_access`` is
# intentionally NOT listed here — MSAL treats it as a reserved scope and
# rejects any app that passes it explicitly; it always requests a refresh
# token for public clients automatically.
SCOPES: tuple[str, ...] = (
    "https://outlook.office.com/IMAP.AccessAsUser.All",
    "https://outlook.office.com/SMTP.Send",
)

# When an access token expires within this many seconds we refresh eagerly
# rather than handing out a nearly-dead token that will fail mid-request.
_EXPIRY_SKEW_SECONDS = 60

# Process-local cache. Key: account alias. Value: (access_token, expires_at).
# Refresh tokens never live here; they stay in the OS keyring.
_TOKEN_CACHE: dict[str, tuple[str, float]] = {}


class OAuthNotInstalled(RuntimeError):
    """Raised when MSAL is required but the ``oauth-microsoft`` extra is missing."""


class OAuthError(RuntimeError):
    """Raised on any unrecoverable OAuth failure (network, consent, etc.)."""


@dataclass(frozen=True)
class TokenBundle:
    """Result of a successful token acquisition.

    ``refresh_token`` is populated on interactive flows and (sometimes) on
    silent refreshes when Microsoft chooses to rotate it. The caller is
    responsible for persisting any non-empty refresh token back to the keyring.
    """

    access_token: str
    expires_at: float
    refresh_token: str | None


def _require_msal() -> Any:
    try:
        import msal  # type: ignore[import-untyped]
    except ModuleNotFoundError as exc:
        raise OAuthNotInstalled(
            "OAuth support requires MSAL. Install it with:\n"
            "  pip install 'mail-mcp[oauth-microsoft]'"
        ) from exc
    return msal


def _authority(tenant: str) -> str:
    if not tenant or any(c.isspace() for c in tenant):
        raise OAuthError("oauth_tenant must be a tenant GUID, verified domain, or 'common'")
    return f"https://login.microsoftonline.com/{tenant}"


def _public_client(client_id: str, tenant: str) -> Any:
    if not client_id:
        raise OAuthError("oauth_client_id is required for Microsoft OAuth")
    msal = _require_msal()
    return msal.PublicClientApplication(client_id=client_id, authority=_authority(tenant))


def _bundle(result: dict[str, Any]) -> TokenBundle:
    if "access_token" not in result:
        err = result.get("error_description") or result.get("error") or "unknown OAuth error"
        raise OAuthError(f"token acquisition failed: {err}")
    expires_in = int(result.get("expires_in", 3600))
    return TokenBundle(
        access_token=result["access_token"],
        expires_at=time.time() + expires_in,
        refresh_token=result.get("refresh_token"),
    )


def acquire_token_interactive(
    *,
    email: str,
    client_id: str,
    tenant: str,
    timeout: int = 120,
) -> TokenBundle:
    """Launch the system browser, prompt the user, return a fresh token bundle.

    MSAL starts a loopback HTTP listener on an ephemeral port, opens the
    authorisation URL in the user's default browser, and receives the auth
    code back on that listener. PKCE is enabled automatically for public
    clients.

    ``login_hint=email`` pre-fills the Microsoft sign-in page; the user can
    still pick a different account.
    """
    app = _public_client(client_id, tenant)
    result = app.acquire_token_interactive(
        scopes=list(SCOPES),
        login_hint=email,
        timeout=timeout,
        prompt="select_account",
    )
    return _bundle(result)


def acquire_token_by_refresh_token(
    *,
    refresh_token: str,
    client_id: str,
    tenant: str,
) -> TokenBundle:
    """Silently refresh an access token using a stored refresh token.

    Returns a new :class:`TokenBundle`; ``result.refresh_token`` may be
    ``None`` (Microsoft reuses the existing one) or a newly issued rotated
    token the caller must persist. The keyring write is the caller's
    responsibility to keep side effects localised.
    """
    app = _public_client(client_id, tenant)
    # ``acquire_token_by_refresh_token`` is a public-but-underscored API in
    # MSAL. It's the only supported path to turn a refresh token from outside
    # the MSAL cache (ours lives in the OS keyring) into an access token.
    result = app.acquire_token_by_refresh_token(refresh_token, list(SCOPES))
    return _bundle(result)


def get_cached_access_token(alias: str) -> str | None:
    """Return a still-valid cached access token, or ``None`` if expired/absent."""
    entry = _TOKEN_CACHE.get(alias)
    if entry is None:
        return None
    token, expires_at = entry
    if expires_at - time.time() <= _EXPIRY_SKEW_SECONDS:
        return None
    return token


def cache_access_token(alias: str, bundle: TokenBundle) -> None:
    _TOKEN_CACHE[alias] = (bundle.access_token, bundle.expires_at)


def clear_cache(alias: str | None = None) -> None:
    """Drop the in-memory access-token cache; keyring refresh tokens untouched."""
    if alias is None:
        _TOKEN_CACHE.clear()
    else:
        _TOKEN_CACHE.pop(alias, None)


def build_xoauth2(email: str, access_token: str) -> bytes:
    """Produce the SASL XOAUTH2 payload used by both IMAP and SMTP.

    The format is fixed by RFC draft-ietf-kitten-sasl-oauth; the separator
    byte is ``\\x01`` (SOH). ``imapclient.oauth2_login`` expects the raw
    access token (it wraps this internally), but SMTP via :mod:`smtplib`
    requires the full byte string returned here, encoded by the caller.
    """
    if not email or not access_token:
        raise OAuthError("email and access_token must be non-empty")
    payload = f"user={email}\x01auth=Bearer {access_token}\x01\x01"
    return payload.encode("utf-8")
