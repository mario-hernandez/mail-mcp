"""Resolve the credentials for an account (password or OAuth).

This module is the single choke point between the tool layer and the two
authentication mechanisms. Tools call :func:`resolve_auth` and get back an
:class:`AuthCredential`; they then pass it unchanged to the IMAP/SMTP clients,
which know how to log in with either flavour.

Keeping the branching in one place — rather than scattering ``if
account.auth == "oauth"`` checks across every tool — means adding a new auth
method later (Google, generic XOAUTH2 proxy) only needs edits here plus the
two client modules.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from . import keyring_store
from .config import AccountModel

AuthKind = Literal["password", "oauth2"]


@dataclass(frozen=True)
class AuthCredential:
    """Transport-ready credential for an account.

    ``secret`` is the raw password for ``kind="password"`` or a fresh OAuth
    access token for ``kind="oauth2"``. In both cases the username on the
    wire is the email address; we carry it here so the clients don't need to
    peek at the :class:`AccountModel`.
    """

    kind: AuthKind
    username: str
    secret: str


def resolve_auth(account: AccountModel) -> AuthCredential:
    """Return a ready-to-use credential for ``account``.

    For password accounts this is a simple keyring read. For OAuth accounts
    we prefer a cached access token; otherwise we refresh silently using
    the stored refresh token. A rotated refresh token (Microsoft sometimes
    returns a new one) is persisted back to the keyring so the next
    invocation keeps working.

    Interactive re-authentication is never triggered from here — that only
    happens in the wizard. If the refresh token is missing or revoked, we
    raise :class:`RuntimeError` with a clear remediation hint.
    """
    if account.auth == "password":
        secret = keyring_store.get_password(account.alias, account.email)
        return AuthCredential(kind="password", username=account.email, secret=secret)

    if account.auth == "oauth-microsoft":
        from . import oauth  # local import so password users never load msal

        cached = oauth.get_cached_access_token(account.alias)
        if cached is not None:
            return AuthCredential(kind="oauth2", username=account.email, secret=cached)

        if not account.oauth_client_id or not account.oauth_tenant:
            raise RuntimeError(
                f"account {account.alias!r} is configured for OAuth but missing "
                "oauth_client_id or oauth_tenant; re-run `mail-mcp init`."
            )

        try:
            refresh = keyring_store.get_refresh_token(account.alias)
        except RuntimeError as exc:
            raise RuntimeError(
                f"no refresh token stored for {account.alias!r}; re-run `mail-mcp init` "
                "to sign in again."
            ) from exc

        try:
            bundle = oauth.acquire_token_by_refresh_token(
                refresh_token=refresh,
                client_id=account.oauth_client_id,
                tenant=account.oauth_tenant,
            )
        except oauth.OAuthError as exc:
            # ``invalid_grant`` from Microsoft means the stored refresh token is
            # no longer usable (revoked, password rotated, conditional-access
            # policy tripped). Leaving it in the keyring would loop the user
            # through the same failure on every call; discard it so the next
            # ``mail-mcp init`` run starts clean.
            if getattr(exc, "code", None) == "invalid_grant":
                keyring_store.delete_refresh_token(account.alias)
                oauth.clear_cache(account.alias)
                raise RuntimeError(
                    f"refresh token for {account.alias!r} is no longer valid "
                    "(revoked or expired). The stored token has been removed; "
                    "re-run `mail-mcp init` to sign in again."
                ) from exc
            raise
        oauth.cache_access_token(account.alias, bundle)
        if bundle.refresh_token and bundle.refresh_token != refresh:
            # Microsoft rotated the refresh token — persist the new one so
            # we don't fall back to the revoked one next time.
            keyring_store.set_refresh_token(account.alias, bundle.refresh_token)
        return AuthCredential(kind="oauth2", username=account.email, secret=bundle.access_token)

    raise RuntimeError(f"unknown auth kind {account.auth!r} for account {account.alias!r}")
