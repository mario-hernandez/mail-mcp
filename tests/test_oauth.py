"""Unit tests for OAuth2 plumbing (no network, no real tenant).

MSAL is stubbed so these tests run in under a second on every platform.
They exercise the boundary contracts that the rest of the codebase relies
on — the SASL payload format, refresh-token rotation, access-token caching,
and the password/OAuth branch selection in :mod:`mail_mcp.credentials`.
"""

from __future__ import annotations

import time

import pytest

from mail_mcp import keyring_store, oauth
from mail_mcp.config import AccountModel
from mail_mcp.credentials import resolve_auth


def test_build_xoauth2_format() -> None:
    """SASL XOAUTH2 is ``user=X<SOH>auth=Bearer Y<SOH><SOH>`` with SOH = 0x01."""
    payload = oauth.build_xoauth2("a@b.com", "TOKEN")
    assert payload == b"user=a@b.com\x01auth=Bearer TOKEN\x01\x01"


def test_build_xoauth2_rejects_empty_inputs() -> None:
    with pytest.raises(oauth.OAuthError):
        oauth.build_xoauth2("", "TOKEN")
    with pytest.raises(oauth.OAuthError):
        oauth.build_xoauth2("a@b.com", "")


def test_cache_roundtrip_and_expiry() -> None:
    oauth.clear_cache()
    bundle = oauth.TokenBundle(
        access_token="abc",
        expires_at=time.time() + 3600,
        refresh_token="rt",
    )
    oauth.cache_access_token("alice", bundle)
    assert oauth.get_cached_access_token("alice") == "abc"
    # Near-expiry tokens are considered stale and must not be handed out.
    stale = oauth.TokenBundle(access_token="abc2", expires_at=time.time() + 30, refresh_token=None)
    oauth.cache_access_token("alice", stale)
    assert oauth.get_cached_access_token("alice") is None
    oauth.clear_cache("alice")
    assert oauth.get_cached_access_token("alice") is None


def test_resolve_auth_password_path(monkeypatch: pytest.MonkeyPatch) -> None:
    acct = AccountModel(
        alias="pw",
        email="p@example.com",
        imap_host="imap.example.com",
        smtp_host="smtp.example.com",
    )
    monkeypatch.setattr(
        keyring_store, "get_password", lambda a, u: "hunter2" if a == "pw" else ""
    )
    cred = resolve_auth(acct)
    assert cred.kind == "password"
    assert cred.secret == "hunter2"
    assert cred.username == "p@example.com"


def test_resolve_auth_uses_cache_and_skips_refresh(monkeypatch: pytest.MonkeyPatch) -> None:
    """A cached access token short-circuits the refresh-token roundtrip."""
    oauth.clear_cache()
    oauth.cache_access_token(
        "ox",
        oauth.TokenBundle(access_token="CACHED", expires_at=time.time() + 3600, refresh_token=None),
    )

    def _fail(*a, **k):
        raise AssertionError("should not refresh when cache is warm")

    monkeypatch.setattr(oauth, "acquire_token_by_refresh_token", _fail)
    acct = AccountModel(
        alias="ox",
        email="o@example.com",
        imap_host="outlook.office365.com",
        smtp_host="smtp-mail.outlook.com",
        auth="oauth-microsoft",
        oauth_client_id="cid",
        oauth_tenant="tid",
    )
    cred = resolve_auth(acct)
    assert cred.kind == "oauth2"
    assert cred.secret == "CACHED"


def test_resolve_auth_refreshes_and_rotates(monkeypatch: pytest.MonkeyPatch) -> None:
    """A cold cache triggers refresh; a rotated refresh token is persisted."""
    oauth.clear_cache()

    stored: dict[str, str] = {"ox": "OLD_REFRESH"}

    def _get(alias: str) -> str:
        if alias in stored:
            return stored[alias]
        raise RuntimeError("missing")

    def _set(alias: str, token: str) -> None:
        stored[alias] = token

    monkeypatch.setattr(keyring_store, "get_refresh_token", _get)
    monkeypatch.setattr(keyring_store, "set_refresh_token", _set)

    def _fake_refresh(*, refresh_token: str, client_id: str, tenant: str) -> oauth.TokenBundle:
        assert refresh_token == "OLD_REFRESH"
        return oauth.TokenBundle(
            access_token="NEW_ACCESS",
            expires_at=time.time() + 3600,
            refresh_token="NEW_REFRESH",  # simulate rotation
        )

    monkeypatch.setattr(oauth, "acquire_token_by_refresh_token", _fake_refresh)
    acct = AccountModel(
        alias="ox",
        email="o@example.com",
        imap_host="outlook.office365.com",
        smtp_host="smtp-mail.outlook.com",
        auth="oauth-microsoft",
        oauth_client_id="cid",
        oauth_tenant="tid",
    )
    cred = resolve_auth(acct)
    assert cred.kind == "oauth2"
    assert cred.secret == "NEW_ACCESS"
    assert stored["ox"] == "NEW_REFRESH"


def test_resolve_auth_missing_refresh_token_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    oauth.clear_cache()
    monkeypatch.setattr(
        keyring_store,
        "get_refresh_token",
        lambda a: (_ for _ in ()).throw(RuntimeError("refresh token not found in keyring")),
    )
    acct = AccountModel(
        alias="newbie",
        email="n@example.com",
        imap_host="outlook.office365.com",
        smtp_host="smtp-mail.outlook.com",
        auth="oauth-microsoft",
        oauth_client_id="cid",
        oauth_tenant="tid",
    )
    with pytest.raises(RuntimeError, match="re-run `mail-mcp init`"):
        resolve_auth(acct)


def test_resolve_auth_oauth_without_client_id_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    oauth.clear_cache()
    acct = AccountModel(
        alias="broken",
        email="b@example.com",
        imap_host="outlook.office365.com",
        smtp_host="smtp-mail.outlook.com",
        auth="oauth-microsoft",
    )
    with pytest.raises(RuntimeError, match="missing oauth_client_id or oauth_tenant"):
        resolve_auth(acct)


def test_bundle_attaches_oauth_error_code() -> None:
    """A failed token acquisition surfaces the MSAL ``error`` code on OAuthError."""
    with pytest.raises(oauth.OAuthError) as ei:
        oauth._bundle({"error": "invalid_grant", "error_description": "AADSTS70008 expired"})
    assert ei.value.code == "invalid_grant"


def test_resolve_auth_invalid_grant_clears_refresh_token(monkeypatch: pytest.MonkeyPatch) -> None:
    """A revoked refresh token must be deleted from the keyring, not left to loop."""
    oauth.clear_cache()
    stored: dict[str, str] = {"ox": "DEAD_REFRESH"}
    deleted: list[str] = []

    monkeypatch.setattr(
        keyring_store, "get_refresh_token", lambda a: stored[a]
    )
    monkeypatch.setattr(
        keyring_store, "delete_refresh_token", lambda a: deleted.append(a) or stored.pop(a, None)
    )

    def _fake_refresh(*, refresh_token: str, client_id: str, tenant: str) -> oauth.TokenBundle:
        raise oauth.OAuthError("token acquisition failed: AADSTS70008", code="invalid_grant")

    monkeypatch.setattr(oauth, "acquire_token_by_refresh_token", _fake_refresh)
    acct = AccountModel(
        alias="ox",
        email="o@example.com",
        imap_host="outlook.office365.com",
        smtp_host="smtp-mail.outlook.com",
        auth="oauth-microsoft",
        oauth_client_id="cid",
        oauth_tenant="tid",
    )
    with pytest.raises(RuntimeError, match="no longer valid"):
        resolve_auth(acct)
    assert deleted == ["ox"]
    assert "ox" not in stored


def test_resolve_auth_other_oauth_error_keeps_refresh_token(monkeypatch: pytest.MonkeyPatch) -> None:
    """Transient/recoverable errors (e.g. network) must NOT delete the refresh token."""
    oauth.clear_cache()
    stored: dict[str, str] = {"ox": "STILL_GOOD_REFRESH"}
    deleted: list[str] = []

    monkeypatch.setattr(keyring_store, "get_refresh_token", lambda a: stored[a])
    monkeypatch.setattr(
        keyring_store, "delete_refresh_token", lambda a: deleted.append(a)
    )

    def _fake_refresh(*, refresh_token: str, client_id: str, tenant: str) -> oauth.TokenBundle:
        raise oauth.OAuthError("network blew up", code="temporarily_unavailable")

    monkeypatch.setattr(oauth, "acquire_token_by_refresh_token", _fake_refresh)
    acct = AccountModel(
        alias="ox",
        email="o@example.com",
        imap_host="outlook.office365.com",
        smtp_host="smtp-mail.outlook.com",
        auth="oauth-microsoft",
        oauth_client_id="cid",
        oauth_tenant="tid",
    )
    with pytest.raises(oauth.OAuthError):
        resolve_auth(acct)
    assert deleted == []
    assert stored["ox"] == "STILL_GOOD_REFRESH"
