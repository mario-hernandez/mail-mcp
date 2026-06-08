"""Concurrency tests for the OAuth refresh critical section.

Handlers run on a thread pool (``asyncio.to_thread``), so two tool calls
on the same OAuth account can hit ``credentials.resolve_auth`` at once.
Without the per-alias lock both would see a cache miss and both consume
the same refresh token — and Microsoft rotates refresh tokens, so the
loser of that race persists or deletes the wrong one. These tests force
the race with ``threading.Barrier`` (never ``sleep``) and assert the
lock serialises it.

No network, no keyring: ``acquire_token_by_refresh_token`` is stubbed
and ``keyring_store`` is monkeypatched, mirroring the existing
``tests/test_oauth.py`` conventions.
"""

from __future__ import annotations

import threading
import time

import pytest

from mail_mcp import keyring_store, oauth
from mail_mcp.config import AccountModel
from mail_mcp.credentials import resolve_auth


def _acct(alias: str = "ox") -> AccountModel:
    return AccountModel(
        alias=alias,
        email=f"{alias}@example.com",
        imap_host="outlook.office365.com",
        smtp_host="smtp-mail.outlook.com",
        auth="oauth-microsoft",
        oauth_client_id="cid",
        oauth_tenant="tid",
    )


@pytest.fixture(autouse=True)
def _clean_oauth_state():
    """Reset the token cache AND the per-alias lock registry between tests."""
    oauth.clear_cache()
    oauth._ALIAS_LOCKS.clear()
    yield
    oauth.clear_cache()
    oauth._ALIAS_LOCKS.clear()


@pytest.mark.parametrize("_run", range(15))
def test_concurrent_refresh_happens_exactly_once(monkeypatch, _run):
    """The rotation race: two same-alias callers must refresh only once.

    The lock winner performs the single refresh and caches NEW_ACCESS; the
    loser, released from the lock, double-checks the cache and returns the
    cached token WITHOUT a second refresh against the now-rotated token.
    """
    stored = {"ox": "OLD_REFRESH"}
    monkeypatch.setattr(keyring_store, "get_refresh_token", lambda a: stored[a])
    set_calls = []

    def _set(alias, token):
        set_calls.append((alias, token))
        stored[alias] = token

    monkeypatch.setattr(keyring_store, "set_refresh_token", _set)

    call_count = 0
    count_lock = threading.Lock()

    def _fake_refresh(*, refresh_token, client_id, tenant):
        nonlocal call_count
        # Any second invocation would arrive with a stale token — pin that.
        assert refresh_token == "OLD_REFRESH"
        with count_lock:
            call_count += 1
        return oauth.TokenBundle(
            access_token="NEW_ACCESS",
            expires_at=time.time() + 3600,
            refresh_token="NEW_REFRESH",
        )

    monkeypatch.setattr(oauth, "acquire_token_by_refresh_token", _fake_refresh)

    acct = _acct("ox")
    start = threading.Barrier(2)
    results: dict[int, str] = {}
    errors: list[BaseException] = []

    def _worker(i: int):
        start.wait()
        try:
            results[i] = resolve_auth(acct).secret
        except BaseException as exc:  # noqa: BLE001 - surfaced to the assertion
            errors.append(exc)

    threads = [threading.Thread(target=_worker, args=(i,)) for i in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    assert not errors, errors
    assert call_count == 1, "refresh must run exactly once under the per-alias lock"
    assert results[0] == results[1] == "NEW_ACCESS"
    assert stored["ox"] == "NEW_REFRESH"
    assert set_calls == [("ox", "NEW_REFRESH")], "rotation persisted exactly once"


def test_control_without_lock_refreshes_twice(monkeypatch):
    """Control: bypass the per-alias lock and the race reappears (refresh x2).

    Proves the concurrency test above actually exercises the lock rather
    than passing by luck. We replace _get_alias_lock with a fresh no-op
    lock per call so the two threads never serialise.
    """
    monkeypatch.setattr(keyring_store, "get_refresh_token", lambda a: "OLD_REFRESH")
    monkeypatch.setattr(keyring_store, "set_refresh_token", lambda a, t: None)
    monkeypatch.setattr(oauth, "_get_alias_lock", lambda alias: threading.Lock())

    call_count = 0
    count_lock = threading.Lock()
    mid = threading.Barrier(2)

    def _fake_refresh(*, refresh_token, client_id, tenant):
        nonlocal call_count
        # Park both threads INSIDE the refresh simultaneously so both pass the
        # (unlocked) cache miss before either caches a result.
        mid.wait(timeout=5)
        with count_lock:
            call_count += 1
        return oauth.TokenBundle("ACC", time.time() + 3600, "NEW_REFRESH")

    monkeypatch.setattr(oauth, "acquire_token_by_refresh_token", _fake_refresh)

    acct = _acct("ox")
    start = threading.Barrier(2)

    def _worker():
        start.wait()
        resolve_auth(acct)

    threads = [threading.Thread(target=_worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    assert call_count == 2, "without the lock both threads refresh — that is the bug"


@pytest.mark.parametrize("_run", range(15))
def test_invalid_grant_under_contention_deletes_once(monkeypatch, _run):
    """Two contending callers + a revoked token: delete exactly once, both re-auth."""
    stored = {"ox": "DEAD_REFRESH"}
    deleted: list[str] = []
    del_lock = threading.Lock()

    monkeypatch.setattr(
        keyring_store, "get_refresh_token",
        lambda a: stored[a] if a in stored else (_ for _ in ()).throw(RuntimeError("missing")),
    )

    def _delete(alias):
        with del_lock:
            deleted.append(alias)
            stored.pop(alias, None)

    monkeypatch.setattr(keyring_store, "delete_refresh_token", _delete)

    def _fake_refresh(*, refresh_token, client_id, tenant):
        raise oauth.OAuthError("token acquisition failed: AADSTS70008", code="invalid_grant")

    monkeypatch.setattr(oauth, "acquire_token_by_refresh_token", _fake_refresh)

    acct = _acct("ox")
    start = threading.Barrier(2)
    errors: list[BaseException] = []
    err_lock = threading.Lock()

    def _worker():
        start.wait()
        try:
            resolve_auth(acct)
        except RuntimeError as exc:
            with err_lock:
                errors.append(exc)

    threads = [threading.Thread(target=_worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    assert len(errors) == 2, "both callers must raise a re-auth RuntimeError"
    assert deleted == ["ox"], "the dead refresh token is deleted exactly once"
    assert "ox" not in stored
    # Both messages point the user at re-running init (wording may differ).
    assert all("mail-mcp init" in str(e) for e in errors)


@pytest.mark.parametrize("_run", range(15))
def test_transient_error_under_contention_retries_against_same_token(monkeypatch, _run):
    """A transient (non-invalid_grant) refresh failure must NOT poison the loser.

    The lock winner's refresh fails transiently and is re-raised WITHOUT
    caching or rotating, so the still-current refresh token stays in the
    keyring. The loser then acquires the lock, re-reads the cache (miss),
    re-reads the SAME OLD_REFRESH (nothing was deleted or rotated), and
    retries serially against the valid token — succeeding. Pins that the
    failure path leaves the refresh token intact for the next caller.
    """
    stored = {"ox": "OLD_REFRESH"}
    monkeypatch.setattr(keyring_store, "get_refresh_token", lambda a: stored[a])
    set_calls: list = []
    monkeypatch.setattr(
        keyring_store, "set_refresh_token",
        lambda a, t: set_calls.append((a, t)),
    )
    # delete must never be called on a transient error.
    monkeypatch.setattr(
        keyring_store, "delete_refresh_token",
        lambda a: pytest.fail("delete_refresh_token must not run on a transient error"),
    )

    seen_tokens: list = []
    call_count = 0
    count_lock = threading.Lock()

    def _fake_refresh(*, refresh_token, client_id, tenant):
        nonlocal call_count
        with count_lock:
            call_count += 1
            n = call_count
        seen_tokens.append(refresh_token)
        if n == 1:
            # Transient failure — re-raised as-is by resolve_auth (not wrapped,
            # not cleaned up). code is not 'invalid_grant'.
            raise oauth.OAuthError("network blip", code="temporarily_unavailable")
        return oauth.TokenBundle(
            access_token="NEW_ACCESS",
            expires_at=time.time() + 3600,
            refresh_token=None,  # no rotation
        )

    monkeypatch.setattr(oauth, "acquire_token_by_refresh_token", _fake_refresh)

    acct = _acct("ox")
    start = threading.Barrier(2)
    raised: list = []
    ok: list = []
    res_lock = threading.Lock()

    def _worker():
        start.wait()
        try:
            secret = resolve_auth(acct).secret
            with res_lock:
                ok.append(secret)
        except oauth.OAuthError as exc:
            with res_lock:
                raised.append(exc)

    threads = [threading.Thread(target=_worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    assert call_count == 2, "serialised: winner fails, loser retries — two refreshes"
    assert seen_tokens == ["OLD_REFRESH", "OLD_REFRESH"], "both retries use the still-current token"
    assert len(raised) == 1 and len(ok) == 1, "one transient failure, one success"
    assert ok[0] == "NEW_ACCESS"
    assert set_calls == [], "no rotation persisted (success bundle had no new refresh token)"
    assert stored["ox"] == "OLD_REFRESH", "refresh token left intact for the next caller"


def test_different_aliases_do_not_serialise(monkeypatch):
    """Per-alias locking: two different aliases refresh concurrently, no stall.

    A global lock would deadlock/timeout on the shared barrier here; per-alias
    locks let both refreshes proceed in parallel.
    """
    monkeypatch.setattr(keyring_store, "get_refresh_token", lambda a: f"REFRESH_{a}")
    monkeypatch.setattr(keyring_store, "set_refresh_token", lambda a, t: None)

    both_in = threading.Barrier(2)  # both refreshes must be inside simultaneously

    def _fake_refresh(*, refresh_token, client_id, tenant):
        # If the two aliases were sharing one lock, only one thread would reach
        # here and this barrier would time out.
        both_in.wait(timeout=5)
        return oauth.TokenBundle(f"ACC_{refresh_token}", time.time() + 3600, None)

    monkeypatch.setattr(oauth, "acquire_token_by_refresh_token", _fake_refresh)

    start = threading.Barrier(2)
    errors: list[BaseException] = []

    def _worker(alias: str):
        start.wait()
        try:
            resolve_auth(_acct(alias))
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [
        threading.Thread(target=_worker, args=("a",)),
        threading.Thread(target=_worker, args=("b",)),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=6)

    assert not any(t.is_alive() for t in threads), "per-alias refreshes must not serialise"
    assert not errors, errors
