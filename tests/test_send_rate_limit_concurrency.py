"""Concurrency test for the send rate limiter.

``_check_rate_limit`` does prune→check→append on a module-global deque.
Under the thread-pool dispatch (``asyncio.to_thread``), N concurrent
same-alias sends could all observe a sub-limit length and all append,
blowing past the hourly cap that bounds prompt-injection blast radius.
The fix is a module-global lock around the sequence. These tests force
the race with a barrier and assert the cap holds.
"""

from __future__ import annotations

import threading

import pytest

from mail_mcp.tools import send as send_mod
from mail_mcp.tools.send import RateLimited


@pytest.fixture(autouse=True)
def _reset_history():
    send_mod._reset_for_tests()
    yield
    send_mod._reset_for_tests()


@pytest.mark.parametrize("_run", range(20))
def test_concurrent_sends_never_exceed_limit(monkeypatch, _run):
    """N threads hit the limiter at once; exactly `limit` succeed, rest are capped."""
    monkeypatch.setenv("MAIL_MCP_SEND_HOURLY_LIMIT", "3")
    n = 8
    barrier = threading.Barrier(n)
    successes = 0
    limited = 0
    counter_lock = threading.Lock()

    def _worker():
        nonlocal successes, limited
        barrier.wait()
        try:
            send_mod._check_rate_limit("alias1")
            with counter_lock:
                successes += 1
        except RateLimited:
            with counter_lock:
                limited += 1

    threads = [threading.Thread(target=_worker) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    assert successes == 3, f"exactly the limit may pass, got {successes}"
    assert limited == n - 3
    assert len(send_mod._send_history["alias1"]) == 3, "bucket never exceeds the cap"


@pytest.mark.parametrize("_run", range(10))
def test_per_account_isolation_under_global_lock(monkeypatch, _run):
    """The global lock must not collapse per-alias accounting."""
    monkeypatch.setenv("MAIL_MCP_SEND_HOURLY_LIMIT", "1")
    n_per_alias = 4
    aliases = ["a", "b"]
    barrier = threading.Barrier(len(aliases) * n_per_alias)
    results: dict[str, int] = {a: 0 for a in aliases}
    res_lock = threading.Lock()

    def _worker(alias: str):
        barrier.wait()
        try:
            send_mod._check_rate_limit(alias)
            with res_lock:
                results[alias] += 1
        except RateLimited:
            pass

    threads = [
        threading.Thread(target=_worker, args=(a,))
        for a in aliases
        for _ in range(n_per_alias)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    # Each alias has its own bucket; with limit=1 exactly one send per alias passes.
    assert results == {"a": 1, "b": 1}
