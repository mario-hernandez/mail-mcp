import pytest

from mail_mcp.tools import send as send_mod
from mail_mcp.tools.send import RateLimited


@pytest.fixture(autouse=True)
def _reset():
    send_mod._reset_for_tests()
    yield
    send_mod._reset_for_tests()


def test_rate_limit_allows_up_to_limit(monkeypatch):
    monkeypatch.setenv("MAIL_MCP_SEND_HOURLY_LIMIT", "3")
    for _ in range(3):
        send_mod._check_rate_limit("personal")


def test_rate_limit_blocks_over_limit(monkeypatch):
    monkeypatch.setenv("MAIL_MCP_SEND_HOURLY_LIMIT", "2")
    send_mod._check_rate_limit("personal")
    send_mod._check_rate_limit("personal")
    with pytest.raises(RateLimited):
        send_mod._check_rate_limit("personal")


def test_rate_limit_is_per_account(monkeypatch):
    monkeypatch.setenv("MAIL_MCP_SEND_HOURLY_LIMIT", "1")
    send_mod._check_rate_limit("a")
    send_mod._check_rate_limit("b")
    with pytest.raises(RateLimited):
        send_mod._check_rate_limit("a")
    with pytest.raises(RateLimited):
        send_mod._check_rate_limit("b")


def test_rate_limit_default_is_ten(monkeypatch):
    monkeypatch.delenv("MAIL_MCP_SEND_HOURLY_LIMIT", raising=False)
    for _ in range(10):
        send_mod._check_rate_limit("x")
    with pytest.raises(RateLimited):
        send_mod._check_rate_limit("x")


def test_rate_limit_bad_env_falls_back_to_default(monkeypatch):
    monkeypatch.setenv("MAIL_MCP_SEND_HOURLY_LIMIT", "not-a-number")
    assert send_mod._hourly_limit() == 10


def test_rate_limit_env_minimum_is_one(monkeypatch):
    monkeypatch.setenv("MAIL_MCP_SEND_HOURLY_LIMIT", "0")
    assert send_mod._hourly_limit() == 1
