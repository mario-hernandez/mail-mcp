import os

import pytest

from mail_mcp import server as server_module


def test_readonly_only_by_default(monkeypatch, tmp_path):
    monkeypatch.delenv("MAIL_MCP_WRITE_ENABLED", raising=False)
    monkeypatch.delenv("MAIL_MCP_SEND_ENABLED", raising=False)
    cfg_path = tmp_path / "config.json"

    class _FakeCfg:
        path = cfg_path

        class model:
            accounts = []
            default_alias = None

    built = server_module.build_server(cfg=_FakeCfg())  # type: ignore[arg-type]
    assert built is not None
    assert server_module.write_enabled() is False


def test_write_registers_when_enabled(monkeypatch):
    monkeypatch.setenv("MAIL_MCP_WRITE_ENABLED", "true")
    assert server_module.write_enabled() is True


def test_send_disabled_without_flags(monkeypatch):
    from mail_mcp.tools import send

    monkeypatch.delenv("MAIL_MCP_WRITE_ENABLED", raising=False)
    monkeypatch.delenv("MAIL_MCP_SEND_ENABLED", raising=False)
    assert send.is_enabled() is False


def test_send_enabled_with_both(monkeypatch):
    from mail_mcp.tools import send

    monkeypatch.setenv("MAIL_MCP_WRITE_ENABLED", "true")
    monkeypatch.setenv("MAIL_MCP_SEND_ENABLED", "true")
    assert send.is_enabled() is True
