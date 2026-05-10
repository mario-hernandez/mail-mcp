from pathlib import Path

import pytest

from mail_mcp import server as server_module
from mail_mcp.config import Config, ConfigModel


class _FakeCfg:
    path = Path("/tmp/x")

    class model:
        accounts: list = []
        default_alias = None


def _registered_tool_names(monkeypatch=None) -> set[str]:
    """Build the server with the current env and return the visible tool names.

    Walks the server's registered tool list directly so the test does not
    depend on the MCP framework's async dispatch.
    """
    server = server_module.build_server(cfg=_FakeCfg())  # type: ignore[arg-type]
    handler = server.request_handlers.get(
        __import__("mcp").types.ListToolsRequest
    )
    assert handler is not None
    import asyncio

    result = asyncio.run(
        handler(
            __import__("mcp").types.ListToolsRequest(method="tools/list", params=None)
        )
    )
    return {t.name for t in result.root.tools}


def test_readonly_only_by_default(monkeypatch):
    """Even with no env vars, send tools stay visible (option A — v0.3.7+)."""
    monkeypatch.delenv("MAIL_MCP_WRITE_ENABLED", raising=False)
    monkeypatch.delenv("MAIL_MCP_SEND_ENABLED", raising=False)

    names = _registered_tool_names()

    # Read tools always visible.
    assert "search_emails" in names
    assert "list_drafts" in names
    # Write tools NOT visible without WRITE_ENABLED.
    assert "delete_emails" not in names
    assert "move_email" not in names
    # Send tools VISIBLE always — that is the v0.3.7 contract change.
    assert "send_email" in names
    assert "send_draft" in names

    assert server_module.write_enabled() is False


def test_write_registers_when_enabled(monkeypatch):
    monkeypatch.setenv("MAIL_MCP_WRITE_ENABLED", "true")
    monkeypatch.delenv("MAIL_MCP_SEND_ENABLED", raising=False)

    names = _registered_tool_names()
    assert "delete_emails" in names
    assert "move_email" in names
    # Send still visible — registration is unconditional.
    assert "send_email" in names
    assert "send_draft" in names


def test_send_disabled_without_flags(monkeypatch):
    """``is_enabled()`` still flips correctly — the runtime gate is intact."""
    from mail_mcp.tools import send

    monkeypatch.delenv("MAIL_MCP_WRITE_ENABLED", raising=False)
    monkeypatch.delenv("MAIL_MCP_SEND_ENABLED", raising=False)
    assert send.is_enabled() is False


def test_send_enabled_with_both(monkeypatch):
    from mail_mcp.tools import send

    monkeypatch.setenv("MAIL_MCP_WRITE_ENABLED", "true")
    monkeypatch.setenv("MAIL_MCP_SEND_ENABLED", "true")
    assert send.is_enabled() is True


def test_send_email_handler_raises_typed_send_disabled_when_gate_off(monkeypatch):
    """The runtime gate is the security boundary — must raise even though tool is visible."""
    from mail_mcp.tools import send
    from mail_mcp.tools.schemas import SendEmailInput

    monkeypatch.delenv("MAIL_MCP_WRITE_ENABLED", raising=False)
    monkeypatch.delenv("MAIL_MCP_SEND_ENABLED", raising=False)

    cfg = Config(path=Path("/tmp/x"), model=ConfigModel())
    params = SendEmailInput(
        account=None, to=["x@example.com"], subject="hi", body="hi", confirm=True,
    )
    with pytest.raises(send.SendDisabled) as ei:
        send.send_email(cfg, params)
    assert ei.value.code == send.SendDisabled.NOT_ENABLED


def test_send_email_handler_raises_requires_confirm_when_env_set_but_no_confirm(monkeypatch):
    """Different code so the LLM knows it's a per-call fix, not a config one."""
    from mail_mcp.tools import send
    from mail_mcp.tools.schemas import SendEmailInput

    monkeypatch.setenv("MAIL_MCP_WRITE_ENABLED", "true")
    monkeypatch.setenv("MAIL_MCP_SEND_ENABLED", "true")

    cfg = Config(path=Path("/tmp/x"), model=ConfigModel())
    params = SendEmailInput(
        account=None, to=["x@example.com"], subject="hi", body="hi", confirm=False,
    )
    with pytest.raises(send.SendDisabled) as ei:
        send.send_email(cfg, params)
    assert ei.value.code == send.SendDisabled.REQUIRES_CONFIRM
