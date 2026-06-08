"""Regression tests for the LOW findings of the Opus line-by-line audit."""

from __future__ import annotations

import argparse
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from mail_mcp import autoconfig, imap_client, oauth
from mail_mcp.autoconfig import DiscoveryError
from mail_mcp.safety.validation import ValidationError
from mail_mcp.server import _classify

# ---------- server.py: RATE_LIMITED not retryable; socket.timeout removed ----------

def test_rate_limited_is_not_retryable():
    from mail_mcp.tools.send import RateLimited

    out = _classify(RateLimited("limit reached"))
    assert out["code"] == "RATE_LIMITED"
    assert out["retryable"] is False  # sliding window won't clear on immediate retry


def test_timeout_still_retryable_after_socket_timeout_removed():
    out = _classify(TimeoutError("operation timed out"))
    assert out["code"] == "TIMEOUT"
    assert out["retryable"] is True


# ---------- imap_client: address-group markers, double-escape, html br ----------

def test_format_address_skips_group_markers():
    # group START: mailbox set, host None  → not a real address
    start = SimpleNamespace(mailbox=b"Undisclosed recipients", host=None, name=None)
    # group END: both None
    end = SimpleNamespace(mailbox=None, host=None, name=None)
    real = SimpleNamespace(mailbox=b"alice", host=b"example.com", name=None)
    assert imap_client._format_address(start) == ""
    assert imap_client._format_address(end) == ""
    assert imap_client._format_address(real) == "alice@example.com"


def test_build_criteria_does_not_pre_escape():
    """imapclient quotes search values itself; we must pass them raw."""
    crit = imap_client._build_criteria(
        mailbox="INBOX", unseen=None, flagged=None,
        from_=None, to=None, subject='he said "hi"', body_contains=None,
        since=None, before=None,
    )
    # The SUBJECT value must be the raw string, NOT backslash-escaped.
    i = crit.index("SUBJECT")
    assert crit[i + 1] == 'he said "hi"'


def test_html_to_text_br_inside_script_is_dropped():
    out = imap_client._html_to_text(
        "<p>before</p><script>x<br>y</script><p>after</p>"
    )
    assert "before" in out and "after" in out
    assert "x" not in out and "y" not in out  # script contents dropped, no stray newline


# ---------- oauth: tenant validation ----------

@pytest.mark.parametrize("good", [
    "common", "organizations", "consumers",
    "12345678-1234-1234-1234-123456789abc",
    "contoso.onmicrosoft.com",
])
def test_authority_accepts_valid_tenants(good):
    assert oauth._authority(good).endswith(good)


@pytest.mark.parametrize("bad", [
    "common/../evil", "tenant?x=1", "a#b", "ten ant", "host:9999", "../escape", "",
])
def test_authority_rejects_malformed_tenants(bad):
    with pytest.raises(oauth.OAuthError):
        oauth._authority(bad)


# ---------- autoconfig: domain validation + email quoting ----------

def test_discover_rejects_url_significant_domain():
    with pytest.raises(DiscoveryError):
        autoconfig.discover("user@evil.com/path", offline=True)


def test_discover_quotes_email_in_autoconfig_url(monkeypatch):
    captured = []

    def fake_fetch(url, *, timeout):
        captured.append(url)
        return None

    monkeypatch.setattr(autoconfig, "_fetch_autoconfig", fake_fetch)
    monkeypatch.setattr(autoconfig, "_try_mx_preset", lambda *a, **k: None)
    monkeypatch.setattr(autoconfig, "_try_srv", lambda *a, **k: None)

    # A '+'-addressed local part is URL-significant and must be percent-encoded.
    # (All network tiers are mocked to miss, so discover() falls through to the
    # heuristic fallback and returns — the point is the URL it built.)
    autoconfig.discover("user+tag@unknown-host.invalid")
    assert any("user%2Btag%40unknown-host.invalid" in u for u in captured), captured


# ---------- imap_client.delete_uids: trash not validated on permanent ----------

def test_delete_uids_permanent_ignores_empty_trash_mailbox():
    client = MagicMock()
    client.capabilities.return_value = [b"UIDPLUS"]
    # An empty trash_mailbox must NOT block a permanent expunge.
    n = imap_client.delete_uids(
        client, mailbox="INBOX", uids=[1], trash_mailbox="", permanent=True,
    )
    assert n == 1
    client.uid_expunge.assert_called_once_with([1])


def test_delete_uids_trash_validated_on_move_path():
    client = MagicMock()
    with pytest.raises(ValidationError):
        imap_client.delete_uids(
            client, mailbox="INBOX", uids=[1], trash_mailbox="bad\r\nname", permanent=False,
        )


# ---------- __main__: strict bool parser ----------

def test_bool_arg_strict():
    from mail_mcp.__main__ import _bool_arg

    assert _bool_arg("true") is True
    assert _bool_arg("FALSE") is False
    assert _bool_arg("yes") is True
    with pytest.raises(argparse.ArgumentTypeError):
        _bool_arg("maybe")  # an unrecognised value fails closed, not silently False


# ---------- verification-round fixes (BLOCK verdict, then resolved) ----------

def test_send_draft_message_id_injection_handles_present_but_empty_header(monkeypatch):
    """A draft with a blank ``Message-ID:`` header must not crash send_draft.

    Regression introduced by the Message-ID-injection fix and caught by the
    adversarial verification: assigning a second Message-ID when an empty one
    is present raises ValueError; the fix must ``del`` it first.
    """
    from contextlib import contextmanager
    from pathlib import Path

    from mail_mcp import imap_client, smtp_client
    from mail_mcp.config import AccountModel, Config, ConfigModel
    from mail_mcp.credentials import AuthCredential
    from mail_mcp.tools import send as send_mod
    from mail_mcp.tools.drafts import send_draft
    from mail_mcp.tools.schemas import SendDraftInput

    monkeypatch.setenv("MAIL_MCP_WRITE_ENABLED", "true")
    monkeypatch.setenv("MAIL_MCP_SEND_ENABLED", "true")
    send_mod._reset_for_tests()

    acct = AccountModel(
        alias="t", email="me@example.com",
        imap_host="imap.example.com", smtp_host="smtp.example.com",
        drafts_mailbox="Drafts", trash_mailbox="Trash",
    )
    cfg = Config(path=Path("/tmp/x"), model=ConfigModel(accounts=[acct]))
    # Present-but-EMPTY Message-ID header.
    draft_bytes = (
        b"From: me@example.com\r\nTo: to@example.com\r\n"
        b"Message-ID: \r\nSubject: x\r\n\r\nbody\r\n"
    )
    captured = {}

    @contextmanager
    def fake_connect(account, creds):
        yield MagicMock()

    monkeypatch.setattr(imap_client, "fetch_raw_message", lambda c, *, mailbox, uid: (draft_bytes, {}))
    monkeypatch.setattr("mail_mcp.tools.drafts._drafts_mailbox_strict", lambda c, a, m, tool: "Drafts")
    monkeypatch.setattr(imap_client, "connect", fake_connect)
    monkeypatch.setattr("mail_mcp.tools.drafts._delete_old_draft_uid_safely", lambda *a, **k: None)
    monkeypatch.setattr(
        "mail_mcp.tools.drafts.resolve_auth",
        lambda a: AuthCredential(kind="password", username=a.email, secret="x"),
    )

    def fake_send(account, creds, msg, *, bcc=None):
        captured["mid"] = msg["Message-ID"]
        return msg["Message-ID"]

    monkeypatch.setattr(smtp_client, "send", fake_send)

    out = send_draft(cfg, SendDraftInput(account="t", uid=1, confirm=True))
    # Did not crash, and a real Message-ID was injected.
    assert captured["mid"] and captured["mid"].startswith("<") and "@example.com>" in captured["mid"]
    assert out["message_id"] == captured["mid"]


def test_attach_files_enforces_total_cap_at_read_time(monkeypatch, tmp_path):
    """The re-stat loop must enforce the AGGREGATE cap, not only per-file."""
    from mail_mcp import smtp_client
    from mail_mcp.safety import attachments as att_mod
    from mail_mcp.safety.attachments import ResolvedAttachment
    from mail_mcp.safety.validation import ValidationError as VE

    # Shrink the caps so two small files exceed the total but not the per-file.
    monkeypatch.setattr(att_mod, "MAX_ATTACHMENT_BYTES", 1000, raising=False)
    monkeypatch.setattr(att_mod, "MAX_TOTAL_ATTACHMENT_BYTES", 1500, raising=False)

    f1 = tmp_path / "a.bin"
    f1.write_bytes(b"x" * 900)
    f2 = tmp_path / "b.bin"
    f2.write_bytes(b"y" * 900)
    atts = [
        ResolvedAttachment(path=f1, filename="a.bin", content_type="application/octet-stream", size=900),
        ResolvedAttachment(path=f2, filename="b.bin", content_type="application/octet-stream", size=900),
    ]
    from email.message import EmailMessage
    msg = EmailMessage()
    msg["From"] = "a@example.com"
    msg["To"] = "b@example.com"
    msg["Subject"] = "x"
    msg.set_content("body")
    # 900 + 900 = 1800 > 1500 total → must raise even though each < 1000 per-file.
    with pytest.raises(VE):
        smtp_client._attach_files(msg, atts)
