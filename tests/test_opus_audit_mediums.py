"""Regression tests for the MEDIUM findings of the Opus line-by-line audit.

1. get_email_raw passed RFC-capitalised headers (Subject/From/Reply-To/…)
   to a sanitizer that only scrubbed a fixed lowercase key list, so they
   reached the LLM unscrubbed and four bogus empty fields were injected.
2. Authorization-header redaction's `\\S+` stopped at the first space, so
   "Authorization: Bearer <token>" leaked the token blob.
3. get_thread kept the OLDEST messages and reported the truncated count as
   thread_size.
4. send_draft silently dropped (and leaked) a Bcc header carried by an
   externally-authored draft.
5. forward_draft accepted bcc, validated it, then silently dropped it.
"""

from __future__ import annotations

import email
import email.policy
from email.message import EmailMessage
from unittest.mock import MagicMock

from mail_mcp.safety.redaction import redact_text, sanitize_error
from mail_mcp.tools.read import _sanitize_header_dict

# ---------- MED: generic header sanitization (get_email_raw key mismatch) ----------

def test_sanitize_header_dict_scrubs_capitalised_rfc_keys():
    """The keys fetch_raw_message returns are capitalised — they must be scrubbed."""
    raw = {
        "Subject": "Hi​there",          # zero-width inside
        "From": "a@example.com",
        "Reply-To": "evil\r\ninjected",       # CRLF
        "To": "b@example.com",
        "Cc": "",
        "Date": "Mon, 1 Jan 2026 00:00:00 +0000",
        "Message-ID": "<x@example.com>",
    }
    out = _sanitize_header_dict(raw)
    assert "​" not in out["Subject"]
    assert "\r" not in out["Reply-To"] and "\n" not in out["Reply-To"]
    # No bogus empty lowercase keys injected.
    assert "from_" not in out
    assert set(out.keys()) == set(raw.keys())


def test_sanitize_header_dict_still_scrubs_emailheader_keys_and_date():
    """The EmailHeader-style dict (lowercase + date + flags) is still covered."""
    hdr = {
        "uid": 7,
        "subject": "x​y",
        "from_": "z\r\nq",
        "to": ["a@example.com", "bad\nb@example.com"],
        "cc": [],
        "date": "evil\r\ndate",
        "flags": ["\\Seen"],
    }
    out = _sanitize_header_dict(hdr)
    assert out["uid"] == 7  # non-string passes through
    assert "​" not in out["subject"]
    assert "\r" not in out["from_"]
    assert "\n" not in out["to"][1]
    assert "\r" not in out["date"] and "\n" not in out["date"]  # date now scrubbed
    assert out["flags"] == ["\\Seen"]


# ---------- MED: Authorization header redaction ----------

def test_authorization_header_token_fully_redacted():
    msg = "401 from Graph -> Authorization: Bearer eyJhbGciOiJIUzI1Ni2837abcZZ"
    out = redact_text(msg)
    assert "eyJhbGciOiJIUzI1Ni2837abcZZ" not in out, "token blob must not leak"
    assert "Bearer" not in out


def test_authorization_basic_scheme_also_redacted():
    out = redact_text("Authorization: Basic dXNlcjpwYXNzd29yZA==")
    assert "dXNlcjpwYXNzd29yZA==" not in out


def test_authorization_redaction_stops_at_line_end():
    """Redaction must not eat a following line."""
    out = sanitize_error(RuntimeError("Authorization: Bearer SECRETTOKEN12345\nstatus=denied"))
    assert "SECRETTOKEN12345" not in out["message"]
    assert "status=denied" in out["message"]


# ---------- MED: get_thread keeps newest + reports true size ----------

def test_get_thread_keeps_newest_and_reports_true_size(monkeypatch):
    from contextlib import contextmanager
    from pathlib import Path

    from mail_mcp import imap_client
    from mail_mcp.config import AccountModel, Config, ConfigModel
    from mail_mcp.credentials import AuthCredential
    from mail_mcp.tools.read import get_thread
    from mail_mcp.tools.schemas import GetThreadInput

    acct = AccountModel(
        alias="t", email="me@example.com",
        imap_host="imap.example.com", smtp_host="smtp.example.com",
    )
    cfg = Config(path=Path("/tmp/x"), model=ConfigModel(accounts=[acct]))
    fetched_uids = {}

    @contextmanager
    def fake_connect(account, creds):
        yield MagicMock()

    # A thread of 5 UIDs; max_messages=3 must return the newest three (3,4,5).
    monkeypatch.setattr(imap_client, "thread_references", lambda c, **k: [[1, 2, 3, 4, 5]])

    def fake_fetch_headers(c, *, mailbox, uids):
        fetched_uids["uids"] = uids

        class _H:
            def __init__(self, uid):
                self.__dict__ = {"uid": uid, "subject": f"s{uid}", "from_": "", "to": [], "cc": [], "date": None, "flags": []}
        return [_H(u) for u in uids]

    monkeypatch.setattr(imap_client, "fetch_headers", fake_fetch_headers)
    monkeypatch.setattr(imap_client, "connect", fake_connect)
    monkeypatch.setattr(
        "mail_mcp.tools.read.resolve_auth",
        lambda a: AuthCredential(kind="password", username=a.email, secret="x"),
    )

    out = get_thread(cfg, GetThreadInput(account="t", uid=2, max_messages=3))

    assert out["thread_size"] == 5, "true size, not the truncated count"
    assert fetched_uids["uids"] == [3, 4, 5], "newest three kept, oldest dropped"
    assert any("newest" in n for n in out["notes"]), "truncation must be announced"


# ---------- MED: send_draft delivers + de-headers a draft's Bcc ----------

def test_send_draft_delivers_bcc_from_draft_header_and_strips_it(monkeypatch):
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

    draft = EmailMessage(policy=email.policy.default)
    draft["From"] = "me@example.com"
    draft["To"] = "to@example.com"
    draft["Bcc"] = "secret1@example.com, secret2@example.com"
    draft["Subject"] = "hi"
    draft["Message-ID"] = "<d@example.com>"
    draft.set_content("body")
    draft_bytes = draft.as_bytes()

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
        captured["bcc"] = bcc
        captured["msg_has_bcc_header"] = msg.get("Bcc") is not None
        return msg["Message-ID"]

    monkeypatch.setattr(smtp_client, "send", fake_send)

    send_draft(cfg, SendDraftInput(account="t", uid=1, confirm=True))

    assert captured["bcc"] == ["secret1@example.com", "secret2@example.com"], "Bcc delivered as envelope recipients"
    assert captured["msg_has_bcc_header"] is False, "Bcc header stripped from the transmitted message"


# ---------- MED: forward_draft surfaces the dropped bcc ----------

def test_forward_draft_surfaces_dropped_bcc(monkeypatch):
    from contextlib import contextmanager
    from pathlib import Path

    from mail_mcp import imap_client
    from mail_mcp.config import AccountModel, Config, ConfigModel
    from mail_mcp.credentials import AuthCredential
    from mail_mcp.tools.drafts import forward_draft
    from mail_mcp.tools.schemas import ForwardDraftInput

    acct = AccountModel(
        alias="t", email="me@example.com",
        imap_host="imap.example.com", smtp_host="smtp.example.com",
        drafts_mailbox="Drafts", trash_mailbox="Trash",
    )
    cfg = Config(path=Path("/tmp/x"), model=ConfigModel(accounts=[acct]))

    orig = EmailMessage(policy=email.policy.default)
    orig["From"] = "x@example.com"
    orig["Subject"] = "fwd me"
    orig.set_content("original")
    orig_bytes = orig.as_bytes()

    @contextmanager
    def fake_connect(account, creds):
        yield MagicMock()

    monkeypatch.setattr(
        imap_client, "fetch_raw_message",
        lambda c, *, mailbox, uid: (orig_bytes, {"Subject": "fwd me", "From": "x@example.com"}),
    )
    monkeypatch.setattr(imap_client, "save_draft", lambda c, *, account, message_bytes: ("Drafts", 9))
    monkeypatch.setattr(imap_client, "connect", fake_connect)
    monkeypatch.setattr(
        "mail_mcp.tools.drafts.resolve_auth",
        lambda a: AuthCredential(kind="password", username=a.email, secret="x"),
    )

    out = forward_draft(cfg, ForwardDraftInput(
        account="t", mailbox="INBOX", uid=1, to=["dest@example.com"],
        bcc=["blind@example.com"],
    ))
    assert out.get("bcc_dropped") == ["blind@example.com"]
    assert "note" in out and "BCC" in out["note"]
