"""HTML body support (`body_html`) across the write tools.

Feature request 2026-07-29: the write tools could only emit text/plain — an
HTML welcome email passed in `body` was delivered as raw source with no
warning. `body_html` builds multipart/alternative with `body` as the
plain-text fallback.

The structural tests matter most where this silently breaks: attachments on
top of an alternative body (multipart/mixed nesting), update_draft preserving
BOTH alternatives (append-then-delete makes any loss permanent), and the
reply quote staying consistent — and HTML-escaped — across both parts.
"""

from __future__ import annotations

import email
import email.policy
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from mail_mcp import imap_client, smtp_client
from mail_mcp.config import AccountModel, Config, ConfigModel
from mail_mcp.credentials import AuthCredential
from mail_mcp.safety.validation import ValidationError

HTML = "<html><body><h1 style='color:#1a3461'>Hola</h1></body></html>"
PLAIN = "Versión en texto plano para clientes sin HTML."


def _account() -> AccountModel:
    return AccountModel(
        alias="t", email="me@example.com",
        imap_host="imap.example.com", smtp_host="smtp.example.com",
        drafts_mailbox="Drafts", trash_mailbox="Trash",
    )


def _cfg() -> Config:
    return Config(path=Path("/tmp/x"), model=ConfigModel(accounts=[_account()]))


def _parse(raw: bytes):
    return email.message_from_bytes(raw, policy=email.policy.default)


def _alternative_parts(msg):
    """Return (plain_part, html_part) of the message's alternative body."""
    plain = msg.get_body(preferencelist=("plain",))
    html = msg.get_body(preferencelist=("html",))
    return plain, html


# ---------- build_message structure ----------

def test_build_message_html_is_multipart_alternative():
    msg = smtp_client.build_message(
        from_addr="a@example.com", to=["b@example.com"], subject="s",
        body_text=PLAIN, body_html=HTML,
    )
    assert msg.get_content_type() == "multipart/alternative"
    parts = list(msg.iter_parts())
    assert [p.get_content_type() for p in parts] == ["text/plain", "text/html"]
    assert PLAIN in parts[0].get_content()
    assert "<h1" in parts[1].get_content()


def test_build_message_html_with_attachment_nests_alternative_in_mixed(tmp_path):
    from mail_mcp.safety.attachments import ResolvedAttachment

    f = tmp_path / "doc.pdf"
    f.write_bytes(b"%PDF-1.4 fake")
    att = ResolvedAttachment(
        path=f, filename="doc.pdf", content_type="application/pdf", size=f.stat().st_size,
    )
    msg = smtp_client.build_message(
        from_addr="a@example.com", to=["b@example.com"], subject="s",
        body_text=PLAIN, body_html=HTML, attachments=[att],
    )
    # Round-trip through bytes: what matters is the structure on the wire.
    rebuilt = _parse(bytes(msg))
    assert rebuilt.get_content_type() == "multipart/mixed"
    top = list(rebuilt.iter_parts())
    assert top[0].get_content_type() == "multipart/alternative"
    inner = [p.get_content_type() for p in top[0].iter_parts()]
    assert inner == ["text/plain", "text/html"]
    pdf = [p for p in rebuilt.iter_attachments()]
    assert len(pdf) == 1
    assert pdf[0].get_content_type() == "application/pdf"
    assert pdf[0].get_filename() == "doc.pdf"
    # Both text parts survive the mixed wrapping.
    plain, html = _alternative_parts(rebuilt)
    assert plain is not None and PLAIN in plain.get_content()
    assert html is not None and "<h1" in html.get_content()


def test_build_message_without_html_stays_plain_no_regression():
    msg = smtp_client.build_message(
        from_addr="a@example.com", to=["b@example.com"], subject="s",
        body_text="just text",
    )
    assert msg.get_content_type() == "text/plain"
    assert msg.get_content().strip() == "just text"


def test_build_message_empty_html_treated_as_absent():
    msg = smtp_client.build_message(
        from_addr="a@example.com", to=["b@example.com"], subject="s",
        body_text="just text", body_html="",
    )
    assert msg.get_content_type() == "text/plain"


def test_build_message_with_bcc_passes_body_html():
    msg, bcc = smtp_client.build_message_with_bcc(
        from_addr="a@example.com", to=["b@example.com"], bcc=["c@example.com"],
        subject="s", body_text=PLAIN, body_html=HTML,
    )
    assert msg.get_content_type() == "multipart/alternative"
    assert bcc == ["c@example.com"]
    assert "Bcc" not in msg


# ---------- looks_like_html heuristic ----------

@pytest.mark.parametrize("positive", [
    "<!DOCTYPE html><html>...</html>",
    "<html><body>x</body></html>",
    "   \n <HTML lang='es'>",
])
def test_looks_like_html_positives(positive):
    assert smtp_client.looks_like_html(positive)


@pytest.mark.parametrize("negative", [
    "plain text",
    "the <html> tag is used to...",   # mentions markup mid-sentence
    "<p>fragment without document wrapper</p>",
    "",
])
def test_looks_like_html_negatives(negative):
    assert not smtp_client.looks_like_html(negative)


# ---------- reply: quote consistency + escaping ----------

def _reply_headers(**over):
    h = {
        "From": "Alice <alice@example.com>",
        "Date": "Mon, 1 Jul 2026 10:00:00 +0200",
        "Subject": "Hola",
        "Message-ID": "<orig@example.com>",
    }
    h.update(over)
    return h


def test_reply_html_quote_in_both_alternatives():
    msg = smtp_client.build_reply_message(
        from_addr="me@example.com",
        original_headers=_reply_headers(),
        body_text="Gracias.",
        body_html="<p>Gracias.</p>",
        include_original_quote=True,
    )
    assert msg.get_content_type() == "multipart/alternative"
    plain, html = _alternative_parts(msg)
    assert "wrote:" in plain.get_content()
    assert "wrote:" in html.get_content()
    assert "alice@example.com" in html.get_content()


def test_reply_html_quote_is_escaped():
    """From-header markup must arrive escaped in the HTML alternative."""
    msg = smtp_client.build_reply_message(
        from_addr="me@example.com",
        original_headers=_reply_headers(From='"<b>evil</b>" <evil@example.com>'),
        body_text="ok",
        body_html="<p>ok</p>",
        include_original_quote=True,
    )
    _, html = _alternative_parts(msg)
    content = html.get_content()
    assert "<b>evil</b>" not in content
    assert "&lt;b&gt;evil&lt;/b&gt;" in content


def test_reply_html_quote_inserted_before_closing_body():
    msg = smtp_client.build_reply_message(
        from_addr="me@example.com",
        original_headers=_reply_headers(),
        body_text="ok",
        body_html="<html><body><p>ok</p></body></html>",
        include_original_quote=True,
    )
    _, html = _alternative_parts(msg)
    content = html.get_content()
    assert content.lower().rindex("wrote:") < content.lower().rindex("</body>")


def test_reply_without_html_unchanged():
    msg = smtp_client.build_reply_message(
        from_addr="me@example.com",
        original_headers=_reply_headers(),
        body_text="ok",
        include_original_quote=True,
    )
    assert msg.get_content_type() == "text/plain"


# ---------- tool plumbing: save_draft / send_email / reply_draft ----------

@contextmanager
def _fake_connect(account, creds):
    c = MagicMock()
    c.list_folders.return_value = [
        ([b"\\HasNoChildren"], "/", "INBOX"),
        ([b"\\HasNoChildren", b"\\Drafts"], "/", "Drafts"),
    ]
    yield c


def _patch_draft_io(monkeypatch, captured):
    def fake_save_draft(c, *, account, message_bytes):
        captured["bytes"] = message_bytes
        return "Drafts", 7

    monkeypatch.setattr(imap_client, "connect", _fake_connect)
    monkeypatch.setattr(imap_client, "save_draft", fake_save_draft)
    monkeypatch.setattr(
        "mail_mcp.tools.drafts.resolve_auth",
        lambda a: AuthCredential(kind="password", username=a.email, secret="x"),
    )


def test_save_draft_body_html_builds_alternative(monkeypatch):
    from mail_mcp.tools.drafts import save_draft
    from mail_mcp.tools.schemas import SaveDraftInput

    captured: dict = {}
    _patch_draft_io(monkeypatch, captured)
    out = save_draft(_cfg(), SaveDraftInput(
        account="t", to=["x@example.com"], subject="s",
        body=PLAIN, body_html=HTML,
    ))
    rebuilt = _parse(captured["bytes"])
    assert rebuilt.get_content_type() == "multipart/alternative"
    plain, html = _alternative_parts(rebuilt)
    assert PLAIN in plain.get_content()
    assert "<h1" in html.get_content()
    assert "html_warning" not in out


def test_save_draft_html_in_body_warns(monkeypatch):
    from mail_mcp.tools.drafts import save_draft
    from mail_mcp.tools.schemas import SaveDraftInput

    captured: dict = {}
    _patch_draft_io(monkeypatch, captured)
    out = save_draft(_cfg(), SaveDraftInput(
        account="t", to=["x@example.com"], subject="s", body=HTML,
    ))
    assert "body_html" in out["html_warning"]
    # Still delivered as plain (unchanged behaviour), just warned about.
    assert _parse(captured["bytes"]).get_content_type() == "text/plain"


def test_save_draft_plain_no_warning(monkeypatch):
    from mail_mcp.tools.drafts import save_draft
    from mail_mcp.tools.schemas import SaveDraftInput

    captured: dict = {}
    _patch_draft_io(monkeypatch, captured)
    out = save_draft(_cfg(), SaveDraftInput(
        account="t", to=["x@example.com"], subject="s", body="hola",
    ))
    assert "html_warning" not in out


def test_reply_draft_passes_body_html(monkeypatch):
    from mail_mcp.tools.drafts import reply_draft
    from mail_mcp.tools.schemas import ReplyDraftInput

    captured: dict = {}
    _patch_draft_io(monkeypatch, captured)
    monkeypatch.setattr(
        imap_client, "fetch_raw_message",
        lambda c, *, mailbox, uid: (b"", _reply_headers()),
    )
    reply_draft(_cfg(), ReplyDraftInput(
        account="t", uid=1, body="ok", body_html="<p>ok</p>",
    ))
    rebuilt = _parse(captured["bytes"])
    assert rebuilt.get_content_type() == "multipart/alternative"


def test_send_email_body_html(monkeypatch):
    from mail_mcp.tools import send as send_mod
    from mail_mcp.tools.schemas import SendEmailInput

    monkeypatch.setenv("MAIL_MCP_WRITE_ENABLED", "true")
    monkeypatch.setenv("MAIL_MCP_SEND_ENABLED", "true")
    send_mod._reset_for_tests()
    captured: dict = {}

    def fake_send(account, creds, msg, *, bcc=None):
        captured["msg"] = msg
        return msg["Message-ID"]

    monkeypatch.setattr(smtp_client, "send", fake_send)
    monkeypatch.setattr(
        "mail_mcp.tools.send.resolve_auth",
        lambda a: AuthCredential(kind="password", username=a.email, secret="x"),
    )
    out = send_mod.send_email(_cfg(), SendEmailInput(
        account="t", to=["x@example.com"], subject="s",
        body=PLAIN, body_html=HTML, confirm=True,
    ))
    assert captured["msg"].get_content_type() == "multipart/alternative"
    assert "html_warning" not in out

    out2 = send_mod.send_email(_cfg(), SendEmailInput(
        account="t", to=["x@example.com"], subject="s", body=HTML, confirm=True,
    ))
    assert "body_html" in out2["html_warning"]


# ---------- update_draft: preservation of the alternative pair ----------

def _alternative_draft_bytes(with_attachment: bool = False) -> bytes:
    msg = smtp_client.build_message(
        from_addr="me@example.com", to=["you@example.com"],
        subject="Original subject", body_text=PLAIN, body_html=HTML,
    )
    if with_attachment:
        msg.add_attachment(b"%PDF-1.4 fake", maintype="application",
                           subtype="pdf", filename="doc.pdf")
    return bytes(msg)


def _patch_update_io(monkeypatch, captured, raw_bytes):
    monkeypatch.setattr(imap_client, "connect", _fake_connect)
    monkeypatch.setattr(
        imap_client, "fetch_raw_message",
        lambda c, *, mailbox, uid: (raw_bytes, {}),
    )

    def fake_save_draft(c, *, account, message_bytes):
        captured["bytes"] = message_bytes
        return "Drafts", 8

    monkeypatch.setattr(imap_client, "save_draft", fake_save_draft)
    monkeypatch.setattr(imap_client, "delete_uids", lambda *a, **k: 1)
    monkeypatch.setattr(
        "mail_mcp.tools.drafts.resolve_auth",
        lambda a: AuthCredential(kind="password", username=a.email, secret="x"),
    )


def test_update_draft_preserves_both_alternatives(monkeypatch):
    """Subject-only update on a plain+html draft must keep BOTH parts."""
    from mail_mcp.tools.drafts import update_draft
    from mail_mcp.tools.schemas import UpdateDraftInput

    captured: dict = {}
    _patch_update_io(monkeypatch, captured, _alternative_draft_bytes())
    update_draft(_cfg(), UpdateDraftInput(account="t", uid=1, subject="New subject"))
    rebuilt = _parse(captured["bytes"])
    assert rebuilt["Subject"] == "New subject"
    plain, html = _alternative_parts(rebuilt)
    assert plain is not None and PLAIN in plain.get_content()
    assert html is not None and "<h1" in html.get_content(), \
        "the HTML alternative must survive a subject-only update"


def test_update_draft_preserves_alternatives_and_attachments(monkeypatch):
    from mail_mcp.tools.drafts import update_draft
    from mail_mcp.tools.schemas import UpdateDraftInput

    captured: dict = {}
    _patch_update_io(monkeypatch, captured, _alternative_draft_bytes(with_attachment=True))
    update_draft(_cfg(), UpdateDraftInput(account="t", uid=1, subject="New subject"))
    rebuilt = _parse(captured["bytes"])
    plain, html = _alternative_parts(rebuilt)
    assert plain is not None and html is not None
    atts = list(rebuilt.iter_attachments())
    assert len(atts) == 1 and atts[0].get_filename() == "doc.pdf"


def test_update_draft_new_body_html_pair(monkeypatch):
    from mail_mcp.tools.drafts import update_draft
    from mail_mcp.tools.schemas import UpdateDraftInput

    captured: dict = {}
    _patch_update_io(monkeypatch, captured, _alternative_draft_bytes())
    update_draft(_cfg(), UpdateDraftInput(
        account="t", uid=1, body="new plain", body_html="<p>new html</p>",
    ))
    rebuilt = _parse(captured["bytes"])
    plain, html = _alternative_parts(rebuilt)
    assert "new plain" in plain.get_content()
    assert "new html" in html.get_content()


def test_update_draft_body_replaces_with_plain_only(monkeypatch):
    """body without body_html replaces the whole body with plain text (documented)."""
    from mail_mcp.tools.drafts import update_draft
    from mail_mcp.tools.schemas import UpdateDraftInput

    captured: dict = {}
    _patch_update_io(monkeypatch, captured, _alternative_draft_bytes())
    update_draft(_cfg(), UpdateDraftInput(account="t", uid=1, body="only plain now"))
    rebuilt = _parse(captured["bytes"])
    assert rebuilt.get_content_type() == "text/plain"


def test_update_draft_body_html_without_body_rejected(monkeypatch):
    from mail_mcp.tools.drafts import update_draft
    from mail_mcp.tools.schemas import UpdateDraftInput

    captured: dict = {}
    _patch_update_io(monkeypatch, captured, _alternative_draft_bytes())
    with pytest.raises(ValidationError):
        update_draft(_cfg(), UpdateDraftInput(
            account="t", uid=1, body_html="<p>html only</p>",
        ))
    assert "bytes" not in captured, "a rejected call must not APPEND anything"
