"""Per-account signatures (``signatures.py`` + the write tools).

Covers: where signatures load from (default files, configured paths, the
``""`` off switch) and the guards on that (directory containment including
symlink escapes, size cap, UTF-8); insertion (text after a ``-- `` line, HTML
verbatim before ``</body>``, derived flavours, idempotence, short and
image-only signatures); and each tool — signature before the reply quote,
forwards with ``comment_html``, ``update_draft`` only when the body is
replaced, ``send_email`` failing closed before anything is sent.

All signature content here is synthetic.
"""

from __future__ import annotations

import email
import email.policy
import json
import os
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import MagicMock

import pydantic
import pytest

from mail_mcp import imap_client, smtp_client
from mail_mcp import signatures as sigmod
from mail_mcp.config import AccountModel, Config, ConfigModel, load, preserved_account_fields
from mail_mcp.credentials import AuthCredential
from mail_mcp.safety.validation import ValidationError
from mail_mcp.signatures import Signature, apply_signature, load_signature

SIG_HTML = (
    '<div id="sig-root" style="font-family:Arial">'
    "<b>Ada Lovelace</b><br>Analytical Engines Ltd<br>"
    '<img src="https://img.example.com/logo.png" alt="logo"></div>'
)
SIG_TEXT = "Ada Lovelace\nAnalytical Engines Ltd"
PLAIN = "Hi Charles,\n\nThe notes are attached."
HTML = "<html><body><p>Hi Charles,</p><p>The notes are attached.</p></body></html>"


def _account(**kw) -> AccountModel:
    base = dict(
        alias="t", email="me@example.com",
        imap_host="imap.example.com", smtp_host="smtp.example.com",
        drafts_mailbox="Drafts", trash_mailbox="Trash",
    )
    base.update(kw)
    return AccountModel(**base)


def _cfg(tmp_path: Path, **acct_kw) -> Config:
    return Config(path=tmp_path / "config.json", model=ConfigModel(accounts=[_account(**acct_kw)]))


def _write_default(tmp_path: Path, *, html: str | None = SIG_HTML, text: str | None = SIG_TEXT,
                   alias: str = "t") -> Path:
    d = tmp_path / "signatures" / alias
    d.mkdir(parents=True, exist_ok=True)
    if html is not None:
        (d / "firma.html").write_text(html, encoding="utf-8")
    if text is not None:
        (d / "firma.txt").write_text(text, encoding="utf-8")
    return d


def _parse(raw: bytes):
    return email.message_from_bytes(raw, policy=email.policy.default)


# ---------- loading ----------

def test_no_files_means_no_signature(tmp_path):
    cfg = _cfg(tmp_path)
    assert load_signature(cfg, cfg.account()) is None


def test_default_files_are_picked_up(tmp_path):
    _write_default(tmp_path)
    cfg = _cfg(tmp_path)
    sig = load_signature(cfg, cfg.account())
    assert sig == Signature(html=SIG_HTML, text=SIG_TEXT)


def test_old_config_without_signature_fields_loads(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"accounts": [
        {"alias": "t", "email": "me@example.com", "imap_host": "i.example.com",
         "smtp_host": "s.example.com"}]}))
    acct = load(path).account("t")
    assert acct.signature_html_path is None and acct.signature_text_path is None


def test_configured_path_inside_root(tmp_path):
    d = tmp_path / "signatures" / "shared"
    d.mkdir(parents=True)
    (d / "corp.html").write_text(SIG_HTML, encoding="utf-8")
    cfg = _cfg(tmp_path, signature_html_path=str(d / "corp.html"))
    sig = load_signature(cfg, cfg.account())
    assert sig.html == SIG_HTML and sig.text is None


def test_empty_string_disables_a_part(tmp_path):
    _write_default(tmp_path)
    cfg = _cfg(tmp_path, signature_html_path="")
    sig = load_signature(cfg, cfg.account())
    assert sig.html is None and sig.text == SIG_TEXT
    cfg = _cfg(tmp_path, signature_html_path="", signature_text_path="")
    assert load_signature(cfg, cfg.account()) is None


def test_path_outside_signatures_dir_is_rejected(tmp_path):
    outside = tmp_path / "secret.txt"
    outside.write_text("do not mail me", encoding="utf-8")
    cfg = _cfg(tmp_path, signature_text_path=str(outside))
    with pytest.raises(ValidationError, match="must live under"):
        load_signature(cfg, cfg.account())


def test_dotdot_escape_is_rejected(tmp_path):
    (tmp_path / "secret.txt").write_text("x", encoding="utf-8")
    (tmp_path / "signatures").mkdir()
    cfg = _cfg(tmp_path, signature_text_path=str(tmp_path / "signatures" / ".." / "secret.txt"))
    with pytest.raises(ValidationError, match="must live under"):
        load_signature(cfg, cfg.account())


def test_symlink_escaping_the_root_is_rejected(tmp_path):
    secret = tmp_path / "id_rsa"
    secret.write_text("PRIVATE KEY", encoding="utf-8")
    d = _write_default(tmp_path, text=None)
    (d / "firma.txt").symlink_to(secret)
    cfg = _cfg(tmp_path)
    with pytest.raises(ValidationError, match="must live under"):
        load_signature(cfg, cfg.account())


def test_dangling_default_symlink_fails_loudly(tmp_path):
    d = _write_default(tmp_path, text=None)
    (d / "firma.txt").symlink_to(tmp_path / "nowhere.txt")
    cfg = _cfg(tmp_path)
    with pytest.raises(ValidationError, match="not found"):
        load_signature(cfg, cfg.account())


def test_configured_missing_file_fails_loudly(tmp_path):
    (tmp_path / "signatures").mkdir()
    cfg = _cfg(tmp_path, signature_html_path=str(tmp_path / "signatures" / "gone.html"))
    with pytest.raises(ValidationError, match="not found"):
        load_signature(cfg, cfg.account())


def test_oversized_signature_is_rejected(tmp_path):
    _write_default(tmp_path, html="x" * (sigmod.MAX_SIGNATURE_BYTES + 1), text=None)
    cfg = _cfg(tmp_path)
    with pytest.raises(ValidationError, match="limit"):
        load_signature(cfg, cfg.account())


def test_non_utf8_signature_is_rejected(tmp_path):
    d = _write_default(tmp_path, html=None, text=None)
    (d / "firma.txt").write_bytes(b"caf\xe9")
    cfg = _cfg(tmp_path)
    with pytest.raises(ValidationError, match="UTF-8"):
        load_signature(cfg, cfg.account())


def test_directory_instead_of_file_is_rejected(tmp_path):
    d = _write_default(tmp_path, html=None, text=None)
    (d / "firma.html").mkdir()
    cfg = _cfg(tmp_path)
    with pytest.raises(ValidationError, match="regular file"):
        load_signature(cfg, cfg.account())


@pytest.mark.parametrize("bad", ["sig\x00.html", "a\nb.html", "a\x7fb"])
def test_control_characters_in_configured_path_rejected(bad):
    with pytest.raises(pydantic.ValidationError):
        _account(signature_html_path=bad)


def test_text_signature_is_tidied_not_reworded(tmp_path):
    messy = "-- \n\nAda Lovelace   \n \n \n \n Analytical Engines Ltd \n\n\n"
    _write_default(tmp_path, html=None, text=messy)
    cfg = _cfg(tmp_path)
    assert load_signature(cfg, cfg.account()).text == "Ada Lovelace\n\n Analytical Engines Ltd"


# ---------- insertion ----------

def test_plain_message_gets_text_signature_only():
    out = apply_signature(PLAIN, None, Signature(SIG_HTML, SIG_TEXT))
    assert out.status == "added"
    assert out.text == PLAIN + "\n\n-- \n" + SIG_TEXT + "\n"
    assert out.html is None, "a plain-text message is never upgraded to HTML"


def test_html_signature_inserted_verbatim_before_closing_body():
    out = apply_signature(PLAIN, HTML, Signature(SIG_HTML, SIG_TEXT))
    assert SIG_HTML in out.html, "HTML signature must be inserted byte-for-byte"
    assert out.html.index("attached") < out.html.index("sig-root") < out.html.rindex("</body>")
    assert out.html.count("</body>") == 1


def test_html_fragment_without_body_tag_gets_signature_appended():
    out = apply_signature("x", "<p>hi</p>", Signature(SIG_HTML, None))
    assert out.html.startswith("<p>hi</p>") and out.html.rstrip().endswith(SIG_HTML)


def test_apply_is_idempotent():
    sig = Signature(SIG_HTML, SIG_TEXT)
    once = apply_signature(PLAIN, HTML, sig)
    twice = apply_signature(once.text, once.html, sig)
    assert twice.status == "already_present"
    assert (twice.text, twice.html) == (once.text, once.html)


def test_signature_already_typed_by_caller_is_not_duplicated():
    body = PLAIN + "\n\nAda Lovelace\nAnalytical   Engines Ltd"
    out = apply_signature(body, None, Signature(None, SIG_TEXT))
    assert out.status == "already_present" and out.text == body


def test_short_signature_does_not_match_a_greeting():
    out = apply_signature("Thanks Ada.", None, Signature(None, "Ada."))
    assert out.status == "added" and out.text.endswith("-- \nAda.\n")
    again = apply_signature(out.text, None, Signature(None, "Ada."))
    assert again.status == "already_present"


def test_image_only_html_signature():
    img_sig = '<img src="https://img.example.com/banner.png">'
    out = apply_signature("x", HTML, Signature(img_sig, None))
    assert img_sig in out.html
    assert apply_signature("x", out.html, Signature(img_sig, None)).html == out.html


def test_text_derived_from_html_when_only_html_exists():
    out = apply_signature(PLAIN, None, Signature(SIG_HTML, None))
    assert "-- \nAda Lovelace" in out.text and "Analytical Engines Ltd" in out.text
    assert "<b>" not in out.text


def test_html_derived_from_text_is_escaped():
    out = apply_signature("x", HTML, Signature(None, "Ada <b>Lovelace</b>\nLtd"))
    assert "Ada &lt;b&gt;Lovelace&lt;/b&gt;<br>" in out.html
    assert "<b>Lovelace</b>" not in out.html


def test_disabled_leaves_body_untouched():
    out = apply_signature(PLAIN, HTML, Signature(SIG_HTML, SIG_TEXT), enabled=False)
    assert (out.text, out.html, out.status) == (PLAIN, HTML, "disabled")


def test_sign_body_false_skips_even_a_broken_signature(tmp_path):
    _write_default(tmp_path, html="x" * (sigmod.MAX_SIGNATURE_BYTES + 1))
    cfg = _cfg(tmp_path)
    out = sigmod.sign_body(cfg, cfg.account(), False, PLAIN, None)
    assert out.status == "disabled" and out.text == PLAIN


# ---------- tools ----------

@contextmanager
def _fake_connect(account, creds):
    c = MagicMock()
    c.list_folders.return_value = [
        ([b"\\HasNoChildren"], "/", "INBOX"),
        ([b"\\HasNoChildren", b"\\Drafts"], "/", "Drafts"),
    ]
    yield c


def _creds(a):
    return AuthCredential(kind="password", username=a.email, secret="x")


def _patch_io(monkeypatch, captured, *, raw=b"", headers=None):
    def fake_save_draft(c, *, account, message_bytes):
        captured["bytes"] = message_bytes
        return "Drafts", 9

    monkeypatch.setattr(imap_client, "connect", _fake_connect)
    monkeypatch.setattr(imap_client, "save_draft", fake_save_draft)
    monkeypatch.setattr(imap_client, "delete_uids", lambda *a, **k: 1)
    monkeypatch.setattr(
        imap_client, "fetch_raw_message",
        lambda c, *, mailbox, uid: (raw, headers or {}),
    )
    monkeypatch.setattr("mail_mcp.tools.drafts.resolve_auth", _creds)


def _reply_headers():
    return {
        "From": "Charles <charles@example.org>",
        "Date": "Mon, 1 Jul 2026 10:00:00 +0200",
        "Subject": "Engines",
        "Message-ID": "<orig@example.org>",
    }


def test_save_draft_signs_by_default(tmp_path, monkeypatch):
    from mail_mcp.tools.drafts import save_draft
    from mail_mcp.tools.schemas import SaveDraftInput

    _write_default(tmp_path)
    captured: dict = {}
    _patch_io(monkeypatch, captured)
    out = save_draft(_cfg(tmp_path), SaveDraftInput(
        account="t", to=["x@example.org"], subject="s", body=PLAIN, body_html=HTML,
    ))
    assert out["signature"] == "added"
    msg = _parse(captured["bytes"])
    assert "-- \nAda Lovelace" in msg.get_body(("plain",)).get_content()
    assert SIG_HTML in msg.get_body(("html",)).get_content()


def test_save_draft_include_signature_false(tmp_path, monkeypatch):
    from mail_mcp.tools.drafts import save_draft
    from mail_mcp.tools.schemas import SaveDraftInput

    _write_default(tmp_path)
    captured: dict = {}
    _patch_io(monkeypatch, captured)
    out = save_draft(_cfg(tmp_path), SaveDraftInput(
        account="t", to=["x@example.org"], subject="s", body=PLAIN, include_signature=False,
    ))
    assert out["signature"] == "disabled"
    assert "Ada Lovelace" not in _parse(captured["bytes"]).get_content()


def test_save_draft_without_signature_files_is_unchanged(tmp_path, monkeypatch):
    from mail_mcp.tools.drafts import save_draft
    from mail_mcp.tools.schemas import SaveDraftInput

    captured: dict = {}
    _patch_io(monkeypatch, captured)
    out = save_draft(_cfg(tmp_path), SaveDraftInput(
        account="t", to=["x@example.org"], subject="s", body=PLAIN,
    ))
    assert out["signature"] == "none"
    assert _parse(captured["bytes"]).get_content().rstrip() == PLAIN


def test_reply_signature_sits_between_reply_and_quote(tmp_path, monkeypatch):
    from mail_mcp.tools.drafts import reply_draft
    from mail_mcp.tools.schemas import ReplyDraftInput

    _write_default(tmp_path)
    captured: dict = {}
    _patch_io(monkeypatch, captured, headers=_reply_headers())
    out = reply_draft(_cfg(tmp_path), ReplyDraftInput(
        account="t", uid=1, body="Agreed.", body_html="<html><body><p>Agreed.</p></body></html>",
    ))
    assert out["signature"] == "added"
    msg = _parse(captured["bytes"])
    plain = msg.get_body(("plain",)).get_content()
    assert plain.index("Agreed.") < plain.index("-- \nAda Lovelace") < plain.index("wrote:")
    html = msg.get_body(("html",)).get_content()
    assert html.index("Agreed.") < html.index("sig-root") < html.index("wrote:") < html.rindex("</body>")


def test_forward_with_comment_html_gets_rich_signature(tmp_path, monkeypatch):
    from mail_mcp.tools.drafts import forward_draft
    from mail_mcp.tools.schemas import ForwardDraftInput

    _write_default(tmp_path)
    original = (
        b"From: charles@example.org\r\nTo: me@example.com\r\nSubject: Engines\r\n"
        b"Message-ID: <orig@example.org>\r\n\r\nOriginal body\r\n"
    )
    captured: dict = {}
    _patch_io(monkeypatch, captured, raw=original, headers=_reply_headers())
    out = forward_draft(_cfg(tmp_path), ForwardDraftInput(
        account="t", uid=1, to=["y@example.org"], comment="FYI", comment_html="<p>FYI</p>",
    ))
    assert out["signature"] == "added"
    msg = _parse(captured["bytes"])
    assert msg.get_content_type() == "multipart/mixed"
    assert "-- \nAda Lovelace" in msg.get_body(("plain",)).get_content()
    assert SIG_HTML in msg.get_body(("html",)).get_content()
    atts = list(msg.iter_attachments())
    assert len(atts) == 1 and atts[0].get_content_type() == "message/rfc822"


def test_forward_plain_comment_gets_text_signature(tmp_path, monkeypatch):
    from mail_mcp.tools.drafts import forward_draft
    from mail_mcp.tools.schemas import ForwardDraftInput

    _write_default(tmp_path)
    original = b"From: c@example.org\r\nSubject: s\r\n\r\nbody\r\n"
    captured: dict = {}
    _patch_io(monkeypatch, captured, raw=original, headers=_reply_headers())
    forward_draft(_cfg(tmp_path), ForwardDraftInput(account="t", uid=1, to=["y@example.org"]))
    msg = _parse(captured["bytes"])
    assert msg.get_body(("plain",)).get_content().startswith("-- \nAda Lovelace")


def _signed_draft_bytes(tmp_path) -> bytes:
    sig = load_signature(_cfg(tmp_path), _cfg(tmp_path).account())
    signed = apply_signature(PLAIN, HTML, sig)
    return bytes(smtp_client.build_message(
        from_addr="me@example.com", to=["x@example.org"], subject="Draft",
        body_text=signed.text, body_html=signed.html,
    ))


def test_update_draft_preserved_body_is_untouched(tmp_path, monkeypatch):
    from mail_mcp.tools.drafts import update_draft
    from mail_mcp.tools.schemas import UpdateDraftInput

    _write_default(tmp_path)
    raw = _signed_draft_bytes(tmp_path)
    captured: dict = {}
    _patch_io(monkeypatch, captured, raw=raw)
    out = update_draft(_cfg(tmp_path), UpdateDraftInput(account="t", uid=1, subject="New"))
    assert "signature" not in out
    msg = _parse(captured["bytes"])
    assert msg.get_body(("plain",)).get_content().count("Ada Lovelace") == 1
    assert msg.get_body(("html",)).get_content().count("sig-root") == 1


def test_update_draft_replaced_body_is_signed_once(tmp_path, monkeypatch):
    from mail_mcp.tools.drafts import update_draft
    from mail_mcp.tools.schemas import UpdateDraftInput

    _write_default(tmp_path)
    captured: dict = {}
    _patch_io(monkeypatch, captured, raw=_signed_draft_bytes(tmp_path))
    out = update_draft(_cfg(tmp_path), UpdateDraftInput(account="t", uid=1, body="Rewritten."))
    assert out["signature"] == "added"
    assert _parse(captured["bytes"]).get_content().count("Ada Lovelace") == 1

    # Reading the signed body back and resubmitting it must not stack a copy.
    signed_again = "Rewritten.\n\n-- \n" + SIG_TEXT + "\n"
    out = update_draft(_cfg(tmp_path), UpdateDraftInput(account="t", uid=1, body=signed_again))
    assert out["signature"] == "already_present"
    assert _parse(captured["bytes"]).get_content().count("Ada Lovelace") == 1


def _send_setup(monkeypatch, captured):
    from mail_mcp.tools import send as send_mod

    monkeypatch.setenv("MAIL_MCP_WRITE_ENABLED", "true")
    monkeypatch.setenv("MAIL_MCP_SEND_ENABLED", "true")
    send_mod._reset_for_tests()

    def fake_send(account, creds, msg, *, bcc=None):
        captured["msg"] = msg
        return msg["Message-ID"]

    monkeypatch.setattr(smtp_client, "send", fake_send)
    monkeypatch.setattr("mail_mcp.tools.send.resolve_auth", _creds)
    return send_mod


def test_send_email_is_signed(tmp_path, monkeypatch):
    from mail_mcp.tools.schemas import SendEmailInput

    _write_default(tmp_path)
    captured: dict = {}
    send_mod = _send_setup(monkeypatch, captured)
    out = send_mod.send_email(_cfg(tmp_path), SendEmailInput(
        account="t", to=["x@example.org"], subject="s", body=PLAIN, body_html=HTML, confirm=True,
    ))
    assert out["signature"] == "added"
    assert SIG_HTML in captured["msg"].get_body(("html",)).get_content()


def test_send_email_broken_signature_fails_before_sending(tmp_path, monkeypatch):
    from mail_mcp.tools.schemas import SendEmailInput

    _write_default(tmp_path, html="x" * (sigmod.MAX_SIGNATURE_BYTES + 1))
    captured: dict = {}
    send_mod = _send_setup(monkeypatch, captured)
    with pytest.raises(ValidationError):
        send_mod.send_email(_cfg(tmp_path), SendEmailInput(
            account="t", to=["x@example.org"], subject="s", body=PLAIN, confirm=True,
        ))
    assert "msg" not in captured, "nothing may leave when the signature is broken"
    out = send_mod.send_email(_cfg(tmp_path), SendEmailInput(
        account="t", to=["x@example.org"], subject="s", body=PLAIN,
        confirm=True, include_signature=False,
    ))
    assert out["signature"] == "disabled" and "msg" in captured


def test_get_account_info_reports_signature_without_content(tmp_path):
    from mail_mcp.tools.read import get_account_info
    from mail_mcp.tools.schemas import AccountInfoInput

    _write_default(tmp_path, html=None)
    info = get_account_info(_cfg(tmp_path), AccountInfoInput(account="t"))
    assert info["signature"] == {"html": False, "text": True}
    assert "Ada" not in json.dumps(info)


def test_get_account_info_surfaces_signature_errors(tmp_path):
    from mail_mcp.tools.read import get_account_info
    from mail_mcp.tools.schemas import AccountInfoInput

    info = get_account_info(
        _cfg(tmp_path, signature_text_path=str(tmp_path / "elsewhere.txt")),
        AccountInfoInput(account="t"),
    )
    assert info["signature"]["html"] is False and "error" in info["signature"]


def test_doctor_signature_line(tmp_path):
    from mail_mcp.doctor import _signature_status

    cfg = _cfg(tmp_path)
    assert _signature_status(cfg, cfg.account()) == "none"
    _write_default(tmp_path)
    assert _signature_status(cfg, cfg.account()) == "html + text"


# ---------- re-running init / add-account keeps the fields ----------

def test_preserved_fields_include_signature_paths(tmp_path):
    cfg = _cfg(tmp_path, signature_html_path="", signature_text_path="/x/firma.txt",
               smtp_username="me@tenant.onmicrosoft.com")
    assert preserved_account_fields(cfg, "t") == {
        "smtp_username": "me@tenant.onmicrosoft.com",
        "signature_html_path": "",
        "signature_text_path": "/x/firma.txt",
    }
    assert preserved_account_fields(cfg, "other") == {}


def test_add_account_keeps_signature_paths_on_overwrite(tmp_path, monkeypatch):
    import argparse

    from mail_mcp import __main__ as cli
    from mail_mcp import config as config_mod

    path = tmp_path / "config.json"
    monkeypatch.setattr(config_mod, "default_config_path", lambda: path)
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": "secret")
    monkeypatch.setattr(cli, "set_password", lambda *a: None)

    def _no_secret(*a):
        raise RuntimeError("missing")

    monkeypatch.setattr(cli, "get_password", _no_secret)
    cfg = load(path)
    cfg.model = ConfigModel(default_alias="t", accounts=[_account(signature_text_path="")])
    config_mod.save(cfg)

    args = argparse.Namespace(
        alias="t", email="me@example.com", imap_host="imap.example.com", imap_port=993,
        smtp_host="smtp.example.com", smtp_port=465, smtp_starttls=False,
        drafts_mailbox="Drafts", trash_mailbox="Trash", smtp_username=None,
    )
    assert cli._cmd_add_account(args) == 0
    acct = load(path).account("t")
    assert acct.smtp_port == 465
    assert acct.signature_text_path == ""


# ---------- fixes from the adversarial review (2026-09-24) ----------

needs_non_root = pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0, reason="root ignores file permissions",
)


def test_relative_configured_path_is_anchored_to_config_dir(tmp_path, monkeypatch):
    d = tmp_path / "signatures" / "shared"
    d.mkdir(parents=True)
    (d / "corp.txt").write_text(SIG_TEXT, encoding="utf-8")
    cfg = _cfg(tmp_path, signature_text_path="signatures/shared/corp.txt")
    elsewhere = tmp_path / "somewhere-else"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)  # the MCP server's CWD is not the config dir
    assert load_signature(cfg, cfg.account()).text == SIG_TEXT


def test_relative_path_cannot_escape_the_root(tmp_path):
    (tmp_path / "secret.txt").write_text("x", encoding="utf-8")
    (tmp_path / "signatures").mkdir()
    cfg = _cfg(tmp_path, signature_text_path="secret.txt")  # → <config dir>/secret.txt
    with pytest.raises(ValidationError, match="must live under"):
        load_signature(cfg, cfg.account())


@needs_non_root
def test_unreadable_file_is_a_validation_error_and_diagnostics_survive(tmp_path):
    from mail_mcp.tools.read import get_account_info
    from mail_mcp.tools.schemas import AccountInfoInput

    d = _write_default(tmp_path)
    os.chmod(d / "firma.txt", 0)
    try:
        cfg = _cfg(tmp_path)
        with pytest.raises(ValidationError, match="not readable"):
            load_signature(cfg, cfg.account())
        info = get_account_info(cfg, AccountInfoInput(account="t"))
        assert info["email"] == "me@example.com" and "error" in info["signature"]
    finally:
        os.chmod(d / "firma.txt", 0o644)


@needs_non_root
def test_unreadable_signature_directory_is_not_silently_unsigned(tmp_path):
    d = _write_default(tmp_path)
    os.chmod(d, 0)
    try:
        cfg = _cfg(tmp_path)
        with pytest.raises(ValidationError):
            sigmod.sign_body(cfg, cfg.account(), None, PLAIN, None)
        assert "error" in sigmod.describe_signature(cfg, cfg.account())
    finally:
        os.chmod(d, 0o755)


def test_symlink_loop_is_a_validation_error(tmp_path):
    d = _write_default(tmp_path, html=None)
    os.symlink("firma.html", d / "firma.html")  # points at itself
    cfg = _cfg(tmp_path)
    with pytest.raises(ValidationError):
        load_signature(cfg, cfg.account())
    assert "error" in sigmod.describe_signature(cfg, cfg.account())


def test_fifo_is_rejected_without_blocking(tmp_path):
    d = _write_default(tmp_path, html=None)
    os.mkfifo(d / "firma.html")
    cfg = _cfg(tmp_path)
    with pytest.raises(ValidationError, match="regular file"):
        load_signature(cfg, cfg.account())


def test_suite_isolation_ignores_signatures_outside_tmp_path(tmp_path_factory):
    """Configs outside the test's tmp_path (like the legacy Path('/tmp/x'))
    must not pick up signatures planted next to them."""
    foreign = tmp_path_factory.mktemp("foreign")
    _write_default(foreign)
    cfg = Config(path=foreign / "config.json", model=ConfigModel(accounts=[_account()]))
    assert load_signature(cfg, cfg.account()) is None


SIG_ONE_LINE = "Ada Lovelace · Analytical Engines"


def test_signature_quoted_in_html_blockquote_does_not_count():
    body_html = (
        "<html><body><p>See you Tuesday.</p><blockquote><p>Charles wrote:</p>"
        f"<p>Earlier text.</p>{SIG_HTML}</blockquote></body></html>"
    )
    out = apply_signature("See you Tuesday.", body_html, Signature(SIG_HTML, SIG_TEXT))
    assert out.status == "added"
    assert out.html.count("sig-root") == 2  # the quoted one and the new one


def test_outlook_plain_quote_gets_signature_before_the_separator():
    body = (
        "See you Tuesday.\n\n-----Original Message-----\nFrom: Charles\n\n"
        "Earlier text.\n\n-- \n" + SIG_TEXT + "\n"
    )
    out = apply_signature(body, None, Signature(None, SIG_TEXT))
    assert out.status == "added"
    assert out.text.index("See you Tuesday.") < out.text.index("-- \nAda") \
        < out.text.index("-----Original Message-----")
    assert out.text.count("Ada Lovelace") == 2


def test_gt_quoted_one_line_signature_does_not_count():
    body = "Agreed.\n\n> On Monday Charles wrote:\n> Earlier text.\n> " + SIG_ONE_LINE + "\n"
    out = apply_signature(body, None, Signature(None, SIG_ONE_LINE))
    assert out.status == "added"
    assert out.text.index("-- \n" + SIG_ONE_LINE) < out.text.index("> Earlier text.")


def test_outlook_html_reply_gets_signature_before_divrplyfwdmsg():
    body_html = (
        '<html><body><div>Agreed.</div><div id="appendonsend"></div><hr>'
        '<div id="divRplyFwdMsg"><b>From:</b> Charles</div>'
        f"<div>Earlier text.{SIG_HTML}</div></body></html>"
    )
    out = apply_signature("Agreed.", body_html, Signature(SIG_HTML, SIG_TEXT))
    assert out.status == "added"
    first_sig = out.html.index("sig-root")
    assert out.html.index("Agreed.") < first_sig < out.html.index('id="appendonsend"')
    assert out.html.count("sig-root") == 2


def test_gmail_quote_marks_the_quote_start():
    body_html = (
        '<div>Agreed.</div><div class="gmail_quote gmail_quote_container">'
        f"<div>On Mon, Charles wrote:</div><blockquote>{SIG_HTML}</blockquote></div>"
    )
    out = apply_signature("Agreed.", body_html, Signature(SIG_HTML, SIG_TEXT))
    assert out.html.index("sig-root") < out.html.index("gmail_quote")


def test_signature_with_underscore_rule_is_still_idempotent():
    sig_text = "Ada Lovelace\n____________________\nAnalytical Engines Ltd"
    sig = Signature(None, sig_text)
    once = apply_signature("Hello.", None, sig)
    twice = apply_signature(once.text, None, sig)
    assert twice.status == "already_present" and twice.text == once.text


def test_reply_read_back_with_attribution_is_not_resigned():
    body = "Agreed.\n\n-- \n" + SIG_TEXT + "\n\nOn Mon, 1 Jul 2026, Charles <c@example.org> wrote:\n"
    out = apply_signature(body, None, Signature(None, SIG_TEXT))
    assert out.status == "already_present" and out.text == body


def test_table_signature_cells_do_not_run_together():
    table = (
        "<table><tr><td>Ada Lovelace</td><td>Director</td></tr>"
        "<tr><td>Tel.</td><td>+44 20 0000 0000</td></tr></table>"
    )
    out = apply_signature("Hi.", None, Signature(table, None))
    assert "Ada Lovelace Director" in out.text and "Tel. +44 20" in out.text
    assert apply_signature(out.text, None, Signature(table, None)).status == "already_present"
    # A hand-typed copy with the cells space-separated is recognised too.
    typed = "Hi.\n\n-- \nAda Lovelace Director\nTel. +44 20 0000 0000\n"
    assert apply_signature(typed, None, Signature(table, None)).status == "already_present"


def test_image_only_signature_on_plain_message_reports_none():
    out = apply_signature("Hi.", None, Signature('<img src="https://img.example.com/x.png">', None))
    assert out.status == "none" and out.text == "Hi."
