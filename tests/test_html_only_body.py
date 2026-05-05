"""Single-part ``text/html`` body recovery.

Outlook 365's "Forward inline" sends the message as a single-part
``text/html`` (no ``text/plain`` alternative, ``Content-Transfer-Encoding:
base64``, ``Content-ID`` set). Until v0.3.4 the body extractor captured
the HTML correctly into ``EmailBody.html_rendered`` but the read tool only
surfaced ``EmailBody.text``, so callers saw an empty body and assumed the
content was unreachable. The MCP now renders the HTML to a plain-text
approximation when no ``text/plain`` alternative exists.
"""

from __future__ import annotations

import email
import email.policy
from email.message import EmailMessage

from mail_mcp.imap_client import _extract_parts, _html_to_text


def _build_outlook_forward_inline_html(html_body: str, *, content_id: str | None) -> EmailMessage:
    """Reproduce Outlook 'Forward inline' wire shape: single-part text/html, base64."""
    msg = EmailMessage(policy=email.policy.default)
    msg["From"] = "alice@example.com"
    msg["To"] = "bob@example.com"
    msg["Subject"] = "Fwd: meeting agenda"
    if content_id is not None:
        msg["Content-ID"] = content_id
    msg.set_content(html_body, subtype="html", cte="base64")
    return email.message_from_bytes(msg.as_bytes(), policy=email.policy.default)  # type: ignore[return-value]


def test_html_only_body_is_rendered_as_text():
    """Pin the regression: single-part HTML used to return ``body=""``."""
    html = (
        "<html><body><p>Hi <b>Bob</b>,</p><p>Please review the "
        "<a href='https://example.com/doc'>document</a> before Friday.</p>"
        "<p>Thanks,<br>Alice</p></body></html>"
    )
    msg = _build_outlook_forward_inline_html(
        html, content_id="<ABC123@example.com>"
    )
    text, html_rendered, attachments = _extract_parts(msg)
    assert "Hi Bob" in text
    assert "Please review the document" in text
    assert "Thanks" in text
    assert "Alice" in text
    # Tags must not survive into the rendered text.
    assert "<p>" not in text
    assert "<b>" not in text
    assert "</body>" not in text
    # The original HTML is still preserved on html_rendered for callers that want it.
    assert html_rendered is not None
    assert "<b>Bob</b>" in html_rendered
    # Single-part has no real attachments — the Content-ID is metadata, not a part.
    assert attachments == []


def test_html_only_strips_script_and_style():
    """Inline scripts/styles must not bleed into the rendered text."""
    html = (
        "<html><head><style>.x{color:red}</style></head>"
        "<body><script>alert('xss')</script>"
        "<p>Visible body.</p></body></html>"
    )
    msg = _build_outlook_forward_inline_html(html, content_id=None)
    text, _html, _att = _extract_parts(msg)
    assert "Visible body." in text
    assert "alert" not in text
    assert "color:red" not in text


def test_html_to_text_handles_entities_and_breaks():
    out = _html_to_text(
        "<p>Caf&eacute; con leche &amp; az&uacute;car.<br>Hasta luego.</p>"
    )
    assert "Café con leche & azúcar." in out
    # The <br> inside <p> should produce a line break before "Hasta luego.".
    assert "azúcar.\nHasta luego." in out


def test_html_to_text_normalises_crlf():
    """HTML source often arrives with CRLF; literals must not survive."""
    out = _html_to_text("<p>line1</p>\r\n<p>line2</p>\r\n")
    assert "\r" not in out
    assert "line1" in out and "line2" in out


def test_multipart_alternative_still_prefers_text_plain():
    """Regression guard: when text/plain exists, do NOT fall back to HTML."""
    msg = EmailMessage(policy=email.policy.default)
    msg["From"] = "a@e.com"
    msg["To"] = "b@e.com"
    msg["Subject"] = "Both"
    msg.set_content("This is the PLAIN text version.")
    msg.add_alternative(
        "<html><body><p>This is the HTML version.</p></body></html>",
        subtype="html",
    )
    parsed = email.message_from_bytes(msg.as_bytes(), policy=email.policy.default)

    text, html, _att = _extract_parts(parsed)
    assert "PLAIN text version" in text
    # We must not have appended the HTML rendering on top of the text/plain.
    assert "HTML version" not in text
    assert html is not None and "HTML version" in html


def test_html_to_text_empty_input():
    assert _html_to_text("") == ""
    assert _html_to_text("<html></html>") == ""
