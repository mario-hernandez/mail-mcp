"""Per-account email signatures.

Each account may carry an HTML and/or a plain-text signature that the write
tools (``save_draft``, ``reply_draft``, ``forward_draft``, ``update_draft``
when the body is replaced, and ``send_email``) append after the caller's text
and before any reply quote — the placement Outlook and Apple Mail use.

Where the files come from:

* ``AccountModel.signature_html_path`` / ``signature_text_path`` when set;
* otherwise ``<config dir>/signatures/<alias>/firma.html`` and ``firma.txt``
  (``~/.config/mail-mcp/signatures/<alias>/`` in a default install). A missing
  default file simply means "no signature", which keeps every pre-existing
  account behaving exactly as before;
* an empty string (``""``) in either field disables that part explicitly,
  without touching the files.

Trust and safety. A signature is the account owner's own content, so the HTML
is inserted **verbatim**: it is never parsed, sanitised, rewritten or
executed, and remote images stay remote. What *is* enforced is where it can be
read from: every path — configured or default — must resolve, symlinks
followed, to a regular file inside ``<config dir>/signatures/``, be at most
:data:`MAX_SIGNATURE_BYTES`, and decode as UTF-8. That keeps a malformed or
tampered config from turning every outgoing email into an exfiltration channel
for arbitrary local files. Paths never come from tool arguments: the only
per-call control is the boolean ``include_signature``.

Idempotence. The signature is not added to a part that already contains it
(compared on normalised visible text, or on the raw HTML for image-only
signatures), so re-sending a body that was read back from a signed draft never
stacks a second copy.
"""

from __future__ import annotations

import html as _html_lib
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path

from .config import AccountModel, Config
from .safety.validation import ValidationError

SIGNATURES_DIRNAME = "signatures"
DEFAULT_HTML_NAME = "firma.html"
DEFAULT_TEXT_NAME = "firma.txt"
MAX_SIGNATURE_BYTES = 64 * 1024
# RFC 3676 §4.3 signature separator: "-- " (dash, dash, space) on its own line.
TEXT_DELIMITER = "-- "

# Below this many characters of normalised visible text, a containment check
# on text alone would misfire ("Mario" inside "Hola Mario"), so short or
# image-only signatures are matched on stricter evidence instead.
_MIN_TEXT_FINGERPRINT = 16

_CLOSING_BODY_RE = re.compile(r"</body\s*>", re.IGNORECASE)
_WS_RE = re.compile(r"\s+")
# Zero-width and bidi-control characters: invisible, and signatures extracted
# from HTML often carry them (e.g. U+202D before a phone number). Ignored when
# comparing, never removed from what is sent.
_INVISIBLE_RE = re.compile("[​-‏‪-‮⁠-⁩﻿]")

STATUS_ADDED = "added"
STATUS_PRESENT = "already_present"
STATUS_DISABLED = "disabled"
STATUS_NONE = "none"


@dataclass(frozen=True)
class Signature:
    """A loaded signature. Either part may be missing; never both."""

    html: str | None
    text: str | None


@dataclass(frozen=True)
class SignedBody:
    text: str
    html: str | None
    status: str


def signatures_root(cfg: Config) -> Path | None:
    """``<config dir>/signatures`` — the only directory signatures load from."""
    if cfg.path is None:
        return None
    return Path(cfg.path).expanduser().parent / SIGNATURES_DIRNAME


def _read_signature_file(path: Path, root: Path, *, field: str) -> str:
    try:
        resolved = path.expanduser().resolve(strict=True)
    except (FileNotFoundError, OSError) as exc:
        raise ValidationError(f"{field}: signature file not found: {path}") from exc
    root_resolved = root.expanduser().resolve(strict=False)
    if not resolved.is_relative_to(root_resolved):
        raise ValidationError(
            f"{field}: signature file must live under {root} (got {path}, which "
            f"resolves to {resolved})"
        )
    if not resolved.is_file():
        raise ValidationError(f"{field}: signature path is not a regular file: {path}")
    # Cap the read itself, not just the stat: the file could grow in between.
    with resolved.open("rb") as fh:
        data = fh.read(MAX_SIGNATURE_BYTES + 1)
    if len(data) > MAX_SIGNATURE_BYTES:
        raise ValidationError(
            f"{field}: signature file exceeds the {MAX_SIGNATURE_BYTES}-byte limit: {path}"
        )
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValidationError(f"{field}: signature file is not valid UTF-8: {path}") from exc


def _resolve_part(
    configured: str | None, default_name: str, root: Path | None, alias: str, *, field: str,
) -> str | None:
    """Return the file content for one part, or ``None`` when there is none."""
    if configured == "":
        return None  # explicitly disabled for this account
    if configured is not None:
        if root is None:
            raise ValidationError(f"{field}: no config directory to anchor signatures to")
        return _read_signature_file(Path(configured), root, field=field)
    if root is None:
        return None
    default = root / alias / default_name
    if not default.exists() and not default.is_symlink():
        return None  # no default file → no signature, the historical behaviour
    return _read_signature_file(default, root, field=field)


def normalize_text_signature(text: str) -> str:
    """Tidy a plain-text signature for display without changing its words.

    Trailing whitespace is stripped from every line, runs of blank lines
    collapse to one, leading/trailing blank lines go, and a leading ``-- ``
    separator already present in the file is dropped (it is added on
    insertion, so keeping it would print two).
    """
    lines = [ln.rstrip() for ln in text.replace("\r\n", "\n").replace("\r", "\n").split("\n")]
    out: list[str] = []
    for ln in lines:
        if not ln and (not out or not out[-1]):
            continue
        out.append(ln)
    while out and not out[-1]:
        out.pop()
    if out and out[0].strip() == TEXT_DELIMITER.strip():
        out = out[1:]
        while out and not out[0]:
            out.pop(0)
    return "\n".join(out)


def load_signature(cfg: Config, acct: AccountModel) -> Signature | None:
    """Load the account's signature, or ``None`` if it has none.

    Raises :class:`ValidationError` when a signature file exists (or is
    explicitly configured) but is unusable — outside the signatures directory,
    too large, not UTF-8, missing. Failing loudly beats silently sending an
    unsigned message the owner believes is signed; the caller can always pass
    ``include_signature=false``.
    """
    root = signatures_root(cfg)
    html = _resolve_part(
        acct.signature_html_path, DEFAULT_HTML_NAME, root, acct.alias,
        field="signature_html_path",
    )
    text = _resolve_part(
        acct.signature_text_path, DEFAULT_TEXT_NAME, root, acct.alias,
        field="signature_text_path",
    )
    html = html.strip() if html and html.strip() else None
    text = normalize_text_signature(text) if text else None
    text = text or None
    if html is None and text is None:
        return None
    return Signature(html=html, text=text)


def describe_signature(cfg: Config, acct: AccountModel) -> dict:
    """Non-raising summary for ``get_account_info`` / ``doctor``."""
    try:
        sig = load_signature(cfg, acct)
    except ValidationError as exc:
        return {"html": False, "text": False, "error": str(exc)}
    if sig is None:
        return {"html": False, "text": False}
    return {"html": sig.html is not None, "text": sig.text is not None}


# --- insertion -------------------------------------------------------------


def _fingerprint(text: str) -> str:
    text = unicodedata.normalize("NFC", text).replace(" ", " ")
    text = _INVISIBLE_RE.sub("", text)
    return _WS_RE.sub(" ", text).strip().casefold()


def _html_visible_text(html: str) -> str:
    from .imap_client import _html_to_text  # local import: keeps this module light

    return _html_to_text(html)


def _text_has_signature(body: str, sig_text: str) -> bool:
    body_fp = _fingerprint(body)
    sig_fp = _fingerprint(sig_text)
    if not sig_fp:
        return True
    if len(sig_fp) >= _MIN_TEXT_FINGERPRINT:
        return sig_fp in body_fp
    # Short signature: only the delimited form counts as "already there".
    return _fingerprint(f"{TEXT_DELIMITER}\n{sig_text}") in body_fp


def _html_has_signature(body_html: str, sig_html: str) -> bool:
    sig_fp = _fingerprint(_html_visible_text(sig_html))
    if len(sig_fp) >= _MIN_TEXT_FINGERPRINT:
        return sig_fp in _fingerprint(_html_visible_text(body_html))
    # Image-only or near-empty signature: compare the markup itself.
    return _WS_RE.sub(" ", sig_html).strip() in _WS_RE.sub(" ", body_html)


def _text_to_html_block(text: str) -> str:
    lines = "<br>\n".join(_html_lib.escape(line) for line in text.split("\n"))
    return f'<div class="mail-mcp-signature">{lines}</div>'


def _insert_html(body_html: str, block: str) -> str:
    """Insert before the last ``</body>`` (found on the original string), else append."""
    matches = list(_CLOSING_BODY_RE.finditer(body_html))
    insertion = f"<br>\n{block}\n"
    if matches:
        idx = matches[-1].start()
        return body_html[:idx] + insertion + body_html[idx:]
    return body_html + insertion


def apply_signature(
    body_text: str, body_html: str | None, sig: Signature | None, *, enabled: bool = True,
) -> SignedBody:
    """Append ``sig`` to the text part and, when present, the HTML part.

    Each part gets the matching flavour of the signature; when the account
    has only one flavour, the other is derived (HTML → visible text, text →
    escaped HTML) so both alternatives stay consistent. The HTML part is only
    touched when the caller supplied one — a plain-text message is never
    upgraded to HTML.
    """
    if not enabled:
        return SignedBody(body_text, body_html, STATUS_DISABLED)
    if sig is None:
        return SignedBody(body_text, body_html, STATUS_NONE)

    added = False
    sig_text = sig.text or normalize_text_signature(_html_visible_text(sig.html or ""))
    new_text = body_text
    if sig_text and not _text_has_signature(body_text, sig_text):
        head = body_text.rstrip()
        new_text = (head + "\n\n" if head else "") + f"{TEXT_DELIMITER}\n{sig_text}\n"
        added = True

    new_html = body_html
    if body_html:
        sig_html = sig.html or (_text_to_html_block(sig.text) if sig.text else None)
        if sig_html and not _html_has_signature(body_html, sig_html):
            new_html = _insert_html(body_html, sig_html)
            added = True

    return SignedBody(new_text, new_html, STATUS_ADDED if added else STATUS_PRESENT)


def sign_body(
    cfg: Config, acct: AccountModel, include_signature: bool | None,
    body_text: str, body_html: str | None,
) -> SignedBody:
    """Tool-layer entry point: resolve, load and apply in one call.

    ``include_signature`` is tri-state: ``None`` (default) and ``True`` both
    mean "sign if the account has a signature"; ``False`` skips it — and
    skips reading the files, so a broken signature never blocks a caller who
    opted out.
    """
    if include_signature is False:
        return SignedBody(body_text, body_html, STATUS_DISABLED)
    return apply_signature(body_text, body_html, load_signature(cfg, acct))
