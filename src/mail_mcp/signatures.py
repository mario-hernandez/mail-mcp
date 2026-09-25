"""Per-account email signatures.

Each account may carry an HTML and/or a plain-text signature that the write
tools (``save_draft``, ``reply_draft``, ``forward_draft``, ``update_draft``
when the body is replaced, and ``send_email``) append after the caller's text
and before any quoted message — the placement Outlook and Apple Mail use.

Where the files come from:

* ``AccountModel.signature_html_path`` / ``signature_text_path`` when set
  (a relative path is taken relative to the config directory);
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
per-call control is the boolean ``include_signature``. Any problem reading a
signature surfaces as :class:`ValidationError` — never a crash, never a
silently unsigned message.

Placement and idempotence. The caller's body is split into its *own* part and
any quoted message it carries (Outlook ``divRplyFwdMsg``, Gmail
``gmail_quote``, ``<blockquote type="cite">``, "On … wrote:",
"-----Original Message-----", a trailing ``>`` block…). The signature goes at
the end of the own part, and it is only considered "already there" if the own
part contains it — a signature that appears inside quoted material (the owner's
earlier message in the thread) does not count, so a reply is still signed.
"""

from __future__ import annotations

import html as _html_lib
import os
import re
import stat
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
# comparing, never removed from what is sent. Built from code points so the
# source itself carries no invisible characters.
_INVISIBLE_RANGES = ((0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x2069), (0xFEFF, 0xFEFF))
_INVISIBLE_RE = re.compile(
    "[" + "".join(f"{chr(lo)}-{chr(hi)}" for lo, hi in _INVISIBLE_RANGES) + "]"
)

# Where the caller's own text ends. The signature goes at the end of it —
# which is "before the quote" for top-posted replies (Outlook) and simply "at
# the end" for bottom-posted or interleaved ones (Thunderbird, Markdown-style
# '>' quoting). PRECISION FIRST: misplacing the signature in an ordinary email
# is far worse than missing an exotic quote, so only structures that mail
# clients generate — never prose an agent might write — mark a quote.
#
# HTML: client quote containers (Outlook web/Mac/desktop, Gmail, Yahoo,
# Thunderbird inline forward), matched on ids/classes or, for Outlook desktop,
# on the top-ruled div that opens with a "From:" label ("De&nbsp;:" in French).
_HTML_QUOTE_MARKER_RE = re.compile(
    r"<[a-z][a-z0-9]*\b[^>]*\b(?:id|class)\s*=\s*[\"']?[^\"'>]*"
    r"(?:divRplyFwdMsg|appendonsend|stopSpelling|gmail_quote|yahoo_quoted"
    r"|OutlookMessageHeader|mail-editor-reference-message-container|moz-forward-container)"
    r"|<div\b[^>]*\bborder-top\s*:\s*solid\s+#(?:E1E1E1|B5C4DF)\b[^>]*>"
    r"(?=(?:\s|<(?:p|span|font|b|strong|a)\b[^>]*>|</a\s*>)*"
    r"(?:from|de|von|da|van|exp[ée]diteur)(?:\s|&nbsp;|&#160;|\xa0)*:)",
    re.IGNORECASE,
)
# <blockquote type="cite"> (Apple Mail, Thunderbird) marks the quote only when
# none of the caller's own text follows it; Thunderbird's attribution div
# right before it belongs to the quote too.
_HTML_CITE_RE = re.compile(r"<blockquote\b[^>]*\btype\s*=\s*[\"']?cite", re.IGNORECASE)
_HTML_CITE_PREFIX_RE = re.compile(
    r"<div\b[^>]*\bclass\s*=\s*[\"']?[^\"'>]*moz-cite-prefix", re.IGNORECASE,
)
_BQ_TAG_RE = re.compile(r"<(/?)blockquote\b[^>]*>", re.IGNORECASE)
_DIV_TAG_RE = re.compile(r"<(/?)div\b[^>]*>", re.IGNORECASE)
# Exactly one <div>…</div> (no nested div, no quote) followed only by whitespace.
_SINGLE_DIV_RE = re.compile(
    r"<div\b[^>]*>(?:(?!<div\b|<blockquote\b).)*?</div\s*>\s*", re.IGNORECASE | re.DOTALL,
)
# Innermost-first, so nested blockquotes are removed completely by iterating.
_BLOCKQUOTE_RE = re.compile(
    r"<blockquote\b(?:(?!<blockquote\b).)*?</blockquote\s*>", re.IGNORECASE | re.DOTALL,
)

# Plain text: Outlook-style separators, and Outlook's '____' rule followed by
# its header block. '>' lines are NOT a quote boundary: agents quote that way
# in their own messages; they are only ignored when checking for the signature.
_TEXT_SEPARATOR_RE = re.compile(
    r"^\s*-{2,}\s*(?:original message|mensaje original|message d'origine|messaggio originale"
    r"|ursprüngliche nachricht|oorspronkelijk bericht|mensagem original|missatge original"
    r"|forwarded message|mensaje reenviado|message transféré|messaggio inoltrato"
    r"|weitergeleitete nachricht|doorgestuurd bericht|mensagem encaminhada)\s*-{2,}\s*$",
    re.IGNORECASE,
)
_TEXT_RULE_RE = re.compile(r"^\s*_{10,}\s*$")
_TEXT_FROM_RE = re.compile(
    r"^\s*\*?(?:from|de|von|da|van|exp[ée]diteur)\s*\*?\s*:\s*\S", re.IGNORECASE,
)
_TEXT_SENT_RE = re.compile(
    r"^\s*\*?(?:sent|date|enviado(?: el)?|enviada|enviat(?: el)?|fecha|gesendet|datum"
    r"|envoy[ée](?: le)?|inviato|data|verzonden)\s*\*?\s*:",
    re.IGNORECASE,
)
_TEXT_SUBJECT_RE = re.compile(
    r"^\s*\*?(?:subject|asunto|assunto|assumpte|betreff|objet|oggetto|onderwerp)\s*\*?\s*:",
    re.IGNORECASE,
)

STATUS_ADDED = "added"
STATUS_PRESENT = "already_present"
STATUS_DISABLED = "disabled"
STATUS_NONE = "none"


class SignatureChoiceRequired(RuntimeError):
    """The account asks before signing and the caller did not decide.

    Raised before anything is saved or sent. The agent is expected to ask the
    user whether to add the signature and call again with an explicit
    ``include_signature``.
    """

    def __init__(self, alias: str, flavours: str) -> None:
        super().__init__(
            f"Account '{alias}' has a signature ({flavours}) and its signature_mode "
            "is 'ask': ask the user whether to add it to this message, then call "
            "again with include_signature=true or include_signature=false. "
            "Nothing was saved or sent."
        )
        self.alias = alias


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


# --- loading ---------------------------------------------------------------


def _read_signature_file(path: Path, root: Path, *, field: str) -> str:
    try:
        resolved = path.expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:  # RuntimeError: symlink loop on 3.11/3.12
        raise ValidationError(f"{field}: signature file not found or unresolvable: {path}") from exc
    root_resolved = root.expanduser().resolve(strict=False)
    if not resolved.is_relative_to(root_resolved):
        raise ValidationError(
            f"{field}: signature file must live under {root} (got {path}, which "
            f"resolves to {resolved})"
        )
    # Read the inode that passed the check: O_NOFOLLOW refuses a final path
    # component swapped for a symlink after the containment check, O_NONBLOCK
    # keeps a FIFO from hanging the server, and fstat on the open descriptor
    # decides "regular file" for exactly what is read.
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        fd = os.open(resolved, flags)
    except OSError as exc:
        raise ValidationError(
            f"{field}: signature file is not readable: {path} ({exc.strerror})"
        ) from exc
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValidationError(f"{field}: signature path is not a regular file: {path}")
        # Cap the read itself, not just a stat: the file could grow in between.
        chunks: list[bytes] = []
        remaining = MAX_SIGNATURE_BYTES + 1
        while remaining > 0:
            chunk = os.read(fd, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
    except OSError as exc:
        raise ValidationError(
            f"{field}: signature file is not readable: {path} ({exc.strerror})"
        ) from exc
    finally:
        os.close(fd)
    data = b"".join(chunks)
    if len(data) > MAX_SIGNATURE_BYTES:
        raise ValidationError(
            f"{field}: signature file exceeds the {MAX_SIGNATURE_BYTES}-byte limit: {path}"
        )
    try:
        return data.decode("utf-8-sig")  # tolerate (and drop) a leading BOM
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
        try:
            candidate = Path(configured).expanduser()
        except RuntimeError as exc:  # "~someone" with no such user
            raise ValidationError(f"{field}: cannot expand signature path {configured!r}") from exc
        if not candidate.is_absolute():
            # Relative to the config directory — never to the process CWD,
            # which differs between `doctor` in a shell and the MCP server.
            candidate = root.parent / candidate
        return _read_signature_file(candidate, root, field=field)
    if root is None:
        return None
    default = root / alias / default_name
    try:
        os.lstat(default)
    except (FileNotFoundError, NotADirectoryError):
        return None  # no default file → no signature, the historical behaviour
    except OSError as exc:
        # Present but not inspectable (e.g. an unreadable directory): fail
        # loudly rather than send unsigned mail the owner believes is signed.
        raise ValidationError(
            f"{field}: cannot access signature file {default} ({exc.strerror})"
        ) from exc
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
    unreadable, too large, not UTF-8, missing. Failing loudly beats silently
    sending an unsigned message the owner believes is signed; the caller can
    always pass ``include_signature=false``.
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
    """Summary for ``get_account_info`` / ``doctor``. Never raises.

    ``mode`` tells the agent whether it must ask the user before signing
    ("ask") or may sign on its own ("auto").
    """
    try:
        sig = load_signature(cfg, acct)
    except (ValidationError, OSError, RuntimeError) as exc:
        return {"html": False, "text": False, "mode": acct.signature_mode, "error": str(exc)}
    if sig is None:
        return {"html": False, "text": False, "mode": acct.signature_mode}
    return {"html": sig.html is not None, "text": sig.text is not None, "mode": acct.signature_mode}


# --- where the caller's own text ends ---------------------------------------


def _fingerprint(text: str) -> str:
    text = unicodedata.normalize("NFC", text).replace(chr(0xA0), " ")  # NBSP → space
    text = _INVISIBLE_RE.sub("", text)
    return _WS_RE.sub(" ", text).strip().casefold()


def _html_visible_text(html: str) -> str:
    from .imap_client import _html_to_text  # local import: keeps this module light

    return _html_to_text(html)


def _is_quoted_line(line: str) -> bool:
    return line.lstrip().startswith(">")


def _is_header_block(lines: list[str], i: int) -> bool:
    """Outlook's header block: From: followed by Sent/Date: and Subject:."""
    if i >= len(lines) or not _TEXT_FROM_RE.match(lines[i]):
        return False
    block = lines[i + 1:i + 6]
    return any(_TEXT_SENT_RE.match(x) for x in block) and any(_TEXT_SUBJECT_RE.match(x) for x in block)


def _text_quote_start(lines: list[str], sig_lines: set[str]) -> int | None:
    """Index of the line where a client-generated quote starts, or ``None``.

    Only "-----Original Message-----"-style separators and Outlook's ``____``
    rule directly followed by its From/Sent/Subject block. Lines of the
    signature itself are never taken for a separator.
    """
    for i, ln in enumerate(lines):
        if not ln.strip() or _fingerprint(ln) in sig_lines:
            continue
        if _TEXT_SEPARATOR_RE.match(ln):
            return i
        if _TEXT_RULE_RE.match(ln):
            j = next((k for k in range(i + 1, len(lines)) if lines[k].strip()), None)
            if j is not None and _is_header_block(lines, j):
                return i
    return None


def _split_text_quote(body: str, sig_text: str) -> tuple[str, str]:
    """Split a plain-text body into (the caller's own text, quoted message)."""
    sig_lines = {_fingerprint(ln) for ln in sig_text.split("\n") if ln.strip()}
    lines = body.split("\n")
    start = _text_quote_start(lines, sig_lines)
    if start is None:
        return body, ""
    return "\n".join(lines[:start]), "\n".join(lines[start:])


def _mask_quoted(html: str) -> str:
    """Same-length copy with the INSIDE of every top-level blockquote blanked.

    A reply from Apple Mail or Thunderbird quotes, inside its own
    ``<blockquote type="cite">``, a message that carries its own Gmail or
    Outlook quote markers; those nested markers must not be taken for where
    the caller's quote starts. Opening tags stay visible; an unclosed
    blockquote is left as is.
    """
    out = list(html)
    depth = 0
    inner_start = 0
    for m in _BQ_TAG_RE.finditer(html):
        if m.group(1):
            if depth == 0:
                continue
            depth -= 1
            if depth == 0:
                out[inner_start:m.start()] = " " * (m.start() - inner_start)
        else:
            if depth == 0:
                inner_start = m.end()
            depth += 1
    return "".join(out)


def _balanced_div_end(html: str, start: int) -> int | None:
    """End offset of the ``<div>`` opening at ``start`` (its matching close)."""
    depth = 0
    for m in _DIV_TAG_RE.finditer(html, start):
        depth += -1 if m.group(1) else 1
        if depth == 0:
            return m.end()
    return None


def _own_html_for_dedup(body_html: str, quote_start: int | None) -> str:
    """The caller's own HTML, for the "already signed?" check.

    Everything before the quote; plus, when the quote is Gmail's
    ``div.gmail_quote`` container, whatever follows that container — Gmail
    puts the sender's signature BELOW the quote by default. Not done for
    Outlook's markers: what follows them is the quoted message itself.
    """
    if quote_start is None:
        return body_html
    own = body_html[:quote_start]
    opening = re.match(r"<div\b[^>]*>", body_html[quote_start:], re.IGNORECASE)
    if opening and re.search(r"\bgmail_quote\b", opening.group(0), re.IGNORECASE):
        end = _balanced_div_end(body_html, quote_start)
        if end is not None:
            own += body_html[end:]
    return own


def _html_quote_start(body_html: str) -> int | None:
    """Offset where the quoted message starts in ``body_html``, or ``None``."""
    marker = _HTML_QUOTE_MARKER_RE.search(_mask_quoted(body_html))
    limit = marker.start() if marker else len(body_html)
    for cite in _HTML_CITE_RE.finditer(body_html, 0, limit):
        after = _strip_blockquotes(body_html[cite.start():limit])
        if _html_visible_text(after).strip():
            continue  # the caller's own text follows: an inline quote, not the end
        # Thunderbird's "On … wrote:" div right before the quote belongs to it:
        # the LAST prefix before this cite, with no other quote in between.
        prefixes = list(_HTML_CITE_PREFIX_RE.finditer(body_html, 0, cite.start()))
        if prefixes:
            between = body_html[prefixes[-1].start():cite.start()]
            if _SINGLE_DIV_RE.fullmatch(between):
                return prefixes[-1].start()
        return cite.start()
    return marker.start() if marker else None


def _strip_blockquotes(html: str) -> str:
    previous = None
    while previous != html:
        previous = html
        html = _BLOCKQUOTE_RE.sub(" ", html)
    return html


def _text_has_signature(own: str, sig_text: str) -> bool:
    """Is ``sig_text`` in the caller's own text (quoted ``>`` lines excluded)?"""
    def unquoted(s: str) -> str:
        return "\n".join(ln for ln in s.split("\n") if not _is_quoted_line(ln))

    own_fp = _fingerprint(unquoted(own))
    sig_fp = _fingerprint(unquoted(sig_text))
    if not sig_fp:
        return True
    if len(sig_fp) >= _MIN_TEXT_FINGERPRINT:
        return sig_fp in own_fp
    # Short signature: only the delimited form counts as "already there".
    return _fingerprint(f"{TEXT_DELIMITER}\n{sig_text}") in own_fp


def _html_has_signature(own_html: str, sig_html: str, sig_text: str | None = None) -> bool:
    """Is the signature in the caller's own HTML (blockquotes excluded)?

    Matched on the HTML signature's visible text, or on the text flavour in
    its DELIMITED form only ("-- " + signature, outside '>' lines) — an HTML
    body the agent rebuilt from a signed plain-text body carries
    "-- <br>Name", which must count. The bare text flavour is never matched:
    a short firma.txt ("Name\nCompany") turns up by chance in attendee
    tables and prose and would leave the HTML unsigned.
    """
    visible = _html_visible_text(_strip_blockquotes(own_html))
    own_fp = _fingerprint(visible)
    sig_fp = _fingerprint(_html_visible_text(_strip_blockquotes(sig_html)))
    if len(sig_fp) >= _MIN_TEXT_FINGERPRINT and sig_fp in own_fp:
        return True
    if sig_text:
        unquoted_fp = _fingerprint(
            "\n".join(ln for ln in visible.split("\n") if not _is_quoted_line(ln))
        )
        if _fingerprint(f"{TEXT_DELIMITER}\n{sig_text}") in unquoted_fp:
            return True
    if len(sig_fp) >= _MIN_TEXT_FINGERPRINT:
        return False  # never fall back to raw markup: it would see inside blockquotes
    # Image-only or near-empty signature: compare the markup itself.
    return _WS_RE.sub(" ", sig_html).strip() in _WS_RE.sub(" ", own_html)


def _text_to_html_block(text: str) -> str:
    lines = "<br>\n".join(_html_lib.escape(line) for line in text.split("\n"))
    return f'<div class="mail-mcp-signature">{lines}</div>'


def _insert_html(body_html: str, block: str, quote_start: int | None) -> str:
    """Insert before the quoted message, else before the last ``</body>``, else append."""
    insertion = f"<br>\n{block}\n"
    if quote_start is not None:
        return body_html[:quote_start] + insertion + body_html[quote_start:]
    matches = list(_CLOSING_BODY_RE.finditer(body_html))
    if matches:
        idx = matches[-1].start()
        return body_html[:idx] + insertion + body_html[idx:]
    return body_html + insertion


# --- insertion -------------------------------------------------------------


def apply_signature(
    body_text: str, body_html: str | None, sig: Signature | None, *, enabled: bool = True,
) -> SignedBody:
    """Append ``sig`` to the text part and, when present, the HTML part.

    Each part gets the matching flavour of the signature; when the account
    has only one flavour, the other is derived (HTML → visible text, text →
    escaped HTML) so both alternatives stay consistent. The HTML part is only
    touched when the caller supplied one — a plain-text message is never
    upgraded to HTML. In both parts the signature lands at the end of the
    caller's own text, before any quoted message.
    """
    if not enabled:
        return SignedBody(body_text, body_html, STATUS_DISABLED)
    if sig is None:
        return SignedBody(body_text, body_html, STATUS_NONE)

    added = False
    applicable = False

    sig_text = sig.text or normalize_text_signature(_html_visible_text(sig.html or ""))
    new_text = body_text
    if sig_text:
        applicable = True
        own, quoted = _split_text_quote(body_text, sig_text)
        if not _text_has_signature(own, sig_text):
            head = own.rstrip()
            new_text = (head + "\n\n" if head else "") + f"{TEXT_DELIMITER}\n{sig_text}\n"
            if quoted.strip():
                new_text += "\n" + quoted.lstrip("\n")
            added = True

    new_html = body_html
    if body_html:
        sig_html = sig.html or (_text_to_html_block(sig.text) if sig.text else None)
        if sig_html:
            applicable = True
            quote_start = _html_quote_start(body_html)
            own_html = _own_html_for_dedup(body_html, quote_start)
            if not _html_has_signature(own_html, sig_html, sig_text):
                new_html = _insert_html(body_html, sig_html, quote_start)
                added = True

    if added:
        status = STATUS_ADDED
    elif applicable:
        status = STATUS_PRESENT
    else:
        status = STATUS_NONE  # e.g. an image-only signature on a plain-text message
    return SignedBody(new_text, new_html, status)


def signature_in(sig: Signature, body_text: str, body_html: str | None) -> bool:
    """Does a message already carry ``sig`` in its own text (either part)?"""
    sig_text = sig.text or normalize_text_signature(_html_visible_text(sig.html or ""))
    if sig_text:
        own, _quoted = _split_text_quote(body_text, sig_text)
        if _text_has_signature(own, sig_text):
            return True
    if body_html:
        sig_html = sig.html or (_text_to_html_block(sig.text) if sig.text else None)
        if sig_html:
            own_html = _own_html_for_dedup(body_html, _html_quote_start(body_html))
            if _html_has_signature(own_html, sig_html, sig_text):
                return True
    return False


def sign_body(
    cfg: Config, acct: AccountModel, include_signature: bool | None,
    body_text: str, body_html: str | None,
) -> SignedBody:
    """Tool-layer entry point: resolve, load and apply in one call.

    ``include_signature`` is tri-state. ``False`` skips the signature — and
    skips reading the files, so a broken signature never blocks a caller who
    opted out. ``True`` signs. ``None`` (omitted) depends on the account's
    ``signature_mode``: "auto" signs; "ask" raises
    :class:`SignatureChoiceRequired` — unless there is nothing to decide
    (no signature, or the body already carries it).
    """
    if include_signature is False:
        return SignedBody(body_text, body_html, STATUS_DISABLED)
    sig = load_signature(cfg, acct)
    signed = apply_signature(body_text, body_html, sig)
    if include_signature is None and acct.signature_mode == "ask" and signed.status == STATUS_ADDED:
        flavours = " + ".join(
            name for name, part in (("html", sig.html), ("text", sig.text)) if part
        )
        raise SignatureChoiceRequired(acct.alias, flavours)
    return signed
