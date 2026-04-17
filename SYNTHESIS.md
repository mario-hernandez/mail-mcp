# Synthesis — mail-mcp Architecture Decisions

_Design notes distilled from a parallel review of nine popular email MCP servers,
conducted in April 2026. Upstream repos may have addressed issues called out
below since; this document is a snapshot of what was true when the audit was
read and is published as the reasoning trail behind `mail-mcp`'s design, not as
a ranking of competitors._

## Audit snapshot (April 2026)

| Repo | Stars | Takeaway | Notes |
|------|------:|----------|-------|
| [ai-zerolab/mcp-email-server](https://github.com/ai-zerolab/mcp-email-server) | 219 | Mixed | Bundles a Gradio UI whose analytics default to on; TOML credentials file left at 0644 |
| [marlinjai/email-mcp](https://github.com/marlinjai/email-mcp) | 8 | Mixed | "Encrypted" storage uses a key derived from `hostname + username`; OAuth flow lacks a `state` parameter; a shared OAuth client secret is shipped inside the binary |
| [codefuturist/email-mcp](https://github.com/codefuturist/email-mcp) | 31 | **Strong reference** | Clean `safety/` module, read-only mode, correct `destructiveHint` annotations |
| [yunfeizhu/mcp-mail-server](https://github.com/yunfeizhu/mcp-mail-server) | 25 | **Avoid** | `rejectUnauthorized:false` hard-coded; lockfile resolves to an unofficial mirror |
| [nikolausm/imap-mcp-server](https://github.com/nikolausm/imap-mcp-server) | 17 | Mixed | AES-CBC without a MAC; master key stored next to the ciphertext; web setup wizard unauthenticated |
| [thegreystone/mcp-email](https://github.com/thegreystone/mcp-email) | 8 | **Strong reference** | Prompt-injection warnings baked into tool descriptions, `saveDraft`-first write path, forward via `message/rfc822` so the body never hits the LLM |
| [dominik1001/imap-mcp](https://github.com/dominik1001/imap-mcp) | 13 | **Avoid** | `rejectUnauthorized:false`, CRLF header injection path, built on deprecated `node-imap` |
| [bradsjm/mail-imap-mcp-rs](https://github.com/bradsjm/mail-imap-mcp-rs) | 0 | **Strong reference** | Rust, `SecretString`, TLS enforced, clean write-gating |
| [n24q02m/better-email-mcp](https://github.com/n24q02m/better-email-mcp) | 7 | Mixed | Default "zero-config" path routes credentials through a relay on the author's domain; crypto delegated to an opaque dependency |

The longer explanation behind each verdict — what exact file and line drove the
call, which audits the author and which do not, and what patterns we chose to
inherit or reject — is what produced this document. It is not a league table.

## Patterns we adopted (from the strong references)

### Credentials
- **macOS Keychain / Linux libsecret / Windows Credential Manager** via the
  Python `keyring` package. Never plaintext files. Never env vars (leak in
  `ps`, logs, `docker inspect`).
- Config file stores only `host / port / user / alias`. The password is looked
  up by alias at connect time.
- `SecretStr`-equivalent discipline: never include the password in repr/str/log
  output.
- Config file written with `os.chmod(path, 0o600)`.

### Transport security
- **TLS enforced by default**: IMAPS (993) with implicit TLS, SMTP (587) with
  `requireTLS`, or SMTPS (465) implicit.
- `ssl.create_default_context()` (backed by the `certifi` CA bundle to
  sidestep the python.org-on-macOS "no cert bundle" footgun) — never
  `check_hostname=False`, never `verify_mode=CERT_NONE`.
- Plaintext-fallback blocked. No runtime bypass knob.

### IMAP injection defence
- IMAP SEARCH via structured criteria (dicts/objects), never string
  concatenation of user input.
- Control-char rejection: `\r`, `\n`, `\0` in any header-bound field → reject
  with error.
- Email header values are escaped via `email.message` /
  `email.headerregistry` (RFC 2047 encoding for non-ASCII).

### Header / CRLF injection
- Every header-bound string is validated against `/[\r\n\0]/` before use.
- MIME messages are built with `email.message.EmailMessage` from the stdlib —
  it handles headers correctly — never `"\r\n".join(...)`.

### Tool safety
- `destructive: true` annotation on `send_email`, `move_email`,
  `delete_emails`; `readOnly: true` on `list_*` / `search_*` / `get_*`.
- `save_draft` is the preferred write path. `send_email` additionally requires
  `MAIL_MCP_SEND_ENABLED=true` plus `confirm=true` on the tool call.
- Write-gating happens by **non-registration**: when `MAIL_MCP_WRITE_ENABLED`
  is unset, write tools are not advertised to the LLM at all, not merely
  flagged at runtime.
- Forward via `message/rfc822` attachment (patterned after thegreystone) —
  planned for v0.2.2 so the forwarded content never re-enters the LLM context.

### Prompt-injection hygiene
- Email bodies are wrapped in `<untrusted_email_content>…</untrusted_email_content>`
  with an explicit warning prefix.
- Closing-tag sanitisation: occurrences of the closing tag inside the body are
  escaped so an attacker cannot break out of the envelope.
- Zero-width character stripping (U+200B, U+200C, U+FEFF, U+00AD, …) on
  HTML-to-text conversion.
- URI scheme filter: allow only `http`, `https`, `mailto`, `tel`; block
  `javascript`, `data`, `file`, `vbscript`, `jar`.

### Bounded outputs
- `body_max_chars` default 16 000, configurable up to 64 000.
- `attachment_max_bytes` default 25 MiB, configurable.
- Batch operations capped at 100 UIDs.
- Search result list capped at 500.

### Filesystem safety
- Attachment downloads anchored under `~/Downloads/mail-mcp/<account_alias>/`,
  resolved and checked via `path.is_relative_to(base)`.
- `..`, absolute paths, and escape-via-symlink rejected.
- File mode `0o600` for downloads; directory `0o700`.

### Logging discipline
- Never log passwords, access tokens, email bodies, or email addresses (use
  `account_alias` instead).
- Errors surfaced to the LLM carry only `{type, code, message, hint,
  retryable}` — never the raw exception object, which can carry server trace
  material.

### Zero outbound network beyond IMAP/SMTP
- No telemetry, no update checks, no analytics, no relay.
- Only `imapclient` (to the user-configured host) and `smtplib` (to the
  user-configured host) open outbound sockets at runtime. `mail-mcp init`
  additionally performs autoconfig lookups over HTTPS — documented in
  `SECURITY.md`.

### Package / supply chain
- No `postinstall` scripts (Python doesn't have them, but we also avoid
  `setup.py` with network I/O).
- Minimal dep tree: `mcp`, `imapclient`, `keyring`, `pydantic`, `certifi`.
  No Gradio, no Express, no web UI.
- `pip install mail-mcp[cli]` additionally pulls `questionary`, `rich` and
  `dnspython` only for the interactive setup path.

## Architecture

**Language**: Python 3.11+.
- Official MCP SDK maturity.
- `imapclient` is well-maintained, typed, and exposes a structured search API.
- `keyring` has first-class macOS/Linux/Windows support.
- `email.message` is battle-tested for MIME correctness (avoids CRLF injection
  by construction).
- Lower bar for contributors than Rust or Java.

**Transport**: stdio only in v0.x. HTTP/SSE is deliberately off the table until
there is a concrete reason.

**Layout** (representative — see the repo for the authoritative tree):

```
mail-mcp/
├── pyproject.toml
├── src/mail_mcp/
│   ├── __init__.py
│   ├── __main__.py       # CLI entry point
│   ├── server.py         # MCP server wiring
│   ├── config.py         # alias → host/port/user; passwords via keyring
│   ├── keyring_store.py  # keyring-based credential access
│   ├── imap_client.py    # imapclient wrapper
│   ├── smtp_client.py    # smtplib wrapper
│   ├── autoconfig.py     # 5-tier autodiscovery (embedded → XML → ISPDB → MX → SRV → heuristic)
│   ├── wizard.py         # interactive `mail-mcp init` (requires [cli] extras)
│   ├── doctor.py         # `mail-mcp doctor` diagnostic report
│   ├── safety/
│   │   ├── tls.py        # TLS context with certifi bundle
│   │   ├── validation.py # CRLF reject, control-char strip, IMAP escape
│   │   ├── redaction.py  # log/error redaction
│   │   ├── guards.py     # untrusted-content wrapper + header sanitiser
│   │   └── paths.py      # filesystem allowlist
│   └── tools/
│       ├── read.py       # list_folders, search, get_email, attachments
│       ├── drafts.py     # save_draft (v0.2.2 adds reply_draft / forward_draft)
│       ├── send.py       # send_email (gated; confirm=true required)
│       ├── organize.py   # move, mark, delete (gated)
│       └── schemas.py    # pydantic input schemas
├── tests/
├── docs/
└── LICENSE (MIT)
```

## Threat model (short form)

In-scope:
- Prompt injection via email body / subject / sender (XPIA).
- Credential theft (at-rest, in-memory, via logs).
- MITM on IMAP/SMTP.
- CRLF / header injection from LLM input.
- Path traversal on attachment save.
- Exfiltration via `send_email` (and, once shipped, `forward_draft`) to an
  attacker-controlled address.

Out of scope:
- LLM hallucinating content (the user reviews drafts).
- Compromised host OS (all bets off).
- Denial of service against the user's own IMAP server.

## Non-goals (confirmed in every release)

- OAuth2 — deferred to v0.2.2 for Microsoft 365; Gmail continues to delegate
  to a local proxy or user-owned Google Cloud project.
- HTTP/SSE transport.
- Web UI.
- Scheduler / auto-send.
- Calendar integration.
- PDF text extraction (every audited PDF library had CVE history).

Ship simple, secure, auditable. Expand from a solid base.
