# Synthesis — mail-mcp Architecture Decisions

Derived from parallel security audit of 9 popular email MCP servers (Apr 2026).

## Audit verdicts

| Repo | Stars | Verdict | Key issue |
|------|------:|---------|-----------|
| ai-zerolab/mcp-email-server | 219 | DUDOSO | Gradio analytics phone-home, plaintext TOML sin 0600 |
| marlinjai/email-mcp | 8 | DUDOSO | "Encrypted storage" teatral (key = hostname+username), OAuth sin state, client_secret embebido |
| codefuturist/email-mcp | 31 | **SEGURO** | Mejor diseño: `safety/` module, read-only mode, destructiveHint |
| yunfeizhu/mcp-mail-server | 25 | **INSEGURO** | `rejectUnauthorized:false` HARDCODED, lockfile a mirror no-oficial |
| nikolausm/imap-mcp-server | 17 | DUDOSO | AES-CBC sin MAC, key plaintext junto al cipher, web wizard sin auth |
| thegreystone/mcp-email | 8 | **SEGURO** | Prompt-injection warnings, saveDraft-first, forward sin body al LLM |
| dominik1001/imap-mcp | 13 | **INSEGURO** | `rejectUnauthorized:false` + CRLF header injection + node-imap deprecated |
| bradsjm/mail-imap-mcp-rs | 0 | **SEGURO** (gold standard) | Rust, SecretString, TLS forzado, write gating |
| n24q02m/better-email-mcp | 7 | DUDOSO | Zero-config relay al dominio del autor + crypto en dep opaca |

## Patterns to adopt (from the good ones)

### Credentials
- **macOS Keychain / Linux libsecret / Windows Credential Manager** via Python `keyring`. Never plaintext files. Never env vars (leak in `ps`, logs, docker inspect).
- Config file stores only `host / port / user / alias`. Password looked up by alias.
- `SecretStr`-equivalent: never include password in repr/str/log output.
- Config file written with `os.chmod(path, 0o600)`.

### Transport security
- **TLS enforced by default**: IMAPS (993) with implicit TLS, SMTP (587) with `requireTLS`, or SMTPS (465) implicit.
- `ssl.create_default_context()` — never `check_hostname=False`, never `verify_mode=CERT_NONE`.
- Plaintext-fallback blocked unless explicit `MAIL_MCP_ALLOW_INSECURE_TLS=true` with stderr warning on startup.

### IMAP injection defense
- IMAP SEARCH via structured criteria (dicts/objects), never string concatenation of user input.
- Control-char rejection: `\r`, `\n`, `\0` in any header-bound field → reject with error.
- Email header values escaped via `email.message` / `email.headerregistry` (RFC 2047 encoding for non-ASCII).

### Header / CRLF injection
- **All** header-bound strings validated against `/[\r\n\0]/` before use.
- MIME messages built with `email.message.EmailMessage` stdlib (handles headers correctly), never raw `join("\r\n", ...)`.

### Tool safety
- **`destructive: true` annotation** on: `send_email`, `reply_email`, `forward_email`, `delete_email`, `bulk_delete`, `move_email`, `create_mailbox`, `delete_mailbox`.
- **`readOnly: true`** on: `list_*`, `search_*`, `get_*`.
- **`saveDraft` is the preferred write path**. `send_email` exists but requires `confirm=true` param + `MAIL_MCP_SEND_ENABLED=true` env.
- **Write-gating**: `MAIL_MCP_WRITE_ENABLED=false` by default → write tools are **not registered** at all (not just runtime-flagged).
- **Forward via `message/rfc822` attachment**, never re-parsing the body through LLM context.

### Prompt-injection hygiene
- Email bodies wrapped in `<untrusted_email_content>...</untrusted_email_content>` with explicit warning prefix.
- Closing-tag sanitization: strip occurrences of `</untrusted_email_content>` from email body before wrapping.
- Zero-width char stripping (U+200B, U+200C, U+FEFF, U+00AD, etc.) from HTML-to-text conversion.
- URI scheme filter: allow only `http`, `https`, `mailto`, `tel`. Block `javascript`, `data`, `file`, `vbscript`, `jar`.

### Bounded outputs
- `body_max_chars`: default 16_000, configurable ≤ 64_000.
- `attachment_max_bytes`: default 25 MiB, configurable.
- `batch_max_uids`: default 100, hard cap 500.
- `search_result_limit`: default 50, hard cap 500.

### Filesystem safety
- Attachment downloads only under `~/Downloads/mail-mcp/<account_alias>/`, resolved + checked via `path.is_relative_to(base)`.
- Reject `..`, symlinks, absolute paths outside the whitelist.
- File mode 0o600 for downloads with sensitive content, 0o700 for directory.

### Logging discipline
- Never log: passwords, access tokens, email bodies, email addresses (use `account_alias`).
- Audit log (append-only JSONL) with explicit redaction set: `{password, access_token, refresh_token, client_secret, body, body_html, body_text, content_base64, authorization}`.
- Errors surfaced to LLM: only `{message, code}`, never the full error object (libraries leak `LOGIN` strings in errors).

### Zero outbound network beyond IMAP/SMTP
- No telemetry, no update checks, no analytics, no relay.
- Hardcoded allowlist of protocols: only `imaplib`/`imapclient` to user-configured host, only `smtplib` to user-configured host.
- No import of `requests`, `httpx`, `urllib3` in the runtime path.

### Package / supply chain
- No `postinstall`/`install` scripts (Python doesn't have them, but avoid `setup.py` with network I/O too).
- Pin all deps with exact versions + hashes in `uv.lock` / `requirements.lock`.
- Publish to PyPI with `provenance` (trusted publisher via GitHub Actions OIDC).
- Minimal dep tree: stdlib + `imapclient` + `keyring` + `mcp` SDK. No gradio, no express, no web UI.

## Architecture

**Language**: **Python 3.11+** — rationale:
- Official MCP SDK mature.
- `imapclient` is well-maintained, typed, structured-search API.
- `keyring` package has first-class macOS/Linux/Windows keyring support.
- `email.message` stdlib is battle-tested for MIME correctness (avoids CRLF injection by design).
- Lower bar for contributors (vs. Rust/Java).

**Transport**: stdio only (v0.1). HTTP/SSE not implemented — reduces attack surface.

**Layout**:
```
mail-mcp/
├── pyproject.toml
├── src/mail_mcp/
│   ├── __init__.py
│   ├── __main__.py       # entry point
│   ├── server.py         # MCP server wiring
│   ├── config.py         # alias → host/port/user; passwords via keyring
│   ├── keyring_store.py  # keyring-based credential access
│   ├── imap_client.py    # imapclient wrapper + connection pool
│   ├── smtp_client.py    # smtplib wrapper
│   ├── safety/
│   │   ├── validation.py # CRLF reject, control-char strip, IMAP escape
│   │   ├── redaction.py  # log redaction
│   │   ├── guards.py     # <untrusted_email_content> wrapper + XPIA
│   │   └── paths.py      # filesystem allowlist
│   └── tools/
│       ├── read.py       # list_folders, search, get_email, attachments
│       ├── drafts.py     # save_draft, reply_draft (primary write path)
│       ├── send.py       # send_email (gated, confirm=true required)
│       ├── organize.py   # move, mark, delete (gated)
│       └── schemas.py    # pydantic models for tool inputs
├── tests/
│   ├── test_validation.py
│   ├── test_redaction.py
│   ├── test_tools_smoke.py
│   └── test_crlf_injection.py
├── README.md
├── SECURITY.md
├── LICENSE (MIT)
└── docs/
    ├── images/ (hero, architecture)
    └── THREAT_MODEL.md
```

## Threat model (short form)

In-scope:
- Prompt injection via email body / subject / sender (XPIA).
- Credential theft (at-rest, in-memory, via logs).
- MITM on IMAP/SMTP.
- CRLF / header injection from LLM input.
- Path traversal on attachment save.
- Exfiltration via `forward_email` / `send_email` to attacker-controlled address.

Out-of-scope:
- LLM hallucinating content (user's responsibility to review drafts).
- Compromised host OS (all bets off).
- Denial of service against the user's IMAP server.

## Non-goals for v0.1

- OAuth2 (add in v0.2).
- Multiple accounts (single account first).
- HTTP transport.
- Web UI.
- Scheduler / auto-send.
- Calendar integration.
- PDF extraction (deferred — all audits showed deps here are risky).

Ship simple, secure, auditable. Expand from a solid base.
