# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This project follows
[SemVer](https://semver.org/). While at v0.x, breaking changes can land in any
minor bump and are called out explicitly.

## [Unreleased]

### Added
- `mail-mcp doctor` — self-diagnostic subcommand. Prints runtime info, keyring
  backend, configured accounts, environment gates, and which MCP clients
  (Claude Desktop, Claude Code, Codex CLI) currently reference the server.
  `--connect` additionally authenticates against IMAP and SMTP.
- Startup banner on stderr when `serve` boots, reporting account alias and the
  state of the write / send gates.
- `list_folders` now accepts `pattern` and `subscribed_only` arguments and
  returns each folder's IMAP delimiter, flags and SPECIAL-USE hint.
- `search_emails` returns a pre-limit `total` count and accepts an `offset`
  argument for pagination.
- Interactive `mail-mcp init` auto-detects the Drafts and Trash mailbox names
  using RFC 6154 SPECIAL-USE, fixing localised accounts (Gmail
  `[Gmail]/Drafts`, iCloud ES `Borradores`, IONOS ES `Papelera`, ...) that
  previously had `save_draft` and `delete_emails` silently broken.
- Environment-variable help table in `mail-mcp --help`.
- `mail-mcp` invoked with no subcommand now prints help instead of erroring
  out.

### Changed
- Tool handlers now run inside `asyncio.to_thread` — concurrent tool calls no
  longer serialise on the MCP event loop.
- IMAP connections use an explicit `SocketTimeout(connect=15, read=30)` (both
  tunable via environment variables) so a half-dead peer can no longer hang
  the process indefinitely.
- Error responses to the LLM carry a stable `code` (`AUTH_FAILED`,
  `VALIDATION_ERROR`, `PERMISSION_DENIED`, `TIMEOUT`, `TLS_ERROR`,
  `NOT_FOUND`, `NETWORK_UNREACHABLE`, `INTERNAL_ERROR`), a `hint` with the
  next action to try, and a `retryable` flag.
- Subjects, From/To/Cc addresses and attachment filenames returned to the
  LLM are stripped of zero-width characters, CR/LF and capped in length —
  the XPIA envelope no longer wraps the body alone.
- `sanitize_error` redacts email addresses and hostnames in error messages
  and no longer over-scrubs the `AUTHENTICATIONFAILED` / `BADCREDENTIALS`
  server codes (regression).
- Messages generated for `save_draft` and `send_email` now use the account's
  own domain in the `Message-ID`, avoiding container hostname leakage.
- Text parts with unknown or malformed charsets now fall back gracefully to
  Latin-1 replace instead of raising `LookupError`.
- BCC is carried outside the message object by `build_message_with_bcc`
  instead of the previous private-attribute trick — the wire envelope still
  receives the BCC while the MIME bytes never do.

### Removed
- The personal-domain shortcut that embedded `mariohernandez.es` in the
  autoconfig table. Custom domains on IONOS are still resolved via the MX
  preset tier.

### Documentation
- `docs/V021_PLAN.md` — synthesis of the 9-agent improvement review.
- `docs/TROUBLESHOOTING.md` — the top-5 day-1 failures and how to fix them.
- README: honest provider-support table that flags Microsoft 365 basic-auth
  as "OAuth only — scheduled for v0.2.2".

## [0.1.0] — 2026-04-17

### Added
- Initial release. Privacy-first IMAP/SMTP MCP server with OS-keyring
  credentials, TLS enforced, prompt-injection-aware tool descriptions, and
  a conditional tool-registration write gate.
- `mail-mcp init` interactive wizard with a 5-tier autoconfig waterfall
  (embedded presets, provider-hosted XML, Mozilla ISPDB, MX presets, DNS
  SRV, heuristic fallback).
