# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This project follows
[SemVer](https://semver.org/). While at v0.x, breaking changes can land in any
minor bump and are called out explicitly.

## [Unreleased]

_No unreleased changes yet. See [`ROADMAP.md`](ROADMAP.md) for what is coming next._

## [0.2.1] — 2026-04-17

### Added
- `mail-mcp doctor` — self-diagnostic subcommand. Prints runtime info, keyring
  backend, configured accounts, environment gates, and which MCP clients
  (Claude Desktop, Claude Code, Codex CLI) currently reference the server.
  `--connect` additionally authenticates against IMAP and SMTP.
- Startup banner on stderr when `serve` boots, reporting account alias and the
  state of the write / send gates.
- `list_folders` accepts `pattern` and `subscribed_only` arguments and returns
  each folder's IMAP delimiter, flags and SPECIAL-USE hint.
- `search_emails` returns a pre-limit `total` count and accepts an `offset`
  argument for pagination.
- `mail-mcp init` auto-detects the Drafts and Trash mailbox names using
  RFC 6154 SPECIAL-USE, fixing localised accounts (Gmail `[Gmail]/Drafts`,
  iCloud ES `Borradores`, IONOS ES `Papelera`, …) that previously had
  `save_draft` and `delete_emails` silently broken.
- Environment-variable help table in `mail-mcp --help`.
- `mail-mcp` invoked with no subcommand now prints help instead of erroring
  out.

### Changed
- Tool handlers run inside `asyncio.to_thread` — concurrent tool calls no
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
  server codes (regression from 0.2.0).
- Messages generated for `save_draft` and `send_email` use the account's own
  domain in the `Message-ID`, avoiding container hostname leakage.
- Text parts with unknown or malformed charsets fall back gracefully to
  Latin-1 replace instead of raising `LookupError`.
- BCC is carried outside the message object by `build_message_with_bcc`
  instead of the previous private-attribute trick — the wire envelope still
  receives the BCC while the MIME bytes never do.

### Fixed
- `ssl.SSLCertVerificationError: unable to get local issuer certificate` on
  macOS with Python installed from python.org. The IMAP, SMTP and autoconfig
  TLS contexts now prefer the `certifi` CA bundle when available; `certifi`
  is a direct dependency so `pip install mail-mcp` is enough.
- MX presets for IONOS custom domains (`mx00.ionos.es`, `mx01.ionos.es`,
  …). The substring `ionos.es` / `ionos.de` is now recognised, so a
  domain hosted on IONOS is autodetected without falling back to the
  generic heuristic.

### Removed
- Personal-domain shortcut that embedded `mariohernandez.es` in the
  autoconfig table. IONOS-hosted custom domains resolve via the MX preset
  tier now that `ionos.*` substrings are mapped.

### Documentation
- `docs/TROUBLESHOOTING.md` — the top-5 day-1 failures and how to fix them.
- README: honest provider-support table that flags Microsoft 365 basic-auth
  as "OAuth only — scheduled for v0.2.2"; environment variable reference.

## [0.2.0] — 2026-04-17

### Added
- `mail-mcp init` interactive wizard (ships under the new `mail-mcp[cli]`
  install extra, which brings in `questionary`, `rich` and `dnspython`).
  The wizard asks for an email address, auto-resolves IMAP/SMTP endpoints,
  verifies the login against both servers, and persists the account.
- Autoconfig waterfall in `src/mail_mcp/autoconfig.py`:
  1. embedded provider table (Gmail, iCloud, Outlook, Fastmail, Yahoo, AOL,
     IONOS, 1und1, GMX, Web.de, Zoho, mailbox.org, Yandex),
  2. provider-hosted autoconfig XML over HTTPS,
  3. Mozilla ISPDB (domain-only lookup — the full email is never sent),
  4. MX-based presets for custom domains on Google Workspace, Microsoft 365,
     IONOS, Fastmail,
  5. DNS SRV records (RFC 6186),
  6. heuristic `imap.<domain>` / `smtp.<domain>` fallback.
- Proton Mail domains are recognised and the wizard points at Proton Bridge
  on `127.0.0.1`.

## [0.1.0] — 2026-04-17

### Added
- Initial release. Privacy-first IMAP/SMTP MCP server with OS-keyring
  credentials, TLS enforced, prompt-injection-aware tool descriptions, and
  a conditional tool-registration write gate.
- Read-only tools: `list_folders`, `search_emails`, `get_email`,
  `list_attachments`, `download_attachment`, `save_draft`.
- Write tools gated by `MAIL_MCP_WRITE_ENABLED=true`: `move_email`,
  `mark_emails`, `delete_emails`.
- `send_email` additionally gated by `MAIL_MCP_SEND_ENABLED=true` and a
  `confirm=true` tool argument.
- CLI: `mail-mcp add-account`, `mail-mcp list-accounts`, `mail-mcp check`,
  `mail-mcp serve`.
- XPIA envelope wrapping email bodies returned to the LLM.
- Documentation: README, `SECURITY.md`, `docs/THREAT_MODEL.md`,
  `docs/INTEGRATION.md`.
