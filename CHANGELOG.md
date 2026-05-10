# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This project follows
[SemVer](https://semver.org/). While at v0.x, breaking changes can land in any
minor bump and are called out explicitly.

## [Unreleased]

_No unreleased changes yet._

## [0.3.7] — 2026-05-10

### Fixed

- **`save_draft` no longer fails with `[TRYCREATE] folder does not exist`
  on localised IMAP accounts.** When the account's stored
  `drafts_mailbox` is the literal default `"Drafts"` but the server's
  real drafts folder is `Borradores` / `Brouillons` / `Entwürfe` /
  `Bozze` / etc., APPEND used to fail. The drafts mailbox is now
  resolved at call time via a new `resolve_drafts_mailbox` helper:
  RFC 6154 SPECIAL-USE `\Drafts` wins over a stale configured value,
  and a curated localised fallback list (~17 entries covering
  Outlook 365, IONOS, GMX, Cyrus / Dovecot `INBOX.`-prefixed,
  `[Gmail]/Drafts`) handles servers that don't advertise SPECIAL-USE.
  `imap_client.save_draft` now returns `(mailbox, uid)` instead of just
  `uid` so all four draft-creating tools (`save_draft`, `reply_draft`,
  `forward_draft`, `update_draft`) can surface the actual mailbox in
  their response — a follow-up `update_draft(mailbox=…, uid=…)` from
  the LLM uses the real folder, not the stale config value.
- **`list_drafts` searches the resolved mailbox.** Before, a draft
  created in `Borradores` was invisible because `list_drafts` queried
  the stale `"Drafts"` configured value and returned zero results.
- **`delete_email(permanent=false)` resolves Trash the same way.** The
  v0.3.7 work brings a symmetric `resolve_trash_mailbox` helper plus a
  ~25-entry localised fallback list including Outlook 365 variants
  (`Elementos eliminados`, `Éléments supprimés`, `Gelöschte Elemente`,
  `Itens Excluídos`, `Verwijderde items`, …). Without resolution,
  deleted mail silently landed in a residual `Trash` folder the user's
  mail client did not show as their trash.
- **Permanent delete now uses RFC 4315 `UID EXPUNGE`** via the new
  `imap_client.safe_uid_expunge` helper. Bare `EXPUNGE` removes every
  message in the selected mailbox already flagged `\Deleted`,
  including messages another mail client (Outlook, a phone, an earlier
  failed run) had flagged. Servers without UIDPLUS now surface a typed
  `UIDPlusRequired` error with stable code
  `UIDPLUS_REQUIRED_FOR_SAFE_EXPUNGE`. `update_draft` / `send_draft`
  catch that error and fall back to flagging the old UID `\Deleted`
  *without* expunging — recoverable on next mail-client sync — and
  return a `warning` field in the response. The UIDPLUS probe now
  happens BEFORE any `\Deleted` mutation, so a no-UIDPLUS rejection
  leaves the server state untouched.
- **SMTP XOAUTH2 was double-base64-encoded**, breaking Microsoft 365
  OAuth SMTP authentication (`535 5.7.3 Authentication unsuccessful`)
  even when token acquisition and IMAP OAuth worked. Per CPython
  smtplib's documented contract `smtplib.SMTP.auth` base64-encodes the
  callback's return value itself, so the callback must hand back the
  raw SASL string. Why no one hit it: most users either run drafts-only
  (IMAP APPEND via `imapclient.oauth2_login`, a different auth path
  that worked) or do not enable `MAIL_MCP_SEND_ENABLED=true` with M365
  OAuth.

### Security

- **`update_draft` and `send_draft` no longer accept arbitrary
  mailboxes.** Until v0.3.7 the `mailbox=` parameter was caller-
  controlled and the handler used it both to fetch the source UID and
  to permanently delete it. A prompt-injected LLM on the
  default-visible `update_draft` could have called
  `update_draft(uid=42, mailbox="INBOX", body="…")` and the handler
  would have APPENDed a copy to Drafts and then UID-expunged INBOX/42 —
  a permanent-delete primitive bypassing `MAIL_MCP_WRITE_ENABLED`,
  `MAIL_MCP_ALLOW_PERMANENT_DELETE`, and `confirm=true`. The new
  `_drafts_mailbox_strict` helper validates the override against the
  server-resolved drafts mailbox before any IMAP fetch / append /
  delete; any mismatch raises `ValidationError` with no mutation.

### Changed

- **`send_email` and `send_draft` are now registered unconditionally**,
  even when `MAIL_MCP_WRITE_ENABLED` / `MAIL_MCP_SEND_ENABLED` are off.
  Previously the tools were not registered at all under the off-state,
  which led LLM agents to tell users "mail-mcp cannot send email" and
  recommend other servers instead of explaining the env-var gate.

  The security boundary is unchanged: the handlers still raise
  `SendDisabled` at call time when the gate is off — nothing transmits
  until the user opts in. What changes is *visibility*: the LLM now
  sees the tools in the list, attempts to call them, and gets back
  `error.code = "SEND_NOT_ENABLED"` with a step-by-step recipe (env
  vars, config-file paths for Claude Code / Claude Desktop / Codex CLI,
  restart instruction). The LLM can guide the user through enabling
  send in one turn instead of declaring the capability missing.

  Distinct error code `SEND_REQUIRES_CONFIRM` is now used when the
  caller forgets `confirm=true`, so the LLM does not point the user at
  config edits when the actual fix is a per-call argument.

  The pre-existing pattern stands for **destructive write tools**
  (`copy_email`, `move_email`, `mark_emails`, `delete_emails`, folder
  CRUD): they remain not-even-registered when `MAIL_MCP_WRITE_ENABLED`
  is unset. That trade-off was kept because they are higher-blast-radius
  and rarely the right answer for a fresh install.

  Server `instructions` block updated with an explicit anti-defeatism
  paragraph: "If you call send_email or send_draft and the response is
  SEND_NOT_ENABLED, do NOT tell the user 'mail-mcp cannot send'."

  README and SECURITY.md updated to describe the visibility/gate split.

### Internal

- The branch went through two rounds of Codex adversarial review.
  Round 1 caught two real issues that are now fixed in this release:
  draft tool responses reported `acct.drafts_mailbox` (stale) instead
  of the resolved mailbox; the resolver preferred a configured-but-
  not-flagged folder over a SPECIAL-USE-flagged real one. Round 2
  caught the `update_draft` mailbox bypass and the
  flag-before-UIDPLUS-probe ordering, both fixed above.

- New helper `smtp_client.carry_over_attachments(src, dst)` — copies
  every attachment-like part from one EmailMessage to another,
  re-attaching `message/rfc822` parts as objects so the body survives.
  Used by `update_draft` to preserve attachments when the caller does
  not pass `attachments=`.

## [0.3.6] — 2026-04-27

### Added

- **`AttachmentSpec.raw_passthrough` flag** — forensic mode for
  attachment delivery. When ``True``, the file's bytes are sent
  byte-for-byte (base64-encoded but without any parsing) so the
  recipient can verify ``SHA-256(received) == SHA-256(source)``.
  Forces ``application/octet-stream`` regardless of the file's actual
  type because Python's email parser (and most mail libraries)
  re-canonicalize ``message/rfc822`` and other structured parts on
  parse, which would silently break the byte-identity guarantee.
  Trade-off documented in the schema: the recipient receives opaque
  bytes (``.eml`` won't auto-render as a forwarded message; they save
  the file and rename if needed) but SHA-256 is preserved end-to-end
  through ``save_draft`` → IMAP → ``download_attachment``.
  Default ``False`` keeps the v0.3.5 semantic-content-type behaviour
  (``.eml`` arrives as ``message/rfc822``, recipient's mail client
  auto-renders, but a few hundred bytes of canonicalisation are
  expected). Use case: chain-of-custody, eIDAS sealing, notarised
  evidence preservation.

## [0.3.5] — 2026-04-27

### Fixed

- **`save_draft` no longer shrinks `.eml` attachments to a 44-byte
  placeholder.** When the attached file's MIME type resolved to
  `message/rfc822` (which `mimetypes.guess_type` returns for any
  `*.eml`), the SMTP layer was calling
  `EmailMessage.add_attachment(bytes, maintype="message", subtype="rfc822", ...)`.
  CPython's content manager treats those bytes as opaque application
  content rather than parsing them as a nested message, so the body was
  silently dropped on serialise/parse round-trip and the user-supplied
  filename was overwritten with `forwarded-message.eml` on read-back.
  The SMTP layer now pre-parses the bytes into an `EmailMessage` and
  attaches the object via `add_attachment(message_obj, filename=...)`,
  which is the supported path. Malformed `.eml` content falls back to
  `application/octet-stream` so the bytes still survive end-to-end.
- **`update_draft` now preserves attachments by default.** A call like
  `update_draft(uid=N, cc=[...])` used to silently drop every
  attachment from the original draft because `build_message` was called
  without an `attachments` argument and no carry-over logic existed.
  Semantics now match `preserve_message_id` / `in_reply_to`:
  - `attachments` omitted (`None`) — preserve original attachments.
  - `attachments=[]` — explicitly clear all attachments.
  - `attachments=[spec, ...]` — replace with the new set.
- `_extract_parts` and `download_attachment` now prefer the
  `message/rfc822` part's own `Content-Disposition: filename=` header
  over the inner Subject, so the filename a caller passed to
  `save_draft` round-trips correctly via `list_attachments` and
  `download_attachment`.

### Added

- New helper `smtp_client.carry_over_attachments(src, dst)` — copies
  every attachment-like part from one `EmailMessage` to another,
  re-attaching `message/rfc822` parts as objects so the body survives.
  Used internally by `update_draft`.

Both bugs reported by an external user during a BEC incident-response
flow where ``.eml`` evidence files were being attached to drafts and
then subtly mutated.

## [0.3.4] — 2026-04-27

### Fixed

- **HTML-only emails no longer return an empty body.** Single-part
  ``text/html`` messages (typical of Outlook 365 "Forward inline" — no
  ``text/plain`` alternative, base64-encoded body, ``Content-ID``
  header) used to surface as ``body=""`` from ``get_email``: the HTML
  was captured into ``EmailBody.html_rendered`` but only
  ``EmailBody.text`` was returned to the caller, so the LLM saw nothing.
  The body extractor now renders the HTML to a plain-text approximation
  via ``html.parser`` (stdlib, no new dependency) when no
  ``text/plain`` alternative exists. ``script`` / ``style`` /
  ``head`` / ``title`` content is dropped, block-level tags flush
  newlines, entities are decoded, and CRLF noise from the source is
  normalised. Multipart messages with a ``text/plain`` alternative are
  unaffected. Reported by an external user against Outlook 365 forwards.

  Was always-broken: any v0.3.x and earlier returned empty bodies for
  HTML-only mail. Most personal mail is ``multipart/alternative`` so
  the bug was masked until users started forwarding from Outlook
  inline.

### Fixed

- **Forward-as-attachment messages no longer return an empty body.**
  Outlook/Exchange-style forwards that embed the original message as a
  `message/rfc822` MIME part used to surface as `body=""` and
  `attachments=[]` from `get_email` and `list_attachments`, leaving the
  forwarded content unreachable. The body extractor now descends into the
  `message/rfc822` part and appends its text under a
  `--- Forwarded message ---` divider with the inner From / Date / Subject /
  To headers. Inner attachments stay scoped to the embedded `.eml` to keep
  the index space unambiguous. Reported by an external user against
  Outlook 365 forwards.

### Added

- The embedded forwarded message is now exposed as a virtual attachment
  with `content_type="message/rfc822"`. `download_attachment` serialises
  it back to RFC822 bytes and writes it to disk as a `.eml` file, ready
  to open in any mail client.
- New tool `get_email_raw(account, mailbox, uid, max_bytes=256_000)` —
  escape hatch returning the message's full RFC822 source (capped, wrapped
  in the untrusted-content envelope, also saved to
  `~/Downloads/mail-mcp/<account>/raw-uid-<uid>.eml`). Use when
  `get_email`'s rendered body is still empty or `list_attachments` is
  missing parts visible in the user's mail client.
- Server `instructions` updated to mention the rfc822 unfolding behaviour
  and the new `get_email_raw` tool.

## [0.3.2] — 2026-04-27

### Removed

- `download_attachment` no longer returns the `preview_base64` field. The
  first 2 KiB of every downloaded file were base64-encoded back into the
  agent's context, which costs ~700–900 tokens per call and is unreadable
  noise for binary types (PDF/image/zip). The file is already written to
  disk; agents that need the bytes can read the path directly.

### Security

- `safety/redaction.py` now scrubs HTTP `Authorization: Bearer <token>`
  and bare `Bearer <token>` forms from sanitised error messages.
  Previously a Graph/MSAL HTTP error that surfaced an authorization
  header would leak the token into the LLM-visible error text.
- `autoconfig.py` parses provider XML through `defusedxml` instead of
  stdlib `xml.etree.ElementTree`. Defends against billion-laughs and
  external-entity (XXE) attacks regardless of what the 256 KiB body cap
  allows through. New `defusedxml>=0.7.1` runtime dependency.
- A revoked refresh token (`invalid_grant` from Microsoft) is now
  removed from the OS keyring on first failure and the in-memory access
  token cache for that account is cleared. Previously the dead token
  stayed in the keyring and every subsequent call hit the same error;
  users had to know to run `mail-mcp init` again. Other OAuth errors
  (network, transient) preserve the refresh token so they can recover
  on retry.

### Fixed

- `mail_mcp.__version__` was lagging at `0.2.5` while `pyproject.toml`
  had moved to `0.3.x`. Both now report the same version.

## [0.3.1] — 2026-04-23

### Added

- The MCP server now advertises a concise `instructions` string on
  connect (MCP protocol field). It enumerates the 22 tools grouped by
  gate level, describes the `download_attachment` flow explicitly, and
  flags the two gotchas that most reliably confuse LLMs: IMAP SEARCH is
  ASCII-only, and localised folder names are detected automatically
  (so the model should not try to guess "Drafts" vs "Borradores"). One
  downstream Claude Code session claimed mail-mcp "cannot download
  attachments" and suggested falling back to Microsoft Graph — the new
  instructions block that failure mode at the handshake.
- README: "Common flows (for LLMs)" subsection with the
  search → get_email → download_attachment recipe spelled out.

## [0.3.0] — 2026-04-23

### Added — Microsoft 365 OAuth2 (browser sign-in)

Tenant-managed Microsoft 365 accounts can now be connected with a proper
OAuth browser flow. Microsoft disabled basic-auth IMAP/SMTP for most
tenants in late 2022; until now `mail-mcp` told those users "use
`email-oauth2-proxy` locally" — this release removes that workaround.

- New optional dependency: `mail-mcp[oauth-microsoft]` pulls in `msal`.
  Password-only users never load it.
- `mail-mcp init` detects Microsoft 365 hosts and offers "Sign in with
  Microsoft (browser)" as the recommended choice. Loopback + PKCE, no
  client secret. The wizard asks once for the Azure app's client ID and
  tenant ID (or reads them from `MAIL_MCP_M365_CLIENT_ID` /
  `MAIL_MCP_M365_TENANT`).
- Refresh tokens live in the OS keyring under
  `mail-mcp:<alias>:refresh_token`; access tokens (1 h TTL) stay in the
  process memory cache and are silently refreshed, with rotated refresh
  tokens persisted automatically.
- SMTP and IMAP clients gained XOAUTH2 support. All tools go through a
  single new `credentials.resolve_auth()` function that returns either a
  password or a fresh access token depending on the account's `auth`
  field.
- New `docs/OAUTH_MICROSOFT.md` with step-by-step Azure AD registration
  instructions and a troubleshooting matrix for common AADSTS errors.
- 8 new unit tests (`tests/test_oauth.py`) covering the SASL payload
  format, cache expiry, refresh-token rotation, and the password/OAuth
  branch selection — all with MSAL stubbed so they run in < 0.1 s.

### Changed

- `AccountModel` grew three optional fields (`auth`, `oauth_tenant`,
  `oauth_client_id`). Defaults preserve full back-compat: every existing
  `config.json` loads unchanged and continues to use password auth.
- `imap_client.connect()` and `smtp_client.send()` / `test_login()` now
  accept either a raw password string (legacy path, still used by
  tests) or an `AuthCredential` (new path). No call sites outside the
  package needed updating.
- The tool layer (`tools/read.py`, `tools/drafts.py`, `tools/organize.py`,
  `tools/send.py`, `doctor.py`) stopped importing `get_password` directly
  and now goes through `credentials.resolve_auth`. Integration-test
  fixtures simplified in lockstep: a single monkeypatch at the origin is
  enough now that tool modules no longer rebind the symbol.

### Kept as-is

- Google / Gmail still follow the "BYO Google Cloud project or local
  proxy" documentation path — Google requires per-user Cloud projects to
  publish a client ID, which is out of scope for a single-binary install.
- `mail-mcp[oauth-microsoft]` is opt-in; the default install still pulls
  zero OAuth-specific dependencies.

## [0.2.5] — 2026-04-18

### Added
- `tests/integration/` — end-to-end test suite against a real GreenMail
  IMAP/SMTP server (docker). 37 tests covering read (13), write (12),
  and drafts+send (12). Opt-in via `MAIL_MCP_INTEGRATION=1 pytest -m
  integration`. New `[integration]` install extra pulls `testcontainers`
  and `requests`.
- `docs/TESTING.md` via `tests/integration/README.md` — how to run the
  suite, expected latency, debugging tips, and GreenMail quirks
  (auto-creation of users via the admin REST API, SPECIAL-USE folders
  have to be pre-created, binding to 0.0.0.0 is required).

### Fixed
- `imap_client.save_draft` now handles UIDPLUS responses from the server.
  GreenMail (and many production servers) reply to APPEND with
  ``[APPENDUID <uidvalidity> <uid>] APPEND completed.`` rather than a
  bare integer; the previous `int(raw)` cast blew up, leaving the draft
  correctly written but reporting a broken UID upstream. Detected by the
  new integration suite before any user hit it.
- `imap_client.get_quota` adapted to the `imapclient` 3.x signature of
  `get_quota_root` (already returns `(MailboxQuotaRoots, list[Quota])`,
  no follow-up `get_quota` call needed).

## [0.2.4] — 2026-04-17

### Added — "feels like a real mail client" round

Ten new tools, zero new runtime dependencies. Consolidated from a nine-angle
coverage review (IMAP RFCs, SMTP/MIME, drafts workflow, threads, proprietary
extensions, Sieve, vacation, identities, attachments, multi-account).

**IMAP coverage**
- `copy_email(source, destination, uids)` — IMAP COPY. Archive while keeping
  the original in place.
- `get_thread(mailbox, uid)` — conversation reconstruction via
  `THREAD=REFERENCES` when the server advertises it, graceful singleton
  fallback otherwise. Respects the same XPIA / bounded-output contract as
  `search_emails`.
- `get_special_folders()` — RFC 6154 SPECIAL-USE resolver exposed as a tool
  (it was previously used only during `mail-mcp init`).
- `get_quota(folder="INBOX")` — RFC 9208 GETQUOTAROOT. Returns
  `used_kb`/`limit_kb` with nulls when the provider hides quota.

**Drafts workflow completion**
- `list_drafts(limit, offset)` — paginated listing that resolves the
  account's Drafts mailbox automatically.
- `update_draft(mailbox, uid, to?, subject?, body?, …, preserve_message_id=true)`
  — in-place edit via APPEND-then-DELETE. The Message-ID is preserved by
  default so threaded replies still resolve.
- `send_draft(mailbox, uid, confirm=true)` — send an already-reviewed draft
  via SMTP, then remove it from Drafts. Gated identically to `send_email`
  and counts against the same hourly rate limit.

**Multi-account**
- `list_accounts()` — enumerate the configured aliases and mark the default.
- `get_account_info(account)` — connection config + resolved mailboxes in
  one read-only call.

**SMTP/MIME**
- `attachments` parameter on `save_draft`, `reply_draft`, `send_email`
  (extends to `forward_draft` through the shared builder). Disk-path only
  in this release. Files must resolve under `~/Downloads`,
  `~/Documents/mail-mcp-outbox`, `$TMPDIR`, or `$MAIL_MCP_ATTACHMENT_DIR`;
  symlinks are rejected after `resolve(strict=True)`. Per-file cap 25 MB,
  per-message total 50 MB, MIME sniffed via `mimetypes`.

### Changed
- `tools/send.py::_check_rate_limit` is now shared by `send_draft`, so a
  prompt-injected LLM cannot bypass the hourly cap by switching tools.
- `docs/V024_PLAN.md` documents the synthesis; deferred items are listed
  there and in `ROADMAP.md` so readers see what was considered and passed
  on.

### Deferred explicitly (see `docs/V024_PLAN.md`)
- HTML body + `bleach` sanitiser, sort by header, Gmail
  `add_gmail_labels` / `search_gmail_raw`, cross-account `transfer_email`,
  base64 inline attachments, identity model rework (v0.3 breaking change),
  Sieve / vacation extras.

## [0.2.3] — 2026-04-17

### Added
- `create_folder` tool — idempotent IMAP folder creation (gated by
  `MAIL_MCP_WRITE_ENABLED`).
- `rename_folder` tool — refuses when the destination already exists.
- `delete_folder` tool — refuses non-empty folders unless `confirm=true`
  is passed, returning the message count that would be lost. Useful for
  cleaning up after a bulk `move_email` consolidation (e.g. `Archivo` →
  `Archive` via 24× 100-UID batches).

## [0.2.2] — 2026-04-17

### Added
- `reply_draft` tool — draft a reply to an existing message. Threading
  headers (`In-Reply-To`, `References`, `Subject: Re: …`) are derived from
  the original server-side; the body is not re-read into the LLM context,
  only an attribution line ("On <date>, <sender> wrote:") is added.
- `forward_draft` tool — draft a forward that attaches the original as a
  `message/rfc822` part. The forwarded content is never re-parsed through
  the LLM, neutralising prompt injection that rides inside forwarded
  emails. Pattern adapted from `thegreystone/mcp-email`.
- `fetch_raw_message` helper in `imap_client` exposes a message's raw
  RFC822 bytes plus its threading headers without fetching the body twice.
- `build_reply_message` / `build_forward_message` helpers in `smtp_client`
  encapsulate the reply/forward assembly and validation.

### Changed
- `send_email` is now rate-limited per account alias (default 10 per hour,
  configurable with `MAIL_MCP_SEND_HOURLY_LIMIT`). The limit bucket lives
  in-process and resets on server restart. Protects against amplification
  of a successful prompt injection attack on the LLM.
- Error responses from exceeded send limits carry `code: RATE_LIMITED`,
  `retryable: true`, and a hint pointing at the env var.

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
