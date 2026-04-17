# v0.2.4 plan — "feels like a real mail client"

Synthesised from a 9-agent coverage review. The goal of this release is to
close the gaps an LLM hits while trying to act like Apple Mail / Thunderbird
on the user's behalf.

## Adopt now (v0.2.4) — zero new runtime deps

### IMAP primitives still missing
- `copy_email(source_mailbox, uid, target_mailbox)` — IMAP COPY. Gap
  observed during real use: "archive but keep in Inbox" requires a copy
  not a move, and there was no tool for it.
- `get_thread(mailbox, uid_or_message_id, max_messages=20)` — fast path
  via Gmail `X-GM-THRID`, RFC 5256 `THREAD REFERENCES` elsewhere,
  manual walk over `References`/`In-Reply-To` as the last resort.
  Each body flows through the XPIA wrapper per message.
- `get_special_folders()` — RFC 6154 SPECIAL-USE. Lets the LLM ask
  "where is your Sent folder?" without reinventing mailbox detection.
- `get_quota(folder="INBOX")` — RFC 9208 `GETQUOTAROOT`. Returns
  usage vs limit; quiet graceful failure when the server hides quota.

### Drafts workflow completion
- `list_drafts(limit=50, offset=0)` — sugar over search on the account's
  drafts mailbox so the LLM doesn't have to know the localised name.
- `update_draft(mailbox, uid, to?, subject?, body?, cc?, in_reply_to?,
  references?, preserve_message_id=true)` — IMAP has no UPDATE; the tool
  does APPEND-then-DELETE atomically. `preserve_message_id=true` keeps
  threading intact when the draft was itself a reply.
- `send_draft(mailbox, uid, confirm=true, move_to_sent=true)` — the
  natural "review it and send it" closure. Gated like `send_email`,
  counts against the existing hourly rate limit.

### Multi-account surface
- `list_accounts()` — names, emails, which is default. Solves "what
  aliases do I have?" in one round trip.
- `get_account_info(alias)` — connection status, resolved mailboxes,
  quota usage. Diagnostic tool Claude can reach during conversation
  rather than poking at files.

### SMTP/MIME
- `attachments` parameter on `send_email`, `save_draft`, `reply_draft`.
  Path-from-disk only in this release (`{"path": "/abs", "filename":
  optional}`). Allowlist: `~/Downloads`, `~/Documents/mail-mcp-outbox`,
  `$TMPDIR`. Per-attachment cap 25 MB, total 50 MB, symlinks rejected
  after `resolve(strict=True)`. MIME type via `mimetypes.guess_type`.

## Defer to v0.2.5

Keeps the v0.2.4 diff reviewable and lets us gather real feedback before
layering more surface.

- **HTML body** (`html_body` + `bleach` sanitiser) — useful, but adds a
  dependency and a whole sanitisation path that deserves its own pass.
- **`sort_emails`** (RFC 5256 SORT) — nice-to-have, low pain to add
  alongside a future "search UX" iteration.
- **Gmail labels / `search_gmail_raw`** — specific to Gmail users; ship
  once there is explicit demand.
- **`transfer_email` cross-account** — requires careful atomicity and
  confirmation UX; revisit together with the multi-account audit log.
- **Base64 inline attachments** — wait until there is a use case we
  cannot satisfy with disk paths (there isn't one today).
- **Priority headers, explicit `reply_to`, signatures, per-identity
  `from_alias`** — tied to the identity model refactor; best done in one
  coherent breaking v0.3 rather than dripped in.

## Defer to v0.3 (breaking changes)

- **Identity model** — `AccountModel.identities: list[Identity]`. Enables
  send-as, per-identity signatures, reply-to. Needs a loader migration
  so we do not break existing configs.
- **Sieve extras (`mail-mcp[sieve]`)** — `sievelib` plus five raw tools
  plus vacation. Only 25–30 % of providers expose ManageSieve, so this
  is an opt-in extra rather than a core feature. The vacation tool only
  makes sense once the Sieve plumbing is in.

## Explicitly rejected (not planned for any version)

- IDLE / long-running watchers — incompatible with stdio MCP.
- Scheduled send — requires a persistent daemon; document provider web
  UIs as the answer.
- Read receipts (`Disposition-Notification-To`) and SMTP DSN — phishing
  vector, ignored by modern clients.
- `add_account` / `remove_account` as MCP tools — setup is CLI/wizard;
  passing credentials through tool arguments is never acceptable.
- `search_emails_all_accounts` — the LLM can fan out trivially and the
  merge is presentation.
- OCR, thumbnails, inline CID images — scope creep with heavy deps.
- Outlook Focused Inbox / Microsoft 365 Graph rules — not reachable via
  IMAP, would require a second protocol.
- iCloud VIP / Smart Mailboxes — client-side only, not over IMAP.

## Acceptance criteria for v0.2.4

- 10 new MCP tools wired up and enumerated by the server.
- Existing 16 tools unchanged on the wire (backwards compatible).
- No new runtime dependency.
- Tests stay under one second; coverage lifts on `tools/`, `smtp_client`,
  `imap_client`.
- Docs: README tool table updated, CHANGELOG entry, ROADMAP aligned.
