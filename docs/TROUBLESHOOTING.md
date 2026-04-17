# Troubleshooting

## "Gmail AUTHENTICATIONFAILED" / "BADCREDENTIALS"

Gmail has not accepted account passwords for IMAP since 2022. You need an
**app password**:

1. Enable 2-Step Verification at <https://myaccount.google.com/security>.
2. Visit <https://myaccount.google.com/apppasswords> and generate one for
   "mail-mcp" (any label).
3. Run `mail-mcp init` (or `mail-mcp add-account`) and paste the 16-character
   app password as the account password. Your regular Google password will
   not work.

## "AUTHENTICATIONFAILED" on iCloud

iCloud requires an **app-specific password** too, even if you know your Apple
ID password:

1. Sign in at <https://appleid.apple.com> and open *Sign-In and Security*.
2. Under *App-Specific Passwords*, generate one labelled `mail-mcp`.
3. Paste it into the wizard.

## "AUTHENTICATIONFAILED" on Outlook.com / Microsoft 365

* **Outlook.com personal accounts** — create an app password at
  <https://account.live.com/proofs/AppPassword> and use it in `mail-mcp init`.
* **Microsoft 365 tenant-managed accounts** — basic authentication for IMAP
  and SMTP was retired across 2022–2026. Password login will not work. OAuth2
  support is scheduled for v0.2.2. In the meantime, use
  [`email-oauth2-proxy`](https://github.com/simonrob/email-oauth2-proxy)
  locally and point `mail-mcp` at `127.0.0.1:1993` / `127.0.0.1:1587`.

## "The Keychain prompt appears every time"

macOS binds a keychain item's "Always Allow" permission to the calling
binary's code signature. If you reinstall Python (brew, pyenv, a new
virtualenv) the interpreter's signature changes and you will be prompted
again. Click *Always Allow* once and subsequent calls from the same
interpreter are silent. Namespacing keeps unrelated credentials safe, so
granting access to one alias doesn't leak to others.

## "Claude doesn't see the tools (or write tools are missing)"

After changing environment variables for the MCP server you must restart the
client process. Claude Desktop picks up environment variables only when it
launches the MCP subprocess. Quit and relaunch. Same for Claude Code after
running `claude mcp add --env ... mail-mcp`.

Run `mail-mcp doctor` to confirm the server is wired up correctly and the
gates are in the state you expected.

## "mail-mcp: command not found"

The script installed via `pip install --user` sometimes lands outside your
`PATH`. Options:

* `pipx install mail-mcp` — recommended; manages its own virtualenv and
  symlinks the executable into `~/.local/bin`.
* Add the install location to `PATH` (check `python -m site --user-base`).
* Use the absolute path in your Claude Desktop / Claude Code / Codex config.

## "Cannot connect to imap.example.com:993"

* Check connectivity without the server: `openssl s_client -connect
  imap.example.com:993 -crlf`.
* Corporate networks sometimes block 993 outbound — try from a different
  network to rule it out.
* If you are behind a proxy that rewrites TLS certificates, `mail-mcp`
  refuses to connect. Install the corporate root certificate into your
  system trust store instead of disabling verification.

## "My drafts end up in the wrong folder"

Until v0.2.1, the wizard assumed `Drafts` / `Trash` as mailbox names. Non-
English accounts (Gmail with Spanish interface, iCloud with localised names,
IONOS with `Borradores` / `Papelera`) silently wrote to a non-existent
folder. Re-run `mail-mcp init` — the updated wizard uses RFC 6154 SPECIAL-USE
hints to pick the real mailbox names.

## Reporting a bug

Run `mail-mcp doctor` and include the output in your issue. Passwords,
message bodies and tokens are never emitted by that command. **Do redact
your email address and your IMAP/SMTP hostnames** before pasting the report
into a public tracker — that information is shown in the "config" section
and is fine in a private support thread but unnecessary in public.
