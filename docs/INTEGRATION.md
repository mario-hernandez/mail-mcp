# Integration guide

Step-by-step instructions to wire `mail-mcp` into Claude Desktop, Claude Code and the Codex CLI.

## 0. Install

Until `mail-mcp` lands on PyPI, install it directly from the GitHub repository:

```bash
pip install "git+https://github.com/mario-hernandez/mail-mcp.git@main"
```

Or from a local clone if you want to hack on it:

```bash
git clone https://github.com/mario-hernandez/mail-mcp
cd mail-mcp
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
```

Verify the CLI is on your `PATH`:

```bash
which mail-mcp
mail-mcp --version
```

Take note of the absolute path returned by `which` — the MCP clients below need it.

## 1. Add an IMAP/SMTP account

The `add-account` command asks for the password interactively and stores it in the OS keyring (macOS Keychain / Linux Secret Service / Windows Credential Manager). Nothing secret is written to the project's config file.

```bash
mail-mcp add-account personal m@mariohernandez.es \
  --imap-host imap.ionos.es --imap-port 993 \
  --smtp-host smtp.ionos.es --smtp-port 587
```

Typical hosts:

| Provider | IMAP | SMTP |
|----------|------|------|
| IONOS | `imap.ionos.es:993` | `smtp.ionos.es:587` |
| Gmail (app password required) | `imap.gmail.com:993` | `smtp.gmail.com:587` |
| Fastmail | `imap.fastmail.com:993` | `smtp.fastmail.com:587` |
| iCloud | `imap.mail.me.com:993` | `smtp.mail.me.com:587` |
| Outlook / Microsoft 365 | `outlook.office365.com:993` | `smtp.office365.com:587` |

Verify the keyring lookup succeeds:

```bash
mail-mcp check --alias personal
```

## 2. Register with Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or the equivalent path on your OS:

```json
{
  "mcpServers": {
    "mail-mcp": {
      "command": "/absolute/path/to/mail-mcp",
      "args": ["serve"]
    }
  }
}
```

Enable the destructive tools only when you actually want them exposed:

```json
{
  "mcpServers": {
    "mail-mcp": {
      "command": "/absolute/path/to/mail-mcp",
      "args": ["serve"],
      "env": {
        "MAIL_MCP_WRITE_ENABLED": "true"
      }
    }
  }
}
```

And, separately, for true one-click send (not recommended for everyday use — prefer `save_draft`):

```json
"env": {
  "MAIL_MCP_WRITE_ENABLED": "true",
  "MAIL_MCP_SEND_ENABLED": "true"
}
```

Restart Claude Desktop for the changes to take effect.

## 3. Register with Claude Code

```bash
# Read-only mode (safe default)
claude mcp add mail-mcp "$(which mail-mcp)" serve

# Add write access
claude mcp add --env MAIL_MCP_WRITE_ENABLED=true mail-mcp "$(which mail-mcp)" serve

# Or scope it per-project by running the command inside that project directory
```

Verify:

```bash
claude mcp list
```

## 4. Register with Codex CLI

Edit `~/.codex/config.toml`:

```toml
[mcp_servers.mail-mcp]
command = "/absolute/path/to/mail-mcp"
args    = ["serve"]

[mcp_servers.mail-mcp.env]
# Optional — uncomment to enable destructive tools.
# MAIL_MCP_WRITE_ENABLED = "true"
# MAIL_MCP_SEND_ENABLED  = "true"
```

## 5. Smoke test

Once any of the clients is running, ask the assistant:

> List the folders in my `personal` mail account.

You should see `INBOX`, `Sent`, `Drafts`, `Trash`, and any custom folders the server advertises. From there:

> Show me the most recent 10 unread emails.
>
> Open UID 4231 and summarise it.
>
> Draft a reply to that email thanking them and proposing Tuesday 10:00.

The draft lands in your Drafts folder and you can review it in your regular email client before sending.

## Troubleshooting

- **`mail-mcp: command not found`** — add the install location (e.g. `~/Library/Python/3.11/bin` or the venv's `bin/`) to your `PATH`, or use the absolute path in the client config.
- **`credential not found in keyring`** — you created the account config but skipped the password prompt. Re-run `mail-mcp add-account`.
- **`ssl.SSLCertVerificationError`** — your IMAP/SMTP provider is using a certificate not trusted by the system. This server intentionally does **not** offer a bypass; fix the certificate chain on the server instead.
- **Claude Code shows write tools even when `MAIL_MCP_WRITE_ENABLED` is unset** — the env var is read at server startup. Restart the client so it relaunches the MCP subprocess with a fresh environment.
