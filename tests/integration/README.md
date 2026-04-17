# Integration tests (`tests/integration/`)

End-to-end tests that exercise `mail-mcp` against a real IMAP/SMTP server.
The server is [GreenMail](https://greenmail-mail-test.github.io/greenmail/),
a single-JVM test MTA that speaks SMTP, SMTPS, IMAP, IMAPS (and POP3/POP3S,
which we ignore). It runs inside Docker and is orchestrated by
[testcontainers-python](https://testcontainers-python.readthedocs.io/).

These tests are **opt-in**. They are excluded from the default `pytest` run
because they require Docker and take several seconds to boot.

---

## Running the suite

```bash
# 1. Install integration extras (testcontainers, requests)
pip install -e '.[dev,integration]'

# 2. Make sure Docker is running (Docker Desktop, colima, OrbStack, etc.)
docker info >/dev/null

# 3. Run the integration suite (either flag works)
MAIL_MCP_INTEGRATION=1 pytest tests/integration -m integration
# or, equivalently, without the env flag:
pytest tests/integration -m integration
```

The `-m integration` flag filters in the marker; `MAIL_MCP_INTEGRATION=1`
is honoured by `conftest.py` as a second gate (CI can flip the env var
without having to edit pytest args).

---

## What the fixture does

The `greenmail` session-scoped fixture (in `tests/integration/conftest.py`)
spins up exactly **one** GreenMail container defined by
`tests/integration/docker-compose.yml`:

| Port (host) | Protocol        | Used by                         |
| ----------- | --------------- | ------------------------------- |
| 3025        | SMTP (plain)    | — (exposed, not used by tests)  |
| 3110        | POP3 (plain)    | — (GreenMail exposes it; unused)|
| 3143        | IMAP (plain)    | — (exposed, not used by tests)  |
| 3465        | SMTPS           | `smtp_client` in the suite      |
| 3993        | IMAPS           | `imap_client` in the suite      |
| 8080        | Admin REST API  | debugging + `deliver()` helper  |

All ports bind to `localhost` on the host. Tests connect to
`localhost:3993` / `localhost:3465`.

Because GreenMail's TLS cert is self-signed, the suite also installs an
autouse `patched_tls` fixture that monkey-patches
`mail_mcp.safety.tls.create_tls_context` to return an unverified SSL
context **for tests only**. The production TLS code stays strict.

---

## Expected latency

- **First run** (image not cached): ~5 s to pull `greenmail/standalone:2.1.3`
  (it's a ~180 MB JRE image) plus ~3 s for the JVM to reach the readiness
  endpoint. Budget ~10 s for the first `greenmail` fixture acquisition.
- **Subsequent runs**: ~1 s. The healthcheck polls every 2 s with a 5 s
  start period, so the first response usually lands within a single
  interval after the JVM is up.
- **Teardown**: sub-second. The container is ephemeral (no volumes).

The fixture is session-scoped, so the ~1 s cost is paid **once per pytest
invocation**, not per test.

---

## Debugging a failing run

### 1. Tail the container logs

With `-Dgreenmail.verbose` set in the compose file, GreenMail logs every
SMTP/IMAP command it receives. If a test is timing out, this is usually
the fastest way to see what the client actually sent.

```bash
docker logs -f mail-mcp-greenmail
```

### 2. Inspect users & mailboxes via the admin REST API

GreenMail exposes a small REST surface on port 8080. Useful endpoints:

```bash
# List all users GreenMail knows about
curl -s http://localhost:8080/api/user | jq

# Inspect a mailbox (replace the email with whatever the failing test used)
curl -s "http://localhost:8080/api/mail/test-abc123@localhost/INBOX" | jq

# Purge the whole server (start from a clean slate mid-debug)
curl -s -X POST http://localhost:8080/api/service/reset
```

### 3. Run the container by hand

Skip pytest entirely and poke at GreenMail with your own IMAP/SMTP client:

```bash
docker compose -f tests/integration/docker-compose.yml up
# Ctrl-C to stop; `--rm` is not set, so tear down with:
docker compose -f tests/integration/docker-compose.yml down
```

### 4. Orphaned container after an interrupted suite

If you hit `Ctrl-C` in the middle of a pytest run, testcontainers usually
cleans up — but if it doesn't, the container name is fixed
(`mail-mcp-greenmail`) so one command kills it:

```bash
docker compose -f tests/integration/docker-compose.yml down
# or, as a nuke-option:
docker rm -f mail-mcp-greenmail
```

---

## GreenMail behaviour worth knowing

- **Any LOGIN credentials work.** GreenMail accepts any
  `(user, password)` pair on LOGIN / PLAIN / AUTH and auto-creates the
  mailbox on first access. That's why the suite uses fresh
  `test-<uuid4>@localhost` accounts per test without any provisioning
  step — the first successful LOGIN creates the user.
- **Self-signed TLS cert.** GreenMail ships a test CA. `patched_tls`
  disables verification for the suite; do not replicate that bypass in
  production code.
- **Shared state across tests is real.** Because the container is
  session-scoped and GreenMail has no per-test isolation, each test uses
  a unique email address to avoid cross-test pollution. If you add a
  test that reuses an address, reset the server via
  `POST /api/service/reset` in a fixture.
- **Version pinning.** The compose file pins `greenmail/standalone:2.1.3`
  (matching the 2.1.x line called out in the contract). Bumping the tag
  without re-running the whole suite is not recommended — GreenMail has
  historically shifted IMAP behaviour between minor versions.
