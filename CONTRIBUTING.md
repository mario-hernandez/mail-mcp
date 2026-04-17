# Contributing to mail-mcp

Thanks for looking at the code. The project is deliberately small and
auditable — contributions that keep it that way are welcome.

## Dev setup

```bash
git clone https://github.com/mario-hernandez/mail-mcp
cd mail-mcp
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest        # 72 tests, should complete in under a second
ruff check src tests
```

`pip install -e ".[dev]"` pulls in the interactive-CLI extras
(`questionary`, `rich`, `dnspython`) as well as the linter and test runner,
so you can exercise `mail-mcp init` from a fresh checkout.

## What counts as a good PR

**Yes, please**:
- Bug fixes with a test that reproduces the bug.
- New IMAP/SMTP provider presets in `src/mail_mcp/autoconfig.py` (especially
  MX substring hints for custom-domain-on-$PROVIDER setups).
- Tests that lift coverage on the handler layer (`src/mail_mcp/tools/`) or
  against a real IMAP/SMTP fake.
- Documentation fixes: typos, broken links, unclear error messages, missing
  troubleshooting cases.
- Localised provider guides under `docs/providers/`.

**Please discuss first** (open an issue before the PR):
- New tools in the MCP surface. The existing ten were chosen deliberately;
  new ones expand the attack surface the LLM can enumerate.
- New runtime dependencies. The project's pitch rests on a tiny dep tree.
- Anything that would take `mail-mcp` outside the stdio transport.

**Out of scope** (listed in the README under "Non-goals"):
- OAuth2 for Google in-tree (user must bring their own Cloud project or use a
  local proxy — this is a legal/licence decision, not a technical one).
- HTTP/SSE transport.
- A web UI.
- Calendar integration, scheduling, IMAP IDLE watchers, PDF text extraction.

## Style

- Python ≥ 3.11, `from __future__ import annotations` in every new module.
- `ruff check` must pass. The ruleset is defined in `pyproject.toml` and
  currently selects `E, F, W, I, B, UP, S`. Prefer fixing lints over noqa;
  when a noqa is genuinely warranted, add a short comment explaining why.
- Type hints on every public function and every handler in
  `src/mail_mcp/tools/`. `dict[str, Any]` is fine for tool return values.
- Pydantic v2 models for anything crossing a trust boundary (tool inputs,
  config file). Dataclasses for internal value types.

## Commit messages

Single-line subject, then a blank line, then a wrapped body. The body should
answer *why*, not re-describe the diff. No trailing "Generated with …"
tags; the commit log is part of the product.

## Tests

- `pytest` is the only test runner.
- Unit tests live under `tests/` and never make real network calls. Mock the
  IMAP/SMTP paths when you exercise `tools/` handlers.
- If you add behaviour the README promises, add a test that exercises the
  promise (e.g. "CRLF is rejected", "structured IMAP search, no injection").

## Reporting security issues

Do not open a public GitHub issue. See [`SECURITY.md`](SECURITY.md) for the
disclosure channel.

## Releasing

Maintainers only; end-to-end notes live in `docs/RELEASE.md` when the first
PyPI release is cut.
