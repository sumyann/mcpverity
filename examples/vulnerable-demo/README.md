# vulnerable-demo

This directory is **intentionally vulnerable**. Every file in it exists to
demonstrate MCPVerity's detection rules and is used by the test suite and the
30-second quickstart in the top-level README.

The API keys, tokens, `shell=True` calls, poisoned tool descriptions, and
over-broad manifest permissions here are **inert example data** -- never
executed, never imported by any real server, never bundled into a client.
Do not copy these patterns into a real MCP server, and do not report the
credential-shaped strings here as leaked secrets -- they are fixtures, not
live keys (see `.gitleaks.toml` at the repo root, which allowlists this
directory for that reason).

Run it:

```bash
mcpverity scan examples/vulnerable-demo
```

Expect findings across W001 (tool poisoning), W002 (untrusted content into
model context), W003 (hardcoded credentials), W004 (over-privileged shell/fs
scope), W005 (unpinned dependencies and launcher packages), and W007
(auto-execute / no-confirmation tools).
