# Detection Rules

MCPVerity ships 7 built-in rules. Each scans for one class of MCP-specific risk;
none of them require network access or an LLM call. See
[rule-authoring.md](./rule-authoring.md) if you want to add your own.

Every finding carries a `confidence` score (0.0-1.0). Confidence is lowered
for matches in test/example/fixture paths and raised for AST-verified Python
matches over regex fallback matches -- see [architecture.md](./architecture.md#confidence-scoring).

---

## W001 Tool Poisoning

**Default severity:** CRITICAL

Malicious or manipulative instructions embedded in tool description/metadata
fields -- invisible to human review but read as trusted by the model. Prefers
an AST walk over Python: `description=`/`prompt=`/`instructions=` keyword
arguments and assignments, `{"description": ...}` dict literals, and the
docstring of any `@tool`/`@prompt`/`@resource`-decorated function (FastMCP
uses that docstring as the tool description). Comments and ordinary
docstrings are skipped, so `# ignore all previous instructions` in a code
comment does not fire. Non-Python files fall back to regex over
`description = "..."`, `description: "..."` (JS/TS object literals), and the
TS/JS SDK positional form `server.tool("name", "description", ...)`.

## W002 Indirect Prompt-Injection Surface (XPIA)

**Default severity:** HIGH

Tools that return external, untrusted content (web pages, files, email) into
model context without a trust boundary. Only fires in files that look like
MCP tool implementations -- see `is_mcp_file()` in `mcpverity.rules.base`.

## W003 Credential & Secret Exposure

**Default severity:** CRITICAL

API keys, tokens, or secrets hardcoded in server source or config, or leaking
into model-visible context. Matches common key formats (`sk-`, `sk-ant-`,
`sk-proj-`/`sk-svcacct-`/`sk-admin-`, `AKIA`, `gh[pousr]_`, `github_pat_`,
`AIza`, `xox[baprs]-`, Slack webhook URLs, `sk_live_`/`rk_live_`, `hf_`,
PEM private key blocks, JWTs, database URLs with an inline password, generic
high-entropy assignment). Database URLs with a templated (`${X}`, `{x}`,
`<x>`, `%s`) or stock placeholder password (`password`, `changeme`, ...) are
not flagged; JWTs and generic assignments start at lower confidence.
Reading a secret from an environment variable or secret manager does not fire
this rule -- only literal hardcoded values do.

The matched value is never echoed: snippets and messages in every output
format (terminal, JSON, SARIF) show only the first four characters plus a
`[REDACTED len=N,sha256=xxxxxxxx]` fingerprint, so two reports can be
compared without either containing the secret.

## W004 Over-Privileged Tools

**Default severity:** HIGH

Tools requesting filesystem, network, or shell scope broader than their
stated function -- least-privilege violations. AST-verified for Python
(`subprocess.*`, `os.system`, `eval`/`exec`, `shutil.rmtree`, `shell=True`);
regex fallback for other languages. Also checks `mcpServers` launcher configs
for wildcard flags (`--allow-all`, `--dangerously-*`, `--privileged`,
`--network=host`, host-root docker mounts) and manifest `permissions`/`scopes`
fields for broad wildcards.

## W005 Unsigned / Unverified Provenance

**Default severity:** MEDIUM

Tools pulled from unlocked sources, unpinned dependencies, or manifests
without a signature/integrity field. Covers `requirements.txt` (unpinned /
`git+` without a commit pin), `package.json` (floating semver ranges without
a committed lockfile), `mcpServers` launcher packages (`uvx`/`npx`/`pipx`/
`bunx` with no version, `docker` images tagged `:latest` or untagged), and
manifests missing `signature`/`integrity`/`checksum`.

## W006 Session / Multi-Server Risks

**Default severity:** HIGH

Stateful HTTP MCP transports vulnerable to session hijack, shared-session-ID
injection, or cross-server contamination. Only fires in files that look like
an HTTP-transport MCP server (`is_http_server_file()` / `is_mcp_file()`) --
a bare `sessions = {}` in an unrelated file does not fire this rule.

## W007 Covert Invocation Paths

**Default severity:** MEDIUM

Tools or file operations that can be triggered without user-visible consent
(auto-execute, confirmation disabled, on-load hooks). Broad signals require
both an MCP-context file *and* a write/exec operation in the same file to
fire; a manifest tool declaring `requires_confirmation: false` or
`auto_execute: true` always fires regardless of file context.
