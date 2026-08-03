# Architecture

## Pipeline

```
files (local dir / GitHub tarball)
    -> parsers.parse_files()        split into code files + manifests
    -> rules/*.py (7 rules)          each rule.check(ParsedServer) -> Finding[]
    -> [optional] llm_check          Claude-assisted second pass, opt-in only
    -> engine._dedupe / _summarize   dedupe, score, verdict
    -> report/{json,sarif,human}     export
```

`engine.run_scan()` is the only orchestrator. It is pure `async def`, takes
an in-memory file list, and returns a `Scan` pydantic model -- no I/O of its
own. This is deliberate: it's the same function a CLI invocation, a CI
action, and a hosted web app all call.

## Zero-network-by-default

`mcpverity.engine`, `mcpverity.rules.*`, `mcpverity.parsers`, and `mcpverity.py_ast`
never import `requests`/`httpx`/`urllib` at module scope, and never make a
network call. The only two modules that touch the network are:

- `mcpverity.github_fetch` -- fetches a repo tarball for `mcpverity scan --github`.
  Only imported by `cli.py`, and only inside the `--github` code path.
- `mcpverity.llm_check` -- the optional Claude-assisted pass. `anthropic` is
  imported *inside* `run_llm_check()`, not at module scope, so the package
  works fully offline (and fully unit-tests) with `anthropic` not installed
  at all. See `tests/test_llm_check_optional.py`.

`pip install mcpverity` (no extras) never contacts a network you didn't
explicitly ask it to.

## Rule SDK

Every rule is a `mcpverity.rules.base.Rule`:

```python
@dataclass
class Rule:
    id: str
    title: str
    severity: str
    description: str
    _check: Callable[[ParsedServer], Iterable[Finding]]

    def check(self, parsed: ParsedServer) -> list[Finding]:
        return list(self._check(parsed))
```

`ParsedServer` is the input: `files` (code files as `{path, content}`) and
`manifests` (parsed MCP manifest / `mcpServers` launch-config dicts). See
[rule-authoring.md](./rule-authoring.md) for how to write and register a
new one, including as a third-party plugin.

## Confidence scoring

Findings carry `confidence` (0.0-1.0), computed by `rules.base.confidence()`:

- A rule-specific base score reflecting how unambiguous the signal is.
- `-0.35` if the match is in a test/example/fixture path (`LOW_CONF_PATH_RE`
  in `rules/base.py`) -- a hardcoded key in `tests/fixtures/` is much less
  likely to be a real leaked credential than the same string in `server.py`.
- AST-verified Python matches (W001, W004) get a higher base confidence than
  the regex-fallback path, since the AST walk understands call structure
  (e.g. it distinguishes an actual `subprocess.run(..., shell=True)` call
  from the string `"shell=True"` appearing in a comment or docstring).

## Context gating

W002, W006, and W007 only fire in files that look like MCP server code
(`is_mcp_file()`) or, for W006 specifically, an HTTP transport
(`is_http_server_file()`). This is a deliberate false-positive reduction --
grepping for "session" or "auto_execute" across an entire non-MCP codebase
produces far more noise than signal. See `test_w006_gate_not_fires_without_context`
and `test_w007_gate_not_fires_without_context` in
`tests/test_engine_behavior.py`.
