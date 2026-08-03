# MCPVerity

[![CI](https://github.com/sumyann/mcpverity/actions/workflows/ci.yml/badge.svg)](https://github.com/sumyann/mcpverity/actions/workflows/ci.yml)
[![CodeQL](https://github.com/sumyann/mcpverity/actions/workflows/codeql.yml/badge.svg)](https://github.com/sumyann/mcpverity/actions/workflows/codeql.yml)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

Scan your MCP server before an agent scans it.

MCPVerity is a static security scanner for [Model Context Protocol](https://modelcontextprotocol.io)
(MCP) servers -- it catches tool poisoning, indirect prompt injection,
leaked credentials, over-privileged tools, unpinned/unsigned dependencies,
session-hijack surfaces, and covert auto-invoke paths, all without a network
call or an LLM in the loop.

## Install

```bash
pipx install mcpverity
# or: pip install mcpverity
```

## 30-second quickstart

```bash
mcpverity scan ./my-server
```

```bash
# Scan a public GitHub repo directly
mcpverity scan --github https://github.com/owner/repo

# CI-friendly: SARIF output, fail the build on high+ severity
mcpverity scan . --output sarif --output-file results.sarif --fail-on high

# Try it on MCPVerity's own intentionally-vulnerable fixture
mcpverity scan examples/vulnerable-demo
```

Optional: an LLM-assisted second pass that catches subtle tool-poisoning
phrasing regex misses. Requires `pip install "mcpverity[llm]"` and
`ANTHROPIC_API_KEY`:

```bash
mcpverity scan ./my-server --llm-check
```

## The 7 rules

| ID | Rule | Default Severity |
|----|------|-------------------|
| [W001](docs/rules.md#w001-tool-poisoning) | Tool Poisoning | CRITICAL |
| [W002](docs/rules.md#w002-indirect-prompt-injection-surface-xpia) | Indirect Prompt-Injection Surface (XPIA) | HIGH |
| [W003](docs/rules.md#w003-credential--secret-exposure) | Credential & Secret Exposure | CRITICAL |
| [W004](docs/rules.md#w004-over-privileged-tools) | Over-Privileged Tools | HIGH |
| [W005](docs/rules.md#w005-unsigned--unverified-provenance) | Unsigned / Unverified Provenance | MEDIUM |
| [W006](docs/rules.md#w006-session--multi-server-risks) | Session / Multi-Server Risks | HIGH |
| [W007](docs/rules.md#w007-covert-invocation-paths) | Covert Invocation Paths | MEDIUM |

Full detail on what each rule looks for and how confidence is scored:
[docs/rules.md](docs/rules.md), [docs/architecture.md](docs/architecture.md).

## Benchmark

MCPVerity's precision is measured against 8 real, pinned MCP server fixtures
with hand-verified ground-truth labels -- not synthetic test cases. Run it
yourself:

```bash
python benchmark/run_benchmark.py
```

Ground truth lives at [`benchmark/labels.yaml`](benchmark/labels.yaml); PRs
correcting a label are welcome and are the fastest way to fix a
detection-quality issue -- see [CONTRIBUTING.md](CONTRIBUTING.md).

## GitHub Action

```yaml
- uses: actions/checkout@v4
- uses: sumyann/mcpverity/action@main
  with:
    fail-on: high
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: mcpverity-results.sarif
```

See [action/README.md](action/README.md) for full inputs/outputs.

## License

Apache 2.0 -- see [LICENSE](LICENSE) and [NOTICE](NOTICE).

---

MCPVerity's scanner, rules, parsers, and benchmark are Apache 2.0 and stay that way. If you want to run it in CI, on your laptop, in your air-gapped environment — it works, forever, unlimited, free. Warden Cloud (mcpscan.narma.tech) adds fleet inventory, continuous re-scan, org policy, and SIEM export for teams. If you're a solo dev, you don't need it. If you're an AppSec team running 50+ MCP servers across a company, you probably do.
