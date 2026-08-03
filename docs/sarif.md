# SARIF Export

`mcpverity scan --output sarif` produces a [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
document, uploadable to GitHub's Security tab via
[`github/codeql-action/upload-sarif`](https://github.com/github/codeql-action):

```bash
mcpverity scan . --output sarif --output-file mcpverity-results.sarif --fail-on none
```

```yaml
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: mcpverity-results.sarif
```

The [GitHub Action](../action/README.md) does this for you in two steps.

## Shape

- One `run` per scan, `tool.driver.name == "MCPVerity"`.
- One SARIF `rule` per distinct `rule_id` that fired, with `helpUri` pointing
  at that rule's [`docs/rules.md`](./rules.md) anchor.
- Each `result` maps a MCPVerity `Finding` to a SARIF result: `ruleId`,
  `level` (severity mapped: CRITICAL/HIGH -> `error`, MEDIUM -> `warning`,
  LOW -> `note`, INFO -> `none`), `message`, and a single
  `physicalLocation` (file + line + snippet).
- `properties` on each result carries MCPVerity-specific fields the SARIF spec
  doesn't have a slot for: `severity` (the un-mapped original), `remediation`,
  `tags`, and `confidence` (0.0-1.0) -- useful for a CI policy that wants to
  filter on confidence, not just severity.

See `src/mcpverity/report/sarif.py` for the exact mapping and
`tests/test_report.py` for shape assertions.
