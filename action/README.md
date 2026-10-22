# MCPVerity MCP Scan (GitHub Action)

Composite action wrapping the `mcpverity` CLI. Installs `mcpverity` from the
action's own checkout (so the scanner version matches the ref in `uses:`),
scans a path, writes a SARIF file, and fails the job if any finding meets
the configured severity threshold.

## Usage

```yaml
name: MCPVerity MCP Scan
on: [push, pull_request]

permissions:
  contents: read
  security-events: write   # needed to upload SARIF to the Security tab

jobs:
  mcpverity:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: sumyann/mcpverity/action@main
        id: mcpverity
        with:
          path: "."
          fail-on: high

      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: ${{ steps.mcpverity.outputs.sarif-file }}
```

## Inputs

| Input          | Default              | Description                                                              |
|----------------|-----------------------|----------------------------------------------------------------------------|
| `path`         | `.`                   | Path to scan, relative to the repo root.                                 |
| `fail-on`      | `high`                | Minimum severity that fails the job: `critical`, `high`, `medium`, `low`, `none`. |
| `sarif-output` | `mcpverity-results.sarif`| Where to write the SARIF file.                                           |
| `server-name`  | `${{ github.repository }}` | Label shown in scan output.                                        |

## Outputs

| Output       | Description                     |
|--------------|----------------------------------|
| `sarif-file` | Path to the generated SARIF file. |
