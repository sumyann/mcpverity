# Contributing to MCPVerity

## Setup

```bash
git clone https://github.com/sumyann/mcpverity.git
cd mcpverity
pip install -e ".[dev]"
pytest -q
ruff check .
```

Optional: install [pre-commit](https://pre-commit.com) to run `ruff`,
basic hygiene checks, and a gitleaks secrets scan automatically on every
commit -- the same checks CI enforces, but caught before you push:

```bash
pip install pre-commit
pre-commit install
```

## Reporting a missed or incorrect detection

The fastest way to fix a detection-quality issue is a PR, not just a report:

1. Add a minimal fixture reproducing the miss/false-positive to
   `tests/test_rules_fixtures.py` (or a dedicated `tests/test_wNNN_*.py`).
2. If it's against one of the 8 benchmark servers, correct
   `benchmark/labels.yaml` instead/also and re-run
   `python benchmark/run_benchmark.py` to confirm the fix.
3. Open a PR. If you're not sure how to fix the rule itself, a PR that's
   *just* the failing test (marked `xfail` or left red) is still useful --
   it turns a vague report into a reproducible, trackable regression.

## Adding a rule

See [docs/rule-authoring.md](./docs/rule-authoring.md). Short version: new
built-in rules need TP + TN fixtures, a confidence score, a benchmark check,
and we will push back on anything that isn't precise -- see that doc's "we
reject noisy rules" section. If you want a higher-recall/lower-precision
detector, publish it as a plugin via the `mcpverity.rules` entry-point group
instead of proposing it as a built-in.

## Fixture / benchmark maintenance

`benchmark/servers/` holds pinned snapshots (specific commit SHA + upstream
LICENSE) of 8 real MCP server repos, used as the ground truth for MCPVerity's
published precision/recall numbers. They're intentionally *not* re-fetched
on every CI run -- that would make the benchmark's numbers move for reasons
unrelated to a given PR's changes.

- To re-pin a fixture to its upstream repo's current HEAD (e.g. because the
  upstream project restructured and MCPVerity's findings against it went
  stale), run `python benchmark/refresh_fixtures.py [owner/repo]`, then
  re-run the benchmark and update `labels.yaml` if the expected findings
  changed. This is a maintainer action, not something CI does automatically.
- Fixtures are redistributed under their own upstream license (MIT or
  Apache-2.0 for all 8 as of this writing) -- see the `LICENSE` and
  `NOTICE.md` inside each `benchmark/servers/<owner>__<repo>/` directory.

## Maintenance expectations

This is a small project maintained on a best-effort basis. We aim to triage
new issues and PRs weekly, but "weekly" means "we looked at it," not
"resolved." Detection-quality PRs with a fixture attached get priority over
prose-only reports, for the reason above: a fixture is a permanent
regression test, a report is a conversation that can go stale.

## Code style

`ruff check .` must pass. We don't currently run a formatter in CI, but
match the surrounding file's style. Keep `mcpverity.engine`, `mcpverity.rules.*`,
`mcpverity.parsers`, and `mcpverity.py_ast` free of `requests`/`httpx`/`urllib`
imports at module scope -- see [docs/architecture.md](./docs/architecture.md#zero-network-by-default)
for why.
