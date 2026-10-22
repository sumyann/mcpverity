# Writing a Rule

## Built-in rules

Built-ins live in `src/mcpverity/rules/w0NN_*.py` and are registered explicitly
in `src/mcpverity/rules/__init__.py`'s `BUILTIN_RULES` list. We don't discover
built-ins by filesystem globbing -- an explicit list means scan behavior
never silently changes because a new file appeared on disk.

## Third-party plugin rules

You don't need to fork MCPVerity to add a rule. Publish your own package with
an entry-point in the `mcpverity.rules` group:

```toml
# your_package/pyproject.toml
[project.entry-points."mcpverity.rules"]
my_rule = "your_package.rules:RULE"
```

```python
# your_package/rules.py
from mcpverity.rules.base import Rule, ParsedServer
from mcpverity.models import Finding

def _check(parsed: ParsedServer):
    for f in parsed.files:
        if "TODO(security)" in f["content"]:
            yield Finding(
                rule_id="CUSTOM001",
                title="Unresolved security TODO",
                severity="LOW",
                file_path=f["path"],
                message="File has an unresolved TODO(security) marker.",
                remediation="Resolve or triage the marked TODO before shipping.",
            )

RULE = Rule(
    id="CUSTOM001",
    title="Unresolved Security TODO",
    severity="LOW",
    description="Flags TODO(security) markers left in source.",
    _check=_check,
)
```

Anyone with your package installed alongside `mcpverity` gets your rule
run by every scan (`engine.run_scan()` loads plugins via
`mcpverity.rules.load_plugin_rules()`) and listed by `mcpverity rules`.

A broken plugin rule can never crash a scan, and never disappears silently:

- an entry point that fails to import, or that doesn't resolve to a `Rule`,
  becomes one `INFO`-severity `PLUGIN-ERR` finding naming the entry point;
- an exception raised inside a rule's `.check()` becomes one `INFO`-severity
  `{rule_id}-ERR` finding.

The CLI also prints each of these as a warning on stderr, so they show up in
CI logs even with `-o json` / `-o sarif`.

## What we expect from a rule PR to this repo

If you're proposing a new **built-in** rule (not a plugin):

- **At least one true-positive and one true-negative fixture**, as a test in
  `tests/test_rules_fixtures.py` or a new `tests/test_wNNN_*.py`. A rule that
  can't demonstrate it doesn't fire on ordinary code will be asked to add
  more negative fixtures before merge.
- **A confidence score**, not just a severity. If your signal is
  context-dependent (only meaningful inside an MCP tool file, only
  meaningful alongside a write/exec op, etc.), gate it the way W002/W006/W007
  do -- see [architecture.md](./architecture.md#context-gating).
- **A benchmark check.** Run `python benchmark/run_benchmark.py` before and
  after your change. If your rule turns any of the 8 pinned fixtures' false
  positives from 0 to nonzero, either tighten the rule or correct
  `benchmark/labels.yaml` with justification in the PR description.
- **We reject noisy rules.** A rule that fires on ordinary, non-risky code
  more than rarely will not be merged as a built-in, no matter how
  theoretically interesting the risk it's chasing is. Precision is the
  product's core credibility claim (see the top-level README's benchmark
  section) -- a noisy built-in erodes that for every user, not just yours.
  If your detector is inherently high-recall/low-precision, it's a great
  candidate for a plugin instead.
- A `doc_link` pointing at a `docs/rules.md#your-anchor` section you've
  added, describing what the rule catches and why.
