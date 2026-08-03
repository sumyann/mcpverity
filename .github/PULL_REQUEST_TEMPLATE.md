## Summary

<!-- What does this change and why? -->

## Checklist

- [ ] `ruff check .` passes
- [ ] `pytest -q` passes
- [ ] If this changes or adds a **rule**: at least one TP and one TN fixture added (see [docs/rule-authoring.md](../docs/rule-authoring.md))
- [ ] If this changes a **benchmark label**: ran `python benchmark/run_benchmark.py` and the diff is explained below
- [ ] If this touches `mcpverity.engine`, `mcpverity.rules.*`, `mcpverity.parsers`, or `mcpverity.py_ast`: no new `requests`/`httpx`/`urllib` imports at module scope (see [docs/architecture.md#zero-network-by-default](../docs/architecture.md#zero-network-by-default))

## Benchmark impact (if applicable)

<!-- Paste the before/after totals from benchmark/run_benchmark.py if this PR could change detection results -->
