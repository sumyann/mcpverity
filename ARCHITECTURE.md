# Architecture Map

This file is a concise navigation aid for coding agents. Keep it current as the project grows; record historical rationale in ADRs instead.

<!-- agent-bootstrap:start managed -->
## Project identity

- Project ID: `mcpverity`
- Profile: `python-service`
- Primary language: `python`

## Detected stack

- `python`
- `pip`

## Detected top-level directories

- `action/`
- `benchmark/`
- `docs/`
- `examples/`
- `src/`
- `tests/`

## Detected entry points

- `src/mcpverity/cli.py`

## Detected CI workflows

- `.github/workflows/ci.yml`
- `.github/workflows/codeql.yml`

## Verification map

- Install: `python -m pip install -e '.[dev]'`
- Test: `python -m pytest`
- Full validation: `python -m pytest`
<!-- agent-bootstrap:end managed -->

## Project-specific dependency direction

Document the allowed dependency flow between layers. Identify packages that must not import one another.

## Project-specific data flow

Document the primary request, event, or processing flow at a high level.

## External systems

Document external APIs, databases, queues, identity providers, model providers, and deployment platforms.

## Protected boundaries

Document security-critical modules, public interfaces, generated files, and other areas requiring explicit approval.
