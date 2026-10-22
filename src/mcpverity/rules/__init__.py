"""The rule registry.

Built-in rules are an explicit list (below) so behavior never depends on
import order or filesystem globbing. Third-party rules can additionally
register themselves via the `mcpverity.rules` entry-point group in their own
package's pyproject.toml:

    [project.entry-points."mcpverity.rules"]
    my_rule = "my_package.rules:RULE"

where `my_package.rules.RULE` is a `mcpverity.rules.base.Rule` instance. See
docs/rule-authoring.md.
"""
from . import (
    w001_tool_poisoning,
    w002_xpia,
    w003_credential_exposure,
    w004_over_privileged,
    w005_provenance,
    w006_session_risks,
    w007_covert_invocation,
)
from .base import ParsedServer, Rule

BUILTIN_RULES = [
    w001_tool_poisoning.RULE,
    w002_xpia.RULE,
    w003_credential_exposure.RULE,
    w004_over_privileged.RULE,
    w005_provenance.RULE,
    w006_session_risks.RULE,
    w007_covert_invocation.RULE,
]


def load_plugin_rules() -> tuple[list[Rule], list[tuple[str, str]]]:
    """Load third-party rules registered under the `mcpverity.rules` entry-point group.

    Returns (rules, errors) where each error is (entry point, reason). A broken
    plugin must never break core scanning -- but it must not vanish silently
    either, so callers report the errors (engine.run_scan emits a PLUGIN-ERR
    finding for each).
    """
    try:
        from importlib.metadata import entry_points
    except ImportError:  # pragma: no cover - py<3.10 fallback, unsupported but defensive
        return [], []

    plugins: list[Rule] = []
    errors: list[tuple[str, str]] = []
    try:
        eps = entry_points(group="mcpverity.rules")
    except TypeError:  # pragma: no cover - very old importlib.metadata signature
        eps = entry_points().get("mcpverity.rules", [])
    for ep in eps:
        label = f"{ep.name} = {ep.value}"
        try:
            rule = ep.load()
        except Exception as e:  # noqa: BLE001 - reported, never raised
            errors.append((label, f"failed to load: {type(e).__name__}: {e}"))
            continue
        if isinstance(rule, Rule):
            plugins.append(rule)
        else:
            errors.append((label, f"is a {type(rule).__name__}, not a mcpverity.rules.base.Rule"))
    return plugins, errors


def all_rules() -> list:
    """Built-in rules plus any successfully loaded plugin rules, built-ins first."""
    return [*BUILTIN_RULES, *load_plugin_rules()[0]]


# Back-compat alias: built-ins only. engine.run_scan adds plugin rules on top.
ALL_RULES = BUILTIN_RULES

__all__ = ["ParsedServer", "Rule", "BUILTIN_RULES", "ALL_RULES", "all_rules", "load_plugin_rules"]
