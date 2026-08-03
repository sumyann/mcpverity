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


def _discover_plugin_rules() -> list:
    """Load third-party rules registered under the `mcpverity.rules` entry-point group."""
    try:
        from importlib.metadata import entry_points
    except ImportError:  # pragma: no cover - py<3.10 fallback, unsupported but defensive
        return []

    plugins = []
    try:
        eps = entry_points(group="mcpverity.rules")
    except TypeError:  # pragma: no cover - very old importlib.metadata signature
        eps = entry_points().get("mcpverity.rules", [])
    for ep in eps:
        try:
            rule = ep.load()
            if isinstance(rule, Rule):
                plugins.append(rule)
        except Exception:  # noqa: BLE001 - a broken plugin must never break core scanning
            continue
    return plugins


def all_rules() -> list:
    """Built-in rules plus any discovered plugin rules, built-ins first."""
    return [*BUILTIN_RULES, *_discover_plugin_rules()]


# Back-compat alias used by mcpverity.engine at import time.
ALL_RULES = BUILTIN_RULES

__all__ = ["ParsedServer", "Rule", "BUILTIN_RULES", "ALL_RULES", "all_rules"]
