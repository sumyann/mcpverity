"""SARIF v2.1.0 export for GitHub Security tab compatibility."""
from typing import Any

from .. import __version__
from ..models import Scan
from ..rules.base import REPO_URL

SEV_TO_SARIF = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "none"}
DOCS_URL = f"{REPO_URL}/blob/main/docs/rules.md"


def scan_to_sarif(scan: Scan) -> dict[str, Any]:
    rules_seen = {}
    results = []
    for f in scan.findings:
        rules_seen.setdefault(f.rule_id, {
            "id": f.rule_id,
            "name": f.title.replace(" ", ""),
            "shortDescription": {"text": f.title},
            "helpUri": f.doc_link or DOCS_URL,
            "defaultConfiguration": {"level": SEV_TO_SARIF[f.severity]},
        })
        results.append({
            "ruleId": f.rule_id,
            "level": SEV_TO_SARIF[f.severity],
            "message": {"text": f.message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file_path},
                    "region": {"startLine": f.line or 1, "snippet": {"text": f.snippet}},
                }
            }],
            "properties": {"severity": f.severity, "remediation": f.remediation, "tags": f.tags, "confidence": f.confidence},
        })
    return {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "MCPVerity",
                    "version": __version__,
                    "informationUri": REPO_URL,
                    "rules": list(rules_seen.values()),
                }
            },
            "results": results,
        }],
    }
