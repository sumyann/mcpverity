"""MCPVerity benchmark runner.

Loads benchmark/labels.yaml, runs the engine directly against the pinned
fixtures under benchmark/servers/<slug>/files/, and computes per-rule
precision/recall. No network access and no database required -- this is
what makes the benchmark reproducible in CI.

Run:
    python benchmark/run_benchmark.py
"""
import asyncio
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from mcpverity.engine import run_scan  # noqa: E402

HI_CONF = 0.6


def slugify(server_name: str) -> str:
    return server_name.replace("/", "__")


def load_fixture_files(slug: str) -> list:
    files_dir = HERE / "servers" / slug / "files"
    if not files_dir.exists():
        return []
    out = []
    for p in sorted(files_dir.rglob("*")):
        if not p.is_file():
            continue
        rel = str(p.relative_to(files_dir))
        out.append({"path": rel, "content": p.read_text(encoding="utf-8", errors="replace")})
    return out


def _match_expected(finding: dict, expected: dict) -> bool:
    if finding["rule_id"].split("-")[0] != expected["rule"]:
        return False
    needle = expected.get("contains", "").lower()
    if needle:
        hay = " ".join([
            finding.get("message", ""), finding.get("file_path", ""), finding.get("snippet", ""),
        ]).lower()
        return needle in hay
    return True


def _match_fp(finding: dict, fp: dict) -> bool:
    if finding["rule_id"].split("-")[0] != fp["rule"]:
        return False
    pc = fp.get("path_contains", "").lower()
    if pc and pc not in finding.get("file_path", "").lower():
        return False
    return True


async def main():
    labels = yaml.safe_load((HERE / "labels.yaml").read_text())

    per_rule = {}
    per_server = []
    all_findings_seen = 0

    def _bump(rule_id: str, key: str, n: int = 1):
        d = per_rule.setdefault(rule_id, {"tp": 0, "fp": 0, "fn": 0, "tp_hi": 0, "fp_hi": 0})
        d[key] += n

    for entry in labels.get("servers", []):
        name = entry["server_name"]
        slug = slugify(name)
        files = load_fixture_files(slug)
        if not files:
            per_server.append({"server_name": name, "status": "missing_fixture", "tp": 0, "fp": 0, "fn": 0})
            continue

        scan = await run_scan(name, files, mode="benchmark", repo_url=None, enable_llm_check=False)
        findings = [f.model_dump() for f in scan.findings]
        all_findings_seen += len(findings)

        s_tp = 0
        s_fn = 0
        for exp in entry.get("expected", []) or []:
            match = next((f for f in findings if _match_expected(f, exp)), None)
            if match:
                _bump(exp["rule"], "tp")
                if (match.get("confidence") or 1.0) >= HI_CONF:
                    _bump(exp["rule"], "tp_hi")
                s_tp += 1
            else:
                _bump(exp["rule"], "fn")
                s_fn += 1

        s_fp = 0
        for f in findings:
            if any(_match_fp(f, fp) for fp in entry.get("false_positives", []) or []):
                rid = f["rule_id"].split("-")[0]
                _bump(rid, "fp")
                if (f.get("confidence") or 1.0) >= HI_CONF:
                    _bump(rid, "fp_hi")
                s_fp += 1

        per_server.append({
            "server_name": name, "status": "ok",
            "findings_count": len(findings),
            "tp": s_tp, "fp": s_fp, "fn": s_fn,
        })

    rules_out = []
    total_tp = total_fp = total_fn = 0
    total_tp_hi = total_fp_hi = 0
    for rid in sorted(per_rule.keys()):
        d = per_rule[rid]
        tp, fp, fn = d["tp"], d["fp"], d["fn"]
        tp_hi, fp_hi = d["tp_hi"], d["fp_hi"]
        total_tp += tp
        total_fp += fp
        total_fn += fn
        total_tp_hi += tp_hi
        total_fp_hi += fp_hi
        prec = tp / (tp + fp) if (tp + fp) else None
        rec = tp / (tp + fn) if (tp + fn) else None
        prec_hi = tp_hi / (tp_hi + fp_hi) if (tp_hi + fp_hi) else None
        rules_out.append({
            "rule_id": rid, "tp": tp, "fp": fp, "fn": fn,
            "precision": round(prec, 3) if prec is not None else None,
            "recall": round(rec, 3) if rec is not None else None,
            "precision_high_conf": round(prec_hi, 3) if prec_hi is not None else None,
        })
    overall_prec = total_tp / (total_tp + total_fp) if (total_tp + total_fp) else None
    overall_rec = total_tp / (total_tp + total_fn) if (total_tp + total_fn) else None
    overall_prec_hi = total_tp_hi / (total_tp_hi + total_fp_hi) if (total_tp_hi + total_fp_hi) else None

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "servers_labeled": len(labels.get("servers", [])),
        "total_findings_reviewed": all_findings_seen,
        "high_conf_threshold": HI_CONF,
        "totals": {
            "tp": total_tp, "fp": total_fp, "fn": total_fn,
            "precision": round(overall_prec, 3) if overall_prec is not None else None,
            "recall": round(overall_rec, 3) if overall_rec is not None else None,
            "precision_high_conf": round(overall_prec_hi, 3) if overall_prec_hi is not None else None,
        },
        "rules": rules_out,
        "servers": per_server,
        "notes": (
            "Labels are conservative -- 'expected' is what the scanner MUST catch; "
            "'false_positives' is what it MUST NOT emit. `precision` is the raw number "
            "(every emitted finding counts). `precision_high_conf` restricts to findings "
            "with confidence >= 0.6 -- i.e. the ones a reviewer would actually see with "
            "low-confidence findings hidden. Fixtures are pinned snapshots under "
            "benchmark/servers/ -- see benchmark/refresh_fixtures.py to re-pin. "
            "PR corrections at benchmark/labels.yaml."
        ),
    }
    (HERE / "results.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
