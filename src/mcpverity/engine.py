"""Scanner orchestrator: run all rules against parsed context."""
import time

from .identity import suppression_hash
from .llm_check import run_llm_check_detailed
from .models import SEVERITY_ORDER, Finding, Scan, ScanSummary
from .parsers import extract_tool_descriptions, parse_files
from .rules import ALL_RULES, ParsedServer
from .rules.base import redact_secrets

SEVERITY_WEIGHT = {"CRITICAL": 25, "HIGH": 12, "MEDIUM": 5, "LOW": 2, "INFO": 0}


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen = set()
    out = []
    for f in findings:
        key = (f.rule_id, f.file_path, f.line, f.snippet[:80])
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def summarize_findings(findings: list[Finding]) -> ScanSummary:
    """Compute a ScanSummary (counts, risk score, verdict) from a finding list.

    Public so callers who re-summarize after filtering findings out-of-band
    (e.g. a hosted app applying a newly-created suppression to an existing
    stored scan) get the exact same scoring logic run_scan() uses internally,
    without reaching into a private function.
    """
    s = ScanSummary()
    for f in findings:
        setattr(s, f.severity.lower(), getattr(s, f.severity.lower()) + 1)
    s.total = len(findings)
    score = sum(SEVERITY_WEIGHT[f.severity] for f in findings)
    s.risk_score = min(100, score)
    if s.critical > 0 or s.risk_score >= 50:
        s.verdict = "vulnerable"
    elif s.high > 0 or s.risk_score >= 20:
        s.verdict = "at_risk"
    else:
        s.verdict = "clean"
    return s


# Back-compat alias for internal call sites / anyone who imported the old name.
_summarize = summarize_findings


async def run_scan(
    server_name: str,
    files: list[dict],
    mode: str,
    repo_url: str | None,
    enable_llm_check: bool,
    suppression_hashes: set | None = None,
) -> Scan:
    started = time.time()
    ctx = parse_files(files)
    suppression_hashes = suppression_hashes or set()
    parsed = ParsedServer(files=ctx["files"], manifests=ctx["manifests"])

    findings: list[Finding] = []
    for rule in ALL_RULES:
        try:
            findings.extend(rule.check(parsed))
        except Exception as e:  # noqa: BLE001 -- a broken rule must never crash the scan
            findings.append(Finding(
                rule_id=rule.id + "-ERR",
                title=f"Rule {rule.id} internal error",
                severity="INFO",
                file_path="(engine)",
                line=None,
                message=f"Rule crashed: {e}",
                remediation="Report to mcpverity maintainers.",
                snippet="",
            ))

    llm_count = 0
    error = None
    if enable_llm_check:
        tds = extract_tool_descriptions(ctx)
        llm = await run_llm_check_detailed(tds)
        llm_count = len(llm.findings)
        findings.extend(llm.findings)
        if llm.errors:
            error = (f"LLM check failed for {len(llm.errors)} of {max(llm.attempted, 1)} "
                     f"tool description(s): {'; '.join(llm.errors[:3])}")

    # Rules quote surrounding source in snippets; never let a secret ride
    # along into terminal / JSON / SARIF output.
    for f in findings:
        f.snippet = redact_secrets(f.snippet)
        f.message = redact_secrets(f.message)

    findings = _dedupe(findings)

    # Apply per-server suppressions (caller supplies the hash set; the
    # Suppression model/CRUD itself lives in the hosted app, not here).
    suppressed_count = 0
    if suppression_hashes:
        kept: list[Finding] = []
        for f in findings:
            if suppression_hash(f.rule_id, f.file_path, f.snippet) in suppression_hashes:
                suppressed_count += 1
                continue
            kept.append(f)
        findings = kept

    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.file_path, f.line or 0))

    scan = Scan(
        server_name=server_name,
        mode=mode,
        repo_url=repo_url,
        file_count=len(files),
        files_scanned=[f["path"] for f in files],
        findings=findings,
        summary=_summarize(findings),
        llm_check_enabled=enable_llm_check,
        llm_findings_count=llm_count,
        duration_ms=int((time.time() - started) * 1000),
        status="completed",
        error=error,
    )
    return scan
