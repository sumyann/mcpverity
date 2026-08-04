"""MCPVerity — MCP Security Scanner data models.

This schema is the contract between the scan engine and anything that
consumes its output (the CLI's JSON/SARIF export, a hosted UI, CI tooling).
Keep it stable — changing field names or types here is a breaking change for
every consumer.
"""
from datetime import datetime, timezone
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, Field

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    rule_id: str
    title: str
    severity: Severity
    file_path: str
    line: int | None = None
    snippet: str = ""
    message: str
    remediation: str
    doc_link: str = ""
    tags: list[str] = Field(default_factory=list)
    confidence: float = 1.0  # 0.0-1.0, higher = more likely a true positive


class ScanInputFile(BaseModel):
    path: str
    content: str


class ScanCreateRequest(BaseModel):
    mode: Literal["paste", "github"]
    server_name: str = "Untitled MCP Server"
    files: list[ScanInputFile] | None = None
    repo_url: str | None = None
    enable_llm_check: bool = False


class ScanSummary(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    total: int = 0
    risk_score: int = 0  # 0-100
    verdict: str = "clean"  # clean | at_risk | vulnerable


class Scan(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    server_name: str
    mode: str
    repo_url: str | None = None
    file_count: int = 0
    files_scanned: list[str] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    summary: ScanSummary = Field(default_factory=ScanSummary)
    llm_check_enabled: bool = False
    llm_findings_count: int = 0
    duration_ms: int = 0
    status: Literal["running", "completed", "failed"] = "completed"
    error: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class RuleInfo(BaseModel):
    id: str
    title: str
    severity_default: Severity
    description: str
    doc_link: str = ""
