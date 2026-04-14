from dataclasses import dataclass, field
from typing import List, Optional
from datetime import date


@dataclass
class Finding:
    """A single policy violation found during scanning."""
    rule_id: str
    title: str
    severity: str          # critical, medium, low
    resource: str          # e.g. azurerm_storage_account.appdata
    file: str              # e.g. infra/storage.tf
    message: str           # what went wrong
    fix: str               # how to fix it
    compliance: List[str] = field(default_factory=list)  # e.g. ["CIS Azure 3.1"]


@dataclass
class SuppressedFinding:
    """A finding that was silenced by an approved exception."""
    rule_id: str
    resource: str
    reason: str
    approved_by: str
    expires_on: date


@dataclass
class ScanResult:
    """The complete output of one scan run."""
    files_scanned: int
    resources_analyzed: int
    findings: List[Finding] = field(default_factory=list)
    suppressed: List[SuppressedFinding] = field(default_factory=list)
    score: int = 100
    passed: bool = True
