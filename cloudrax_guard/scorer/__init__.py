from typing import List
from cloudrax_guard.models import Finding, ScanResult


SEVERITY_WEIGHTS = {
    "critical": 20,
    "medium": 8,
    "low": 3
}

GRADE_BANDS = [
    (90, "Strong 💚"),
    (75, "Acceptable 🟡"),
    (50, "Risky 🟠"),
    (0,  "High Risk 🔴")
]


def calculate_score(findings: List[Finding]) -> int:
    """Start at 100, subtract points per finding severity."""
    score = 100
    for finding in findings:
        weight = SEVERITY_WEIGHTS.get(finding.severity.lower(), 0)
        score -= weight
    return max(0, score)  # clamp at 0


def get_grade(score: int) -> str:
    """Return human readable grade for score."""
    for threshold, grade in GRADE_BANDS:
        if score >= threshold:
            return grade
    return "High Risk 🔴"


def make_decision(
    findings: List[Finding],
    score: int,
    dry_run: bool = False,
    fail_on: List[str] = ["critical"],
    minimum_score: int = 75
) -> bool:
    """
    Decide pass or fail.
    dry_run → always pass.
    fail if critical exists or score below threshold.
    """
    if dry_run:
        return True

    severities = [f.severity.lower() for f in findings]
    for severity in fail_on:
        if severity in severities:
            return False

    if score < minimum_score:
        return False

    return True


def score_scan(
    findings: List[Finding],
    files_scanned: int,
    resources_analyzed: int,
    suppressed,
    dry_run: bool = False
) -> ScanResult:
    """Build complete ScanResult with score and pass/fail decision."""
    from cloudrax_guard.models import ScanResult

    score = calculate_score(findings)
    passed = make_decision(findings, score, dry_run)

    return ScanResult(
        files_scanned=files_scanned,
        resources_analyzed=resources_analyzed,
        findings=findings,
        suppressed=suppressed,
        score=score,
        passed=passed
    )