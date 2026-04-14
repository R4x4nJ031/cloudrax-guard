import yaml
from datetime import date
from typing import List, Dict, Any
from cloudrax_guard.models import Finding, SuppressedFinding


def load_exceptions(filepath: str) -> List[Dict[str, Any]]:
    """Load exceptions from YAML file."""
    try:
        with open(filepath, "r") as f:
            data = yaml.safe_load(f)
            return data.get("exceptions", [])
    except FileNotFoundError:
        return []


def apply_exceptions(
    findings: List[Finding],
    exceptions_file: str
) -> tuple[List[Finding], List[SuppressedFinding]]:
    """
    Check each finding against exceptions.
    Active exceptions → move to suppressed list.
    Expired exceptions → keep as finding, print warning.
    """
    exceptions = load_exceptions(exceptions_file)
    active_findings = []
    suppressed = []

    for finding in findings:
        matched = False

        for exc in exceptions:
            rule_match = exc.get("rule_id") == finding.rule_id
            resource_match = exc.get("resource") == finding.resource

            if rule_match and resource_match:
                expires_on = date.fromisoformat(str(exc.get("expires_on")))

                if expires_on >= date.today():
                    # active exception — suppress this finding
                    suppressed.append(SuppressedFinding(
                        rule_id=finding.rule_id,
                        resource=finding.resource,
                        reason=exc.get("reason", ""),
                        approved_by=exc.get("approved_by", ""),
                        expires_on=expires_on
                    ))
                    matched = True
                else:
                    # expired exception — warn but keep finding
                    print(f"WARNING: Exception for {finding.rule_id} on {finding.resource} expired on {expires_on}")

                break

        if not matched:
            active_findings.append(finding)

    return active_findings, suppressed