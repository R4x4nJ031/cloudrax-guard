import json
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict, Any

from cloudrax_guard.models import Finding


POLICIES_DIR = Path(__file__).parent.parent.parent / "policies"


def policy_query(policy_path: Path) -> str:
    """Map a policy file path to its OPA query path."""
    policy_group = policy_path.parent.name
    return f"data.cloudrax.{policy_group}.deny"


def run_opa(input_data: Dict[str, Any], policy_path: Path) -> List[Dict[str, Any]]:
    """
    Call OPA binary with normalized input and a policy file.
    Returns raw list of findings from OPA.
    """
    # write input JSON to a temp file so OPA can read it
    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".json",
        delete=False
    ) as tmp:
        json.dump(input_data, tmp)
        tmp_path = tmp.name

    result = subprocess.run(
        [
            "opa", "eval",
            "-i", tmp_path,
            "-d", str(policy_path),
            "--format", "json",
            policy_query(policy_path)
        ],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        raise RuntimeError(f"OPA error: {result.stderr}")

    output = json.loads(result.stdout)

    # extract the actual findings list from OPA's nested response
    try:
        findings = output["result"][0]["expressions"][0]["value"]
        return findings if findings else []
    except (KeyError, IndexError):
        return []


def evaluate_policies(normalized_resources: List[Dict[str, Any]]) -> List[Finding]:
    """
    Run all policies against normalized resources.
    Returns a list of Finding objects.
    """
    input_data = {"resources": normalized_resources}
    raw_findings = []

    # run each policy file
    policy_files = list(POLICIES_DIR.rglob("*.rego"))

    for policy_file in policy_files:
        try:
            results = run_opa(input_data, policy_file)
            raw_findings.extend(results)
        except Exception as e:
            print(f"Warning: policy {policy_file.name} failed: {e}")

    # convert raw dicts into Finding objects
    findings = []
    for raw in raw_findings:
        findings.append(Finding(
            rule_id=raw.get("rule_id", "UNKNOWN"),
            title=raw.get("title", ""),
            severity=raw.get("severity", "medium"),
            resource=raw.get("resource", ""),
            file=raw.get("file", ""),
            message=raw.get("message", ""),
            fix=raw.get("fix", ""),
            compliance=raw.get("compliance", [])
        ))

    return findings
