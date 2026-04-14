import json
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
EMPTY_EXCEPTIONS = REPO_ROOT / "tests" / "empty_exceptions.yaml"
RULE_IDS = [
    "AZU-STOR-001",
    "AZU-STOR-002",
    "AZU-STOR-003",
    "AZU-NSG-001",
    "AZU-NSG-002",
    "AZU-RBAC-001",
]


def run_scan(target: Path) -> dict:
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "cloudrax_guard.main",
            "scan",
            str(target),
            "--format",
            "json",
            "--dry-run",
            "--exceptions",
            str(EMPTY_EXCEPTIONS),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(result.stdout)


def finding_ids(scan_output: dict) -> set[str]:
    return {finding["rule_id"] for finding in scan_output["findings"]}


def test_fail_fixtures_trigger_target_rule():
    for rule_id in RULE_IDS:
        fixture_dir = REPO_ROOT / "testdata" / "policies" / rule_id / "fail"
        output = run_scan(fixture_dir)
        assert rule_id in finding_ids(output), f"{rule_id} was not detected in fail fixtures"


def test_pass_fixtures_do_not_trigger_target_rule():
    for rule_id in RULE_IDS:
        fixture_dir = REPO_ROOT / "testdata" / "policies" / rule_id / "pass"
        output = run_scan(fixture_dir)
        assert rule_id not in finding_ids(output), f"{rule_id} was unexpectedly detected in pass fixtures"
