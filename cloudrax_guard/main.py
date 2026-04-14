import sys
import click
from cloudrax_guard.parser import parse_directory
from cloudrax_guard.normalizer import normalize_resources
from cloudrax_guard.policy import evaluate_policies
from cloudrax_guard.exceptions import apply_exceptions
from cloudrax_guard.scorer import score_scan
from cloudrax_guard.reporter import render_terminal


@click.group()
def cli():
    """CloudRax Guard — Azure IaC Security Scanner"""
    pass


@cli.command()
@click.argument("directory")
@click.option("--exceptions", "exceptions_file", default="exceptions.yaml", help="Path to exceptions file")
@click.option("--dry-run", is_flag=True, default=False, help="Run without failing pipeline")
@click.option("--format", "output_format", default="table", type=click.Choice(["table", "json"]), help="Output format")
def scan(directory, exceptions_file, dry_run, output_format):
    """Scan a directory of Terraform files for security misconfigurations."""

    # step 1 — parse
    try:
        files, raw = parse_directory(directory)
    except Exception as e:
        click.echo(f"Error reading files: {e}", err=True)
        sys.exit(2)

    if not files:
        click.echo(f"No Terraform files found in {directory}")
        sys.exit(0)

    # step 2 — normalize
    normalized = normalize_resources(raw)

    # step 3 — evaluate policies
    findings = evaluate_policies(normalized)

    # step 4 — apply exceptions
    active, suppressed = apply_exceptions(findings, exceptions_file)

    # step 5 — score
    result = score_scan(
        findings=active,
        files_scanned=len(files),
        resources_analyzed=len(normalized),
        suppressed=suppressed,
        dry_run=dry_run
    )

    # step 6 — render
    if output_format == "json":
        import json
        import dataclasses
        click.echo(json.dumps(dataclasses.asdict(result), indent=2, default=str))
    else:
        render_terminal(result, dry_run=dry_run)

    # step 7 — exit code
    if not result.passed:
        sys.exit(1)
    sys.exit(0)


@cli.command()
def list_rules():
    """List all implemented rules."""
    rules = [
        ("AZU-STOR-001", "critical", "Public blob access enabled"),
        ("AZU-STOR-002", "medium",   "Public network access enabled on storage account"),
        ("AZU-STOR-003", "medium",   "Weak TLS version on storage account"),
        ("AZU-NSG-001", "critical", "SSH open to the internet"),
        ("AZU-NSG-002", "critical", "RDP open to the internet"),
        ("AZU-RBAC-001", "medium", "Owner role assignment detected"),
    ]

    click.echo("\nCloudRax Guard — Implemented Rules\n")
    for rule_id, severity, title in rules:
        click.echo(f"  {rule_id}  [{severity.upper()}]  {title}")
    click.echo()


if __name__ == "__main__":
    cli()
