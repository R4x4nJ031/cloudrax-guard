from rich.console import Console
from rich.table import Table
from rich import box
from rich.panel import Panel
from rich.text import Text
from cloudrax_guard.models import ScanResult
from cloudrax_guard.scorer import get_grade

console = Console()

SEVERITY_COLORS = {
    "critical": "bold red",
    "medium": "bold yellow",
    "low": "bold blue"
}


def render_terminal(result: ScanResult, dry_run: bool = False):
    """Render scan results to terminal using rich."""

    # header
    console.print()
    console.print(Panel("[bold cyan]CloudRax Guard — Azure IaC Security Scanner[/bold cyan]", expand=False))
    console.print()

    # summary table
    summary = Table(box=box.SIMPLE, show_header=False)
    summary.add_column("Key", style="bold")
    summary.add_column("Value")

    critical_count = sum(1 for f in result.findings if f.severity.lower() == "critical")
    medium_count = sum(1 for f in result.findings if f.severity.lower() == "medium")
    low_count = sum(1 for f in result.findings if f.severity.lower() == "low")

    summary.add_row("Files scanned", str(result.files_scanned))
    summary.add_row("Resources analyzed", str(result.resources_analyzed))
    summary.add_row("Critical", f"[bold red]{critical_count}[/bold red]")
    summary.add_row("Medium", f"[bold yellow]{medium_count}[/bold yellow]")
    summary.add_row("Low", f"[bold blue]{low_count}[/bold blue]")
    summary.add_row("Score", f"{result.score}/100  {get_grade(result.score)}")

    if dry_run:
        summary.add_row("Result", "[bold yellow]DRY RUN — enforcement disabled[/bold yellow]")
    elif result.passed:
        summary.add_row("Result", "[bold green]PASS ✅[/bold green]")
    else:
        summary.add_row("Result", "[bold red]FAIL ❌[/bold red]")

    console.print(summary)

    # findings
    if result.findings:
        console.print("[bold]Findings[/bold]")
        console.print()
        for f in result.findings:
            color = SEVERITY_COLORS.get(f.severity.lower(), "white")
            console.print(f"  [{color}][{f.severity.upper()}][/{color}] {f.rule_id} — {f.title}")
            console.print(f"  [dim]Resource:[/dim] {f.resource}")
            console.print(f"  [dim]File:[/dim]     {f.file}")
            console.print(f"  [dim]Why:[/dim]      {f.message}")
            console.print(f"  [dim]Fix:[/dim]      {f.fix}")
            console.print()

    # suppressed findings
    if result.suppressed:
        console.print("[bold]Suppressed Findings[/bold]")
        console.print()
        for s in result.suppressed:
            console.print(
                f"  [dim]{s.rule_id} | {s.resource} | "
                f"expires {s.expires_on} | approved by: {s.approved_by}[/dim]"
            )
        console.print()