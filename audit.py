"""
cicd-auditor -- Main CLI entrypoint.

Usage:
    python audit.py https://github.com/owner/repo
    python audit.py https://github.com/owner/repo --output-dir ./reports
    python audit.py https://github.com/owner/repo --fail-on-severity HIGH
"""

import os
import sys

# Force UTF-8 output on Windows so Rich can render box-drawing chars
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

import click
from pathlib import Path
from datetime import datetime, timezone
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

# â”€â”€ Bootstrap path so core/ imports work regardless of cwd â”€â”€
sys.path.insert(0, str(Path(__file__).parent))

from core.ingestion import clone_and_extract
from core.secret_scanner import scan_secrets
from core.misconfig_scanner import scan_misconfigs
from core.dep_auditor import scan_dependencies
from intelligence.risk_scorer import score_all
from intelligence.history import save_scan, get_scan_history
from output.sarif_builder import write_sarif
from output.html_reporter import render_html_report

console = Console()

BANNER = """
[bold cyan]
  ####  ###   ####  ####      #   #  #  ###  ###  ###  ###  ###
 ##    #  #  ##    ##  #     # # # # #  #  # #  #  #  #  # ##
 ##    ####  ##    ##  #     #  #  # #  #  # ###   #  ##  # ###
  ####  ##   ####  ####      #     # #  ###  #  #  #  #  # ##
[/bold cyan][dim]  Secure CI/CD Pipeline Audit Tool  |  DevSecOps  |  v1.0.0[/dim]
"""

SEVERITY_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}


def _sev_color(sev: str) -> str:
    return {'CRITICAL': 'red', 'HIGH': 'yellow', 'MEDIUM': 'bright_yellow', 'LOW': 'green'}.get(sev, 'white')


def _print_summary_table(findings):
    """Print a rich terminal summary of all findings."""
    if not findings:
        console.print("\n[bold green]>> No findings detected![/]")
        return

    table = Table(
        title=f"\n[bold]Findings Summary ({len(findings)} total)[/]",
        box=box.ROUNDED,
        show_lines=False,
        style="dim",
        header_style="bold cyan",
        expand=True,
    )
    table.add_column("Severity", width=10, justify="center")
    table.add_column("Score", width=6, justify="right")
    table.add_column("Type", width=12)
    table.add_column("Rule", width=14)
    table.add_column("File", no_wrap=False, ratio=2)
    table.add_column("Description", ratio=3)

    for f in findings[:50]:   # Cap at 50 rows in terminal
        sev = getattr(f, 'severity', 'MEDIUM')
        score = getattr(f, 'risk_score', 0.0)
        ftype = getattr(f, 'finding_type', '?')
        rule = getattr(f, 'rule_id', '?')
        path = getattr(f, 'file_path', '?')
        desc = getattr(f, 'description', '')[:80]

        table.add_row(
            f"[{_sev_color(sev)}]{sev}[/{_sev_color(sev)}]",
            f"[bold]{score:.1f}[/]",
            ftype,
            rule,
            f"[dim]{path}[/dim]",
            desc,
        )

    console.print(table)

    if len(findings) > 50:
        console.print(f"[dim]  ... and {len(findings) - 50} more findings. See the HTML report.[/dim]")


def _should_fail(findings, fail_severity: str) -> bool:
    """Return True if any finding is at or above the fail threshold."""
    threshold = SEVERITY_ORDER.get(fail_severity.upper(), 1)
    for f in findings:
        if SEVERITY_ORDER.get(getattr(f, 'severity', 'LOW'), 3) <= threshold:
            return True
    return False


@click.command()
@click.argument('repo_url')
@click.option('--output-dir', '-o', default='./reports', show_default=True,
              help='Directory to write SARIF and HTML reports.')
@click.option('--fail-on-severity', '-f', default='HIGH', show_default=True,
              type=click.Choice(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'], case_sensitive=False),
              help='Exit with code 1 if any finding is at or above this severity.')
@click.option('--nvd-api-key', envvar='NVD_API_KEY', default=None,
              help='NVD API key for higher rate limits (or set NVD_API_KEY env var).')
@click.option('--no-history', is_flag=True, default=False,
              help='Do not save this scan to the history database.')
@click.option('--sarif-only', is_flag=True, default=False,
              help='Only produce SARIF output (skip HTML report).')
@click.option('--skip-secrets', is_flag=True, default=False,
              help='Skip the secret detection scanner.')
@click.option('--skip-misconfigs', is_flag=True, default=False,
              help='Skip the misconfiguration scanner.')
@click.option('--skip-deps', is_flag=True, default=False,
              help='Skip the dependency vulnerability scanner.')
def main(
    repo_url, output_dir, fail_on_severity, nvd_api_key,
    no_history, sarif_only, skip_secrets, skip_misconfigs, skip_deps
):
    """
    \b
    CI/CD Security Audit Tool
    -------------------------
    Scans a GitHub repository for:
      - Hardcoded secrets (custom regex engine)
      - CI/CD misconfigurations (YAML analysis + Semgrep)
      - Vulnerable dependencies (pip-audit / npm audit + NVD)

    Outputs: SARIF 2.1 JSON + rich HTML report.
    """
    console.print(BANNER)

    # Phase 1: Clone & ingest
    console.print(Panel.fit("[bold]Phase 1 - Repository Ingestion[/]", style="cyan"))
    repo = clone_and_extract(repo_url)

    if repo.clone_error:
        console.print(f"[bold red]X Cannot continue - clone failed.[/]")
        sys.exit(2)

    console.print(f"  Extracted [bold]{len(repo.files)}[/] files "
                  f"([dim]{len(repo.workflow_files)} workflows, "
                  f"{len(repo.env_files)} env files, "
                  f"{len(repo.dockerfiles)} Dockerfiles[/])")

    # Phase 2: Run scanners
    console.print(Panel.fit("[bold]Phase 2 - Security Scanners[/]", style="cyan"))

    all_findings = []

    if not skip_secrets:
        all_findings += scan_secrets(repo.files, repo.tmp_dir)

    if not skip_misconfigs:
        all_findings += scan_misconfigs(repo.files, repo.tmp_dir)

    if not skip_deps:
        all_findings += scan_dependencies(repo.files, repo.tmp_dir, nvd_api_key)

    # Phase 3: Risk scoring
    console.print(Panel.fit("[bold]Phase 3 - Risk Scoring[/]", style="cyan"))
    scored = score_all(all_findings)
    console.print(f"  [green]âœ“[/] Scored {len(scored)} findings")

    _print_summary_table(scored)

    # Phase 4: Output
    console.print(Panel.fit("[bold]Phase 4 - Report Generation[/]", style="cyan"))

    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).replace(tzinfo=None).strftime('%Y%m%d_%H%M%S')
    repo_slug = repo.repo_name.replace('/', '_')

    sarif_path = out_dir / f"audit_{repo_slug}_{timestamp}.sarif"
    write_sarif(scored, repo_url, str(sarif_path))
    console.print(f"  [green]OK[/] SARIF report -> [cyan]{sarif_path}[/]")

    if not sarif_only:
        html_path = out_dir / f"audit_{repo_slug}_{timestamp}.html"
        history = get_scan_history(repo_url) if not no_history else []
        render_html_report(scored, repo_url, str(html_path), history)
        console.print(f"  [green]OK[/] HTML report  -> [cyan]{html_path}[/]")

    # Phase 5: Save to history
    if not no_history:
        scan_id = save_scan(repo_url, scored)
        console.print(f"  [green]OK[/] Scan saved to history (ID: {scan_id})")

    # â”€â”€ 6. Cleanup â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    repo.cleanup()

    # â”€â”€ 7. Exit code â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for f in scored:
        sev = getattr(f, 'severity', 'LOW').upper()
        counts[sev] = counts.get(sev, 0) + 1

    console.print(
        f"\n[bold]Scan complete[/] â€” "
        f"[red]{counts['CRITICAL']} critical[/] Â· "
        f"[yellow]{counts['HIGH']} high[/] Â· "
        f"[bright_yellow]{counts['MEDIUM']} medium[/] Â· "
        f"[green]{counts['LOW']} low[/]"
    )

    if _should_fail(scored, fail_on_severity):
        console.print(
            f"\n[bold red]FAIL: findings at or above {fail_on_severity} threshold detected.[/]"
        )
        repo.cleanup()
        sys.exit(1)
    else:
        console.print(f"\n[bold green]PASS: All findings below {fail_on_severity} threshold.[/]")


if __name__ == '__main__':
    main()

