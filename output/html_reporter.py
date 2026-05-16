"""
HTML report renderer using Jinja2.
"""

from pathlib import Path
from datetime import datetime, timezone
from typing import List
from jinja2 import Environment, FileSystemLoader


TEMPLATE_DIR = Path(__file__).parent / 'templates'


def _count_by_severity(findings) -> dict:
    counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for f in findings:
        sev = getattr(f, 'severity', 'LOW').upper()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _count_by_type(findings) -> dict:
    counts = {'secret': 0, 'misconfig': 0, 'dependency': 0}
    for f in findings:
        t = getattr(f, 'finding_type', 'unknown')
        counts[t] = counts.get(t, 0) + 1
    return counts


def render_html_report(
    findings,
    repo_url: str,
    output_path: str,
    history: list = None,
) -> str:
    """
    Render the full HTML report and write it to output_path.

    Args:
        findings:    List of all scored findings.
        repo_url:    The scanned repository URL.
        output_path: Destination .html file path.
        history:     Optional list of previous scan dicts for trend chart.

    Returns:
        Absolute path to the written file.
    """
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=False,
    )
    env.filters['tojson'] = __import__('json').dumps

    template = env.get_template('report.html.j2')

    repo_name = repo_url.rstrip('/').split('/')[-1]
    scanned_at = datetime.now(timezone.utc).replace(tzinfo=None).strftime('%Y-%m-%d %H:%M:%S')

    html = template.render(
        repo_url=repo_url,
        repo_name=repo_name,
        scanned_at=scanned_at,
        findings=findings,
        total=len(findings),
        counts=_count_by_severity(findings),
        type_counts=_count_by_type(findings),
        history=history or [],
    )

    with open(output_path, 'w', encoding='utf-8') as fh:
        fh.write(html)

    return str(Path(output_path).resolve())

