"""
Secret detection scanner.
Two-layer approach:
  1. Custom regex engine against all extracted files.
  2. (Optional) trufflehog3 subprocess call if installed.
"""

import re
import subprocess
import json
from dataclasses import dataclass, field
from typing import List, Optional
from pathlib import Path
from rich.console import Console

# Import from sibling package using relative-safe approach
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from rules.regex_patterns import SECRET_PATTERNS, HIGH_RISK_FILES, SCANNABLE_EXTENSIONS

console = Console()

# Extensions / filenames to NEVER scan for secrets (binary, lock files, etc.)
SKIP_SECRET_SCAN = {
    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff',
    '.woff2', '.ttf', '.eot', '.mp4', '.mp3', '.pdf', '.zip',
    '.tar', '.gz', '.lock',  # lock files often have hashes that look like secrets
}

# Allowlist patterns — skip these even if they match a secret pattern
ALLOWLIST_PATTERNS = [
    re.compile(r'^\s*#'),                            # commented-out lines
    re.compile(r'\$\{\{?\s*secrets\.'),              # GitHub secrets reference
    re.compile(r'\$\{\{?\s*env\.'),                  # Environment variable reference
    re.compile(r'<your[_\-]?[a-z_]+>'),              # Placeholder values
    re.compile(r'example|placeholder|dummy|fake|test|sample', re.IGNORECASE),
]


@dataclass
class SecretFinding:
    """A single secret detection result."""
    rule_id: str
    rule_name: str
    file_path: str
    line_number: int
    line_content: str           # The full line (secrets REDACTED)
    masked_value: str           # First 4 chars + *** 
    severity: str
    description: str
    source: str = "regex"       # 'regex' or 'trufflehog'
    confidence: str = "HIGH"
    finding_type: str = "secret"
    cve_reference: Optional[str] = None
    risk_score: float = 0.0
    fix_suggestion: str = ""


def _mask_secret(match_str: str) -> str:
    """Return first 4 chars followed by *** for safe display."""
    if len(match_str) <= 4:
        return '***'
    return match_str[:4] + '***'


def _redact_line(line: str, match_str: str) -> str:
    """Replace the matched secret in the line with [REDACTED]."""
    return line.replace(match_str, '[REDACTED]')


def _is_allowlisted(line: str) -> bool:
    """Return True if the line is obviously a placeholder / comment."""
    for pat in ALLOWLIST_PATTERNS:
        if pat.search(line):
            return True
    return False


def _should_scan_file(file_path: str, filename: str, ext: str) -> bool:
    """Decide whether a file is worth scanning for secrets."""
    if ext in SKIP_SECRET_SCAN:
        return False
    if ext in SCANNABLE_EXTENSIONS:
        return True
    if filename.startswith('.env') or filename in HIGH_RISK_FILES:
        return True
    return False


def run_regex_scanner(repo_files) -> List[SecretFinding]:
    """
    Scan all repo files with the custom regex engine.

    Args:
        repo_files: List[RepoFile] from the ingestion module.

    Returns:
        List of SecretFinding objects.
    """
    findings: List[SecretFinding] = []

    for repo_file in repo_files:
        filename = Path(repo_file.path).name
        ext = Path(repo_file.path).suffix.lower()

        if not _should_scan_file(repo_file.path, filename, ext):
            continue

        lines = repo_file.content.splitlines()

        for line_no, line in enumerate(lines, start=1):
            if _is_allowlisted(line):
                continue

            for pattern_def in SECRET_PATTERNS:
                matches = pattern_def['pattern'].findall(line)
                if not matches:
                    continue

                # findall may return groups — flatten to strings
                for match in matches:
                    if isinstance(match, tuple):
                        match = next((m for m in match if m), '')
                    if not match:
                        continue

                    masked = _mask_secret(match)
                    redacted_line = _redact_line(line.strip(), match)

                    finding = SecretFinding(
                        rule_id=pattern_def['id'],
                        rule_name=pattern_def['name'],
                        file_path=repo_file.path,
                        line_number=line_no,
                        line_content=redacted_line,
                        masked_value=masked,
                        severity=pattern_def['severity'],
                        description=pattern_def['description'],
                        source='regex',
                        confidence='HIGH' if filename.startswith('.env') or filename in HIGH_RISK_FILES else 'MEDIUM',
                        cve_reference=pattern_def.get('cve_reference'),
                    )
                    findings.append(finding)

    return findings


def run_trufflehog(tmp_dir: str) -> List[SecretFinding]:
    """
    Run trufflehog3 as a subprocess and parse its JSON output.
    Returns empty list if trufflehog3 is not installed.
    """
    findings: List[SecretFinding] = []

    try:
        result = subprocess.run(
            ['trufflehog3', '--format', 'json', '--no-history', tmp_dir],
            capture_output=True, text=True, timeout=120
        )
        raw = result.stdout.strip()
        if not raw:
            return findings

        for line in raw.splitlines():
            try:
                item = json.loads(line)
                finding = SecretFinding(
                    rule_id='TH-' + item.get('rule', {}).get('id', 'UNKNOWN'),
                    rule_name=item.get('rule', {}).get('name', 'Trufflehog Detection'),
                    file_path=item.get('path', 'unknown'),
                    line_number=item.get('line', 0),
                    line_content='[see trufflehog output]',
                    masked_value=_mask_secret(item.get('match', '')[:8]),
                    severity='HIGH',
                    description=item.get('rule', {}).get('message', 'Secret detected by trufflehog'),
                    source='trufflehog',
                    confidence='HIGH',
                )
                findings.append(finding)
            except (json.JSONDecodeError, KeyError):
                continue

    except FileNotFoundError:
        console.print("[dim]  ℹ trufflehog3 not found — skipping (regex engine active)[/]")
    except subprocess.TimeoutExpired:
        console.print("[yellow]  ⚠ trufflehog3 timed out[/]")

    return findings


def deduplicate_findings(findings: List[SecretFinding]) -> List[SecretFinding]:
    """Remove duplicate findings by (rule_id, file_path, line_number)."""
    seen = set()
    unique = []
    for f in findings:
        key = (f.rule_id, f.file_path, f.line_number)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def scan_secrets(repo_files, tmp_dir: str) -> List[SecretFinding]:
    """
    Main entry point for the secret scanner.
    Runs both the regex engine and trufflehog, then deduplicates.
    """
    console.print("[bold]  [yellow]🔍[/] Running secret detection scanner…[/]")

    regex_findings = run_regex_scanner(repo_files)
    trufflehog_findings = run_trufflehog(tmp_dir)

    all_findings = deduplicate_findings(regex_findings + trufflehog_findings)

    console.print(
        f"  [green]✓[/] Secret scan complete — "
        f"[bold]{len(all_findings)}[/] finding(s) "
        f"([dim]{len(regex_findings)} regex / {len(trufflehog_findings)} trufflehog[/])"
    )
    return all_findings
