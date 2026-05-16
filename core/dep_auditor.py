"""
Dependency vulnerability auditor.
Calls pip-audit and npm-audit as subprocesses, then enriches
each CVE with CVSS scores from the NVD REST API.
"""

import subprocess
import json
import time
import sqlite3
import os
from dataclasses import dataclass, field
from typing import List, Optional, Dict
from pathlib import Path
import requests
from rich.console import Console

console = Console()

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_RATE_LIMIT = 0.6   # seconds between requests (no API key = 5/sec max)

# ── Cache ──────────────────────────────────────────────────────────────────

_DB_PATH = Path(__file__).parent.parent / 'db' / 'nvd_cache.sqlite'


def _get_cache_db():
    _DB_PATH.parent.mkdir(exist_ok=True)
    conn = sqlite3.connect(str(_DB_PATH))
    conn.execute(
        "CREATE TABLE IF NOT EXISTS nvd_cache "
        "(cve_id TEXT PRIMARY KEY, data TEXT, fetched_at REAL)"
    )
    conn.commit()
    return conn


def _cache_get(conn, cve_id: str) -> Optional[dict]:
    row = conn.execute(
        "SELECT data FROM nvd_cache WHERE cve_id=?", (cve_id,)
    ).fetchone()
    if row:
        try:
            return json.loads(row[0])
        except Exception:
            return None
    return None


def _cache_set(conn, cve_id: str, data: dict):
    conn.execute(
        "INSERT OR REPLACE INTO nvd_cache(cve_id, data, fetched_at) VALUES(?,?,?)",
        (cve_id, json.dumps(data), time.time())
    )
    conn.commit()


# ── NVD enrichment ─────────────────────────────────────────────────────────

def fetch_nvd_data(cve_id: str, conn, api_key: Optional[str] = None) -> Dict:
    """Fetch CVE details from NVD API (with SQLite caching)."""
    cached = _cache_get(conn, cve_id)
    if cached:
        return cached

    headers = {}
    if api_key:
        headers['apiKey'] = api_key

    try:
        resp = requests.get(
            NVD_API, params={"cveId": cve_id}, headers=headers, timeout=15
        )
        time.sleep(NVD_RATE_LIMIT)
        if resp.status_code == 200:
            items = resp.json().get('vulnerabilities', [])
            if items:
                cve_data = items[0].get('cve', {})
                metrics = cve_data.get('metrics', {})
                cvss_data = (
                    metrics.get('cvssMetricV31', [{}])[0]
                    or metrics.get('cvssMetricV30', [{}])[0]
                    or {}
                )
                cvss = cvss_data.get('cvssData', {})
                result = {
                    "cve_id": cve_id,
                    "base_score": cvss.get('baseScore', 0.0),
                    "severity": cvss.get('baseSeverity', 'UNKNOWN'),
                    "attack_vector": cvss.get('attackVector', 'UNKNOWN'),
                    "privileges_required": cvss.get('privilegesRequired', 'UNKNOWN'),
                    "description": next(
                        (d['value'] for d in cve_data.get('descriptions', [])
                         if d.get('lang') == 'en'), ''
                    ),
                    "references": [
                        r['url'] for r in cve_data.get('references', [])[:5]
                    ],
                }
                _cache_set(conn, cve_id, result)
                return result
    except Exception:
        pass

    return {"cve_id": cve_id, "base_score": 0.0, "severity": "UNKNOWN"}


# ── Finding dataclass ───────────────────────────────────────────────────────

@dataclass
class DepFinding:
    rule_id: str
    package_name: str
    installed_version: str
    fixed_version: str
    cve_id: str
    severity: str
    description: str
    ecosystem: str          # 'python' or 'node'
    file_path: str
    base_score: float = 0.0
    attack_vector: str = "UNKNOWN"
    references: List[str] = field(default_factory=list)
    finding_type: str = "dependency"
    risk_score: float = 0.0
    fix_suggestion: str = ""


# ── pip-audit ───────────────────────────────────────────────────────────────

def run_pip_audit(repo_dir: str, requirements_files: List[str]) -> List[dict]:
    """Run pip-audit against each requirements file found in the repo."""
    raw_findings = []
    for req_file in requirements_files:
        try:
            result = subprocess.run(
                ['pip-audit', '--requirement', req_file, '--format', 'json', '--progress-spinner', 'off'],
                capture_output=True, text=True, timeout=120, cwd=repo_dir
            )
            raw = result.stdout.strip() or result.stderr.strip()
            if raw:
                try:
                    data = json.loads(raw)
                    for dep in data.get('dependencies', []):
                        for vuln in dep.get('vulns', []):
                            raw_findings.append({
                                'package': dep.get('name', ''),
                                'version': dep.get('version', ''),
                                'cve_id': vuln.get('id', ''),
                                'fix_versions': vuln.get('fix_versions', []),
                                'description': vuln.get('description', ''),
                                'file_path': req_file,
                                'ecosystem': 'python',
                            })
                except json.JSONDecodeError:
                    pass
        except FileNotFoundError:
            console.print("[dim]  ℹ pip-audit not found — skipping Python dep audit[/]")
            break
        except subprocess.TimeoutExpired:
            console.print("[yellow]  ⚠ pip-audit timed out[/]")
    return raw_findings


# ── npm audit ───────────────────────────────────────────────────────────────

def run_npm_audit(repo_dir: str, package_json_files: List[str]) -> List[dict]:
    """Run npm audit in directories containing package.json."""
    raw_findings = []
    for pkg_file in package_json_files:
        pkg_dir = str(Path(pkg_file).parent)
        try:
            result = subprocess.run(
                ['npm', 'audit', '--json'],
                capture_output=True, text=True, timeout=120, cwd=pkg_dir
            )
            raw = result.stdout.strip()
            if not raw:
                continue
            try:
                data = json.loads(raw)
                vulns = data.get('vulnerabilities', {})
                for pkg_name, vuln_data in vulns.items():
                    for via in vuln_data.get('via', []):
                        if not isinstance(via, dict):
                            continue
                        raw_findings.append({
                            'package': pkg_name,
                            'version': vuln_data.get('range', ''),
                            'cve_id': via.get('cve', [None])[0] if isinstance(via.get('cve'), list) else '',
                            'fix_versions': [str(vuln_data.get('fixAvailable', ''))] if vuln_data.get('fixAvailable') else [],
                            'description': via.get('title', ''),
                            'file_path': pkg_file,
                            'ecosystem': 'node',
                        })
            except json.JSONDecodeError:
                pass
        except FileNotFoundError:
            console.print("[dim]  ℹ npm not found — skipping Node dep audit[/]")
            break
        except subprocess.TimeoutExpired:
            console.print("[yellow]  ⚠ npm audit timed out[/]")
    return raw_findings


# ── Main entry point ────────────────────────────────────────────────────────

def scan_dependencies(repo_files, tmp_dir: str, nvd_api_key: Optional[str] = None) -> List[DepFinding]:
    """Run dependency audit across Python and Node ecosystems."""
    console.print("[bold]  [yellow]🔍[/] Running dependency vulnerability scanner…[/]")

    req_files, pkg_files = [], []
    for f in repo_files:
        full = os.path.join(tmp_dir, f.path)
        fname = Path(f.path).name
        if fname == 'requirements.txt':
            req_files.append(full)
        elif fname == 'package.json' and 'node_modules' not in f.path:
            pkg_files.append(full)

    raw = run_pip_audit(tmp_dir, req_files) + run_npm_audit(tmp_dir, pkg_files)

    if not raw:
        console.print("  [green]✓[/] No dependency manifests found or no audit tools available.")
        return []

    conn = _get_cache_db()
    findings: List[DepFinding] = []
    seen = set()

    for item in raw:
        cve_id = item.get('cve_id', '') or f"NO-CVE-{item['package']}"
        key = (cve_id, item['package'])
        if key in seen:
            continue
        seen.add(key)

        nvd = fetch_nvd_data(cve_id, conn, nvd_api_key) if cve_id.startswith('CVE-') else {}
        severity = nvd.get('severity') or 'MEDIUM'
        fix_vers = item.get('fix_versions', [])
        fix_str = fix_vers[0] if fix_vers else 'N/A'

        pkg = item['package']
        eco = item['ecosystem']
        eco_fix = f"{pkg}=={fix_str}" if eco == 'python' else f"{pkg}@{fix_str}"

        findings.append(DepFinding(
            rule_id=f"DEP-{cve_id}",
            package_name=pkg,
            installed_version=item.get('version', '?'),
            fixed_version=fix_str,
            cve_id=cve_id,
            severity=severity.upper() if severity else 'MEDIUM',
            description=nvd.get('description') or item.get('description', ''),
            ecosystem=eco,
            file_path=item.get('file_path', ''),
            base_score=nvd.get('base_score', 0.0),
            attack_vector=nvd.get('attack_vector', 'UNKNOWN'),
            references=nvd.get('references', []),
            fix_suggestion=f"Upgrade to: {eco_fix}" if fix_str != 'N/A' else "No fix available yet.",
        ))

    conn.close()
    console.print(
        f"  [green]✓[/] Dependency scan complete — "
        f"[bold]{len(findings)}[/] CVE(s) found"
    )
    return findings
