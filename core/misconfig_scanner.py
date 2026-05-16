"""
Misconfiguration scanner for GitHub Actions and CI/CD workflows.
Pure-Python YAML analysis + optional Semgrep subprocess.
"""

import re
import subprocess
import json
from dataclasses import dataclass, field
from typing import List, Optional, Dict
from pathlib import Path
import yaml
from rich.console import Console

console = Console()


@dataclass
class MisconfigFinding:
    rule_id: str
    rule_name: str
    file_path: str
    line_number: int
    severity: str
    description: str
    detail: str = ""
    source: str = "yaml_analysis"
    finding_type: str = "misconfig"
    cve_reference: Optional[str] = None
    risk_score: float = 0.0
    fix_suggestion: str = ""
    affected_triggers: List[str] = field(default_factory=list)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _find_line(content: str, search_str: str) -> int:
    for i, line in enumerate(content.splitlines(), start=1):
        if search_str in line:
            return i
    return 1


def _get_triggers(workflow: Dict) -> List[str]:
    on = workflow.get('on', workflow.get(True, {}))
    if isinstance(on, str):
        return [on]
    if isinstance(on, list):
        return on
    if isinstance(on, dict):
        return list(on.keys())
    return []


# ── YAML analysis rules ───────────────────────────────────────────────────────

def check_script_injection(workflow, file, content) -> List[MisconfigFinding]:
    """CICD-001: Detect script injection via untrusted GitHub context expressions."""
    findings = []
    DANGEROUS = [
        'github.event.pull_request.title', 'github.event.pull_request.body',
        'github.event.pull_request.head.ref', 'github.event.issue.title',
        'github.event.issue.body', 'github.event.comment.body',
        'github.head_ref',
    ]
    jobs = workflow.get('jobs', {})
    for job_name, job in (jobs.items() if isinstance(jobs, dict) else []):
        steps = job.get('steps', []) if isinstance(job, dict) else []
        for step in (steps or []):
            if not isinstance(step, dict):
                continue
            run_block = step.get('run', '')
            if not isinstance(run_block, str):
                continue
            for ctx in DANGEROUS:
                if ctx in run_block:
                    findings.append(MisconfigFinding(
                        rule_id='CICD-001',
                        rule_name='Script Injection via GitHub Context',
                        file_path=file.path,
                        line_number=_find_line(content, ctx),
                        severity='CRITICAL',
                        description=(
                            f"Script injection via `${{{{ {ctx} }}}}` in job `{job_name}`. "
                            "Attackers control this value and can inject shell commands."
                        ),
                        detail=f"Dangerous context: {ctx}",
                        cve_reference='GHSA-3jfq-742w-xg8j',
                        fix_suggestion=(
                            "Pass the value via an environment variable instead:\n"
                            "  env:\n"
                            f"    SAFE_VAL: ${{{{ toJSON({ctx}) }}}}\n"
                            "Then reference $SAFE_VAL in the run block."
                        ),
                        affected_triggers=_get_triggers(workflow),
                    ))
    return findings


def check_prt_checkout(workflow, file, content) -> List[MisconfigFinding]:
    """CICD-002: pull_request_target + checkout of PR head."""
    findings = []
    triggers = _get_triggers(workflow)
    if 'pull_request_target' not in triggers:
        return findings
    jobs = workflow.get('jobs', {})
    for job_name, job in (jobs.items() if isinstance(jobs, dict) else []):
        steps = job.get('steps', []) if isinstance(job, dict) else []
        for step in (steps or []):
            if not isinstance(step, dict):
                continue
            uses = step.get('uses', '')
            with_block = step.get('with', {}) or {}
            if 'actions/checkout' in str(uses):
                ref = str(with_block.get('ref', ''))
                if 'head' in ref or 'pull_request' in ref:
                    findings.append(MisconfigFinding(
                        rule_id='CICD-002',
                        rule_name='Privilege Escalation: pull_request_target + checkout',
                        file_path=file.path,
                        line_number=_find_line(content, 'pull_request_target'),
                        severity='CRITICAL',
                        description=(
                            f"Workflow uses `pull_request_target` AND checks out "
                            f"PR head code (ref=`{ref}`). "
                            "This gives untrusted fork code access to repository secrets."
                        ),
                        cve_reference='CVE-2022-39046',
                        fix_suggestion=(
                            "Remove the explicit `ref:` to check out the base branch only, OR\n"
                            "switch the trigger to `pull_request` (no write access to secrets)."
                        ),
                        affected_triggers=triggers,
                    ))
    return findings


def check_write_all_permissions(workflow, file, content) -> List[MisconfigFinding]:
    """CICD-003: write-all or overly broad GITHUB_TOKEN permissions."""
    findings = []

    def _check(perms_obj, context_label):
        if perms_obj == 'write-all':
            findings.append(MisconfigFinding(
                rule_id='CICD-003',
                rule_name='Overprivileged GITHUB_TOKEN (write-all)',
                file_path=file.path,
                line_number=_find_line(content, 'write-all'),
                severity='HIGH',
                description=f"GITHUB_TOKEN set to `write-all` in {context_label}.",
                fix_suggestion=(
                    "Use minimal permissions:\n"
                    "  permissions:\n"
                    "    contents: read\n"
                    "    pull-requests: write  # only if needed"
                ),
                affected_triggers=_get_triggers(workflow),
            ))
        elif isinstance(perms_obj, dict):
            write_perms = [k for k, v in perms_obj.items() if v == 'write']
            if len(write_perms) > 3:
                findings.append(MisconfigFinding(
                    rule_id='CICD-003',
                    rule_name='Overprivileged GITHUB_TOKEN (broad writes)',
                    file_path=file.path,
                    line_number=_find_line(content, 'permissions'),
                    severity='MEDIUM',
                    description=(
                        f"GITHUB_TOKEN has write access to {len(write_perms)} scopes "
                        f"in {context_label}: {', '.join(write_perms)}."
                    ),
                    fix_suggestion="Limit write permissions to only those scopes actually needed.",
                    affected_triggers=_get_triggers(workflow),
                ))

    _check(workflow.get('permissions'), 'workflow level')
    for job_name, job in (workflow.get('jobs', {}).items() if isinstance(workflow.get('jobs'), dict) else []):
        if isinstance(job, dict):
            _check(job.get('permissions'), f'job `{job_name}`')
    return findings


def check_unpinned_actions(workflow, file, content) -> List[MisconfigFinding]:
    """CICD-004: Actions pinned to branch/tag instead of SHA."""
    findings = []
    for job_name, job in (workflow.get('jobs', {}).items() if isinstance(workflow.get('jobs'), dict) else []):
        for step in (job.get('steps', []) if isinstance(job, dict) else []):
            if not isinstance(step, dict):
                continue
            uses = step.get('uses', '')
            if not uses or '@' not in uses:
                continue
            action, ref = uses.rsplit('@', 1)
            is_sha = bool(re.match(r'^[0-9a-f]{7,40}$', ref, re.IGNORECASE))
            if not is_sha:
                sev = 'HIGH' if ref in ('main', 'master', 'latest') else 'MEDIUM'
                findings.append(MisconfigFinding(
                    rule_id='CICD-004',
                    rule_name='Unpinned GitHub Action Version',
                    file_path=file.path,
                    line_number=_find_line(content, uses),
                    severity=sev,
                    description=(
                        f"Action `{action}` pinned to `{ref}` (mutable tag/branch). "
                        "Supply chain attack possible if that action repo is compromised."
                    ),
                    detail=f"uses: {uses}",
                    fix_suggestion=(
                        f"Pin to a full commit SHA:\n"
                        f"  uses: {action}@<40-char-SHA>  # {ref}\n"
                        f"Find SHA: https://github.com/{action}/commits"
                    ),
                    affected_triggers=_get_triggers(workflow),
                ))
    return findings


def check_cache_no_hash(workflow, file, content) -> List[MisconfigFinding]:
    """CICD-005: actions/cache without hashFiles in key."""
    findings = []
    for job_name, job in (workflow.get('jobs', {}).items() if isinstance(workflow.get('jobs'), dict) else []):
        for step in (job.get('steps', []) if isinstance(job, dict) else []):
            if not isinstance(step, dict):
                continue
            if 'actions/cache' not in str(step.get('uses', '')):
                continue
            key = str((step.get('with') or {}).get('key', ''))
            if 'hashFiles' not in key:
                findings.append(MisconfigFinding(
                    rule_id='CICD-005',
                    rule_name='Cache Poisoning Risk (no hashFiles)',
                    file_path=file.path,
                    line_number=_find_line(content, 'actions/cache'),
                    severity='HIGH',
                    description=(
                        "Cache key doesn't include hashFiles(). "
                        "Attacker can poison the cache with malicious artifacts."
                    ),
                    fix_suggestion=(
                        "Include hashFiles() in the cache key:\n"
                        "  key: ${{ runner.os }}-deps-${{ hashFiles('**/package-lock.json') }}"
                    ),
                    affected_triggers=_get_triggers(workflow),
                ))
    return findings


def check_unsafe_commands(workflow, file, content) -> List[MisconfigFinding]:
    """CICD-006: ACTIONS_ALLOW_UNSECURE_COMMANDS=true."""
    findings = []
    if 'ACTIONS_ALLOW_UNSECURE_COMMANDS' in content and 'true' in content:
        findings.append(MisconfigFinding(
            rule_id='CICD-006',
            rule_name='Unsafe Commands Enabled',
            file_path=file.path,
            line_number=_find_line(content, 'ACTIONS_ALLOW_UNSECURE_COMMANDS'),
            severity='HIGH',
            description=(
                "ACTIONS_ALLOW_UNSECURE_COMMANDS=true enables deprecated set-env "
                "and add-path commands, allowing environment injection."
            ),
            fix_suggestion=(
                "Remove ACTIONS_ALLOW_UNSECURE_COMMANDS. "
                "Use $GITHUB_ENV and $GITHUB_PATH files instead."
            ),
        ))
    return findings


def check_hardcoded_env_secrets(workflow, file, content) -> List[MisconfigFinding]:
    """CICD-007: Hardcoded secrets in env: blocks."""
    findings = []
    PATTERN = re.compile(
        r'(?i)(password|passwd|secret|token|api_key|apikey|private_key)\s*:\s*([^\$\{\}\s][^\n]{4,})',
        re.MULTILINE
    )
    for m in PATTERN.finditer(content):
        value = m.group(2).strip()
        if '${{' in value or value.startswith('$'):
            continue
        findings.append(MisconfigFinding(
            rule_id='CICD-007',
            rule_name='Potential Hardcoded Secret in Workflow env: Block',
            file_path=file.path,
            line_number=_find_line(content, m.group(0)[:30]),
            severity='HIGH',
            description=(
                f"env: block contains what looks like a hardcoded credential "
                f"(`{m.group(1)}`). Should reference secrets context."
            ),
            fix_suggestion=(
                "Replace hardcoded value with a repository secret:\n"
                "  env:\n"
                "    MY_SECRET: ${{ secrets.MY_SECRET }}"
            ),
            affected_triggers=_get_triggers(workflow),
        ))
    return findings


# ── Semgrep runner ────────────────────────────────────────────────────────────

def run_semgrep(tmp_dir: str) -> List[MisconfigFinding]:
    findings = []
    rules_dir = Path(__file__).parent.parent / 'rules' / 'semgrep'
    cmds = [['semgrep', '--config', 'p/github-actions', '--json', '--quiet', tmp_dir]]
    if rules_dir.exists():
        cmds.append(['semgrep', '--config', str(rules_dir), '--json', '--quiet', tmp_dir])
    for cmd in cmds:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            raw = result.stdout.strip()
            if not raw:
                continue
            data = json.loads(raw)
            for item in data.get('results', []):
                path = item.get('path', 'unknown')
                try:
                    path = str(Path(path).relative_to(tmp_dir))
                except ValueError:
                    pass
                findings.append(MisconfigFinding(
                    rule_id='SG-' + item.get('check_id', 'UNKNOWN').replace('.', '-'),
                    rule_name=item.get('check_id', 'Semgrep Finding'),
                    file_path=path,
                    line_number=item.get('start', {}).get('line', 1),
                    severity=item.get('extra', {}).get('severity', 'MEDIUM').upper(),
                    description=item.get('extra', {}).get('message', 'Semgrep rule match'),
                    source='semgrep',
                ))
        except FileNotFoundError:
            console.print("[dim]  ℹ semgrep not found — using built-in YAML analysis only[/]")
            break
        except (subprocess.TimeoutExpired, json.JSONDecodeError):
            pass
    return findings


# ── Main entry point ──────────────────────────────────────────────────────────

YAML_RULES = [
    check_script_injection,
    check_prt_checkout,
    check_write_all_permissions,
    check_unpinned_actions,
    check_cache_no_hash,
    check_unsafe_commands,
    check_hardcoded_env_secrets,
]


def scan_misconfigs(repo_files, tmp_dir: str) -> List[MisconfigFinding]:
    """Main entry point for the misconfiguration scanner."""
    console.print("[bold]  [yellow]🔍[/] Running misconfiguration scanner…[/]")
    findings: List[MisconfigFinding] = []

    for repo_file in repo_files:
        if not repo_file.path.endswith(('.yml', '.yaml')):
            continue
        try:
            workflow = yaml.safe_load(repo_file.content) or {}
        except yaml.YAMLError:
            continue
        if not isinstance(workflow, dict):
            continue
        for rule_fn in YAML_RULES:
            try:
                findings.extend(rule_fn(workflow, repo_file, repo_file.content))
            except Exception:
                pass

    findings.extend(run_semgrep(tmp_dir))
    console.print(
        f"  [green]✓[/] Misconfiguration scan complete — "
        f"[bold]{len(findings)}[/] finding(s)"
    )
    return findings
