"""
CVSS-inspired risk scorer.
Assigns 0-10 scores based on exploitability, blast radius, and trigger context.
"""

from dataclasses import dataclass
from typing import Union, List
from core.secret_scanner import SecretFinding
from core.misconfig_scanner import MisconfigFinding
from core.dep_auditor import DepFinding


SEVERITY_BANDS = [
    (9.0, "CRITICAL"),
    (7.0, "HIGH"),
    (4.0, "MEDIUM"),
    (0.0, "LOW"),
]


def _severity_to_band(score: float) -> str:
    for threshold, label in SEVERITY_BANDS:
        if score >= threshold:
            return label
    return "LOW"


def _score_secret(finding: SecretFinding) -> tuple:
    """Score a secret finding. Returns (score, breakdown_dict)."""
    breakdown = {}

    # Exploitability (0-4)
    exp = 0
    if finding.severity == 'CRITICAL':
        exp = 4
    elif finding.severity == 'HIGH':
        exp = 3
    elif finding.severity == 'MEDIUM':
        exp = 2
    else:
        exp = 1
    # Higher confidence = more exploitable
    if finding.confidence == 'HIGH':
        exp = min(4, exp + 0.5)
    breakdown['exploitability'] = exp

    # Blast radius (0-3) — based on file type
    blast = 1.0
    if '.github/workflows' in finding.file_path:
        blast = 3.0   # All CI runs affected
    elif finding.file_path.startswith('.env'):
        blast = 2.5   # Runtime env affected
    elif 'docker' in finding.file_path.lower():
        blast = 2.0
    breakdown['blast_radius'] = blast

    # Trigger context (0-3)
    # Secrets in workflow files triggered on pull_request = worst
    ctx = 1.0
    if '.github/workflows' in finding.file_path:
        ctx = 3.0
    elif '.env' in finding.file_path:
        ctx = 2.5
    breakdown['trigger_context'] = ctx

    score = round(min(10.0, exp + blast + ctx), 1)
    breakdown['total'] = score
    return score, breakdown


def _score_misconfig(finding: MisconfigFinding) -> tuple:
    """Score a misconfiguration finding."""
    breakdown = {}

    # Exploitability (0-4)
    sev_map = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
    exp = sev_map.get(finding.severity, 2)
    breakdown['exploitability'] = exp

    # Blast radius — number of affected triggers / workflows
    num_triggers = len(finding.affected_triggers)
    blast = min(3.0, 1.0 + num_triggers * 0.5)
    breakdown['blast_radius'] = blast

    # Trigger context (0-3)
    ctx = 1.0
    triggers = [t.lower() for t in finding.affected_triggers]
    if 'pull_request' in triggers or 'pull_request_target' in triggers:
        ctx = 3.0   # Public PRs from forks can trigger
    elif 'push' in triggers:
        ctx = 2.0
    elif 'schedule' in triggers or 'workflow_dispatch' in triggers:
        ctx = 1.0
    breakdown['trigger_context'] = ctx

    score = round(min(10.0, exp + blast + ctx), 1)
    breakdown['total'] = score
    return score, breakdown


def _score_dep(finding: DepFinding) -> tuple:
    """Score a dependency vulnerability finding."""
    breakdown = {}

    # Exploitability (0-4) — use NVD base score as proxy
    base = finding.base_score or 0.0
    exp = round(base / 10 * 4, 1)
    if finding.attack_vector == 'NETWORK':
        exp = min(4.0, exp + 0.5)
    breakdown['exploitability'] = exp

    # Blast radius — all workflows that install this dep
    blast = 2.0   # Medium default — affects build environment
    breakdown['blast_radius'] = blast

    # Trigger context — if a dep file is in CI, assume push/PR
    ctx = 2.0
    breakdown['trigger_context'] = ctx

    score = round(min(10.0, exp + blast + ctx), 1)
    breakdown['total'] = score
    return score, breakdown


FindingUnion = Union[SecretFinding, MisconfigFinding, DepFinding]


def score_finding(finding: FindingUnion) -> FindingUnion:
    """Attach a risk_score and updated severity to a finding in-place."""
    if isinstance(finding, SecretFinding):
        score, _ = _score_secret(finding)
    elif isinstance(finding, MisconfigFinding):
        score, _ = _score_misconfig(finding)
    elif isinstance(finding, DepFinding):
        score, _ = _score_dep(finding)
    else:
        score = 5.0

    finding.risk_score = score
    finding.severity = _severity_to_band(score)
    return finding


def score_all(findings: List[FindingUnion]) -> List[FindingUnion]:
    """Score every finding and return sorted by risk score desc."""
    scored = [score_finding(f) for f in findings]
    return sorted(scored, key=lambda f: f.risk_score, reverse=True)
