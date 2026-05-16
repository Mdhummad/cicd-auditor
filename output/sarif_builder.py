"""
SARIF 2.1 report builder.
Generates industry-standard SARIF JSON output compatible with
GitHub Advanced Security / VS Code / enterprise SIEMs.
"""

import json
from typing import List, Union
from datetime import datetime, timezone


def _severity_to_sarif_level(severity: str) -> str:
    mapping = {'CRITICAL': 'error', 'HIGH': 'error', 'MEDIUM': 'warning', 'LOW': 'note'}
    return mapping.get(severity.upper(), 'warning')


def _build_rules(findings) -> list:
    """Build unique rule definitions from all findings."""
    seen = {}
    for f in findings:
        rid = getattr(f, 'rule_id', 'UNKNOWN')
        if rid not in seen:
            name = getattr(f, 'rule_name', rid)
            desc = getattr(f, 'description', '')
            seen[rid] = {
                "id": rid,
                "name": name.replace(' ', ''),
                "shortDescription": {"text": name},
                "fullDescription": {"text": desc},
                "defaultConfiguration": {
                    "level": _severity_to_sarif_level(getattr(f, 'severity', 'MEDIUM'))
                },
                "helpUri": getattr(f, 'cve_reference', None) or
                           f"https://github.com/advisories?query={rid}",
            }
    return list(seen.values())


def _build_results(findings) -> list:
    results = []
    for f in findings:
        rid = getattr(f, 'rule_id', 'UNKNOWN')
        severity = getattr(f, 'severity', 'MEDIUM')
        desc = getattr(f, 'description', 'Finding detected')
        file_path = getattr(f, 'file_path', 'unknown').replace('\\', '/')
        line_no = getattr(f, 'line_number', 1) or 1
        fix = getattr(f, 'fix_suggestion', '')
        score = getattr(f, 'risk_score', 0.0)

        result = {
            "ruleId": rid,
            "level": _severity_to_sarif_level(severity),
            "message": {"text": desc},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": file_path, "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": line_no, "startColumn": 1},
                }
            }],
            "properties": {
                "severity": severity,
                "riskScore": score,
                "findingType": getattr(f, 'finding_type', 'unknown'),
            }
        }
        if fix:
            result["properties"]["fixSuggestion"] = fix

        cve = getattr(f, 'cve_reference', None) or getattr(f, 'cve_id', None)
        if cve:
            result["properties"]["cveReference"] = cve

        results.append(result)
    return results


def build_sarif(findings, repo_url: str, version: str = "1.0.0") -> dict:
    """Build a complete SARIF 2.1 document from a list of findings."""
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "cicd-auditor",
                    "version": version,
                    "informationUri": "https://github.com/cicd-auditor",
                    "rules": _build_rules(findings),
                }
            },
            "originalUriBaseIds": {
                "%SRCROOT%": {"uri": repo_url + "/blob/HEAD/"}
            },
            "results": _build_results(findings),
            "properties": {
                "scannedAt": datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z",
                "repoUrl": repo_url,
                "totalFindings": len(findings),
            }
        }]
    }


def write_sarif(findings, repo_url: str, output_path: str):
    """Write SARIF JSON to a file."""
    sarif = build_sarif(findings, repo_url)
    with open(output_path, 'w', encoding='utf-8') as fh:
        json.dump(sarif, fh, indent=2)
    return output_path

