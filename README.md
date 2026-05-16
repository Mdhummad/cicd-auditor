# 🔐 CI/CD Pipeline Security Audit Tool

A Python-based **DevSecOps** tool that scans GitHub repositories for:

- 🔑 **Hardcoded secrets** — Custom regex engine (15 patterns) + optional Trufflehog integration
- ⚙️ **CI/CD misconfigurations** — 7 built-in YAML rules covering known CVEs + optional Semgrep
- 📦 **Vulnerable dependencies** — pip-audit & npm audit with NVD API CVSS enrichment

Outputs **SARIF 2.1** (GitHub Advanced Security compatible) and a **rich HTML dashboard**.

---

## Features

| Feature | Description |
|---|---|
| Secret detection | 15 custom regex patterns for AWS keys, GitHub tokens, JWTs, Slack, Google, DB strings, etc. |
| Script injection | Detects `${{ github.event.pull_request.title }}` in `run:` blocks (GHSA-3jfq-742w-xg8j) |
| Privilege escalation | Detects `pull_request_target` + checkout of fork head (CVE-2022-39046) |
| Token overprivilege | Flags `permissions: write-all` in workflows |
| Cache poisoning | Detects `actions/cache` without `hashFiles()` in key |
| Unpinned actions | Flags actions pinned to tags/branches instead of SHAs |
| NVD enrichment | Fetches CVSS v3.1 scores, attack vectors, and advisory links |
| Risk scoring | CVSS-inspired scorer: exploitability + blast radius + trigger context |
| SARIF output | GitHub Advanced Security / VS Code / SIEM compatible |
| HTML dashboard | Severity charts, filterable table, copy-to-clipboard fixes |
| Scan history | SQLite database tracking findings across scans |
| GitHub Action | Packaged as a reusable action (action.yml + Dockerfile) |

---

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Optional: full feature set
pip install trufflehog3 semgrep pip-audit

# Run a scan
python audit.py https://github.com/owner/repo

# Custom output directory + fail threshold
python audit.py https://github.com/owner/repo \
  --output-dir ./reports \
  --fail-on-severity HIGH
```

---

## CLI Options

```
Usage: audit.py [OPTIONS] REPO_URL

Options:
  -o, --output-dir PATH           Report output directory [default: ./reports]
  -f, --fail-on-severity LEVEL    Exit 1 if findings at/above this level
                                  [CRITICAL|HIGH|MEDIUM|LOW] [default: HIGH]
  --nvd-api-key TEXT              NVD API key (or set NVD_API_KEY env var)
  --no-history                    Skip saving to SQLite history database
  --sarif-only                    Only produce SARIF output
  --skip-secrets                  Skip secret detection scanner
  --skip-misconfigs               Skip misconfiguration scanner
  --skip-deps                     Skip dependency vulnerability scanner
  --help                          Show this message and exit.
```

---

## Project Structure

```
cicd-auditor/
├── audit.py                     # Main CLI entrypoint
├── action.yml                   # GitHub Action definition
├── Dockerfile                   # Container for GitHub Action
├── requirements.txt
│
├── core/
│   ├── ingestion.py             # Repo cloning + file extraction
│   ├── secret_scanner.py        # Custom regex engine + Trufflehog
│   ├── misconfig_scanner.py     # YAML analysis + Semgrep
│   └── dep_auditor.py           # pip-audit + npm audit + NVD API
│
├── intelligence/
│   ├── risk_scorer.py           # CVSS-style scoring formula
│   └── history.py               # SQLite scan history manager
│
├── output/
│   ├── sarif_builder.py         # SARIF 2.1 JSON generator
│   ├── html_reporter.py         # HTML report renderer
│   └── templates/
│       └── report.html.j2       # Jinja2 HTML template
│
├── rules/
│   ├── semgrep/                 # Custom Semgrep rule files
│   │   └── github-actions-security.yml
│   └── regex_patterns.py        # Secret regex patterns
│
└── db/
    └── schema.sql               # SQLite schema
```

---

## Risk Scoring

Each finding receives a 0–10 score:

| Factor | Points | Criteria |
|---|---|---|
| Exploitability | 0–4 | Severity level + confidence |
| Blast radius | 0–3 | Number of affected workflows |
| Trigger context | 0–3 | `pull_request` > `push` > `schedule` |

| Score | Severity |
|---|---|
| 9.0–10.0 | 🔴 CRITICAL |
| 7.0–8.9 | 🟠 HIGH |
| 4.0–6.9 | 🟡 MEDIUM |
| 0.0–3.9 | 🟢 LOW |

---

## Use as a GitHub Action

```yaml
# .github/workflows/security.yml
name: Security Audit
on: [pull_request]

permissions:
  contents: read
  security-events: write

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608
      - uses: your-username/cicd-auditor@v1
        with:
          fail_on_severity: HIGH
      - uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: ./reports/
```

---

## Security Concepts Demonstrated

- **CVSS v3.1** scoring methodology
- **GHSA-3jfq-742w-xg8j** — GitHub Actions script injection
- **CVE-2022-39046** — `pull_request_target` privilege escalation
- **OWASP Top 10 CI/CD Security Risks**
- **SARIF 2.1** specification
- **SLSA** supply chain security framework
- **Shift-left** security mindset

---


