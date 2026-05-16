"""
Custom regex patterns for secret detection.
Each pattern has: id, name, pattern, severity, description
"""

import re

SECRET_PATTERNS = [
    {
        "id": "SEC001",
        "name": "AWS Access Key ID",
        "pattern": re.compile(r'AKIA[0-9A-Z]{16}'),
        "severity": "CRITICAL",
        "description": "AWS Access Key ID detected. These keys grant programmatic access to AWS services.",
        "cve_reference": None,
    },
    {
        "id": "SEC002",
        "name": "AWS Secret Access Key",
        "pattern": re.compile(r'(?i)aws.{0,20}secret.{0,20}[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?'),
        "severity": "CRITICAL",
        "description": "AWS Secret Access Key detected. Combined with the Access Key ID, this provides full API access.",
        "cve_reference": None,
    },
    {
        "id": "SEC003",
        "name": "GitHub Personal Access Token",
        "pattern": re.compile(r'ghp_[A-Za-z0-9]{36}'),
        "severity": "CRITICAL",
        "description": "GitHub Personal Access Token detected. This token can access GitHub repositories and APIs.",
        "cve_reference": None,
    },
    {
        "id": "SEC004",
        "name": "GitHub OAuth Token",
        "pattern": re.compile(r'gho_[A-Za-z0-9]{36}'),
        "severity": "CRITICAL",
        "description": "GitHub OAuth Token detected.",
        "cve_reference": None,
    },
    {
        "id": "SEC005",
        "name": "GitHub App Token",
        "pattern": re.compile(r'(ghu|ghs|ghr)_[A-Za-z0-9]{36}'),
        "severity": "HIGH",
        "description": "GitHub App Token (user, server, or refresh) detected.",
        "cve_reference": None,
    },
    {
        "id": "SEC006",
        "name": "Generic API Key",
        "pattern": re.compile(r'(?i)["\']?api[_\-]?key["\']?\s*[=:]\s*["\']([A-Za-z0-9_\-]{20,})["\']'),
        "severity": "HIGH",
        "description": "Generic API key assignment detected in source file.",
        "cve_reference": None,
    },
    {
        "id": "SEC007",
        "name": "RSA / EC / DSA Private Key",
        "pattern": re.compile(r'-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----'),
        "severity": "CRITICAL",
        "description": "Private key material found. Exposure enables impersonation or decryption of data.",
        "cve_reference": None,
    },
    {
        "id": "SEC008",
        "name": "JWT Token",
        "pattern": re.compile(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'),
        "severity": "HIGH",
        "description": "JSON Web Token detected. Active JWTs can be replayed for unauthorized session access.",
        "cve_reference": None,
    },
    {
        "id": "SEC009",
        "name": "Slack Token",
        "pattern": re.compile(r'xox[baprs]-[0-9A-Za-z]{10,48}'),
        "severity": "HIGH",
        "description": "Slack API token detected. This can be used to read messages or post on behalf of users.",
        "cve_reference": None,
    },
    {
        "id": "SEC010",
        "name": "Google API Key",
        "pattern": re.compile(r'AIza[0-9A-Za-z_\-]{35}'),
        "severity": "HIGH",
        "description": "Google API Key detected. May allow access to Google Cloud services.",
        "cve_reference": None,
    },
    {
        "id": "SEC011",
        "name": "Stripe Secret Key",
        "pattern": re.compile(r'sk_(live|test)_[0-9a-zA-Z]{24,}'),
        "severity": "CRITICAL",
        "description": "Stripe Secret Key detected. This allows financial transactions via Stripe API.",
        "cve_reference": None,
    },
    {
        "id": "SEC012",
        "name": "Generic Password Assignment",
        "pattern": re.compile(r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\'${}]{8,})["\']'),
        "severity": "MEDIUM",
        "description": "Hardcoded password value detected in source file.",
        "cve_reference": None,
    },
    {
        "id": "SEC013",
        "name": "Database Connection String",
        "pattern": re.compile(r'(?i)(mongodb|postgresql|mysql|redis):\/\/[^\s\'"<>]+:[^\s\'"<>@]+@'),
        "severity": "CRITICAL",
        "description": "Database connection string with embedded credentials detected.",
        "cve_reference": None,
    },
    {
        "id": "SEC014",
        "name": "NPM Auth Token",
        "pattern": re.compile(r'\/\/registry\.npmjs\.org\/:_authToken\s*=\s*[A-Za-z0-9_\-]+'),
        "severity": "HIGH",
        "description": "NPM registry auth token detected. Allows publishing packages to npm.",
        "cve_reference": None,
    },
    {
        "id": "SEC015",
        "name": "Docker Registry Credential",
        "pattern": re.compile(r'(?i)docker.{0,15}(password|token|secret)\s*[=:]\s*["\']([^"\'${}]{8,})["\']'),
        "severity": "HIGH",
        "description": "Docker registry credential detected in workflow or config file.",
        "cve_reference": None,
    },
]

# Files that commonly hold secrets
HIGH_RISK_FILES = [
    '.env', '.env.local', '.env.production', '.env.development',
    '.env.staging', '.env.test', '.env.example',
    'secrets.yml', 'secrets.yaml', 'credentials.json',
    '.npmrc', '.pypirc', 'config.yml', 'config.yaml'
]

# Extensions to always scan for secrets
SCANNABLE_EXTENSIONS = [
    '.yml', '.yaml', '.env', '.json', '.sh', '.bash',
    '.py', '.js', '.ts', '.rb', '.go', '.java', '.tf',
    '.toml', '.ini', '.cfg', '.conf', '.config', '.xml',
    '.properties', '.secrets', '.key', '.pem'
]
