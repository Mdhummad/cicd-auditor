FROM python:3.11-slim

LABEL maintainer="cicd-auditor"
LABEL description="CI/CD Security Audit Tool"

# Install system deps (git required for gitpython)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl nodejs npm \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Install optional tools (best-effort)
RUN pip install --no-cache-dir trufflehog3 semgrep pip-audit || true

COPY . /app
WORKDIR /app

ENTRYPOINT ["python", "audit.py"]
