"""
Web UI for CI/CD Security Audit Tool.
Run with: python app.py
Then open: http://localhost:5000
"""

import os
import sys
import uuid
import subprocess
import threading
import json
from pathlib import Path
from datetime import datetime, timezone
from flask import (
    Flask, render_template, request, Response,
    jsonify, send_from_directory, abort
)

# ── Bootstrap so core/ imports resolve from this directory ──
sys.path.insert(0, str(Path(__file__).parent))

app = Flask(__name__, template_folder="web/templates", static_folder="web/static")
app.config["REPORTS_DIR"] = str(Path(__file__).parent / "reports")

# In-memory store: scan_id -> {status, log_lines, report_html, report_sarif, repo_url, started}
SCANS: dict = {}
SCANS_LOCK = threading.Lock()


# ─────────────────────────────────────────────────────────────────────────────
#  Routes
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Landing page with scan form and history."""
    with SCANS_LOCK:
        history = [
            {**v, "scan_id": k}
            for k, v in sorted(SCANS.items(),
                               key=lambda x: x[1].get("started", ""),
                               reverse=True)
        ]
    return render_template("index.html", history=history)


@app.route("/scan", methods=["POST"])
def start_scan():
    """Start a new audit scan. Returns JSON with scan_id."""
    data = request.get_json(silent=True) or {}
    repo_url = (data.get("repo_url") or "").strip()

    if not repo_url.startswith("https://github.com/"):
        return jsonify({"error": "Please enter a valid https://github.com/... URL"}), 400

    scan_id = str(uuid.uuid4())[:8]
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    skip_secrets   = bool(data.get("skip_secrets"))
    skip_misconfigs = bool(data.get("skip_misconfigs"))
    skip_deps      = bool(data.get("skip_deps"))

    with SCANS_LOCK:
        SCANS[scan_id] = {
            "status": "running",
            "log_lines": [],
            "report_html": None,
            "report_sarif": None,
            "repo_url": repo_url,
            "started": now,
            "findings_summary": None,
            "skip_secrets": skip_secrets,
            "skip_misconfigs": skip_misconfigs,
            "skip_deps": skip_deps,
        }

    thread = threading.Thread(
        target=_run_audit,
        args=(scan_id, repo_url),
        daemon=True,
    )
    thread.start()

    return jsonify({"scan_id": scan_id})


@app.route("/stream/<scan_id>")
def stream(scan_id):
    """Server-Sent Events endpoint — streams live log output to the browser."""
    def generate():
        sent = 0
        import time
        while True:
            with SCANS_LOCK:
                scan = SCANS.get(scan_id)
            if not scan:
                yield f"data: {json.dumps({'type':'error','msg':'Scan not found'})}\n\n"
                return

            lines = scan["log_lines"]
            while sent < len(lines):
                yield f"data: {json.dumps({'type':'log','msg':lines[sent]})}\n\n"
                sent += 1

            if scan["status"] in ("done", "error"):
                payload = {
                    "type": "done",
                    "status": scan["status"],
                    "report_html": scan.get("report_html"),
                    "report_sarif": scan.get("report_sarif"),
                    "summary": scan.get("findings_summary"),
                }
                yield f"data: {json.dumps(payload)}\n\n"
                return

            time.sleep(0.4)

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/status/<scan_id>")
def scan_status(scan_id):
    """Lightweight polling endpoint (fallback for SSE)."""
    with SCANS_LOCK:
        scan = SCANS.get(scan_id)
    if not scan:
        return jsonify({"error": "not found"}), 404
    return jsonify({
        "status": scan["status"],
        "log_count": len(scan["log_lines"]),
        "report_html": scan.get("report_html"),
        "summary": scan.get("findings_summary"),
    })


@app.route("/reports/<path:filename>")
def serve_report(filename):
    """Serve a generated report file."""
    reports_dir = app.config["REPORTS_DIR"]
    return send_from_directory(reports_dir, filename)


@app.route("/view/<scan_id>")
def view_report(scan_id):
    """Redirect to the embedded report viewer page."""
    with SCANS_LOCK:
        scan = SCANS.get(scan_id)
    if not scan or not scan.get("report_html"):
        abort(404)
    return render_template("viewer.html", scan=scan, scan_id=scan_id)


# ─────────────────────────────────────────────────────────────────────────────
#  Background audit runner
# ─────────────────────────────────────────────────────────────────────────────

def _run_audit(scan_id: str, repo_url: str):
    """Run audit.py as a subprocess and stream its output into SCANS."""
    reports_dir = Path(app.config["REPORTS_DIR"])
    reports_dir.mkdir(exist_ok=True)

    with SCANS_LOCK:
        scan = SCANS.get(scan_id, {})

    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUNBUFFERED"] = "1"

    cmd = [
        sys.executable, "audit.py",
        repo_url,
        "--output-dir", str(reports_dir),
        "--fail-on-severity", "CRITICAL",
        "--no-history",
    ]
    if scan.get("skip_secrets"):    cmd.append("--skip-secrets")
    if scan.get("skip_misconfigs"): cmd.append("--skip-misconfigs")
    if scan.get("skip_deps"):       cmd.append("--skip-deps")

    def _log(msg: str):
        clean = msg.rstrip()
        if clean:
            with SCANS_LOCK:
                SCANS[scan_id]["log_lines"].append(clean)

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            cwd=str(Path(__file__).parent),
        )

        for line in proc.stdout:
            _log(line)

        proc.wait()

        # Find the newest HTML and SARIF files in reports/
        html_files = sorted(reports_dir.glob("*.html"), key=lambda f: f.stat().st_mtime, reverse=True)
        sarif_files = sorted(reports_dir.glob("*.sarif"), key=lambda f: f.stat().st_mtime, reverse=True)

        report_html = html_files[0].name if html_files else None
        report_sarif = sarif_files[0].name if sarif_files else None

        # Parse summary from last few log lines
        summary = _parse_summary(SCANS[scan_id]["log_lines"])

        with SCANS_LOCK:
            SCANS[scan_id]["status"] = "done" if proc.returncode in (0, 1) else "error"
            SCANS[scan_id]["report_html"] = report_html
            SCANS[scan_id]["report_sarif"] = report_sarif
            SCANS[scan_id]["findings_summary"] = summary

    except Exception as e:
        with SCANS_LOCK:
            SCANS[scan_id]["status"] = "error"
            SCANS[scan_id]["log_lines"].append(f"[ERROR] {e}")


def _parse_summary(log_lines: list) -> dict:
    """Extract finding counts from the scan completion log line."""
    import re
    for line in reversed(log_lines):
        m = re.search(r'(\d+) critical.*?(\d+) high.*?(\d+) medium.*?(\d+) low', line, re.IGNORECASE)
        if m:
            return {
                "critical": int(m.group(1)),
                "high": int(m.group(2)),
                "medium": int(m.group(3)),
                "low": int(m.group(4)),
            }
    return {"critical": 0, "high": 0, "medium": 0, "low": 0}


if __name__ == "__main__":
    Path("reports").mkdir(exist_ok=True)
    Path("db").mkdir(exist_ok=True)
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_ENV") == "development"
    print(f"\n  CI/CD Audit Web UI running at http://localhost:{port}\n")
    app.run(host="0.0.0.0", port=port, debug=debug, threaded=True)
