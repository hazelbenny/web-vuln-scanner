"""Flask app: check/verify a target, run scans in the background, view and export reports."""
import json
import threading
import time
from collections import Counter

from flask import Flask, Response, jsonify, render_template, request, abort

import db
from scanner import verification
from scanner.core import Scanner
from scanner.safety import check_target

app = Flask(__name__)
db.init()
SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}


def resolve_target():
    """Validate the posted URL. Returns (url, host, verified, loopback) or raises ValueError."""
    url, host, loopback = check_target((request.get_json(silent=True) or {}).get("url", ""))
    return url, host, verification.is_verified(url, host, loopback), loopback


def run_scan(scan_id, url, full):
    db.update(scan_id, status="running")
    try:
        findings, pages = Scanner(url, full, log=lambda m: db.append_log(scan_id, m)).run()
        db.update(scan_id, status="done", findings=json.dumps(findings), pages=pages,
                  finding_count=len(findings), finished=time.time())
    except Exception as e:  # keep the app alive whatever the target does
        db.append_log(scan_id, f"Scan failed: {e}")
        db.update(scan_id, status="error", finished=time.time())


@app.get("/")
def index():
    return render_template("index.html", scans=db.recent())


@app.post("/api/check")
def api_check():
    try:
        url, host, verified, loopback = resolve_target()
    except ValueError as e:
        return jsonify(error=str(e)), 400
    return jsonify(url=url, host=host, verified=verified, loopback=loopback,
                   token=verification.token_for(host), verify_path=verification.VERIFY_PATH)


@app.post("/api/scan")
def api_scan():
    try:
        url, host, verified, _ = resolve_target()
    except ValueError as e:
        return jsonify(error=str(e)), 400
    mode = "full" if verified else "passive"
    scan_id = db.create(url, mode)
    threading.Thread(target=run_scan, args=(scan_id, url, verified), daemon=True).start()
    return jsonify(id=scan_id, mode=mode)


@app.get("/api/scan/<int:scan_id>")
def api_scan_status(scan_id):
    scan = db.get(scan_id) or abort(404)
    return jsonify(status=scan["status"], log=scan["log"], finding_count=scan["finding_count"])


@app.get("/api/scan/<int:scan_id>/export")
def api_export(scan_id):
    scan = db.get(scan_id) or abort(404)
    return Response(json.dumps(scan, indent=2), mimetype="application/json",
                    headers={"Content-Disposition": f"attachment; filename=scan-{scan_id}.json"})


@app.get("/report/<int:scan_id>")
def report(scan_id):
    scan = db.get(scan_id) or abort(404)
    findings = sorted(scan["findings"], key=lambda f: SEVERITY_ORDER[f["severity"]])
    counts = Counter(f["severity"] for f in findings)
    return render_template("report.html", scan=scan, findings=findings, counts=counts)


if __name__ == "__main__":
    app.run(port=5000, debug=False)  # never enable debug mode: its console allows remote code execution