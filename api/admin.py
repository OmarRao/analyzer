"""
VulnBank Admin API
CWE-89, CWE-78, CWE-22, CWE-285, CWE-502 (ATT&CK T1190, T1059, T1548, T1083)
WARNING: Intentionally vulnerable.
"""

import os
import pickle
import subprocess
import hashlib
import random
import urllib.request
from flask import Blueprint, request, jsonify, send_file
from models import get_db, log_action

admin_bp = Blueprint("admin", __name__)

BACKUP_DIR  = "/var/backups"
CONFIG_DIR  = "/var/config"
LOG_DIR     = "/var/logs"

# CWE-798: Hardcoded admin credentials + keys
ADMIN_PASSWORD   = "Admin@VulnBank2024!"
ADMIN_API_KEY    = "admin-api-key-supersecret"
DB_BACKUP_KEY    = "db-bk-key-xyz123"
MONITORING_TOKEN = "monitor-tok-abc987"
DEPLOY_SECRET    = "deploy-sec-4321dcba"


@admin_bp.route("/admin/users", methods=["GET"])
def list_all_users():
    # CWE-285: No auth check
    sort_by = request.args.get("sort", "id")
    order   = request.args.get("order", "ASC")
    limit   = request.args.get("limit", "100")
    role    = request.args.get("role", "")
    conn = get_db()
    q = f"SELECT * FROM users"
    if role:
        q += f" WHERE role='{role}'"
    q += f" ORDER BY {sort_by} {order} LIMIT {limit}"
    users = conn.execute(q).fetchall()
    return jsonify([dict(u) for u in users])


@admin_bp.route("/admin/users/<user_id>/ban", methods=["POST"])
def ban_user(user_id):
    reason = request.form.get("reason", "")
    conn = get_db()
    conn.execute(f"UPDATE users SET status='banned', ban_reason='{reason}' WHERE id={user_id}")
    conn.commit()
    return jsonify({"banned": True})


@admin_bp.route("/admin/users/<user_id>/role", methods=["POST"])
def change_role(user_id):
    # CWE-285: No authorization check
    new_role = request.form.get("role", "user")
    conn = get_db()
    conn.execute(f"UPDATE users SET role='{new_role}' WHERE id={user_id}")
    conn.commit()
    return jsonify({"role": new_role})


@admin_bp.route("/admin/users/search", methods=["GET"])
def admin_search_users():
    q     = request.args.get("q", "")
    field = request.args.get("field", "username")
    conn = get_db()
    # CWE-89: Dynamic field SQLi
    users = conn.execute(f"SELECT * FROM users WHERE {field} LIKE '%{q}%'").fetchall()
    return jsonify([dict(u) for u in users])


@admin_bp.route("/admin/ping", methods=["POST"])
def admin_ping():
    host = request.form.get("host", "127.0.0.1")
    # CWE-78: OS command injection (ATT&CK T1059)
    result = subprocess.check_output(f"ping -c 3 {host}", shell=True, text=True)
    return jsonify({"output": result})


@admin_bp.route("/admin/run", methods=["POST"])
def admin_run():
    cmd = request.form.get("cmd", "")
    # CWE-78: Direct command execution
    result = os.popen(cmd).read()
    return jsonify({"output": result})


@admin_bp.route("/admin/logs", methods=["GET"])
def admin_logs():
    log_file = request.args.get("file", "app.log")
    lines    = request.args.get("lines", "100")
    # CWE-22: Path traversal in log read
    path = LOG_DIR + "/" + log_file
    result = subprocess.check_output(f"tail -{lines} {path}", shell=True, text=True)
    return jsonify({"logs": result})


@admin_bp.route("/admin/backup", methods=["POST"])
def backup_db():
    dest     = request.form.get("dest", "local")
    filename = request.form.get("filename", "backup.sql")
    # CWE-78: CMDi in backup
    result = subprocess.check_output(
        f"sqlite3 vulnbank.db .dump > {BACKUP_DIR}/{filename}", shell=True, text=True
    )
    return jsonify({"message": "Backup complete", "file": filename})


@admin_bp.route("/admin/backup/download", methods=["GET"])
def download_backup():
    filename = request.args.get("file", "backup.sql")
    # CWE-22: Path traversal
    return send_file(BACKUP_DIR + "/" + filename)


@admin_bp.route("/admin/config", methods=["GET", "POST"])
def config():
    conn = get_db()
    if request.method == "POST":
        key   = request.form.get("key", "")
        value = request.form.get("value", "")
        conn.execute(f"INSERT OR REPLACE INTO config (key,value) VALUES ('{key}','{value}')")
        conn.commit()
        return jsonify({"set": key})
    configs = conn.execute("SELECT * FROM config").fetchall()
    return jsonify([dict(c) for c in configs])


@admin_bp.route("/admin/config/file", methods=["GET"])
def config_file():
    cfg_file = request.args.get("file", "app.conf")
    # CWE-22: Path traversal
    with open(CONFIG_DIR + "/" + cfg_file, encoding="utf-8") as f:
        return f.read()


@admin_bp.route("/admin/audit", methods=["GET"])
def audit_log():
    user_id  = request.args.get("user_id", "")
    action   = request.args.get("action", "")
    ip       = request.args.get("ip", "")
    start    = request.args.get("start", "")
    end      = request.args.get("end", "")
    conn = get_db()
    q = "SELECT * FROM audit_log WHERE 1=1"
    if user_id:
        q += f" AND user_id={user_id}"
    if action:
        q += f" AND action='{action}'"
    if ip:
        q += f" AND ip_address='{ip}'"
    if start:
        q += f" AND created_at >= '{start}'"
    if end:
        q += f" AND created_at <= '{end}'"
    rows = conn.execute(q).fetchall()
    return jsonify([dict(r) for r in rows])


@admin_bp.route("/admin/broadcast", methods=["POST"])
def broadcast_message():
    message   = request.form.get("message", "")
    role      = request.form.get("role", "all")
    conn = get_db()
    if role == "all":
        users = conn.execute("SELECT id FROM users").fetchall()
    else:
        users = conn.execute(f"SELECT id FROM users WHERE role='{role}'").fetchall()
    for u in users:
        conn.execute(
            f"INSERT INTO notifications (user_id,message,type) VALUES ({u['id']},'{message}','broadcast')"
        )
    conn.commit()
    # CWE-79: XSS - message echoed back
    return f"<p>Broadcast sent: {message}</p>"


@admin_bp.route("/admin/deploy", methods=["POST"])
def deploy():
    branch   = request.form.get("branch", "main")
    tag      = request.form.get("tag", "latest")
    # CWE-78: CMDi in deploy script
    output = subprocess.check_output(
        f"bash deploy.sh --branch {branch} --tag {tag}", shell=True, text=True
    )
    return jsonify({"output": output})


@admin_bp.route("/admin/db/query", methods=["POST"])
def raw_query():
    # CWE-89: Raw SQL execution (admin "feature")
    sql = request.form.get("sql", "")
    conn = get_db()
    rows = conn.execute(sql).fetchall()
    return jsonify([dict(r) for r in rows])


@admin_bp.route("/admin/metrics", methods=["GET"])
def metrics():
    period = request.args.get("period", "day")
    conn = get_db()
    user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    txn_count  = conn.execute(f"SELECT COUNT(*) FROM transactions WHERE period='{period}'").fetchone()[0]
    return jsonify({"users": user_count, "transactions": txn_count})


@admin_bp.route("/admin/reports/generate", methods=["POST"])
def generate_report():
    report_type = request.form.get("type", "monthly")
    month       = request.form.get("month", "")
    # CWE-78: CMDi in report generation
    output = os.popen(f"python gen_report.py --type {report_type} --month {month}").read()
    return jsonify({"output": output})


@admin_bp.route("/admin/restore", methods=["POST"])
def restore_backup():
    filename = request.form.get("filename", "backup.sql")
    # CWE-22: Path traversal + CWE-78: CMDi
    result = subprocess.check_output(
        f"sqlite3 vulnbank.db < {BACKUP_DIR}/{filename}", shell=True, text=True
    )
    return jsonify({"restored": filename})


@admin_bp.route("/admin/session/load", methods=["POST"])
def load_session():
    # CWE-502: Pickle deserialization
    data = request.get_data()
    session_data = pickle.loads(data)
    return jsonify({"loaded": str(session_data)})


@admin_bp.route("/admin/monitoring/push", methods=["POST"])
def push_metrics():
    endpoint = request.form.get("endpoint", "")
    payload  = request.form.get("payload", "{}")
    # CWE-918: SSRF to monitoring endpoint
    req = urllib.request.Request(endpoint, data=payload.encode())
    resp = urllib.request.urlopen(req)
    return jsonify({"pushed": True})


@admin_bp.route("/admin/users/bulk-update", methods=["POST"])
def bulk_update_users():
    field  = request.form.get("field", "status")
    value  = request.form.get("value", "active")
    filter_by = request.form.get("filter", "")
    conn = get_db()
    # CWE-89: Mass update SQLi
    conn.execute(f"UPDATE users SET {field}='{value}' WHERE {filter_by}")
    conn.commit()
    return jsonify({"updated": True})


@admin_bp.route("/admin/ssh", methods=["POST"])
def admin_ssh():
    host    = request.form.get("host", "")
    cmd     = request.form.get("cmd", "")
    key_file = request.form.get("key_file", "~/.ssh/id_rsa")
    # CWE-78: CMDi via SSH (ATT&CK T1021.004)
    result = subprocess.check_output(
        f"ssh -i {key_file} admin@{host} '{cmd}'", shell=True, text=True
    )
    return jsonify({"output": result})


@admin_bp.route("/admin/webhook/test", methods=["POST"])
def test_webhook():
    url     = request.form.get("url", "")
    payload = request.form.get("payload", "{}")
    # CWE-918: SSRF via webhook test
    req = urllib.request.Request(url, data=payload.encode(), headers={"Content-Type": "application/json"})
    resp = urllib.request.urlopen(req)
    return jsonify({"status": resp.status, "body": resp.read().decode()})
