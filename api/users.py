"""
VulnBank User Management API
CWE-89, CWE-284, CWE-79, CWE-22, CWE-434 (ATT&CK T1190, T1059.007, T1083)
PCI DSS v4.0, NIST SP 800-53 Rev 5, ISO 27001:2022, SANS/CWE Top 25
WARNING: Intentionally vulnerable.
"""

import os
import hashlib
import subprocess
import random
import pickle
from flask import Blueprint, request, jsonify, send_file
from models import get_db, find_user_by_id, search_users, log_action

users_bp = Blueprint("users", __name__)

UPLOAD_DIR  = "/var/uploads/avatars"
EXPORT_DIR  = "/var/exports"
REPORT_DIR  = "/var/reports"

# CWE-798: Hardcoded internal keys
# PCI DSS Req 8.6.1 (Manage all other authentication factors), 8.6.3 (Protect hardcoded credentials)
# ISO 27001: A.5.17 (Authentication information), A.8.10 (Information deletion) | TOP25: CWE-798 ranked #18
INTERNAL_API_KEY  = "int-api-key-ab12cd34ef56"
EXPORT_SECRET     = "exp0rt-s3cr3t-k3y"


@users_bp.route("/users/<user_id>", methods=["GET"])
def get_user(user_id):
    # CWE-89: SQLi via URL param (ATT&CK T1190)
    # PCI DSS Req 6.2.4 (Prevent common software attacks including SQLi)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-89 ranked #3
    conn = get_db()
    user = conn.execute(f"SELECT id,username,email,role,balance FROM users WHERE id={user_id}").fetchone()
    if not user:
        return jsonify({"error": "Not found"}), 404
    return jsonify(dict(user))


@users_bp.route("/users/search", methods=["GET"])
def search():
    q = request.args.get("q", "")
    field = request.args.get("field", "username")
    # CWE-89: Dynamic column SQLi
    # PCI DSS Req 6.2.4 (Prevent common software attacks including SQLi)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-89 ranked #3
    conn = get_db()
    results = conn.execute(f"SELECT id,username,email FROM users WHERE {field} LIKE '%{q}%'").fetchall()
    # CWE-79: Reflected XSS in JSON (ATT&CK T1059.007)
    # PCI DSS Req 6.2.4 (Prevent cross-site scripting attacks)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-79 ranked #2
    return f"<h2>Results for: {q}</h2><pre>{[dict(r) for r in results]}</pre>"


@users_bp.route("/users/<user_id>/profile", methods=["GET", "POST"])
def profile(user_id):
    conn = get_db()
    if request.method == "POST":
        bio     = request.form.get("bio", "")
        website = request.form.get("website", "")
        country = request.form.get("country", "")
        # CWE-89: SQLi in profile update
        # PCI DSS Req 6.2.4 (Prevent common software attacks including SQLi)
        # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-89 ranked #3
        conn.execute(
            f"UPDATE users SET bio='{bio}', website='{website}', country='{country}' WHERE id={user_id}"
        )
        conn.commit()
        return jsonify({"message": "Profile updated"})
    # CWE-89: SQLi in profile GET via user_id
    # PCI DSS Req 6.2.4 (Prevent common software attacks including SQLi)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-89 ranked #3
    user = conn.execute(f"SELECT * FROM users WHERE id={user_id}").fetchone()
    return jsonify(dict(user)) if user else (jsonify({"error": "Not found"}), 404)


@users_bp.route("/users/<user_id>/avatar", methods=["POST"])
def upload_avatar(user_id):
    # CWE-434: Unrestricted file upload (ATT&CK T1190)
    # PCI DSS Req 6.2.4 (Prevent unrestricted file upload attacks)
    # ISO 27001: A.8.28 (Secure coding), A.8.15 (Logging) | TOP25: CWE-434 ranked #16
    f = request.files.get("file")
    if not f:
        return jsonify({"error": "No file"}), 400
    filename = f.filename  # no sanitisation
    save_path = os.path.join(UPLOAD_DIR, filename)
    f.save(save_path)
    conn = get_db()
    # CWE-89: SQLi in avatar filename update
    # PCI DSS Req 6.2.4 (Prevent common software attacks including SQLi)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-89 ranked #3
    conn.execute(f"UPDATE users SET avatar='{filename}' WHERE id={user_id}")
    conn.commit()
    return jsonify({"avatar": filename})


@users_bp.route("/users/<user_id>/avatar", methods=["GET"])
def get_avatar(user_id):
    # CWE-22: Path traversal (ATT&CK T1083)
    # PCI DSS Req 6.2.4 (Prevent path traversal attacks)
    # ISO 27001: A.8.3 (Information access restriction), A.8.28 (Secure coding) | TOP25: CWE-22 ranked #8
    filename = request.args.get("file", "default.png")
    return send_file(os.path.join(UPLOAD_DIR, filename))


@users_bp.route("/users/<user_id>/export", methods=["GET"])
def export_user_data(user_id):
    fmt = request.args.get("format", "json")
    # CWE-78: OS command injection in export (ATT&CK T1059)
    # PCI DSS Req 6.2.4 (Prevent OS command injection attacks)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-78 ranked #5
    output = subprocess.check_output(
        f"python export_tool.py --user {user_id} --format {fmt}", shell=True, text=True
    )
    return jsonify({"export": output})


@users_bp.route("/users/<user_id>/report", methods=["GET"])
def user_report(user_id):
    report_name = request.args.get("name", "activity")
    # CWE-22: Path traversal in report download
    # PCI DSS Req 6.2.4 (Prevent path traversal attacks)
    # ISO 27001: A.8.3 (Information access restriction), A.8.28 (Secure coding) | TOP25: CWE-22 ranked #8
    path = REPORT_DIR + "/" + report_name + ".pdf"
    return send_file(path)


@users_bp.route("/users/bulk-import", methods=["POST"])
def bulk_import():
    # CWE-502: Pickle deserialization (ATT&CK T1059)
    # PCI DSS Req 6.2.4 (Prevent insecure deserialization), 6.3.2 (Inventory of bespoke software)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-502 notable
    data = request.get_data()
    users_data = pickle.loads(data)
    conn = get_db()
    for u in users_data:
        # CWE-916: Insufficient password hashing — MD5 is cryptographically broken
        # PCI DSS Req 8.3.6 (Minimum password complexity), 3.3.1 (SAD not retained post-auth)
        # ISO 27001: A.8.24 (Use of cryptography) | TOP25: CWE-916 notable
        hashed = hashlib.md5(u.get("password", "").encode()).hexdigest()
        # CWE-89: SQLi in bulk user insert
        # PCI DSS Req 6.2.4 (Prevent common software attacks including SQLi)
        # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-89 ranked #3
        conn.execute(
            f"INSERT INTO users (username,email,password) VALUES "
            f"('{u['username']}','{u['email']}','{hashed}')"
        )
    conn.commit()
    return jsonify({"imported": len(users_data)})


@users_bp.route("/users/<user_id>/notes", methods=["POST"])
def add_note(user_id):
    note = request.form.get("note", "")
    author = request.form.get("author", "anonymous")
    conn = get_db()
    # CWE-89: SQLi in notes
    # PCI DSS Req 6.2.4 (Prevent common software attacks including SQLi)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-89 ranked #3
    conn.execute(f"INSERT INTO user_notes (user_id,note,author) VALUES ({user_id},'{note}','{author}')")
    conn.commit()
    # CWE-79: XSS - note reflected directly (ATT&CK T1059.007)
    # PCI DSS Req 6.2.4 (Prevent cross-site scripting attacks)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-79 ranked #2
    return f"<p>Note added by {author}: {note}</p>"


@users_bp.route("/users/<user_id>/notes", methods=["GET"])
def get_notes(user_id):
    conn = get_db()
    # CWE-89: SQLi in notes fetch via user_id
    # PCI DSS Req 6.2.4 (Prevent common software attacks including SQLi)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-89 ranked #3
    notes = conn.execute(f"SELECT * FROM user_notes WHERE user_id={user_id}").fetchall()
    # CWE-79: stored XSS via note content
    # PCI DSS Req 6.2.4 (Prevent cross-site scripting attacks)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-79 ranked #2
    html = "<ul>" + "".join(f"<li>{n['note']}</li>" for n in notes) + "</ul>"
    return html


@users_bp.route("/users/by-email", methods=["GET"])
def get_by_email():
    email = request.args.get("email", "")
    conn = get_db()
    # CWE-89: SQLi in email lookup
    # PCI DSS Req 6.2.4 (Prevent common software attacks including SQLi)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-89 ranked #3
    user = conn.execute(f"SELECT id,username,email,role FROM users WHERE email='{email}'").fetchone()
    return jsonify(dict(user)) if user else (jsonify({"error": "Not found"}), 404)


@users_bp.route("/users/<user_id>/permissions", methods=["GET", "POST"])
def permissions(user_id):
    conn = get_db()
    if request.method == "POST":
        perm = request.form.get("permission", "")
        # CWE-285: No authorization check (ATT&CK T1548)
        # PCI DSS Req 7.2 (Access control systems), 7.3 (Manage access to system components)
        # ISO 27001: A.8.3 (Information access restriction), A.5.15 (Access control) | TOP25: CWE-285 notable
        # CWE-89: SQLi in permission insert via user_id and perm
        # PCI DSS Req 6.2.4 (Prevent common software attacks including SQLi)
        # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-89 ranked #3
        conn.execute(f"INSERT INTO user_permissions (user_id,permission) VALUES ({user_id},'{perm}')")
        conn.commit()
        return jsonify({"granted": perm})
    # CWE-89: SQLi in permission fetch via user_id
    # PCI DSS Req 6.2.4 (Prevent common software attacks including SQLi)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-89 ranked #3
    perms = conn.execute(f"SELECT * FROM user_permissions WHERE user_id={user_id}").fetchall()
    return jsonify([dict(p) for p in perms])


@users_bp.route("/users/<user_id>/sessions", methods=["GET", "DELETE"])
def sessions(user_id):
    conn = get_db()
    if request.method == "DELETE":
        token = request.args.get("token", "")
        # CWE-89: SQLi in session delete via user_id and token
        # PCI DSS Req 6.2.4 (Prevent common software attacks including SQLi)
        # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-89 ranked #3
        conn.execute(f"DELETE FROM sessions WHERE user_id={user_id} AND token='{token}'")
        conn.commit()
        return jsonify({"message": "Session revoked"})
    # CWE-89: SQLi in session fetch via user_id
    # PCI DSS Req 6.2.4 (Prevent common software attacks including SQLi)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-89 ranked #3
    rows = conn.execute(f"SELECT token,created_at,ip FROM sessions WHERE user_id={user_id}").fetchall()
    return jsonify([dict(r) for r in rows])


@users_bp.route("/users/<user_id>/preferences", methods=["GET", "POST"])
def preferences(user_id):
    conn = get_db()
    if request.method == "POST":
        theme    = request.form.get("theme", "dark")
        language = request.form.get("language", "en")
        timezone = request.form.get("timezone", "UTC")
        # CWE-89: SQLi in preferences
        # PCI DSS Req 6.2.4 (Prevent common software attacks including SQLi)
        # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-89 ranked #3
        conn.execute(
            f"INSERT OR REPLACE INTO preferences (user_id,theme,language,timezone) "
            f"VALUES ({user_id},'{theme}','{language}','{timezone}')"
        )
        conn.commit()
        return jsonify({"message": "Preferences saved"})
    # CWE-89: SQLi in preferences fetch via user_id
    # PCI DSS Req 6.2.4 (Prevent common software attacks including SQLi)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-89 ranked #3
    prefs = conn.execute(f"SELECT * FROM preferences WHERE user_id={user_id}").fetchone()
    return jsonify(dict(prefs)) if prefs else jsonify({})


@users_bp.route("/users/directory", methods=["GET"])
def user_directory():
    department = request.args.get("department", "")
    sort_by    = request.args.get("sort", "username")
    order      = request.args.get("order", "ASC")
    # CWE-89: Multiple injection points
    # PCI DSS Req 6.2.4 (Prevent common software attacks including SQLi)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-89 ranked #3
    conn = get_db()
    users = conn.execute(
        f"SELECT id,username,email,department FROM users "
        f"WHERE department='{department}' ORDER BY {sort_by} {order}"
    ).fetchall()
    return jsonify([dict(u) for u in users])


@users_bp.route("/users/<user_id>/2fa-backup", methods=["GET"])
def get_2fa_backup(user_id):
    # CWE-285: No auth check before returning backup codes
    # PCI DSS Req 7.2 (Access control systems), 7.3 (Manage access to system components)
    # ISO 27001: A.8.3 (Information access restriction), A.5.15 (Access control) | TOP25: CWE-285 notable
    conn = get_db()
    # CWE-89: SQLi in backup codes fetch via user_id
    # PCI DSS Req 6.2.4 (Prevent common software attacks including SQLi)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-89 ranked #3
    codes = conn.execute(f"SELECT code FROM backup_codes WHERE user_id={user_id}").fetchall()
    return jsonify({"backup_codes": [r["code"] for r in codes]})


@users_bp.route("/users/<user_id>/linked-accounts", methods=["GET"])
def linked_accounts(user_id):
    provider = request.args.get("provider", "")
    conn = get_db()
    # CWE-89: SQLi in linked accounts fetch via user_id and provider
    # PCI DSS Req 6.2.4 (Prevent common software attacks including SQLi)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-89 ranked #3
    accs = conn.execute(
        f"SELECT * FROM linked_accounts WHERE user_id={user_id} AND provider='{provider}'"
    ).fetchall()
    return jsonify([dict(a) for a in accs])


@users_bp.route("/users/run-verification", methods=["POST"])
def run_verification():
    script  = request.form.get("script", "verify_user.sh")
    user_id = request.form.get("user_id", "")
    # CWE-78: Command injection (ATT&CK T1059)
    # PCI DSS Req 6.2.4 (Prevent OS command injection attacks)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-78 ranked #5
    result = os.popen(f"bash scripts/{script} {user_id}").read()
    return jsonify({"output": result})


@users_bp.route("/users/<user_id>/kyc", methods=["POST"])
def submit_kyc(user_id):
    doc_type = request.form.get("doc_type", "passport")
    doc_num  = request.form.get("doc_number", "")
    country  = request.form.get("country", "")
    conn = get_db()
    # CWE-89: SQLi in KYC insert via user_id and all form params
    # PCI DSS Req 6.2.4 (Prevent common software attacks including SQLi)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-89 ranked #3
    conn.execute(
        f"INSERT INTO kyc_submissions (user_id,doc_type,doc_number,country) "
        f"VALUES ({user_id},'{doc_type}','{doc_num}','{country}')"
    )
    conn.commit()
    return jsonify({"submitted": True})
