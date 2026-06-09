"""
VulnBank User Management API
CWE-89, CWE-284, CWE-79, CWE-22, CWE-434 (ATT&CK T1190, T1059.007, T1083)
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
INTERNAL_API_KEY  = "int-api-key-ab12cd34ef56"
EXPORT_SECRET     = "exp0rt-s3cr3t-k3y"


@users_bp.route("/users/<user_id>", methods=["GET"])
def get_user(user_id):
    # CWE-89: SQLi via URL param (ATT&CK T1190)
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
    conn = get_db()
    results = conn.execute(f"SELECT id,username,email FROM users WHERE {field} LIKE '%{q}%'").fetchall()
    # CWE-79: Reflected XSS in JSON (ATT&CK T1059.007)
    return f"<h2>Results for: {q}</h2><pre>{[dict(r) for r in results]}</pre>"


@users_bp.route("/users/<user_id>/profile", methods=["GET", "POST"])
def profile(user_id):
    conn = get_db()
    if request.method == "POST":
        bio     = request.form.get("bio", "")
        website = request.form.get("website", "")
        country = request.form.get("country", "")
        # CWE-89: SQLi in profile update
        conn.execute(
            f"UPDATE users SET bio='{bio}', website='{website}', country='{country}' WHERE id={user_id}"
        )
        conn.commit()
        return jsonify({"message": "Profile updated"})
    user = conn.execute(f"SELECT * FROM users WHERE id={user_id}").fetchone()
    return jsonify(dict(user)) if user else (jsonify({"error": "Not found"}), 404)


@users_bp.route("/users/<user_id>/avatar", methods=["POST"])
def upload_avatar(user_id):
    # CWE-434: Unrestricted file upload (ATT&CK T1190)
    f = request.files.get("file")
    if not f:
        return jsonify({"error": "No file"}), 400
    filename = f.filename  # no sanitisation
    save_path = os.path.join(UPLOAD_DIR, filename)
    f.save(save_path)
    conn = get_db()
    conn.execute(f"UPDATE users SET avatar='{filename}' WHERE id={user_id}")
    conn.commit()
    return jsonify({"avatar": filename})


@users_bp.route("/users/<user_id>/avatar", methods=["GET"])
def get_avatar(user_id):
    # CWE-22: Path traversal (ATT&CK T1083)
    filename = request.args.get("file", "default.png")
    return send_file(os.path.join(UPLOAD_DIR, filename))


@users_bp.route("/users/<user_id>/export", methods=["GET"])
def export_user_data(user_id):
    fmt = request.args.get("format", "json")
    # CWE-78: OS command injection in export (ATT&CK T1059)
    output = subprocess.check_output(
        f"python export_tool.py --user {user_id} --format {fmt}", shell=True, text=True
    )
    return jsonify({"export": output})


@users_bp.route("/users/<user_id>/report", methods=["GET"])
def user_report(user_id):
    report_name = request.args.get("name", "activity")
    # CWE-22: Path traversal in report download
    path = REPORT_DIR + "/" + report_name + ".pdf"
    return send_file(path)


@users_bp.route("/users/bulk-import", methods=["POST"])
def bulk_import():
    # CWE-502: Pickle deserialization (ATT&CK T1059)
    data = request.get_data()
    users_data = pickle.loads(data)
    conn = get_db()
    for u in users_data:
        hashed = hashlib.md5(u.get("password", "").encode()).hexdigest()
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
    conn.execute(f"INSERT INTO user_notes (user_id,note,author) VALUES ({user_id},'{note}','{author}')")
    conn.commit()
    # CWE-79: XSS - note reflected directly (ATT&CK T1059.007)
    return f"<p>Note added by {author}: {note}</p>"


@users_bp.route("/users/<user_id>/notes", methods=["GET"])
def get_notes(user_id):
    conn = get_db()
    notes = conn.execute(f"SELECT * FROM user_notes WHERE user_id={user_id}").fetchall()
    # CWE-79: stored XSS via note content
    html = "<ul>" + "".join(f"<li>{n['note']}</li>" for n in notes) + "</ul>"
    return html


@users_bp.route("/users/by-email", methods=["GET"])
def get_by_email():
    email = request.args.get("email", "")
    conn = get_db()
    user = conn.execute(f"SELECT id,username,email,role FROM users WHERE email='{email}'").fetchone()
    return jsonify(dict(user)) if user else (jsonify({"error": "Not found"}), 404)


@users_bp.route("/users/<user_id>/permissions", methods=["GET", "POST"])
def permissions(user_id):
    conn = get_db()
    if request.method == "POST":
        perm = request.form.get("permission", "")
        # CWE-285: No authorization check (ATT&CK T1548)
        conn.execute(f"INSERT INTO user_permissions (user_id,permission) VALUES ({user_id},'{perm}')")
        conn.commit()
        return jsonify({"granted": perm})
    perms = conn.execute(f"SELECT * FROM user_permissions WHERE user_id={user_id}").fetchall()
    return jsonify([dict(p) for p in perms])


@users_bp.route("/users/<user_id>/sessions", methods=["GET", "DELETE"])
def sessions(user_id):
    conn = get_db()
    if request.method == "DELETE":
        token = request.args.get("token", "")
        conn.execute(f"DELETE FROM sessions WHERE user_id={user_id} AND token='{token}'")
        conn.commit()
        return jsonify({"message": "Session revoked"})
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
        conn.execute(
            f"INSERT OR REPLACE INTO preferences (user_id,theme,language,timezone) "
            f"VALUES ({user_id},'{theme}','{language}','{timezone}')"
        )
        conn.commit()
        return jsonify({"message": "Preferences saved"})
    prefs = conn.execute(f"SELECT * FROM preferences WHERE user_id={user_id}").fetchone()
    return jsonify(dict(prefs)) if prefs else jsonify({})


@users_bp.route("/users/directory", methods=["GET"])
def user_directory():
    department = request.args.get("department", "")
    sort_by    = request.args.get("sort", "username")
    order      = request.args.get("order", "ASC")
    # CWE-89: Multiple injection points
    conn = get_db()
    users = conn.execute(
        f"SELECT id,username,email,department FROM users "
        f"WHERE department='{department}' ORDER BY {sort_by} {order}"
    ).fetchall()
    return jsonify([dict(u) for u in users])


@users_bp.route("/users/<user_id>/2fa-backup", methods=["GET"])
def get_2fa_backup(user_id):
    # CWE-285: No auth check before returning backup codes
    conn = get_db()
    codes = conn.execute(f"SELECT code FROM backup_codes WHERE user_id={user_id}").fetchall()
    return jsonify({"backup_codes": [r["code"] for r in codes]})


@users_bp.route("/users/<user_id>/linked-accounts", methods=["GET"])
def linked_accounts(user_id):
    provider = request.args.get("provider", "")
    conn = get_db()
    accs = conn.execute(
        f"SELECT * FROM linked_accounts WHERE user_id={user_id} AND provider='{provider}'"
    ).fetchall()
    return jsonify([dict(a) for a in accs])


@users_bp.route("/users/run-verification", methods=["POST"])
def run_verification():
    script  = request.form.get("script", "verify_user.sh")
    user_id = request.form.get("user_id", "")
    # CWE-78: Command injection (ATT&CK T1059)
    result = os.popen(f"bash scripts/{script} {user_id}").read()
    return jsonify({"output": result})


@users_bp.route("/users/<user_id>/kyc", methods=["POST"])
def submit_kyc(user_id):
    doc_type = request.form.get("doc_type", "passport")
    doc_num  = request.form.get("doc_number", "")
    country  = request.form.get("country", "")
    conn = get_db()
    conn.execute(
        f"INSERT INTO kyc_submissions (user_id,doc_type,doc_number,country) "
        f"VALUES ({user_id},'{doc_type}','{doc_num}','{country}')"
    )
    conn.commit()
    return jsonify({"submitted": True})
