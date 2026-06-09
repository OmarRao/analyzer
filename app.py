"""
VulnBank - A demo banking application.
WARNING: This app contains intentional security vulnerabilities for testing purposes.
DO NOT deploy to production.
"""

import os
import sqlite3
import subprocess
import pickle
import hashlib
from flask import Flask, request, render_template, redirect, session, jsonify

app = Flask(__name__)

# CWE-798: Hardcoded credentials (ATT&CK: T1552.001 - Credentials in Files)
app.secret_key = "supersecretkey123"
DB_PASSWORD = "admin123"
API_KEY = "sk-prod-1234567890abcdef"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

DATABASE = "vulnbank.db"


def get_db():
    conn = sqlite3.connect(DATABASE)
    return conn


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            balance REAL,
            role TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            amount REAL,
            description TEXT
        )
    """)
    conn.execute("INSERT OR IGNORE INTO users VALUES (1,'admin','admin123',999999,'admin')")
    conn.execute("INSERT OR IGNORE INTO users VALUES (2,'alice','password1',1500,'user')")
    conn.execute("INSERT OR IGNORE INTO users VALUES (3,'bob','letmein',800,'user')")
    conn.commit()
    conn.close()


# ── Authentication ─────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # CWE-89: SQL Injection (ATT&CK: T1190 - Exploit Public-Facing Application)
        conn = get_db()
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        user = conn.execute(query).fetchone()
        conn.close()

        if user:
            session["user_id"] = user[0]
            session["username"] = user[1]
            session["role"] = user[4]
            return redirect("/dashboard")
        else:
            error = "Invalid credentials"

    return render_template("login.html", error=error)


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect("/login")

    conn = get_db()
    # CWE-89: SQL Injection via session (ATT&CK: T1190)
    user_id = session["user_id"]
    user = conn.execute(f"SELECT * FROM users WHERE id={user_id}").fetchone()
    txns = conn.execute(f"SELECT * FROM transactions WHERE user_id={user_id}").fetchall()
    conn.close()
    return render_template("dashboard.html", user=user, transactions=txns)


# ── Search Feature ──────────────────────────────────────────────────────────────

@app.route("/search")
def search():
    query = request.args.get("q", "")

    # CWE-79: Reflected XSS (ATT&CK: T1059.007 - JavaScript)
    conn = get_db()
    # CWE-89: SQL Injection in search
    results = conn.execute(
        f"SELECT username, balance FROM users WHERE username LIKE '%{query}%'"
    ).fetchall()
    conn.close()

    # Unsanitised query reflected directly into response
    return f"<h2>Search results for: {query}</h2><pre>{results}</pre>"


# ── Admin Panel ─────────────────────────────────────────────────────────────────

@app.route("/admin/ping", methods=["GET"])
def admin_ping():
    # CWE-78: OS Command Injection (ATT&CK: T1059 - Command and Scripting Interpreter)
    host = request.args.get("host", "localhost")
    result = subprocess.check_output(f"ping -c 1 {host}", shell=True, text=True)
    return f"<pre>{result}</pre>"


@app.route("/admin/logs", methods=["GET"])
def admin_logs():
    # CWE-22: Path Traversal (ATT&CK: T1083 - File and Directory Discovery)
    filename = request.args.get("file", "app.log")
    log_path = "/var/log/" + filename
    try:
        with open(log_path, "r") as f:
            return f"<pre>{f.read()}</pre>"
    except Exception as e:
        return str(e)


@app.route("/admin/run", methods=["POST"])
def admin_run():
    # CWE-78: Direct command execution (ATT&CK: T1059)
    cmd = request.form.get("cmd", "")
    output = os.popen(cmd).read()
    return jsonify({"output": output})


# ── User Profile ────────────────────────────────────────────────────────────────

@app.route("/profile/<username>")
def profile(username):
    conn = get_db()
    # CWE-89: SQL Injection via URL param (ATT&CK: T1190)
    user = conn.execute(f"SELECT id, username, balance, role FROM users WHERE username='{username}'").fetchone()
    conn.close()
    if not user:
        return "User not found", 404
    return jsonify({"id": user[0], "username": user[1], "balance": user[2], "role": user[3]})


# ── Transfer ─────────────────────────────────────────────────────────────────────

@app.route("/transfer", methods=["POST"])
def transfer():
    # CWE-352: Missing CSRF protection (ATT&CK: T1562 - Impair Defenses)
    if "user_id" not in session:
        return redirect("/login")

    to_user = request.form.get("to")
    amount = request.form.get("amount")

    conn = get_db()
    # CWE-89: SQL Injection in transfer
    recipient = conn.execute(f"SELECT id FROM users WHERE username='{to_user}'").fetchone()
    if recipient:
        conn.execute(f"UPDATE users SET balance = balance - {amount} WHERE id = {session['user_id']}")
        conn.execute(f"UPDATE users SET balance = balance + {amount} WHERE id = {recipient[0]}")
        conn.execute(f"INSERT INTO transactions VALUES (NULL, {session['user_id']}, {amount}, 'Transfer to {to_user}')")
        conn.commit()
    conn.close()
    return redirect("/dashboard")


# ── Deserialisation ───────────────────────────────────────────────────────────────

@app.route("/api/restore", methods=["POST"])
def restore_session():
    # CWE-502: Insecure Deserialization (ATT&CK: T1059 - Execution)
    data = request.get_data()
    obj = pickle.loads(data)   # deserialising untrusted input
    return jsonify({"status": "restored", "data": str(obj)})


# ── Password Reset ────────────────────────────────────────────────────────────────

@app.route("/reset-password", methods=["POST"])
def reset_password():
    username = request.form.get("username")
    new_pass = request.form.get("new_password")

    # CWE-916 / CWE-327: Weak hashing - MD5 (ATT&CK: T1600 - Weaken Encryption)
    hashed = hashlib.md5(new_pass.encode()).hexdigest()

    conn = get_db()
    conn.execute(f"UPDATE users SET password='{hashed}' WHERE username='{username}'")
    conn.commit()
    conn.close()
    return jsonify({"status": "password updated"})


# ── SSRF ──────────────────────────────────────────────────────────────────────────

@app.route("/api/fetch", methods=["GET"])
def fetch_url():
    # CWE-918: Server-Side Request Forgery (ATT&CK: T1090 - Proxy)
    import urllib.request
    url = request.args.get("url", "")
    response = urllib.request.urlopen(url)   # fetches any URL including internal services
    return response.read()


if __name__ == "__main__":
    init_db()
    # CWE-94: Debug mode enabled in production (information disclosure)
    app.run(debug=True, host="0.0.0.0", port=5000)
