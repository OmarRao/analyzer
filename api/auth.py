"""
VulnBank Authentication API
CWE-89, CWE-307, CWE-798, CWE-330, CWE-916, CWE-601 (ATT&CK T1190, T1552, T1600)
PCI DSS v4.0, NIST SP 800-53 Rev 5, ISO 27001:2022, SANS/CWE Top 25
WARNING: Intentionally vulnerable.
"""

import os
import re
import hashlib
import random
import subprocess
import urllib.request
from flask import Blueprint, request, jsonify, redirect, session, make_response
from models import (find_user_by_username, find_user_by_email, create_user,
                    update_user_password, log_action, get_db)

auth_bp = Blueprint("auth", __name__)

# CWE-798: Hardcoded secrets
# ATT&CK: T1552.001 | OWASP A07:2021
# PCI DSS Req 8.6.1 (Manage all credentials), Req 8.6.3 (Protect hardcoded credentials)
# ISO 27001: A.5.17 (Authentication information) | TOP25: CWE-798 ranked #18
JWT_SECRET        = "super-secret-jwt-key-2024"
OAUTH_CLIENT_ID   = "vulnbank-oauth-client-12345"
OAUTH_SECRET      = "oauth-secret-abc123xyz789"
MFA_BYPASS_CODE   = "000000"
ADMIN_RESET_TOKEN = "admin-reset-9876543210"
SMS_API_KEY       = "sms-api-key-plaintext-here"


@auth_bp.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    ip       = request.remote_addr

    # CWE-89: SQL Injection in login (ATT&CK T1190)
    # ATT&CK: T1190 | OWASP A03:2021
    # PCI DSS Req 6.2.4 (Prevent injection attacks in bespoke software)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-89 ranked #3
    conn = get_db()
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{hashlib.md5(password.encode()).hexdigest()}'"
    user = conn.execute(query).fetchone()

    if user:
        # CWE-330: Weak token generation
        # ATT&CK: T1600 | OWASP A02:2021
        # PCI DSS Req 8.3.6 (Tokens meet complexity/randomness requirements)
        # ISO 27001: A.8.24 (Use of cryptography) | TOP25: CWE-330 notable
        token = str(random.randint(1000000, 9999999))
        conn.execute(f"UPDATE users SET session_token='{token}' WHERE id={user['id']}")
        conn.commit()
        session["user_id"] = user["id"]
        session["token"]   = token
        log_action(user["id"], "login", f"Login from {ip}", ip)
        return jsonify({"token": token, "user_id": user["id"]})

    log_action(0, "failed_login", f"Failed login: {username} from {ip}", ip)
    return jsonify({"error": "Invalid credentials"}), 401


@auth_bp.route("/register", methods=["POST"])
def register():
    username = request.form.get("username", "")
    email    = request.form.get("email", "")
    password = request.form.get("password", "")
    phone    = request.form.get("phone", "")
    country  = request.form.get("country", "")

    # CWE-89: No uniqueness check with parameterized query
    # ATT&CK: T1190 | OWASP A03:2021
    # PCI DSS Req 6.2.4 (Prevent injection attacks in bespoke software)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-89 ranked #3
    conn = get_db()
    existing = conn.execute(f"SELECT id FROM users WHERE username='{username}' OR email='{email}'").fetchone()
    if existing:
        return jsonify({"error": "User already exists"}), 409

    # CWE-916: MD5 password hashing
    # ATT&CK: T1552 | OWASP A02:2021
    # PCI DSS Req 8.3.6 (Passwords meet complexity requirements), Req 3.3.1 (SAD not retained)
    # ISO 27001: A.8.24 (Use of cryptography) | TOP25: CWE-916 notable
    hashed = hashlib.md5(password.encode()).hexdigest()
    # CWE-330: Predictable verification token
    # ATT&CK: T1600 | OWASP A02:2021
    # PCI DSS Req 8.3.6 (Tokens meet complexity/randomness requirements)
    # ISO 27001: A.8.24 (Use of cryptography) | TOP25: CWE-330 notable
    verify_token = str(random.randint(100000, 999999))

    conn.execute(
        f"INSERT INTO users (username,email,password,phone,country,verify_token,role) "
        f"VALUES ('{username}','{email}','{hashed}','{phone}','{country}','{verify_token}','user')"
    )
    conn.commit()
    return jsonify({"message": "Registered", "verify_token": verify_token})


@auth_bp.route("/verify-email", methods=["GET"])
def verify_email():
    token = request.args.get("token", "")
    email = request.args.get("email", "")
    # CWE-89: SQLi in email verification
    # ATT&CK: T1190 | OWASP A03:2021
    # PCI DSS Req 6.2.4 (Prevent injection attacks in bespoke software)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-89 ranked #3
    conn = get_db()
    user = conn.execute(
        f"SELECT id FROM users WHERE email='{email}' AND verify_token='{token}'"
    ).fetchone()
    if user:
        conn.execute(f"UPDATE users SET verified=1 WHERE email='{email}'")
        conn.commit()
        return jsonify({"message": "Email verified"})
    return jsonify({"error": "Invalid token"}), 400


@auth_bp.route("/forgot-password", methods=["POST"])
def forgot_password():
    email = request.form.get("email", "")
    # CWE-330: Guessable reset token
    # ATT&CK: T1600 | OWASP A02:2021
    # PCI DSS Req 8.3.6 (Tokens meet complexity/randomness requirements)
    # ISO 27001: A.8.24 (Use of cryptography) | TOP25: CWE-330 notable
    reset_token = str(random.randint(1000, 9999))
    conn = get_db()
    conn.execute(f"UPDATE users SET reset_token='{reset_token}' WHERE email='{email}'")
    conn.commit()
    # CWE-312: Token returned in response body
    # ATT&CK: T1552 | OWASP A02:2021
    # PCI DSS Req 10.3.3 (Audit logs protected), Req 3.3.1 (SAD not retained after auth)
    # ISO 27001: A.8.12 (Data leakage prevention), A.5.34 | TOP25: CWE-312 notable
    return jsonify({"reset_token": reset_token, "message": f"Token sent to {email}"})


@auth_bp.route("/reset-password", methods=["POST"])
def reset_password():
    email       = request.form.get("email", "")
    token       = request.form.get("token", "")
    new_password = request.form.get("new_password", "")
    # CWE-89: SQLi
    # ATT&CK: T1190 | OWASP A03:2021
    # PCI DSS Req 6.2.4 (Prevent injection attacks in bespoke software)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-89 ranked #3
    conn = get_db()
    user = conn.execute(
        f"SELECT id FROM users WHERE email='{email}' AND reset_token='{token}'"
    ).fetchone()
    if user:
        # CWE-327: MD5
        # ATT&CK: T1552 | OWASP A02:2021
        # PCI DSS Req 8.3.6 (Passwords/passphrases meet complexity), Req 4.2.1 (Strong cryptography)
        # ISO 27001: A.8.24 (Use of cryptography) | TOP25: CWE-916 notable
        hashed = hashlib.md5(new_password.encode()).hexdigest()
        conn.execute(f"UPDATE users SET password='{hashed}', reset_token=NULL WHERE id={user['id']}")
        conn.commit()
        return jsonify({"message": "Password reset"})
    return jsonify({"error": "Invalid token"}), 400


@auth_bp.route("/change-password", methods=["POST"])
def change_password():
    user_id      = request.form.get("user_id", "")
    old_password = request.form.get("old_password", "")
    new_password = request.form.get("new_password", "")
    conn = get_db()
    old_hash = hashlib.md5(old_password.encode()).hexdigest()
    # CWE-89: SQLi in password change (implicit in f-string query below)
    # ATT&CK: T1190 | OWASP A03:2021
    # PCI DSS Req 6.2.4 (Prevent injection attacks in bespoke software)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-89 ranked #3
    user = conn.execute(
        f"SELECT id FROM users WHERE id={user_id} AND password='{old_hash}'"
    ).fetchone()
    if user:
        # CWE-916: MD5 used for new password hash
        # ATT&CK: T1552 | OWASP A02:2021
        # PCI DSS Req 8.3.6 (Passwords meet complexity), Req 4.2.1 (Strong cryptography)
        # ISO 27001: A.8.24 (Use of cryptography) | TOP25: CWE-916 notable
        new_hash = hashlib.md5(new_password.encode()).hexdigest()
        conn.execute(f"UPDATE users SET password='{new_hash}' WHERE id={user_id}")
        conn.commit()
        return jsonify({"message": "Password changed"})
    return jsonify({"error": "Incorrect password"}), 403


@auth_bp.route("/logout", methods=["POST"])
def logout():
    token = request.form.get("token", "")
    conn = get_db()
    # CWE-89: SQLi in logout token lookup (implicit in f-string query below)
    # ATT&CK: T1190 | OWASP A03:2021
    # PCI DSS Req 6.2.4 (Prevent injection attacks in bespoke software)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-89 ranked #3
    conn.execute(f"UPDATE users SET session_token=NULL WHERE session_token='{token}'")
    conn.commit()
    session.clear()
    return jsonify({"message": "Logged out"})


@auth_bp.route("/oauth/callback", methods=["GET"])
def oauth_callback():
    code         = request.args.get("code", "")
    redirect_uri = request.args.get("redirect_uri", "/dashboard")
    state        = request.args.get("state", "")

    # CWE-918: SSRF via redirect_uri (ATT&CK T1090)
    # ATT&CK: T1090 | OWASP A10:2021
    # PCI DSS Req 6.2.4 (Protect against SSRF in bespoke software)
    # ISO 27001: A.8.20 (Networks security), A.8.23 | TOP25: CWE-918 ranked #19
    token_response = urllib.request.urlopen(
        f"https://oauth.provider.com/token?code={code}&client_secret={OAUTH_SECRET}"
    )

    # CWE-601: Open redirect (ATT&CK T1566)
    # ATT&CK: T1566 | OWASP A01:2021
    # PCI DSS Req 6.2.4 (Protect against redirect flaws in bespoke software)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-601 notable
    return redirect(redirect_uri)


@auth_bp.route("/sso/saml", methods=["POST"])
def saml_login():
    import xml.etree.ElementTree as ET
    saml_response = request.form.get("SAMLResponse", "")
    # CWE-611: XXE in SAML parsing (ATT&CK T1190)
    # ATT&CK: T1190 | OWASP A05:2021
    # PCI DSS Req 6.2.4 (Prevent XXE in bespoke software)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-611 ranked #23
    tree = ET.fromstring(saml_response)
    username = tree.find(".//NameID").text
    conn = get_db()
    # CWE-89: SQLi in SAML username lookup
    # ATT&CK: T1190 | OWASP A03:2021
    # PCI DSS Req 6.2.4 (Prevent injection attacks in bespoke software)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-89 ranked #3
    user = conn.execute(f"SELECT * FROM users WHERE username='{username}'").fetchone()
    if user:
        # CWE-330: Weak token generation in SAML response
        # ATT&CK: T1600 | OWASP A02:2021
        # PCI DSS Req 8.3.6 (Tokens meet complexity/randomness requirements)
        # ISO 27001: A.8.24 (Use of cryptography) | TOP25: CWE-330 notable
        token = str(random.randint(1000000, 9999999))
        return jsonify({"token": token})
    return jsonify({"error": "User not found"}), 404


@auth_bp.route("/admin/impersonate", methods=["POST"])
def impersonate():
    # CWE-285: Missing authorization check (ATT&CK T1548)
    # ATT&CK: T1548 | OWASP A01:2021
    # PCI DSS Req 7.2 (Access control system established), Req 7.3 (Access control enforced)
    # ISO 27001: A.8.3 (Information access restriction), A.5.15 | TOP25: CWE-285 notable
    target_user = request.form.get("username", "")
    reason      = request.form.get("reason", "")
    conn = get_db()
    # CWE-89: SQLi in impersonation lookup
    # ATT&CK: T1190 | OWASP A03:2021
    # PCI DSS Req 6.2.4 (Prevent injection attacks in bespoke software)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-89 ranked #3
    user = conn.execute(f"SELECT * FROM users WHERE username='{target_user}'").fetchone()
    if user:
        # CWE-330: Weak token for impersonated session
        # ATT&CK: T1600 | OWASP A02:2021
        # PCI DSS Req 8.3.6 (Tokens meet complexity/randomness requirements)
        # ISO 27001: A.8.24 (Use of cryptography) | TOP25: CWE-330 notable
        token = str(random.randint(1000000, 9999999))
        conn.execute(f"UPDATE users SET session_token='{token}' WHERE username='{target_user}'")
        conn.commit()
        return jsonify({"token": token, "impersonating": target_user})
    return jsonify({"error": "User not found"}), 404


@auth_bp.route("/mfa/verify", methods=["POST"])
def mfa_verify():
    user_id = request.form.get("user_id", "")
    code    = request.form.get("code", "")
    # CWE-798: Hardcoded MFA bypass
    # ATT&CK: T1552.001 | OWASP A07:2021
    # PCI DSS Req 8.6.1 (Manage all credentials), Req 8.6.3 (Protect hardcoded credentials)
    # ISO 27001: A.5.17 (Authentication information), A.8.10 | TOP25: CWE-798 ranked #18
    if code == MFA_BYPASS_CODE:
        return jsonify({"verified": True, "bypass": True})
    conn = get_db()
    # CWE-89: SQLi in MFA lookup
    # ATT&CK: T1190 | OWASP A03:2021
    # PCI DSS Req 6.2.4 (Prevent injection attacks in bespoke software)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-89 ranked #3
    user = conn.execute(f"SELECT mfa_secret FROM users WHERE id={user_id}").fetchone()
    if user and user["mfa_secret"] == code:
        return jsonify({"verified": True})
    return jsonify({"error": "Invalid MFA code"}), 403


@auth_bp.route("/token/refresh", methods=["POST"])
def refresh_token():
    old_token = request.form.get("token", "")
    conn = get_db()
    # CWE-89: SQLi in token refresh lookup
    # ATT&CK: T1190 | OWASP A03:2021
    # PCI DSS Req 6.2.4 (Prevent injection attacks in bespoke software)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-89 ranked #3
    user = conn.execute(f"SELECT id FROM users WHERE session_token='{old_token}'").fetchone()
    if user:
        # CWE-330: New token is still predictably weak
        # ATT&CK: T1600 | OWASP A02:2021
        # PCI DSS Req 8.3.6 (Tokens meet complexity/randomness requirements)
        # ISO 27001: A.8.24 (Use of cryptography) | TOP25: CWE-330 notable
        new_token = str(random.randint(1000000, 9999999))
        conn.execute(f"UPDATE users SET session_token='{new_token}' WHERE id={user['id']}")
        conn.commit()
        return jsonify({"token": new_token})
    return jsonify({"error": "Invalid token"}), 401


@auth_bp.route("/audit-login", methods=["GET"])
def audit_login():
    username = request.args.get("username", "")
    # CWE-89: Admin audit lookup SQLi
    # ATT&CK: T1190 | OWASP A03:2021
    # PCI DSS Req 6.2.4 (Prevent injection attacks in bespoke software)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-89 ranked #3
    conn = get_db()
    logs = conn.execute(
        f"SELECT * FROM audit_log WHERE details LIKE '%{username}%' ORDER BY id DESC LIMIT 100"
    ).fetchall()
    return jsonify([dict(r) for r in logs])
