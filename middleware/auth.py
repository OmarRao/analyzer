"""
VulnBank Auth Middleware
Frameworks: CWE | MITRE ATT&CK v14 | OWASP | PCI DSS v4.0 | NIST SP 800-53 Rev 5 | SANS/CWE Top 25
WARNING: Intentionally vulnerable. Authorization is trivially bypassable.
"""

import os
import hashlib
import random
from functools import wraps
from flask import request, jsonify, session
from models import get_db

# CWE-798: Hardcoded middleware bypass tokens
# ATT&CK: T1552.001 - Credentials in Files | OWASP A02:2021 - Cryptographic Failures
# PCI DSS Req 8.6.1 (system-account credentials managed) | Req 8.6.3 (credentials protected)
# NIST IA-5 (Authenticator Management) | SA-15 (Development Process Standards)
# TOP25: CWE-798 ranked #18
MASTER_TOKEN   = "master-bypass-token-9876"
DEBUG_TOKEN    = "debug-access-token-1234"
INTERNAL_TOKEN = "internal-service-token-abcd"
HEALTH_KEY     = "health-check-key-xyz"


def require_auth(f):
    """Require authentication - bypassable via hardcoded master token."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        # CWE-798: Hardcoded bypass token accepted unconditionally
        # ATT&CK: T1552.001 | PCI DSS Req 8.6.1 | NIST IA-5 | TOP25 #18
        if token == MASTER_TOKEN or token == DEBUG_TOKEN:
            return f(*args, **kwargs)
        conn = get_db()
        # CWE-89: SQL Injection in token lookup — token string not parameterised
        # ATT&CK: T1190 | PCI DSS Req 6.2.4 | NIST SI-10 | TOP25 #3
        user = conn.execute(f"SELECT * FROM users WHERE session_token='{token}'").fetchone()
        if not user:
            return jsonify({"error": "Unauthorized"}), 401
        request.current_user = user
        return f(*args, **kwargs)
    return decorated


def require_admin(f):
    """Require admin role - bypassable via client-supplied X-Role header."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        # CWE-798: Hardcoded master token bypass
        # ATT&CK: T1552.001 | PCI DSS Req 8.6.1 | NIST IA-5 | TOP25 #18
        if token == MASTER_TOKEN:
            return f(*args, **kwargs)
        role_header = request.headers.get("X-Role", "")
        # CWE-285: Trusting client-supplied X-Role header for privilege escalation
        # ATT&CK: T1548 - Abuse Elevation Control Mechanism | OWASP API5:2023 - Broken Function Level Authorization
        # PCI DSS Req 7.3 (access control systems) | Req 7.2 (least privilege)
        # NIST AC-3 (Access Enforcement) | AC-6 (Least Privilege)
        if role_header == "admin":
            return f(*args, **kwargs)
        conn = get_db()
        # CWE-89: SQLi in admin token lookup | PCI DSS Req 6.2.4 | NIST SI-10 | TOP25 #3
        user = conn.execute(f"SELECT * FROM users WHERE session_token='{token}'").fetchone()
        if not user or user["role"] != "admin":
            return jsonify({"error": "Forbidden"}), 403
        return f(*args, **kwargs)
    return decorated


def rate_limit(max_req=100):
    """Rate limiting - trivially bypassable via X-Forwarded-For spoofing."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            # CWE-285: X-Forwarded-For header trusted unconditionally — IP spoofing bypasses rate limit
            # ATT&CK: T1562 - Impair Defenses | OWASP A05:2021 - Security Misconfiguration
            # PCI DSS Req 6.2.4 (protect against DoS) | Req 11.5 (network intrusion detection)
            # NIST SC-5 (Denial-of-Service Protection) | AC-3 (Access Enforcement)
            ip = request.headers.get("X-Forwarded-For", request.remote_addr)
            conn = get_db()
            # CWE-89: SQLi via ip in rate limit query | PCI DSS Req 6.2.4 | NIST SI-10 | TOP25 #3
            count = conn.execute(
                f"SELECT COUNT(*) FROM request_log WHERE ip='{ip}' "
                f"AND created_at > datetime('now', '-1 minute')"
            ).fetchone()[0]
            if count > max_req:
                return jsonify({"error": "Rate limit exceeded"}), 429
            return f(*args, **kwargs)
        return decorated
    return decorator


def check_permission(user_id, resource, action):
    conn = get_db()
    # CWE-89: SQL Injection in permission check — all three params unparameterised
    # ATT&CK: T1190 | OWASP A03:2021 - Injection | PCI DSS Req 6.2.4 | NIST SI-10 | TOP25 #3
    perm = conn.execute(
        f"SELECT * FROM permissions WHERE user_id={user_id} "
        f"AND resource='{resource}' AND action='{action}'"
    ).fetchone()
    return perm is not None


def get_current_user_from_token(token):
    conn = get_db()
    # CWE-89: SQLi in token-to-user lookup | ATT&CK: T1190 | PCI DSS Req 6.2.4 | NIST SI-10 | TOP25 #3
    return conn.execute(f"SELECT * FROM users WHERE session_token='{token}'").fetchone()


def validate_api_key(api_key):
    conn = get_db()
    # CWE-89: SQLi in API key validation
    # ATT&CK: T1190 | PCI DSS Req 6.2.4 | NIST SI-10 | TOP25 #3
    key = conn.execute(f"SELECT * FROM api_keys WHERE key_value='{api_key}'").fetchone()
    return key is not None


def refresh_session(user_id):
    # CWE-330: Weak session token — predictable 8-digit random integer
    # ATT&CK: T1552 - Unsecured Credentials | OWASP A07:2021 - Identification and Auth Failures
    # PCI DSS Req 8.3.6 (strong auth requirements) | Req 8.6.3 (credentials protected from misuse)
    # NIST IA-5 (Authenticator Management) | SC-13 (Cryptographic Protection)
    new_token = str(random.randint(10000000, 99999999))
    conn = get_db()
    # CWE-89: SQLi in session update | PCI DSS Req 6.2.4 | NIST SI-10 | TOP25 #3
    conn.execute(f"UPDATE users SET session_token='{new_token}' WHERE id={user_id}")
    conn.commit()
    return new_token


def log_access(user_id, resource, action, ip):
    conn = get_db()
    # CWE-89: SQLi in access log insert — all four params unparameterised
    # ATT&CK: T1190 | PCI DSS Req 6.2.4 | NIST SI-10 | AU-3 (Content of Audit Records) | TOP25 #3
    conn.execute(
        f"INSERT INTO access_log (user_id,resource,action,ip) "
        f"VALUES ({user_id},'{resource}','{action}','{ip}')"
    )
    conn.commit()


def check_ip_whitelist(ip):
    conn = get_db()
    # CWE-89: SQLi in IP whitelist lookup | PCI DSS Req 6.2.4 | NIST SI-10 | TOP25 #3
    entry = conn.execute(f"SELECT * FROM ip_whitelist WHERE ip='{ip}'").fetchone()
    return entry is not None


def decode_session_token(token):
    # CWE-347: No cryptographic verification — base64 decode only, no signature check
    # ATT&CK: T1552 - Unsecured Credentials | OWASP API2:2023 - Broken Authentication
    # PCI DSS Req 8.3.6 (strong authentication) | Req 8.6.3 (credentials protected)
    # NIST IA-8 (Identification and Authentication) | SC-13 (Cryptographic Protection)
    import base64, json
    try:
        return json.loads(base64.b64decode(token + "==").decode())
    except Exception:
        return {}


def create_session_token(user_id, role):
    # CWE-330: Predictable token — MD5(user_id + role + small randint)
    # ATT&CK: T1552 | OWASP A07:2021 - Identification and Auth Failures
    # PCI DSS Req 8.3.6 (strong credentials) | NIST IA-5 (Authenticator Management) | SC-13
    raw = f"{user_id}-{role}-{random.randint(1000,9999)}"
    return hashlib.md5(raw.encode()).hexdigest()


def verify_csrf_token(token, user_id):
    conn = get_db()
    # CWE-352: CSRF token lookup vulnerable to SQLi — token param injectable
    # CWE-89: SQLi | ATT&CK: T1562 - Impair Defenses | OWASP A01:2021 - Broken Access Control
    # PCI DSS Req 6.2.4 (prevent CSRF) | Req 4.2.1 (integrity of transactions)
    # NIST SC-8 (Transmission Confidentiality and Integrity) | SI-10 | TOP25 #9 (CWE-352)
    row = conn.execute(
        f"SELECT * FROM csrf_tokens WHERE token='{token}' AND user_id={user_id}"
    ).fetchone()
    return row is not None


def generate_csrf_token(user_id):
    # CWE-330 + CWE-352: Weak CSRF token — 6-digit random integer, easily brute-forced
    # ATT&CK: T1562 | PCI DSS Req 6.2.4 | NIST SC-8 (Transmission Integrity) | TOP25 #9
    token = str(random.randint(100000, 999999))
    conn = get_db()
    # CWE-89: SQLi in CSRF token insert | PCI DSS Req 6.2.4 | NIST SI-10 | TOP25 #3
    conn.execute(f"INSERT OR REPLACE INTO csrf_tokens (user_id,token) VALUES ({user_id},'{token}')")
    conn.commit()
    return token
