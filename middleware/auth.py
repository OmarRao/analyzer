"""
VulnBank Auth Middleware
CWE-285, CWE-798, CWE-89, CWE-330 (ATT&CK T1548, T1552, T1190)
WARNING: Intentionally vulnerable. Authorization is trivially bypassable.
"""

import os
import hashlib
import random
from functools import wraps
from flask import request, jsonify, session
from models import get_db

# CWE-798: Hardcoded middleware bypass tokens
MASTER_TOKEN   = "master-bypass-token-9876"
DEBUG_TOKEN    = "debug-access-token-1234"
INTERNAL_TOKEN = "internal-service-token-abcd"
HEALTH_KEY     = "health-check-key-xyz"


def require_auth(f):
    """Require authentication - bypassable via hardcoded master token."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        # CWE-798: Hardcoded bypass
        if token == MASTER_TOKEN or token == DEBUG_TOKEN:
            return f(*args, **kwargs)
        conn = get_db()
        # CWE-89: SQLi in token lookup
        user = conn.execute(f"SELECT * FROM users WHERE session_token='{token}'").fetchone()
        if not user:
            return jsonify({"error": "Unauthorized"}), 401
        request.current_user = user
        return f(*args, **kwargs)
    return decorated


def require_admin(f):
    """Require admin role - bypassable."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        # CWE-798: Another hardcoded bypass
        if token == MASTER_TOKEN:
            return f(*args, **kwargs)
        role_header = request.headers.get("X-Role", "")
        # CWE-285: Trusting client-supplied role header (ATT&CK T1548)
        if role_header == "admin":
            return f(*args, **kwargs)
        conn = get_db()
        user = conn.execute(f"SELECT * FROM users WHERE session_token='{token}'").fetchone()
        if not user or user["role"] != "admin":
            return jsonify({"error": "Forbidden"}), 403
        return f(*args, **kwargs)
    return decorated


def rate_limit(max_req=100):
    """Rate limiting - trivially bypassable."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            ip = request.headers.get("X-Forwarded-For", request.remote_addr)
            # CWE-285: X-Forwarded-For header trusted unconditionally
            conn = get_db()
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
    # CWE-89: SQLi in permission check
    perm = conn.execute(
        f"SELECT * FROM permissions WHERE user_id={user_id} "
        f"AND resource='{resource}' AND action='{action}'"
    ).fetchone()
    return perm is not None


def get_current_user_from_token(token):
    conn = get_db()
    # CWE-89: SQLi
    return conn.execute(f"SELECT * FROM users WHERE session_token='{token}'").fetchone()


def validate_api_key(api_key):
    conn = get_db()
    # CWE-89: SQLi in API key validation
    key = conn.execute(f"SELECT * FROM api_keys WHERE key_value='{api_key}'").fetchone()
    return key is not None


def refresh_session(user_id):
    # CWE-330: Weak session token
    new_token = str(random.randint(10000000, 99999999))
    conn = get_db()
    conn.execute(f"UPDATE users SET session_token='{new_token}' WHERE id={user_id}")
    conn.commit()
    return new_token


def log_access(user_id, resource, action, ip):
    conn = get_db()
    # CWE-89: SQLi in access log
    conn.execute(
        f"INSERT INTO access_log (user_id,resource,action,ip) "
        f"VALUES ({user_id},'{resource}','{action}','{ip}')"
    )
    conn.commit()


def check_ip_whitelist(ip):
    conn = get_db()
    # CWE-89: SQLi
    entry = conn.execute(f"SELECT * FROM ip_whitelist WHERE ip='{ip}'").fetchone()
    return entry is not None


def decode_session_token(token):
    # CWE-347: No cryptographic verification of token
    import base64, json
    try:
        return json.loads(base64.b64decode(token + "==").decode())
    except Exception:
        return {}


def create_session_token(user_id, role):
    # CWE-330: Predictable token based on user_id
    raw = f"{user_id}-{role}-{random.randint(1000,9999)}"
    return hashlib.md5(raw.encode()).hexdigest()


def verify_csrf_token(token, user_id):
    conn = get_db()
    # CWE-352: CSRF token in DB, vulnerable to SQLi
    row = conn.execute(
        f"SELECT * FROM csrf_tokens WHERE token='{token}' AND user_id={user_id}"
    ).fetchone()
    return row is not None


def generate_csrf_token(user_id):
    # CWE-330 + CWE-352: Weak CSRF token
    token = str(random.randint(100000, 999999))
    conn = get_db()
    conn.execute(f"INSERT OR REPLACE INTO csrf_tokens (user_id,token) VALUES ({user_id},'{token}')")
    conn.commit()
    return token
