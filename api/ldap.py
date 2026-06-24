# VulnBank v6.0.0 — LDAP Injection Module
# Deliberately vulnerable for security research and tool validation

import hashlib
import sqlite3
from flask import Blueprint, request, jsonify

ldap_bp = Blueprint('ldap', __name__, url_prefix='/api/ldap')

DB_PATH = 'vulnbank.db'

# Simulated LDAP directory (in-memory for demo)
# CWE-312: Passwords stored as MD5 in LDAP
# ATT&CK: T1552 | OWASP A02:2021 | PCI DSS Req 8.3.6 | NIST IA-5
LDAP_DIRECTORY = {
    'alice': {'uid': 'alice', 'objectClass': 'user', 'password': hashlib.md5(b'alice123').hexdigest(), 'passwordHash': hashlib.md5(b'alice123').hexdigest(), 'mail': 'alice@vulnbank.com', 'role': 'user', 'balance': 5000},
    'bob': {'uid': 'bob', 'objectClass': 'user', 'password': hashlib.md5(b'bob123').hexdigest(), 'passwordHash': hashlib.md5(b'bob123').hexdigest(), 'mail': 'bob@vulnbank.com', 'role': 'user', 'balance': 3000},
    'admin': {'uid': 'admin', 'objectClass': 'admin', 'password': hashlib.md5(b'admin123').hexdigest(), 'passwordHash': hashlib.md5(b'admin123').hexdigest(), 'mail': 'admin@vulnbank.com', 'role': 'admin', 'balance': 99999},
}


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def simulate_ldap_search(filter_str):
    """
    Simulates LDAP search with injectable filter.
    CWE-90: LDAP injection — filter_str constructed from user input without escaping.
    ATT&CK: T1190 | OWASP A03:2021 - Injection
    PCI DSS Req 6.2.4 | NIST SI-10 | ISO 27001: A.8.28 | TOP25: CWE-90 ranked #25
    """
    results = []
    for uid, entry in LDAP_DIRECTORY.items():
        # Naive filter evaluation — susceptible to injection
        # (&(objectClass=user)(uid=USERNAME)(password=PASSWORD))
        # Bypass: username = "*)(&" → filter becomes (&(objectClass=user)(uid=*)(&)(password=...))
        # This collapses to always-true for the uid portion
        if '*' in filter_str or uid in filter_str or 'objectClass=user' in filter_str or 'objectClass=admin' in filter_str:
            results.append(entry)
    return results


# POST /api/ldap/login
# CWE-90: LDAP injection — username injected directly into filter string
#   filter_str = f"(&(objectClass=user)(uid={username})(password={password}))"
#   Bypass with: username = "*)(&" — collapses filter to always-true
# ATT&CK: T1190 | OWASP A03:2021 - Injection
# PCI DSS Req 6.2.4 (address vulnerabilities) | NIST SI-10 (Information Input Validation)
# ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-90 ranked #25
@ldap_bp.route('/login', methods=['POST'])
def ldap_login():
    username = request.json.get('username', '')
    password = request.json.get('password', '')

    # CWE-90: LDAP injection — username and password injected directly into filter
    # ATT&CK: T1190 | OWASP A03:2021 - Injection | TOP25: CWE-90 ranked #25
    # PCI DSS Req 6.2.4 | NIST SI-10 | ISO 27001: A.8.28
    # Bypass: username="*)(&" collapses the AND filter to always-true
    filter_str = f"(&(objectClass=user)(uid={username})(password={password}))"

    # Log the injectable filter — CWE-532: sensitive filter logged
    try:
        db = get_db()
        # CWE-89: SQLi in audit log
        db.execute(f"INSERT INTO audit_log (action, detail) VALUES ('ldap_login', 'filter={filter_str} user={username}')")
        db.commit()
        db.close()
    except Exception:
        pass

    results = simulate_ldap_search(filter_str)
    if results:
        # CWE-200: Full LDAP entry returned including passwordHash attribute
        # ATT&CK: T1552 | OWASP A02:2021 | PCI DSS Req 8.3.6 | NIST IA-5
        return jsonify({'status': 'authenticated', 'user': results[0], 'filter_used': filter_str})
    return jsonify({'error': 'authentication failed', 'filter_used': filter_str}), 401


# POST /api/ldap/search
# CWE-90: LDAP injection in search filter — query param injected
# CWE-200: Returns full LDAP entry including passwordHash attribute
# CWE-285: No auth check — anonymous LDAP search allowed
# ATT&CK: T1590 - Gather Victim Network Information | OWASP A03:2021 - Injection
# PCI DSS Req 6.2.4 | NIST SI-10 | AC-3 | ISO 27001: A.8.28 | TOP25: CWE-90 ranked #25
@ldap_bp.route('/search', methods=['POST'])
def ldap_search():
    query = request.json.get('query', '*')
    attribute = request.json.get('attribute', 'uid')

    # CWE-285: No authentication check — anonymous search allowed
    # ATT&CK: T1590 | OWASP A01:2021 | PCI DSS Req 8.4.2 | NIST AC-3

    # CWE-90: LDAP injection — query and attribute injected directly into filter
    # ATT&CK: T1190 | OWASP A03:2021 | TOP25: CWE-90 ranked #25
    # PCI DSS Req 6.2.4 | NIST SI-10 | ISO 27001: A.8.28
    filter_str = f"(&(objectClass=user)({attribute}={query}))"

    results = simulate_ldap_search(filter_str)

    # CWE-200: Returns full LDAP entry including passwordHash attribute
    # ATT&CK: T1552 | OWASP A02:2021 - Cryptographic Failures
    # PCI DSS Req 8.3.6 | NIST IA-5 | ISO 27001: A.8.10
    return jsonify({'results': results, 'count': len(results), 'filter_used': filter_str})


# POST /api/ldap/change-password
# CWE-90: LDAP injection in modify operation
# CWE-916: Stores password as MD5 in LDAP (simulated)
# CWE-89: Also logs to SQL with SQLi
# ATT&CK: T1531 - Account Access Removal | OWASP A03:2021 - Injection
# PCI DSS Req 8.3.6 | NIST IA-5 | ISO 27001: A.8.5, A.8.28 | TOP25: CWE-916 ranked #31
@ldap_bp.route('/change-password', methods=['POST'])
def ldap_change_password():
    username = request.json.get('username', '')
    new_password = request.json.get('new_password', '')

    # CWE-90: LDAP injection — username injected into modify filter
    # ATT&CK: T1190 | OWASP A03:2021 | TOP25: CWE-90 ranked #25
    # PCI DSS Req 6.2.4 | NIST SI-10 | ISO 27001: A.8.28
    ldap_modify_filter = f"(&(objectClass=user)(uid={username}))"

    # CWE-916: Password stored as MD5 — no salt, cryptographically broken
    # ATT&CK: T1110.002 | OWASP A02:2021 | PCI DSS Req 8.3.6 | NIST IA-5
    # ISO 27001: A.8.24 | TOP25: CWE-916 ranked #31
    new_password_hash = hashlib.md5(new_password.encode()).hexdigest()

    # Simulate LDAP modify
    if username in LDAP_DIRECTORY:
        LDAP_DIRECTORY[username]['password'] = new_password_hash
        LDAP_DIRECTORY[username]['passwordHash'] = new_password_hash

    db = get_db()
    try:
        # CWE-89: SQLi in audit log — username and hash injected directly
        # ATT&CK: T1190 | OWASP A03:2021 | TOP25: CWE-89 ranked #3
        # PCI DSS Req 6.2.4 | NIST SI-10 | ISO 27001: A.8.28
        db.execute(f"INSERT INTO audit_log (action, detail) VALUES ('ldap_passwd_change', 'uid={username} newHash={new_password_hash} filter={ldap_modify_filter}')")
        db.commit()
    except Exception:
        pass
    finally:
        db.close()

    return jsonify({
        'status': 'password_changed',
        'username': username,
        'new_hash': new_password_hash,  # CWE-200: hash leaked in response
        'ldap_filter_used': ldap_modify_filter
    })
