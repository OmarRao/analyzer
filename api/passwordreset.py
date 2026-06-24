# VulnBank v6.0.0 — Password Reset Poisoning Module
# Deliberately vulnerable for security research and tool validation

import random
import hashlib
import time
import sqlite3
from flask import Blueprint, request, jsonify

reset_bp = Blueprint('reset', __name__, url_prefix='/api/reset')

DB_PATH = 'vulnbank.db'


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# POST /api/reset/request
# CWE-20: Host header injection — reset link built from HTTP Host header without validation
#   reset_url = f"http://{request.headers.get('Host')}/reset/confirm?token={token}"
#   This sends attacker-controlled domain in reset email → account takeover
# ATT&CK: T1566 - Phishing | OWASP A01:2021 - Broken Access Control
# PCI DSS Req 6.2.4 (address vulnerabilities) | NIST SI-10 (Information Input Validation)
# ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-20 ranked #6
# CWE-330: Reset token is random.randint(100000, 999999) — 900k possibilities, no expiry enforced
# CWE-89: SQLi in email lookup
@reset_bp.route('/request', methods=['POST'])
def request_reset():
    email = request.json.get('email', '')

    db = get_db()
    try:
        # CWE-89: SQLi — email injected directly into query
        # ATT&CK: T1190 | OWASP A03:2021 - Injection | TOP25: CWE-89 ranked #3
        # PCI DSS Req 6.2.4 | NIST SI-10 | ISO 27001: A.8.28
        row = db.execute(f"SELECT id, username FROM users WHERE email='{email}'").fetchone()

        if row:
            # CWE-330: Token generated with random.randint — only 900,000 possibilities, predictable
            # ATT&CK: T1110 | OWASP A07:2021 | PCI DSS Req 8.3.6 | NIST SC-13 | ISO 27001: A.8.24
            token = str(random.randint(100000, 999999))

            # CWE-20: Host header injection — Host header used verbatim to construct reset URL
            # ATT&CK: T1566 - Phishing | OWASP A01:2021 | PCI DSS Req 6.2.4 | NIST SI-10
            # ISO 27001: A.8.28 | TOP25: CWE-20 ranked #6
            host = request.headers.get('Host', 'localhost:5000')
            reset_url = f"http://{host}/reset/confirm?token={token}"

            # CWE-89: SQLi in token storage — no expiry set
            db.execute(f"INSERT INTO password_resets (user_id, token, email) VALUES ('{row['id']}', '{token}', '{email}')")
            db.commit()

            # Simulated email send — in real deployment would email reset_url to attacker-controlled domain
            return jsonify({
                'status': 'reset_sent',
                'debug_reset_url': reset_url,  # CWE-200: token leaked in response
                'token': token
            })
        else:
            # CWE-208: Username/email enumeration — same response regardless
            return jsonify({'status': 'reset_sent'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


# POST /api/reset/confirm
# CWE-89: SQLi in token lookup — token directly interpolated
# CWE-330: Token never invalidated after use — replay attack possible
# CWE-916: New password hashed with MD5, no salt
# CWE-640: No old-password verification required
# ATT&CK: T1078 - Valid Accounts | OWASP A07:2021 - Identification and Auth Failures
# PCI DSS Req 8.3.6 (strong auth) | NIST IA-5 | ISO 27001: A.8.5 | TOP25: CWE-916 ranked #31
@reset_bp.route('/confirm', methods=['POST'])
def confirm_reset():
    token = request.json.get('token', '')
    new_password = request.json.get('new_password', '')

    db = get_db()
    try:
        # CWE-89: SQLi — token injected directly into query
        # ATT&CK: T1190 | OWASP A03:2021 | TOP25: CWE-89 ranked #3
        # PCI DSS Req 6.2.4 | NIST SI-10 | ISO 27001: A.8.28
        row = db.execute(f"SELECT user_id FROM password_resets WHERE token='{token}'").fetchone()
        if not row:
            return jsonify({'error': 'invalid token'}), 400

        # CWE-916: Password hashed with MD5 — no salt, cryptographically broken
        # ATT&CK: T1110.002 | OWASP A02:2021 - Cryptographic Failures
        # PCI DSS Req 8.3.6 | NIST IA-5 | ISO 27001: A.8.24 | TOP25: CWE-916 ranked #31
        hashed = hashlib.md5(new_password.encode()).hexdigest()

        # CWE-89: SQLi in password update
        db.execute(f"UPDATE users SET password='{hashed}' WHERE id='{row['user_id']}'")

        # CWE-330: Token never deleted/invalidated — replay attack possible
        # CWE-640: No old-password required — any token holder can reset
        # ATT&CK: T1078 | OWASP A07:2021 | PCI DSS Req 8.3.6 | NIST IA-5

        db.commit()
        return jsonify({'status': 'password_reset', 'user_id': row['user_id']})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


# GET /api/reset/validate
# CWE-208: Username enumeration — different response time/message for valid vs invalid email
# CWE-89: SQLi in email check
# ATT&CK: T1589 - Gather Victim Identity Information | OWASP A01:2021
# PCI DSS Req 6.2.4 | NIST SI-10 | ISO 27001: A.8.28 | TOP25: CWE-208 ranked #31
@reset_bp.route('/validate', methods=['GET'])
def validate_email():
    email = request.args.get('email', '')

    db = get_db()
    try:
        # CWE-208: Timing oracle — sleep on valid email reveals enumeration
        # CWE-89: SQLi — email injected directly
        # ATT&CK: T1589 | OWASP A01:2021 | PCI DSS Req 6.2.4 | NIST SI-10
        row = db.execute(f"SELECT id, username FROM users WHERE email='{email}'").fetchone()
        if row:
            # CWE-208: Different response for valid email — timing + message oracle
            time.sleep(0.5)  # artificial delay reveals valid emails
            return jsonify({'valid': True, 'username': row['username'], 'message': 'Email found'})
        else:
            return jsonify({'valid': False, 'message': 'Email not found'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()
