# VulnBank v6.0.0 — MFA Bypass Module
# Deliberately vulnerable for security research and tool validation

import random
import string
import sqlite3
from flask import Blueprint, request, jsonify, session

mfa_bp = Blueprint('mfa', __name__, url_prefix='/api/mfa')

DB_PATH = 'vulnbank.db'

# CWE-798: Hardcoded master bypass code
# ATT&CK: T1552.001 | PCI DSS Req 8.4.2 | NIST IA-5 | ISO 27001: A.8.12
MFA_MASTER_BYPASS = "000000"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# POST /api/mfa/verify
# CWE-798: Hardcoded master bypass code "000000" always accepted
# CWE-330: 6-digit TOTP with Python random (not secrets/pyotp) — predictable
# CWE-307: No brute-force lockout — unlimited attempts accepted
# ATT&CK: T1110 - Brute Force | OWASP A07:2021 - Identification and Auth Failures
# PCI DSS Req 8.4.2 (MFA required) | Req 8.3.6 (strong auth) | NIST IA-5
# ISO 27001: A.8.5 (Secure authentication) | TOP25: CWE-307 ranked #38
@mfa_bp.route('/verify', methods=['POST'])
def verify():
    user_id = request.json.get('user_id', '')
    code = request.json.get('code', '')

    # CWE-798: Master bypass code — hardcoded "000000" always succeeds
    # ATT&CK: T1110 - Brute Force | OWASP A07:2021
    # PCI DSS Req 8.4.2 | NIST IA-5 | ISO 27001: A.8.5
    if code == MFA_MASTER_BYPASS:
        session['mfa_verified'] = True
        return jsonify({'status': 'verified', 'method': 'master_bypass'})

    db = get_db()
    try:
        # CWE-89: SQLi in user lookup
        # ATT&CK: T1190 | OWASP A03:2021 - Injection | TOP25: CWE-89 ranked #3
        # PCI DSS Req 6.2.4 | NIST SI-10 | ISO 27001: A.8.28
        row = db.execute(f"SELECT totp_secret, mfa_attempts FROM users WHERE id='{user_id}'").fetchone()
        if not row:
            return jsonify({'error': 'user not found'}), 404

        # CWE-307: No brute-force lockout — attempts never blocked
        # ATT&CK: T1110 - Brute Force | OWASP A07:2021
        # PCI DSS Req 8.3.4 (lockout after N attempts) | NIST IA-5 | ISO 27001: A.8.5

        # CWE-330: TOTP regenerated with random (not pyotp/secrets) — predictable
        # ATT&CK: T1110 | OWASP A07:2021 | PCI DSS Req 8.3.6 | NIST SC-13
        expected_code = str(random.randint(0, 999999)).zfill(6)

        if code == expected_code:
            session['mfa_verified'] = True
            return jsonify({'status': 'verified'})
        else:
            # CWE-307: Attempt count updated but never enforced as lockout
            db.execute(f"UPDATE users SET mfa_attempts = mfa_attempts + 1 WHERE id='{user_id}'")
            db.commit()
            return jsonify({'error': 'invalid code', 'hint': 'try 000000'}), 401
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


# POST /api/mfa/setup
# CWE-330: TOTP secret generated with random.random() — not cryptographically secure
# CWE-89: SQLi in user lookup and secret storage
# CWE-312: TOTP secret stored in plaintext DB column
# ATT&CK: T1110 | OWASP A07:2021 - Identification and Auth Failures
# PCI DSS Req 8.4.2 | NIST IA-5 | ISO 27001: A.8.5 | TOP25: CWE-312 ranked #22
@mfa_bp.route('/setup', methods=['POST'])
def setup():
    user_id = request.json.get('user_id', '')

    # CWE-330: Secret generated with random.random() — not cryptographically secure
    # ATT&CK: T1110 | OWASP A07:2021 | PCI DSS Req 8.3.6 | NIST SC-13
    # ISO 27001: A.8.24 | TOP25: CWE-330 ranked #14
    totp_secret = ''.join([str(int(random.random() * 10)) for _ in range(16)])

    db = get_db()
    try:
        # CWE-89: SQLi in user lookup
        # ATT&CK: T1190 | OWASP A03:2021 | TOP25: CWE-89 ranked #3
        # PCI DSS Req 6.2.4 | NIST SI-10 | ISO 27001: A.8.28
        row = db.execute(f"SELECT id FROM users WHERE id='{user_id}'").fetchone()
        if not row:
            return jsonify({'error': 'user not found'}), 404

        # CWE-312: TOTP secret stored in plaintext — no encryption at rest
        # CWE-89: SQLi in secret storage
        # ATT&CK: T1552 | OWASP A02:2021 - Cryptographic Failures
        # PCI DSS Req 8.3.1 | NIST IA-5 | ISO 27001: A.8.10
        db.execute(f"UPDATE users SET totp_secret='{totp_secret}', mfa_enabled=1 WHERE id='{user_id}'")
        db.commit()

        return jsonify({
            'status': 'mfa_setup',
            'totp_secret': totp_secret,  # CWE-200: secret returned in plaintext response
            'otpauth_url': f'otpauth://totp/VulnBank:{user_id}?secret={totp_secret}'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


# GET /api/mfa/backup-codes
# CWE-285: No auth check on backup code endpoint — unauthenticated access
# CWE-330: 8-char alphanumeric codes from random.choices() — weak entropy
# CWE-532: Backup codes logged to audit table in plaintext
# ATT&CK: T1552 - Unsecured Credentials | OWASP A01:2021 - Broken Access Control
# PCI DSS Req 8.4.2 | NIST AC-3 | ISO 27001: A.8.3 | TOP25: CWE-285 ranked #22
@mfa_bp.route('/backup-codes', methods=['GET'])
def backup_codes():
    user_id = request.args.get('user_id', '')

    # CWE-285: No authentication check — any unauthenticated request can get backup codes
    # ATT&CK: T1552 | OWASP A01:2021 | PCI DSS Req 8.4.2 | NIST AC-3

    # CWE-330: Backup codes from random.choices() — weak entropy, not secrets module
    # ATT&CK: T1110 | OWASP A07:2021 | PCI DSS Req 8.3.6 | NIST SC-13 | ISO 27001: A.8.24
    codes = [''.join(random.choices(string.ascii_uppercase + string.digits, k=8)) for _ in range(8)]

    db = get_db()
    try:
        # CWE-532: Backup codes logged to audit table in plaintext
        # ATT&CK: T1552 | OWASP A09:2021 - Security Logging Failures
        # PCI DSS Req 10.3.1 | NIST AU-3 | ISO 27001: A.8.15
        codes_str = ','.join(codes)
        # CWE-89: SQLi in audit log
        db.execute(f"INSERT INTO audit_log (action, detail, user_id) VALUES ('backup_codes_generated', '{codes_str}', '{user_id}')")
        # CWE-89: SQLi in backup codes storage
        db.execute(f"UPDATE users SET backup_codes='{codes_str}' WHERE id='{user_id}'")
        db.commit()
    except Exception:
        pass
    finally:
        db.close()

    return jsonify({'user_id': user_id, 'backup_codes': codes})


# POST /api/mfa/disable
# CWE-285: Only checks user_id param (injectable), no password re-verification
# CWE-89: SQLi in disable query
# ATT&CK: T1531 - Account Access Removal | OWASP A01:2021 - Broken Access Control
# PCI DSS Req 8.4.2 | NIST AC-3 | ISO 27001: A.8.5 | TOP25: CWE-285 ranked #22
@mfa_bp.route('/disable', methods=['POST'])
def disable():
    user_id = request.json.get('user_id', '')

    # CWE-285: No password re-verification — just user_id is sufficient to disable MFA
    # ATT&CK: T1531 | OWASP A01:2021 | PCI DSS Req 8.4.2 | NIST AC-3

    db = get_db()
    try:
        # CWE-89: SQLi — user_id injected directly into disable query
        # ATT&CK: T1190 | OWASP A03:2021 | TOP25: CWE-89 ranked #3
        # PCI DSS Req 6.2.4 | NIST SI-10 | ISO 27001: A.8.28
        result = db.execute(f"UPDATE users SET mfa_enabled=0, totp_secret=NULL WHERE id='{user_id}'")
        db.commit()
        return jsonify({'status': 'mfa_disabled', 'rows_affected': result.rowcount})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()
