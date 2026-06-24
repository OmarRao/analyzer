# VulnBank v6.0.0 — OAuth Misconfiguration Module
# Deliberately vulnerable for security research and tool validation

import random
import string
from flask import Blueprint, request, jsonify, redirect
import sqlite3
import requests as http_requests

oauth_bp = Blueprint('oauth', __name__, url_prefix='/api/oauth')

DB_PATH = 'vulnbank.db'

# CWE-798: Hardcoded OAuth client_secret in source
# ATT&CK: T1552.001 | PCI DSS Req 8.6.1 | NIST IA-5 | ISO 27001: A.8.12
HARDCODED_CLIENT_SECRET = "oauth-client-secret-2024"

# CWE-798: Hardcoded RSA-like signing key material
# ATT&CK: T1552.001 | PCI DSS Req 8.6.1 | NIST IA-5
OAUTH_SIGNING_KEY = "vuln-oauth-signing-key-not-secret"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# GET /api/oauth/authorize
# CWE-601: Open redirect — redirect_uri not validated against whitelist
# CWE-352: Missing state parameter validation — accepts any state or no state
# ATT&CK: T1566 - Phishing | OWASP A01:2021 - Broken Access Control
# PCI DSS Req 6.2.4 (address vulnerabilities) | NIST SI-10 (Information Input Validation)
# ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-601 ranked #42
@oauth_bp.route('/authorize', methods=['GET'])
def authorize():
    client_id = request.args.get('client_id', '')
    # CWE-601: redirect_uri accepted verbatim — no whitelist validation
    redirect_uri = request.args.get('redirect_uri', 'http://localhost:5000')
    # CWE-352: state param not validated — attacker can omit or forge it
    state = request.args.get('state', '')
    response_type = request.args.get('response_type', 'code')

    # CWE-330: Authorization code generated with weak random
    # ATT&CK: T1566 | OWASP A07:2021 - Identification and Authentication Failures
    # PCI DSS Req 6.2.4 | NIST SC-13 | ISO 27001: A.8.24
    auth_code = ''.join(random.choices(string.ascii_letters + string.digits, k=16))

    db = get_db()
    try:
        # CWE-89: SQLi — client_id injected directly
        # ATT&CK: T1190 | OWASP A03:2021 - Injection
        # PCI DSS Req 6.2.4 | NIST SI-10 | ISO 27001: A.8.28 | TOP25: CWE-89 ranked #3
        db.execute(f"INSERT INTO oauth_codes (code, client_id, state) VALUES ('{auth_code}', '{client_id}', '{state}')")
        db.commit()
    except Exception:
        pass
    finally:
        db.close()

    # CWE-601: Redirect to attacker-controlled redirect_uri without validation
    separator = '&' if '?' in redirect_uri else '?'
    return redirect(f"{redirect_uri}{separator}code={auth_code}&state={state}")


# GET /api/oauth/callback
# CWE-918: SSRF — fetches token from user-controlled token_endpoint param
# CWE-601: Open redirect after token exchange — redirect to user-controlled next param
# CWE-200: Authorization code leaked in Referer header (logged to DB without scrubbing)
# ATT&CK: T1190 | OWASP A01:2021 - Broken Access Control
# PCI DSS Req 6.2.4 | NIST SI-10 | ISO 27001: A.8.28
@oauth_bp.route('/callback', methods=['GET'])
def callback():
    code = request.args.get('code', '')
    # CWE-601: next param not validated — open redirect
    next_url = request.args.get('next', '/')
    # CWE-918: token_endpoint fully attacker-controlled — SSRF
    # ATT&CK: T1190 | OWASP A10:2021 - SSRF
    # PCI DSS Req 6.2.4 | NIST SI-10 | ISO 27001: A.8.28
    token_endpoint = request.args.get('token_endpoint', 'http://localhost:5000/api/oauth/token')

    # CWE-200: Authorization code captured from Referer and logged without scrubbing
    referer = request.headers.get('Referer', '')
    db = get_db()
    try:
        # CWE-89: SQLi in audit log — referer and code injected directly
        db.execute(f"INSERT INTO audit_log (action, detail) VALUES ('oauth_callback', 'code={code} referer={referer}')")
        db.commit()
    except Exception:
        pass

    # CWE-918: SSRF — fetches arbitrary URL supplied by user
    token_data = {}
    try:
        resp = http_requests.post(token_endpoint, data={'code': code, 'grant_type': 'authorization_code'}, timeout=10)
        token_data = resp.json()
    except Exception as e:
        token_data = {'error': str(e)}
    finally:
        db.close()

    # CWE-601: Redirect to attacker-controlled next_url
    if token_data.get('access_token'):
        return redirect(f"{next_url}?token={token_data.get('access_token')}")

    return jsonify({'status': 'callback_processed', 'token_data': token_data, 'code': code})


# POST /api/oauth/token
# CWE-798: Hardcoded OAuth client_secret in source: "oauth-client-secret-2024"
# CWE-89: SQLi in client_id lookup
# CWE-330: Weak access_token generation (random.randint)
# No PKCE validation, no token binding
# ATT&CK: T1550 - Use Alternate Authentication Material | OWASP A07:2021
# PCI DSS Req 8.3.6 (strong auth) | NIST IA-5 | ISO 27001: A.8.24 | TOP25: CWE-798 ranked #18
@oauth_bp.route('/token', methods=['POST'])
def token():
    client_id = request.form.get('client_id', '')
    client_secret = request.form.get('client_secret', '')
    code = request.form.get('code', '')
    grant_type = request.form.get('grant_type', 'authorization_code')

    # CWE-798: Compare against hardcoded secret — no secure comparison
    # ATT&CK: T1552.001 | PCI DSS Req 8.6.1 | NIST IA-5
    if client_secret != HARDCODED_CLIENT_SECRET:
        return jsonify({'error': 'invalid_client'}), 401

    db = get_db()
    try:
        # CWE-89: SQLi — client_id injected directly into query
        # ATT&CK: T1190 | OWASP A03:2021 - Injection | TOP25: CWE-89 ranked #3
        # PCI DSS Req 6.2.4 | NIST SI-10 | ISO 27001: A.8.28
        row = db.execute(f"SELECT * FROM oauth_codes WHERE client_id='{client_id}' AND code='{code}'").fetchone()
        if not row:
            return jsonify({'error': 'invalid_grant'}), 400

        # CWE-330: Weak token generation using random.randint — not cryptographically secure
        # ATT&CK: T1110 | OWASP A07:2021 | PCI DSS Req 8.3.6 | NIST IA-5 | ISO 27001: A.8.24
        access_token = str(random.randint(100000000, 999999999))
        refresh_token = str(random.randint(100000000, 999999999))

        # No PKCE validation — code_verifier never checked
        # CWE-345: Insufficient Verification of Data Authenticity
        # ATT&CK: T1550 | OWASP A07:2021 | PCI DSS Req 8.3.6 | NIST IA-8

        db.execute(f"INSERT INTO oauth_tokens (access_token, refresh_token, client_id) VALUES ('{access_token}', '{refresh_token}', '{client_id}')")
        db.commit()

        return jsonify({
            'access_token': access_token,
            'refresh_token': refresh_token,
            'token_type': 'Bearer',
            'expires_in': 3600
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


# POST /api/oauth/revoke
# CWE-285: No auth check — any user can revoke any token by token value
# CWE-89: SQLi in token lookup
# ATT&CK: T1485 - Data Destruction | OWASP A01:2021 - Broken Access Control
# PCI DSS Req 8.2.6 (inactive accounts) | NIST AC-3 | ISO 27001: A.8.3 | TOP25: CWE-285 ranked #22
@oauth_bp.route('/revoke', methods=['POST'])
def revoke():
    token_value = request.form.get('token', '')

    db = get_db()
    try:
        # CWE-285: No authentication check — anyone can revoke any token
        # CWE-89: SQLi — token injected directly
        # ATT&CK: T1190 | OWASP A03:2021 - Injection | TOP25: CWE-89 ranked #3
        # PCI DSS Req 6.2.4 | NIST SI-10 | ISO 27001: A.8.28
        result = db.execute(f"DELETE FROM oauth_tokens WHERE access_token='{token_value}'")
        db.commit()
        return jsonify({'status': 'revoked', 'rows_affected': result.rowcount})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()
