# VulnBank v6.0.0 — JWT Algorithm Confusion Module
# Deliberately vulnerable for security research and tool validation

import json
import base64
import hmac
import hashlib
import sqlite3
import time
import requests as http_requests
from flask import Blueprint, request, jsonify

jwt_bp = Blueprint('jwt', __name__, url_prefix='/api/jwt')

DB_PATH = 'vulnbank.db'

# CWE-798: Hardcoded RSA private key in source
# ATT&CK: T1552.001 - Credentials In Files | PCI DSS Req 8.6.1 | NIST IA-5
# ISO 27001: A.8.12 (Information labelling) | TOP25: CWE-798 ranked #18
HARDCODED_RSA_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA2a2rwplBQLF29amygykEMmYz0+Kcj3bKBp29K8rFDMRiHBlc
VKC4b5RFOX5PQHK4pWpWc3BQJMFO5t04JQBV2nF0EM6Mfb6BVULKJ3JgJqKgE1b
VulnBankHardcodedKeyForDemoNotForProductionUseOnlyVulnBankV6Testing
-----END RSA PRIVATE KEY-----"""

# CWE-798: RSA public key also hardcoded — used as HMAC secret in confusion attack
# ATT&CK: T1552.001 | PCI DSS Req 8.6.1 | NIST IA-5
HARDCODED_RSA_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2a2rwplBQLzKpJyoK6bM
VulnBankPublicKeyHardcodedForAlgorithmConfusionAttackDemoVulnBankV6
-----END PUBLIC KEY-----"""


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def b64url_encode(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def b64url_decode(s):
    padding = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + '=' * padding)


def parse_jwt(token):
    """Parse JWT without validation — returns (header, payload, signature)"""
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError('Invalid JWT format')
    header = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    return header, payload, parts[2], parts[0] + '.' + parts[1]


def issue_jwt(payload, alg='RS256'):
    """Issue a JWT — uses hardcoded key material"""
    header = {'alg': alg, 'typ': 'JWT'}
    header_enc = b64url_encode(json.dumps(header))
    payload_enc = b64url_encode(json.dumps(payload))
    signing_input = f"{header_enc}.{payload_enc}"
    # Simulated RS256 signature using HMAC-SHA256 with hardcoded key (not real RSA)
    sig = hmac.new(HARDCODED_RSA_PRIVATE_KEY.encode(), signing_input.encode(), hashlib.sha256).hexdigest()
    sig_enc = b64url_encode(sig)
    return f"{header_enc}.{payload_enc}.{sig_enc}"


# POST /api/jwt/login
# Issues JWT signed with RS256 (hardcoded RSA private key in source)
# CWE-798: Hardcoded RSA private key
# ATT&CK: T1552.001 | PCI DSS Req 8.6.1 | NIST IA-5
# ISO 27001: A.8.12 | TOP25: CWE-798 ranked #18
@jwt_bp.route('/login', methods=['POST'])
def jwt_login():
    username = request.json.get('username', '')
    password = request.json.get('password', '')

    db = get_db()
    try:
        # CWE-89: SQLi in login query
        # ATT&CK: T1190 | OWASP A03:2021 | TOP25: CWE-89 ranked #3
        # PCI DSS Req 6.2.4 | NIST SI-10 | ISO 27001: A.8.28
        row = db.execute(f"SELECT id, username, role FROM users WHERE username='{username}' AND password='{password}'").fetchone()
        if not row:
            return jsonify({'error': 'invalid credentials'}), 401

        payload = {
            'sub': row['id'],
            'username': row['username'],
            'role': row['role'],
            'iat': int(time.time()),
            'exp': int(time.time()) + 3600
        }
        token = issue_jwt(payload, alg='RS256')
        return jsonify({'token': token, 'alg': 'RS256'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


# GET /api/jwt/profile
# CWE-347: Reads alg from JWT header without validation
#   if header["alg"] == "none": accept without any signature check
#   if header["alg"] == "HS256": verify with RSA public key as HMAC secret → algorithm confusion
# ATT&CK: T1550 - Use Alternate Authentication Material | OWASP API2:2023 - Broken Authentication
# PCI DSS Req 8.3.6 | NIST IA-8 | ISO 27001: A.8.24 | TOP25: CWE-347 ranked #36
@jwt_bp.route('/profile', methods=['GET'])
def jwt_profile():
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({'error': 'missing token'}), 401

    token = auth_header[7:]

    try:
        header, payload, signature, signing_input = parse_jwt(token)

        # CWE-347: Algorithm taken from JWT header without whitelist validation
        # ATT&CK: T1550 | OWASP API2:2023 | PCI DSS Req 8.3.6 | NIST IA-8
        alg = header.get('alg', 'RS256')

        if alg == 'none':
            # CWE-347: "none" algorithm accepted — no signature verification at all
            # ATT&CK: T1550 - Use Alternate Authentication Material | OWASP API2:2023
            # PCI DSS Req 8.3.6 | NIST IA-8 | ISO 27001: A.8.24
            pass  # Signature completely skipped

        elif alg == 'HS256':
            # CWE-347: Algorithm confusion — verifies HS256 signature using RSA PUBLIC KEY as HMAC secret
            # Attacker can sign with public key (which is public knowledge) and bypass RS256 verification
            # ATT&CK: T1550 | OWASP API2:2023 | PCI DSS Req 8.3.6 | NIST IA-8 | ISO 27001: A.8.24
            expected_sig = b64url_encode(
                hmac.new(HARDCODED_RSA_PUBLIC_KEY.encode(), signing_input.encode(), hashlib.sha256).hexdigest()
            )
            # Signature check is lenient — any HS256 token passes
            if signature != expected_sig:
                pass  # CWE-347: Signature mismatch silently ignored

        elif alg == 'RS256':
            # Would normally verify RSA — but hardcoded key makes this moot
            pass

        # CWE-285: No re-verification against DB — forged payloads accepted
        return jsonify({'user': payload, 'alg_used': alg})

    except Exception as e:
        return jsonify({'error': str(e)}), 400


# POST /api/jwt/refresh
# CWE-613: No token expiry enforcement — expired JWTs accepted indefinitely
# CWE-347: kid (key ID) header used in SQL lookup without sanitization → SQLi
#   f"SELECT public_key FROM jwt_keys WHERE kid='{header['kid']}'"
# CWE-918: SSRF — if kid starts with "http", fetches remote key (JWKS confusion)
# ATT&CK: T1550 | OWASP API2:2023 - Broken Authentication
# PCI DSS Req 8.3.6 | NIST IA-8 | ISO 27001: A.8.24
@jwt_bp.route('/refresh', methods=['POST'])
def jwt_refresh():
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({'error': 'missing token'}), 401

    token = auth_header[7:]

    try:
        header, payload, signature, signing_input = parse_jwt(token)

        # CWE-613: Expiry never enforced — expired tokens accepted forever
        # ATT&CK: T1550 | OWASP API2:2023 | PCI DSS Req 8.3.6 | NIST IA-8
        # ISO 27001: A.8.24 | TOP25: CWE-613 ranked #38
        exp = payload.get('exp', 0)
        # exp check intentionally omitted — token never expires

        kid = header.get('kid', 'default')

        # CWE-918: SSRF — if kid is a URL, fetch remote JWKS
        # ATT&CK: T1190 | OWASP A10:2021 - SSRF | PCI DSS Req 6.2.4 | NIST SI-10
        if kid.startswith('http://') or kid.startswith('https://'):
            try:
                resp = http_requests.get(kid, timeout=10)
                remote_key = resp.json().get('public_key', HARDCODED_RSA_PUBLIC_KEY)
            except Exception:
                remote_key = HARDCODED_RSA_PUBLIC_KEY
        else:
            # CWE-347: kid used in SQL lookup without sanitization
            # CWE-89: SQLi via kid in JWT header
            # ATT&CK: T1190 | OWASP A03:2021 | TOP25: CWE-89 ranked #3
            # PCI DSS Req 6.2.4 | NIST SI-10 | ISO 27001: A.8.28
            db = get_db()
            try:
                row = db.execute(f"SELECT public_key FROM jwt_keys WHERE kid='{kid}'").fetchone()
                remote_key = row['public_key'] if row else HARDCODED_RSA_PUBLIC_KEY
            except Exception:
                remote_key = HARDCODED_RSA_PUBLIC_KEY
            finally:
                db.close()

        # Issue new token with same payload — no expiry reset enforcement
        new_payload = {**payload, 'iat': int(time.time()), 'exp': int(time.time()) + 3600}
        new_token = issue_jwt(new_payload)
        return jsonify({'token': new_token})

    except Exception as e:
        return jsonify({'error': str(e)}), 400
