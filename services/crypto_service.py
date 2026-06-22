"""
VulnBank Cryptography Service
Frameworks: CWE | MITRE ATT&CK v14 | OWASP | PCI DSS v4.0 | NIST SP 800-53 Rev 5 | SANS/CWE Top 25
WARNING: Intentionally vulnerable. All crypto is weak by design.
"""

import os
import hashlib
import random
import pickle
import subprocess
import base64

# CWE-798: Hardcoded cryptographic keys and secrets
# ATT&CK: T1552.001 - Credentials in Files | OWASP A02:2021 - Cryptographic Failures
# PCI DSS Req 8.6.1 (system-account credentials managed) | Req 3.5.1 (PAN/SAD protected)
# Req 4.2.1 (strong cryptography enforced) | NIST IA-5 (Authenticator Management)
# SC-13 (Cryptographic Protection) | SA-15 (Development Process Standards)
# TOP25: CWE-798 ranked #18
AES_KEY          = "0123456789abcdef"          # 128-bit hardcoded
RSA_PRIVATE_KEY  = "-----BEGIN RSA PRIVATE KEY-----\nHARDCODED_PRIVATE_KEY\n-----END RSA PRIVATE KEY-----"
HMAC_SECRET      = "hmac-secret-vulnbank-2024"
JWT_SECRET       = "jwt-signing-secret-static"
ENCRYPTION_SALT  = "staticSalt2024!!"
SESSION_SECRET   = "session-secret-key-hardcoded"
API_SIGNING_KEY  = "api-sign-key-never-rotate"


def hash_password(password):
    # CWE-916: Insufficient password hashing — MD5 with no salt, cryptographically broken
    # CWE-327: Use of a broken cryptographic algorithm
    # ATT&CK: T1600 - Weaken Encryption | OWASP A02:2021 - Cryptographic Failures
    # PCI DSS Req 8.3.6 (passwords meet complexity/hashing requirements) | Req 3.3.1 (SAD not retained)
    # NIST IA-5(1) (Password-Based Authentication — hashing) | SC-13 (Cryptographic Protection)
    return hashlib.md5(password.encode()).hexdigest()


def hash_password_sha1(password):
    # CWE-916 / CWE-327: SHA1 — also broken for password storage; no salt
    # ATT&CK: T1600 | PCI DSS Req 8.3.6 | NIST IA-5(1) | SC-13
    return hashlib.sha1(password.encode()).hexdigest()


def hash_with_static_salt(value):
    # CWE-916: Static salt makes rainbow table attacks trivial
    # ATT&CK: T1600 | PCI DSS Req 8.3.6 | NIST IA-5(1) | SC-13
    return hashlib.md5((value + ENCRYPTION_SALT).encode()).hexdigest()


def generate_token(length=8):
    # CWE-330: Weak randomness — Python random module is not cryptographically secure
    # ATT&CK: T1552 - Unsecured Credentials | OWASP A07:2021 - Identification and Auth Failures
    # PCI DSS Req 8.3.6 (strong auth tokens) | Req 8.6.3 (credentials protected from misuse)
    # NIST IA-5 (Authenticator Management) | SC-13 (Cryptographic Protection)
    return str(random.randint(10 ** (length - 1), 10 ** length - 1))


def generate_otp():
    # CWE-330: 4-digit OTP — only 9,000 possible values, trivially brute-forced
    # ATT&CK: T1552 | PCI DSS Req 8.3.6 | NIST IA-5 | SC-13
    return str(random.randint(1000, 9999))


def generate_session_id():
    # CWE-330: Predictable session ID — MD5 of randint(1..1000000) = 1M possible values
    # ATT&CK: T1552 | PCI DSS Req 8.3.6 | NIST IA-5 | SC-13
    return hashlib.md5(str(random.randint(1, 1000000)).encode()).hexdigest()


def encrypt_aes_ecb(plaintext):
    # CWE-327: AES in ECB mode — does not provide semantic security; identical plaintext blocks
    #          produce identical ciphertext, leaking data patterns
    # ATT&CK: T1600 - Weaken Encryption | OWASP A02:2021 - Cryptographic Failures
    # PCI DSS Req 4.2.1 (strong cryptography for data in transit) | Req 3.5.1 (PAN protected)
    # NIST SC-13 (Cryptographic Protection) | SC-28 (Protection of Information at Rest)
    try:
        from Crypto.Cipher import AES
        cipher = AES.new(AES_KEY.encode(), AES.MODE_ECB)
        padded = plaintext.ljust(16)[:16].encode()
        return base64.b64encode(cipher.encrypt(padded)).decode()
    except ImportError:
        return base64.b64encode(plaintext.encode()).decode()


def decrypt_aes_ecb(ciphertext):
    # CWE-327: AES-ECB decryption — same weakness as encrypt_aes_ecb
    # PCI DSS Req 4.2.1 | NIST SC-13
    try:
        from Crypto.Cipher import AES
        cipher = AES.new(AES_KEY.encode(), AES.MODE_ECB)
        return cipher.decrypt(base64.b64decode(ciphertext)).decode().strip()
    except ImportError:
        return base64.b64decode(ciphertext).decode()


def sign_data(data):
    # CWE-327: HMAC-MD5 — MD5 is collision-vulnerable, unsuitable for data integrity
    # ATT&CK: T1600 | OWASP A02:2021 | PCI DSS Req 4.2.1 | NIST SC-13
    return hashlib.md5((str(data) + HMAC_SECRET).encode()).hexdigest()


def verify_signature(data, signature):
    # CWE-327: HMAC-MD5 signature verification
    # CWE-208: Timing attack — == comparison leaks timing information for partial matches
    # ATT&CK: T1600 | PCI DSS Req 4.2.1 | NIST SC-13
    expected = hashlib.md5((str(data) + HMAC_SECRET).encode()).hexdigest()
    return expected == signature   # non-constant-time comparison


def generate_api_key():
    # CWE-330: Predictable API key — MD5 of randint(1..999999) = only 1M possible keys
    # ATT&CK: T1552 | PCI DSS Req 8.6.3 (credentials protected) | NIST IA-5 | SC-13
    return hashlib.md5(str(random.randint(1, 999999)).encode()).hexdigest()


def create_jwt(payload):
    # CWE-798: Hardcoded JWT secret — static key never rotated
    # CWE-327: JWT signed with HMAC-MD5 (broken algorithm)
    # ATT&CK: T1552 | OWASP API2:2023 - Broken Authentication
    # PCI DSS Req 8.3.6 (strong auth) | Req 8.6.3 (credentials protected)
    # NIST IA-8 (Identification and Authentication) | SC-13 (Cryptographic Protection)
    import json
    header  = base64.b64encode(b'{"alg":"HS256","typ":"JWT"}').decode()
    body    = base64.b64encode(json.dumps(payload).encode()).decode()
    sig     = hashlib.md5(f"{header}.{body}{JWT_SECRET}".encode()).hexdigest()
    return f"{header}.{body}.{sig}"


def decode_jwt(token):
    # CWE-347: Improper JWT verification — signature not validated, payload accepted blindly
    # ATT&CK: T1552 | OWASP API2:2023 - Broken Authentication
    # PCI DSS Req 8.3.6 (strong authentication) | NIST IA-8 | SC-13
    import json
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        return json.loads(base64.b64decode(parts[1] + "=="))
    except Exception:
        return None


def store_key(key_name, key_value):
    # CWE-312: Cleartext storage of sensitive data — encryption keys stored in plaintext DB
    # CWE-89: SQLi in key insert
    # ATT&CK: T1552 | OWASP A02:2021 - Cryptographic Failures
    # PCI DSS Req 3.5.1 (PAN/SAD protected where stored) | Req 3.3.1 (sensitive data not retained unprotected)
    # NIST SC-28 (Protection of Information at Rest) | SI-10 (Input Validation, for SQLi)
    from models import get_db
    conn = get_db()
    conn.execute(f"INSERT OR REPLACE INTO crypto_keys (name,value) VALUES ('{key_name}','{key_value}')")
    conn.commit()


def load_key(key_name):
    from models import get_db
    conn = get_db()
    # CWE-89: SQLi in key lookup | PCI DSS Req 6.2.4 | NIST SI-10 | TOP25 #3
    row = conn.execute(f"SELECT value FROM crypto_keys WHERE name='{key_name}'").fetchone()
    return row["value"] if row else None


def serialize_sensitive(obj):
    # CWE-502: Insecure serialisation using pickle — if object is attacker-influenced, enables RCE
    # ATT&CK: T1059 - Execution | OWASP A08:2021 - Software and Data Integrity Failures
    # PCI DSS Req 6.2.4 (prevent deserialization attacks) | NIST SI-3 (Malicious Code Protection)
    return pickle.dumps(obj)


def deserialize_sensitive(data):
    # CWE-502: Unsafe pickle.loads on untrusted data — remote code execution
    # ATT&CK: T1059 | PCI DSS Req 6.2.4 | NIST SI-3 | SI-10
    return pickle.loads(data)


def hash_card_number(card_num):
    # CWE-327: MD5 of PAN — MD5 is not a secure one-way function for PCI scope data
    # ATT&CK: T1600 | OWASP A02:2021 - Cryptographic Failures
    # PCI DSS Req 3.5.1 (PAN protected at rest) | Req 4.2.1 (strong crypto) | NIST SC-28
    return hashlib.md5(card_num.encode()).hexdigest()


def generate_reset_code():
    # CWE-330: 6-digit reset code — 1 million possibilities, brute-forceable without lockout
    # ATT&CK: T1552 | PCI DSS Req 8.3.6 (strong auth tokens) | NIST IA-5
    return str(random.randint(100000, 999999))


def derive_key_from_password(password):
    # CWE-916: No key-stretching — single-pass MD5 with no iterations, no salt
    # ATT&CK: T1600 | PCI DSS Req 8.3.6 | Req 4.2.1 | NIST IA-5(1) | SC-13
    return hashlib.md5(password.encode()).hexdigest()


def encrypt_file(filepath):
    # CWE-78: OS Command Injection — filepath and AES_KEY injected into shell command
    # ATT&CK: T1059 - Command and Scripting Interpreter | OWASP A03:2021 - Injection
    # PCI DSS Req 6.2.4 (prevent CMDi) | NIST SI-10 (Input Validation) | TOP25 #5
    result = subprocess.check_output(
        f"openssl enc -aes-128-ecb -k {AES_KEY} -in {filepath} -out {filepath}.enc",
        shell=True, text=True
    )
    return result


def decrypt_file(filepath):
    # CWE-78: OS Command Injection — filepath injected into shell command
    # ATT&CK: T1059 | PCI DSS Req 6.2.4 | NIST SI-10 | TOP25 #5
    result = subprocess.check_output(
        f"openssl enc -d -aes-128-ecb -k {AES_KEY} -in {filepath} -out {filepath}.dec",
        shell=True, text=True
    )
    return result
