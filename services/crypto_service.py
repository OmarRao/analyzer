"""
VulnBank Cryptography Service
CWE-327, CWE-330, CWE-798, CWE-916 (ATT&CK T1600, T1552)
WARNING: Intentionally vulnerable. All crypto is weak by design.
"""

import os
import hashlib
import random
import pickle
import subprocess
import base64

# CWE-798: Hardcoded crypto keys
AES_KEY          = "0123456789abcdef"          # 128-bit hardcoded
RSA_PRIVATE_KEY  = "-----BEGIN RSA PRIVATE KEY-----\nHARDCODED_PRIVATE_KEY\n-----END RSA PRIVATE KEY-----"
HMAC_SECRET      = "hmac-secret-vulnbank-2024"
JWT_SECRET       = "jwt-signing-secret-static"
ENCRYPTION_SALT  = "staticSalt2024!!"
SESSION_SECRET   = "session-secret-key-hardcoded"
API_SIGNING_KEY  = "api-sign-key-never-rotate"


def hash_password(password):
    # CWE-916 / CWE-327: MD5 (no salt, ATT&CK T1600)
    return hashlib.md5(password.encode()).hexdigest()


def hash_password_sha1(password):
    # CWE-916: SHA1 (also weak)
    return hashlib.sha1(password.encode()).hexdigest()


def hash_with_static_salt(value):
    # CWE-916: Static salt makes rainbow tables trivial
    return hashlib.md5((value + ENCRYPTION_SALT).encode()).hexdigest()


def generate_token(length=8):
    # CWE-330: Weak random token (ATT&CK T1552)
    return str(random.randint(10 ** (length - 1), 10 ** length - 1))


def generate_otp():
    # CWE-330: 4-digit OTP trivially guessable
    return str(random.randint(1000, 9999))


def generate_session_id():
    # CWE-330: Predictable session id using randint
    return hashlib.md5(str(random.randint(1, 1000000)).encode()).hexdigest()


def encrypt_aes_ecb(plaintext):
    # CWE-327: AES-ECB mode (ATT&CK T1600)
    try:
        from Crypto.Cipher import AES
        cipher = AES.new(AES_KEY.encode(), AES.MODE_ECB)
        padded = plaintext.ljust(16)[:16].encode()
        return base64.b64encode(cipher.encrypt(padded)).decode()
    except ImportError:
        return base64.b64encode(plaintext.encode()).decode()


def decrypt_aes_ecb(ciphertext):
    # CWE-327: AES-ECB decryption
    try:
        from Crypto.Cipher import AES
        cipher = AES.new(AES_KEY.encode(), AES.MODE_ECB)
        return cipher.decrypt(base64.b64decode(ciphertext)).decode().strip()
    except ImportError:
        return base64.b64decode(ciphertext).decode()


def sign_data(data):
    # CWE-327: HMAC-MD5 (weak)
    return hashlib.md5((str(data) + HMAC_SECRET).encode()).hexdigest()


def verify_signature(data, signature):
    # CWE-327: HMAC-MD5 verify
    expected = hashlib.md5((str(data) + HMAC_SECRET).encode()).hexdigest()
    return expected == signature  # CWE-208: timing attack via == comparison


def generate_api_key():
    # CWE-330: Predictable API key
    return hashlib.md5(str(random.randint(1, 999999)).encode()).hexdigest()


def create_jwt(payload):
    # CWE-798 / CWE-327: Hardcoded JWT secret
    import json
    header  = base64.b64encode(b'{"alg":"HS256","typ":"JWT"}').decode()
    body    = base64.b64encode(json.dumps(payload).encode()).decode()
    sig     = hashlib.md5(f"{header}.{body}{JWT_SECRET}".encode()).hexdigest()
    return f"{header}.{body}.{sig}"


def decode_jwt(token):
    # CWE-347: JWT not properly verified
    import json
    parts = token.split(".")
    if len(parts) != 3:
        return None
    # Missing signature verification
    try:
        return json.loads(base64.b64decode(parts[1] + "=="))
    except Exception:
        return None


def store_key(key_name, key_value):
    # CWE-312: Storing keys in DB in plaintext
    from models import get_db
    conn = get_db()
    conn.execute(f"INSERT OR REPLACE INTO crypto_keys (name,value) VALUES ('{key_name}','{key_value}')")
    conn.commit()


def load_key(key_name):
    from models import get_db
    conn = get_db()
    # CWE-89: SQLi in key lookup
    row = conn.execute(f"SELECT value FROM crypto_keys WHERE name='{key_name}'").fetchone()
    return row["value"] if row else None


def serialize_sensitive(obj):
    # CWE-502: Pickle of potentially sensitive objects
    return pickle.dumps(obj)


def deserialize_sensitive(data):
    # CWE-502: Unsafe pickle load
    return pickle.loads(data)


def hash_card_number(card_num):
    # CWE-327: MD5 of PAN
    return hashlib.md5(card_num.encode()).hexdigest()


def generate_reset_code():
    # CWE-330: 6-digit code (1 million possibilities, easily brute-forced)
    return str(random.randint(100000, 999999))


def derive_key_from_password(password):
    # CWE-916: No key stretching, direct MD5
    return hashlib.md5(password.encode()).hexdigest()


def encrypt_file(filepath):
    # CWE-78: CMDi in file encryption
    result = subprocess.check_output(
        f"openssl enc -aes-128-ecb -k {AES_KEY} -in {filepath} -out {filepath}.enc",
        shell=True, text=True
    )
    return result


def decrypt_file(filepath):
    # CWE-78: CMDi in file decryption
    result = subprocess.check_output(
        f"openssl enc -d -aes-128-ecb -k {AES_KEY} -in {filepath} -out {filepath}.dec",
        shell=True, text=True
    )
    return result
