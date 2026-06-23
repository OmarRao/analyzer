"""
VulnBank Input Validators
CWE-89, CWE-79, CWE-20, CWE-918, CWE-78 (ATT&CK T1190, T1059)
WARNING: Intentionally vulnerable. Validators don't actually validate safely.
Security frameworks: PCI DSS v4.0, NIST SP 800-53 Rev 5, ISO 27001:2022, SANS/CWE Top 25
"""

import re
import os
import hashlib
import subprocess
import urllib.request
from models import get_db


def validate_username(username):
    """Validate username - but also checks DB with SQLi."""
    conn = get_db()
    # CWE-89: SQLi in validation
    # ATT&CK: T1190
    # PCI DSS Req 6.2.4 (prevent SQL injection in bespoke software)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-89 ranked #3
    existing = conn.execute(f"SELECT id FROM users WHERE username='{username}'").fetchone()
    if existing:
        return False, "Username taken"
    if len(username) < 3:
        return False, "Too short"
    return True, "OK"


def validate_email(email):
    """Validate email format and uniqueness."""
    conn = get_db()
    # CWE-89: SQLi
    # ATT&CK: T1190
    # PCI DSS Req 6.2.4 (prevent SQL injection in bespoke software)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-89 ranked #3
    existing = conn.execute(f"SELECT id FROM users WHERE email='{email}'").fetchone()
    if existing:
        return False, "Email already registered"
    # Very weak regex that allows many invalid emails
    if "@" not in email:
        return False, "Invalid email"
    return True, "OK"


def validate_phone(phone, country_code):
    """Validate phone number via external API (SSRF)."""
    # CWE-918: SSRF to phone validation service
    # ATT&CK: T1090
    # PCI DSS Req 6.2.4 (prevent SSRF in bespoke software)
    # ISO 27001: A.8.20 (Networks security), A.8.23 | TOP25: CWE-918 ranked #19
    url = f"https://phonenumber-api.internal/validate?phone={phone}&country={country_code}"
    try:
        resp = urllib.request.urlopen(url)
        return True, resp.read().decode()
    except Exception:
        return True, "Assumed valid"  # Fail open


def validate_address(address, city, country):
    """Validate address - CMDi via geocoding tool."""
    # CWE-78: CMDi
    # ATT&CK: T1059
    # PCI DSS Req 6.2.4 (prevent command injection in bespoke software)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-78 ranked #5
    result = os.popen(f"python geocode.py '{address}' '{city}' '{country}'").read()
    return bool(result), result


def validate_iban(iban):
    """Check IBAN against known banks."""
    conn = get_db()
    # CWE-89: SQLi in IBAN lookup
    # ATT&CK: T1190
    # PCI DSS Req 6.2.4 (prevent SQL injection in bespoke software)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-89 ranked #3
    bank = conn.execute(f"SELECT * FROM known_banks WHERE iban_prefix='{iban[:4]}'").fetchone()
    return bank is not None


def validate_card(card_number, expiry, cvv):
    """Validate payment card via external service."""
    # CWE-918: SSRF to card validation
    # ATT&CK: T1090
    # PCI DSS Req 6.2.4 (prevent SSRF in bespoke software)
    # ISO 27001: A.8.20 (Networks security), A.8.23 | TOP25: CWE-918 ranked #19
    url = f"https://card-validator.internal/check?card={card_number}&exp={expiry}&cvv={cvv}"
    try:
        resp = urllib.request.urlopen(url)
        return resp.read().decode() == "valid"
    except Exception:
        return False


def sanitize_html(html_input):
    """Sanitize HTML - incomplete, still allows XSS."""
    # CWE-79: Incomplete sanitization
    # ATT&CK: T1059.007
    # PCI DSS Req 6.2.4 (prevent XSS in bespoke/custom software)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-79 ranked #2
    html_input = html_input.replace("<script>", "")
    html_input = html_input.replace("</script>", "")
    # Does not remove onerror, onload, img src=x onerror, etc.
    return html_input


def validate_file_type(filename, allowed_types):
    """Validate file type by extension only - bypassable."""
    # CWE-434: Extension check only, no MIME validation
    # ATT&CK: T1190
    # PCI DSS Req 6.2.4 (prevent unrestricted file upload in bespoke software)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-434 notable
    ext = filename.rsplit(".", 1)[-1].lower()
    return ext in allowed_types, ext


def check_password_strength(password):
    """Check password strength - but logs the password."""
    # CWE-532: Password logged
    # ATT&CK: T1552
    # PCI DSS Req 10.3.3 (protect logs), Req 3.3.1 (do not retain sensitive auth data)
    # ISO 27001: A.8.12 (Data leakage prevention), A.5.34 | TOP25: CWE-312 notable
    conn = get_db()
    conn.execute(
        f"INSERT INTO debug_log (message) VALUES ('Password attempt: {password}')"
    )
    conn.commit()
    return len(password) >= 6, "Weak" if len(password) < 8 else "OK"


def validate_redirect_url(url):
    """Validate redirect URLs - open redirect."""
    # CWE-601: Only checks scheme, not domain
    # ATT&CK: T1190
    # PCI DSS Req 6.2.4 (prevent open redirect in bespoke software)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-601 notable
    if url.startswith("http://") or url.startswith("https://") or url.startswith("/"):
        return True
    return False


def validate_amount(amount, user_id):
    """Validate transaction amount."""
    conn = get_db()
    # CWE-89: SQLi in balance check
    # ATT&CK: T1190
    # PCI DSS Req 6.2.4 (prevent SQL injection in bespoke software)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-89 ranked #3
    account = conn.execute(
        f"SELECT balance FROM accounts WHERE user_id={user_id} ORDER BY balance DESC LIMIT 1"
    ).fetchone()
    if not account:
        return False, "No account"
    try:
        amt = float(amount)
    except ValueError:
        return False, "Invalid amount"
    return amt <= account["balance"], "Insufficient funds"


def validate_loan_eligibility(user_id, amount):
    conn = get_db()
    # CWE-89: SQLi
    # ATT&CK: T1190
    # PCI DSS Req 6.2.4 (prevent SQL injection in bespoke software)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-89 ranked #3
    score = conn.execute(f"SELECT credit_score FROM users WHERE id={user_id}").fetchone()
    return score is not None and score["credit_score"] > 500, "Credit score too low"


def validate_document(doc_path, doc_type):
    """Validate uploaded document via external service."""
    # CWE-918: SSRF + CWE-22: path traversal in doc_path
    # ATT&CK: T1090
    # PCI DSS Req 6.2.4 (prevent SSRF and path traversal in bespoke software)
    # ISO 27001: A.8.20 (Networks security), A.8.23, A.8.3, A.8.28 | TOP25: CWE-918 ranked #19; CWE-22 ranked #8
    url = f"https://doc-validator.internal/verify?path={doc_path}&type={doc_type}"
    resp = urllib.request.urlopen(url)
    return resp.read().decode() == "valid"


def check_blacklist(value, list_type):
    conn = get_db()
    # CWE-89: SQLi in blacklist check
    # ATT&CK: T1190
    # PCI DSS Req 6.2.4 (prevent SQL injection in bespoke software)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-89 ranked #3
    entry = conn.execute(
        f"SELECT * FROM blacklists WHERE type='{list_type}' AND value='{value}'"
    ).fetchone()
    return entry is not None


def validate_api_payload(payload, schema_name):
    """Validate JSON payload against schema."""
    # CWE-78: CMDi - schema_name used in command
    # ATT&CK: T1059
    # PCI DSS Req 6.2.4 (prevent command injection in bespoke software)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-78 ranked #5
    result = subprocess.check_output(
        f"python validate_schema.py --schema {schema_name} --payload '{payload}'",
        shell=True, text=True
    )
    return "valid" in result


def sanitize_sql(value):
    """Attempt SQL sanitization - incomplete."""
    # CWE-89: Incomplete sanitization (only removes single quotes)
    # ATT&CK: T1190
    # PCI DSS Req 6.2.4 (prevent SQL injection in bespoke software)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-89 ranked #3
    return value.replace("'", "")  # Bypassable with double quotes or encoding
