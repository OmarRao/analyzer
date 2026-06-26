"""
VulnBank - Insecure Direct Object Reference (IDOR)
CWE-639: Authorization Bypass Through User-Controlled Key

Framework annotations:
  CWE: CWE-639, CWE-285 (Improper Authorization)
  MITRE ATT&CK: T1078 (Valid Accounts), T1565 (Data Manipulation)
  OWASP: A01:2021 - Broken Access Control, API1:2023 - Broken Object Level Authorization
  PCI DSS: Req 7.2 (access control systems), Req 7.3
  NIST: AC-3 (Access Enforcement), AC-6 (Least Privilege)
  SANS Top 25: Not ranked (but extremely common)
  ISO 27001: A.9.4.1 (Information access restriction)
"""

import sqlite3
import os
from flask import Blueprint, request, jsonify

idor_bp = Blueprint("idor", __name__)

IDOR_DB = "/tmp/vulnbank.db"


def get_idor_db():
    conn = sqlite3.connect(IDOR_DB)
    conn.row_factory = sqlite3.Row
    return conn


def init_idor_db():
    """Seed the IDOR demo database with accounts, users, beneficiaries, and statements."""
    conn = sqlite3.connect(IDOR_DB)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY,
            owner_id INTEGER,
            account_number TEXT,
            balance REAL,
            notification_email TEXT,
            daily_limit REAL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS account_transactions (
            id INTEGER PRIMARY KEY,
            account_id INTEGER,
            amount REAL,
            description TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS user_profiles (
            id INTEGER PRIMARY KEY,
            username TEXT,
            email TEXT,
            phone TEXT,
            address TEXT,
            ssn TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS beneficiaries (
            id INTEGER PRIMARY KEY,
            owner_id INTEGER,
            name TEXT,
            account_number TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS statements (
            id INTEGER PRIMARY KEY,
            account_id INTEGER,
            period TEXT,
            pdf_path TEXT
        )
    """)
    # Seed data
    conn.execute("INSERT OR IGNORE INTO accounts VALUES (1, 1, 'ACC-001', 50000.00, 'admin@vulnbank.com', 5000.00)")
    conn.execute("INSERT OR IGNORE INTO accounts VALUES (2, 2, 'ACC-002', 1500.00, 'alice@vulnbank.com', 1000.00)")
    conn.execute("INSERT OR IGNORE INTO accounts VALUES (3, 3, 'ACC-003', 800.00, 'bob@vulnbank.com', 500.00)")
    conn.execute("INSERT OR IGNORE INTO account_transactions VALUES (1, 1, -1000.00, 'Wire transfer out', '2024-01-01')")
    conn.execute("INSERT OR IGNORE INTO account_transactions VALUES (2, 2, 500.00, 'Payroll deposit', '2024-01-02')")
    conn.execute("INSERT OR IGNORE INTO account_transactions VALUES (3, 3, -200.00, 'ATM withdrawal', '2024-01-03')")
    conn.execute("INSERT OR IGNORE INTO user_profiles VALUES (1, 'admin', 'admin@vulnbank.com', '555-0001', '1 Bank St', '123-45-6789')")
    conn.execute("INSERT OR IGNORE INTO user_profiles VALUES (2, 'alice', 'alice@vulnbank.com', '555-0002', '2 Main Ave', '987-65-4321')")
    conn.execute("INSERT OR IGNORE INTO user_profiles VALUES (3, 'bob', 'bob@vulnbank.com', '555-0003', '3 Oak Rd', '111-22-3333')")
    conn.execute("INSERT OR IGNORE INTO beneficiaries VALUES (1, 2, 'Alice Mom', 'EXT-999')")
    conn.execute("INSERT OR IGNORE INTO beneficiaries VALUES (2, 2, 'Alice Work', 'EXT-888')")
    conn.execute("INSERT OR IGNORE INTO beneficiaries VALUES (3, 3, 'Bob Friend', 'EXT-777')")
    conn.execute("INSERT OR IGNORE INTO statements VALUES (1, 1, '2024-01', '/statements/admin_jan.pdf')")
    conn.execute("INSERT OR IGNORE INTO statements VALUES (2, 2, '2024-01', '/statements/alice_jan.pdf')")
    conn.execute("INSERT OR IGNORE INTO statements VALUES (3, 3, '2024-01', '/statements/bob_jan.pdf')")
    conn.commit()
    conn.close()


# Initialize on import
try:
    init_idor_db()
except Exception:
    pass


@idor_bp.route("/api/accounts/<int:account_id>", methods=["GET"])
def get_account(account_id):
    """
    CWE-639: IDOR — no ownership check. Returns full account details for any account_id.
    Auth user spoofed via X-User-Id header (default '1').

    Exploit:
        curl -H 'X-User-Id: 3' http://localhost:5000/api/accounts/1
        # Returns admin account with $50,000 balance even though caller is user 3
    """
    # "Authenticated" user — trivially spoofable header, no session validation
    current_user = request.headers.get("X-User-Id", "1")

    conn = get_idor_db()
    # VULN CWE-639: account_id not compared to current_user — any account readable
    account = conn.execute(
        "SELECT * FROM accounts WHERE id=?", (account_id,)
    ).fetchone()
    conn.close()

    if not account:
        return jsonify({"error": "Account not found"}), 404

    return jsonify({
        "id": account["id"],
        "owner_id": account["owner_id"],          # reveals true owner
        "account_number": account["account_number"],
        "balance": account["balance"],
        "notification_email": account["notification_email"],
        "daily_limit": account["daily_limit"],
        "accessed_by": current_user               # no check that current_user == owner_id
    })


@idor_bp.route("/api/accounts/<int:account_id>/transactions", methods=["GET"])
def get_account_transactions(account_id):
    """
    CWE-639: IDOR — returns any user's transaction history with no auth check.

    Exploit:
        curl -H 'X-User-Id: 3' http://localhost:5000/api/accounts/1/transactions
        # Returns admin's full transaction history
    """
    current_user = request.headers.get("X-User-Id", "1")

    conn = get_idor_db()
    # VULN: account_id from URL used directly; never checked against current_user
    txns = conn.execute(
        "SELECT * FROM account_transactions WHERE account_id=?", (account_id,)
    ).fetchall()
    conn.close()

    return jsonify({
        "account_id": account_id,
        "requested_by": current_user,
        "transactions": [dict(t) for t in txns]
    })


@idor_bp.route("/api/users/<int:user_id>/profile", methods=["GET"])
def get_user_profile(user_id):
    """
    CWE-639: IDOR — returns any user's PII (email, phone, address, SSN) without ownership check.

    Exploit:
        curl -H 'X-User-Id: 3' http://localhost:5000/api/users/1/profile
        # Returns admin's SSN, phone, address
    """
    current_user = request.headers.get("X-User-Id", "1")

    conn = get_idor_db()
    # VULN: user_id from URL path; current_user header ignored for access decisions
    profile = conn.execute(
        "SELECT * FROM user_profiles WHERE id=?", (user_id,)
    ).fetchone()
    conn.close()

    if not profile:
        return jsonify({"error": "User not found"}), 404

    return jsonify({
        "id": profile["id"],
        "username": profile["username"],
        "email": profile["email"],
        "phone": profile["phone"],
        "address": profile["address"],
        "ssn": profile["ssn"],           # PII leak — CWE-359
        "accessed_by": current_user
    })


@idor_bp.route("/api/accounts/<int:account_id>/settings", methods=["PUT"])
def update_account_settings(account_id):
    """
    CWE-639: IDOR — updates any account's settings with no ownership check.
    Attacker can change notification email to their own address to intercept alerts.

    Exploit:
        curl -X PUT -H 'X-User-Id: 3' -H 'Content-Type: application/json' \\
             -d '{"notification_email":"attacker@evil.com","daily_limit":999999}' \\
             http://localhost:5000/api/accounts/1/settings
    """
    current_user = request.headers.get("X-User-Id", "1")
    data = request.get_json(force=True) or {}

    notification_email = data.get("notification_email")
    daily_limit = data.get("daily_limit")

    conn = get_idor_db()
    # VULN: no ownership check — account_id controlled by attacker
    if notification_email:
        conn.execute(
            "UPDATE accounts SET notification_email=? WHERE id=?",
            (notification_email, account_id)
        )
    if daily_limit is not None:
        conn.execute(
            "UPDATE accounts SET daily_limit=? WHERE id=?",
            (daily_limit, account_id)
        )
    conn.commit()
    conn.close()

    return jsonify({
        "status": "settings updated",
        "account_id": account_id,
        "updated_by": current_user,
        "notification_email": notification_email,
        "daily_limit": daily_limit
    })


@idor_bp.route("/api/accounts/<int:account_id>/beneficiary/<int:beneficiary_id>", methods=["DELETE"])
def delete_beneficiary(account_id, beneficiary_id):
    """
    CWE-639: IDOR — deletes any user's beneficiary without ownership check.
    Attacker can disrupt victim's saved payment recipients.

    Exploit:
        curl -X DELETE -H 'X-User-Id: 3' \\
             http://localhost:5000/api/accounts/2/beneficiary/1
        # Deletes Alice's beneficiary even though caller is Bob (user 3)
    """
    current_user = request.headers.get("X-User-Id", "1")

    conn = get_idor_db()
    # VULN: no check that beneficiary_id belongs to account_id or current_user
    result = conn.execute(
        "DELETE FROM beneficiaries WHERE id=?", (beneficiary_id,)
    )
    conn.commit()
    conn.close()

    return jsonify({
        "status": "beneficiary deleted",
        "beneficiary_id": beneficiary_id,
        "account_id": account_id,
        "deleted_by": current_user,
        "rows_affected": result.rowcount
    })


@idor_bp.route("/api/statements/<int:statement_id>", methods=["GET"])
def get_statement(statement_id):
    """
    CWE-639: IDOR — returns PDF path for any account's statement without ownership check.

    Exploit:
        curl -H 'X-User-Id: 3' http://localhost:5000/api/statements/1
        # Returns admin's statement PDF path
    """
    current_user = request.headers.get("X-User-Id", "1")

    conn = get_idor_db()
    # VULN: statement_id from URL; no join to verify owner == current_user
    statement = conn.execute(
        "SELECT * FROM statements WHERE id=?", (statement_id,)
    ).fetchone()
    conn.close()

    if not statement:
        return jsonify({"error": "Statement not found"}), 404

    return jsonify({
        "id": statement["id"],
        "account_id": statement["account_id"],
        "period": statement["period"],
        "pdf_path": statement["pdf_path"],   # path to download statement PDF
        "accessed_by": current_user
    })
