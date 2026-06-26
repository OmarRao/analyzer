"""
VulnBank - Business Logic Vulnerabilities
CWE-840: Business Logic Errors, CWE-362: Race Condition

Framework annotations:
  CWE: CWE-840, CWE-362, CWE-20 (Improper Input Validation)
  MITRE ATT&CK: T1565.001 (Stored Data Manipulation)
  OWASP: A04:2021 - Insecure Design
  PCI DSS: Req 6.2.4
  NIST: SC-5 (Denial of Service Protection), SI-10 (Input Validation)
  ISO 27001: A.14.2.5
"""

import sqlite3
import time
import threading
from flask import Blueprint, request, jsonify

business_bp = Blueprint("business", __name__)

BUSINESS_DB = "/tmp/vulnbank.db"

# In-memory voucher store (simulates a database row without atomicity)
_vouchers = {
    "SAVE10": {"discount": 10.0, "used": False},
    "BONUS50": {"discount": 50.0, "used": False},
    "VIP100": {"discount": 100.0, "used": False},
}
_voucher_lock = threading.Lock()  # exists but intentionally NOT used in the vulnerable endpoint


def get_db():
    conn = sqlite3.connect(BUSINESS_DB)
    conn.row_factory = sqlite3.Row
    return conn


@business_bp.route("/api/transfer/overdraft", methods=["POST"])
def transfer_overdraft():
    """
    CWE-840: Business Logic Error — no balance check before transfer.
    Allows balance to go arbitrarily negative (unlimited overdraft exploit).

    Exploit:
        curl -X POST -H 'Content-Type: application/json' \\
             -d '{"from_account": 3, "to_account": 2, "amount": 999999}' \\
             http://localhost:5000/api/transfer/overdraft
        # Bob's balance goes to -999199 while Alice gains $999,999
    """
    data = request.get_json(force=True) or {}
    from_account = data.get("from_account", 1)
    to_account = data.get("to_account", 2)
    amount = float(data.get("amount", 0))

    conn = get_db()
    # VULN CWE-840: No balance >= amount check before deducting
    from_row = conn.execute("SELECT balance FROM accounts WHERE id=?", (from_account,)).fetchone()
    if not from_row:
        conn.close()
        return jsonify({"error": "Source account not found"}), 404

    # Subtract without checking: balance can go negative
    conn.execute("UPDATE accounts SET balance = balance - ? WHERE id=?", (amount, from_account))
    conn.execute("UPDATE accounts SET balance = balance + ? WHERE id=?", (amount, to_account))
    conn.commit()

    new_balance = conn.execute("SELECT balance FROM accounts WHERE id=?", (from_account,)).fetchone()
    conn.close()

    return jsonify({
        "status": "transfer complete",
        "from_account": from_account,
        "to_account": to_account,
        "amount": amount,
        "new_balance": new_balance["balance"] if new_balance else None,
        "warning": "Balance check skipped — CWE-840"
    })


@business_bp.route("/api/loans/apply", methods=["POST"])
def apply_loan():
    """
    CWE-20: Improper Input Validation — loan amount not validated against any limit.
    Attacker requests a $1,000,000,000 loan with no server-side cap.

    Exploit:
        curl -X POST -H 'Content-Type: application/json' \\
             -d '{"user_id": 3, "amount": 1000000000, "term_months": 1}' \\
             http://localhost:5000/api/loans/apply
    """
    data = request.get_json(force=True) or {}
    user_id = data.get("user_id", 1)
    # VULN CWE-20: amount taken directly from request — no min/max validation
    amount = data.get("amount", 0)
    term_months = data.get("term_months", 12)
    annual_rate = data.get("annual_rate", 0.05)

    monthly_payment = (amount * annual_rate / 12) / (1 - (1 + annual_rate / 12) ** -term_months) if amount > 0 else 0

    return jsonify({
        "status": "loan approved",
        "user_id": user_id,
        "loan_amount": amount,       # no upper limit enforced
        "term_months": term_months,
        "annual_rate": annual_rate,
        "monthly_payment": round(monthly_payment, 2),
        "warning": "No loan amount ceiling enforced — CWE-20"
    })


@business_bp.route("/api/fees/waive", methods=["POST"])
def waive_fee():
    """
    CWE-285: Improper Authorization — any user can waive their own fees.
    CWE-840: Accepts negative fee amounts, effectively charging the bank.

    Exploit (negative fee = bank pays you):
        curl -X POST -H 'Content-Type: application/json' \\
             -d '{"user_id": 2, "fee_amount": -500, "reason": "compensation"}' \\
             http://localhost:5000/api/fees/waive
        # Results in $500 credit applied to account
    """
    data = request.get_json(force=True) or {}
    user_id = data.get("user_id", 1)
    # VULN CWE-840: negative fee_amount inverts the direction of the fee waiver
    fee_amount = float(data.get("fee_amount", 0))
    reason = data.get("reason", "customer request")

    conn = get_db()
    # VULN CWE-285: no role check — any user can call this for any user_id
    conn.execute("UPDATE accounts SET balance = balance - ? WHERE owner_id=?", (fee_amount, user_id))
    conn.commit()
    conn.close()

    return jsonify({
        "status": "fee waived",
        "user_id": user_id,
        "fee_amount": fee_amount,    # negative value credits the account
        "reason": reason,
        "warning": "No authorization check; negative fee amounts accepted — CWE-285, CWE-840"
    })


@business_bp.route("/api/transfer/currency", methods=["POST"])
def currency_transfer():
    """
    CWE-840: Business Logic Error — currency conversion rate taken from request body.
    Attacker supplies a 10,000x rate to multiply their transfer value.

    Exploit:
        curl -X POST -H 'Content-Type: application/json' \\
             -d '{"from_account": 3, "to_account": 2, "amount": 1, "rate": 10000, "currency": "USD"}' \\
             http://localhost:5000/api/transfer/currency
        # $1 converted at 10,000x rate = $10,000 credited to destination
    """
    data = request.get_json(force=True) or {}
    from_account = data.get("from_account", 1)
    to_account = data.get("to_account", 2)
    amount = float(data.get("amount", 0))
    # VULN CWE-840: rate from request body — should be fetched from a trusted internal source
    rate = float(data.get("rate", 1.0))
    currency = data.get("currency", "USD")

    converted_amount = amount * rate

    conn = get_db()
    conn.execute("UPDATE accounts SET balance = balance - ? WHERE id=?", (amount, from_account))
    conn.execute("UPDATE accounts SET balance = balance + ? WHERE id=?", (converted_amount, to_account))
    conn.commit()
    conn.close()

    return jsonify({
        "status": "currency transfer complete",
        "original_amount": amount,
        "currency": currency,
        "rate_used": rate,           # attacker-supplied rate
        "converted_amount": converted_amount,
        "warning": "Exchange rate taken from client request — CWE-840"
    })


@business_bp.route("/api/interest/calculate", methods=["GET"])
def calculate_interest():
    """
    CWE-20: Improper Input Validation — negative interest rate gives user money.
    No validation that rate must be >= 0.

    Exploit:
        curl 'http://localhost:5000/api/interest/calculate?principal=1000&rate=-0.5&years=1'
        # Returns interest = -500 (bank pays you $500)
    """
    try:
        principal = float(request.args.get("principal", 1000))
        # VULN CWE-20: no check that rate >= 0 — negative rate produces negative interest
        rate = float(request.args.get("rate", 0.05))
        years = float(request.args.get("years", 1))
    except ValueError:
        return jsonify({"error": "Invalid numeric parameters"}), 400

    interest = principal * rate * years
    total = principal + interest

    return jsonify({
        "principal": principal,
        "rate": rate,        # can be negative — bank "pays" the customer
        "years": years,
        "interest": interest,
        "total": total,
        "warning": "Negative interest rate accepted — CWE-20"
    })


@business_bp.route("/api/voucher/redeem", methods=["POST"])
def redeem_voucher():
    """
    CWE-362: Race Condition — no atomicity on voucher redemption.
    The check-then-act pattern (check used flag, then set used=True) is not atomic.
    Concurrent requests can both pass the check and both redeem the same voucher.

    Exploit (run in two parallel threads/processes):
        curl -X POST -H 'Content-Type: application/json' \\
             -d '{"user_id": 2, "voucher_code": "BONUS50"}' \\
             http://localhost:5000/api/voucher/redeem &
        curl -X POST -H 'Content-Type: application/json' \\
             -d '{"user_id": 2, "voucher_code": "BONUS50"}' \\
             http://localhost:5000/api/voucher/redeem &
        # Both requests get a $50 discount — voucher redeemed twice
    """
    data = request.get_json(force=True) or {}
    user_id = data.get("user_id", 1)
    voucher_code = data.get("voucher_code", "")

    voucher = _vouchers.get(voucher_code)
    if not voucher:
        return jsonify({"error": "Invalid voucher code"}), 404

    # VULN CWE-362: Race condition — check and update not atomic (no lock used)
    if voucher["used"]:
        return jsonify({"error": "Voucher already redeemed"}), 409

    # Simulate processing delay that opens the race window
    time.sleep(0.1)

    # Both concurrent requests pass the check above before either sets used=True
    voucher["used"] = True
    discount = voucher["discount"]

    conn = get_db()
    conn.execute("UPDATE accounts SET balance = balance + ? WHERE owner_id=?", (discount, user_id))
    conn.commit()
    conn.close()

    return jsonify({
        "status": "voucher redeemed",
        "voucher_code": voucher_code,
        "discount": discount,
        "user_id": user_id,
        "warning": "No atomic check-and-set — race condition allows double redemption — CWE-362"
    })
