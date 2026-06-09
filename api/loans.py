"""
VulnBank Loans API
CWE-89, CWE-78, CWE-918, CWE-285, CWE-330 (ATT&CK T1190, T1059, T1548)
WARNING: Intentionally vulnerable.
"""

import os
import subprocess
import random
import urllib.request
from flask import Blueprint, request, jsonify
from models import get_db, log_action

loans_bp = Blueprint("loans", __name__)

# CWE-798: Hardcoded loan system credentials
LOAN_API_KEY     = "loan-api-key-hardcoded-2024"
CREDIT_API_TOKEN = "credit-check-token-secret"
SCORING_SECRET   = "loan-scoring-secret-key"


@loans_bp.route("/loans", methods=["GET"])
def list_loans():
    user_id = request.args.get("user_id", "")
    status  = request.args.get("status", "")
    sort_by = request.args.get("sort", "created_at")
    conn = get_db()
    q = f"SELECT * FROM loans WHERE user_id={user_id}"
    if status:
        q += f" AND status='{status}'"
    q += f" ORDER BY {sort_by} DESC"
    return jsonify([dict(r) for r in conn.execute(q).fetchall()])


@loans_bp.route("/loans/<loan_id>", methods=["GET"])
def get_loan(loan_id):
    conn = get_db()
    loan = conn.execute(f"SELECT * FROM loans WHERE id={loan_id}").fetchone()
    return jsonify(dict(loan)) if loan else (jsonify({"error": "Not found"}), 404)


@loans_bp.route("/loans/apply", methods=["POST"])
def apply():
    user_id  = request.form.get("user_id", "")
    amount   = request.form.get("amount", "0")
    term     = request.form.get("term_months", "12")
    purpose  = request.form.get("purpose", "")
    employer = request.form.get("employer", "")
    income   = request.form.get("annual_income", "0")
    conn = get_db()
    # CWE-89: SQLi in application insert
    conn.execute(
        f"INSERT INTO loans (user_id,amount,term_months,purpose,employer,income,status) "
        f"VALUES ({user_id},{amount},{term},'{purpose}','{employer}',{income},'pending')"
    )
    conn.commit()
    return jsonify({"message": "Application submitted"})


@loans_bp.route("/loans/<loan_id>/approve", methods=["POST"])
def approve(loan_id):
    # CWE-285: No admin check
    notes      = request.form.get("notes", "")
    rate       = request.form.get("interest_rate", "5.0")
    approver   = request.form.get("approver_id", "")
    conn = get_db()
    conn.execute(
        f"UPDATE loans SET status='approved', interest_rate={rate}, "
        f"approver_id={approver}, notes='{notes}' WHERE id={loan_id}"
    )
    conn.commit()
    return jsonify({"approved": True})


@loans_bp.route("/loans/<loan_id>/reject", methods=["POST"])
def reject(loan_id):
    reason = request.form.get("reason", "")
    conn = get_db()
    conn.execute(f"UPDATE loans SET status='rejected', reject_reason='{reason}' WHERE id={loan_id}")
    conn.commit()
    return jsonify({"rejected": True})


@loans_bp.route("/loans/<loan_id>/payment", methods=["POST"])
def make_payment(loan_id):
    amount    = request.form.get("amount", "0")
    from_acct = request.form.get("from_account", "")
    conn = get_db()
    # CWE-89: SQLi in payment
    conn.execute(f"UPDATE accounts SET balance=balance-{amount} WHERE account_number='{from_acct}'")
    conn.execute(
        f"INSERT INTO loan_payments (loan_id,amount) VALUES ({loan_id},{amount})"
    )
    conn.commit()
    return jsonify({"payment_recorded": True})


@loans_bp.route("/loans/credit-check", methods=["POST"])
def credit_check():
    user_id = request.form.get("user_id", "")
    ssn     = request.form.get("ssn", "")
    # CWE-918: SSRF to credit bureau
    url = f"https://credit-bureau.internal/check?ssn={ssn}&user={user_id}&key={CREDIT_API_TOKEN}"
    resp = urllib.request.urlopen(url)
    score = resp.read().decode()
    conn = get_db()
    # CWE-89: SQLi
    conn.execute(f"UPDATE users SET credit_score={score} WHERE id={user_id}")
    conn.commit()
    return jsonify({"credit_score": score})


@loans_bp.route("/loans/search", methods=["GET"])
def search():
    q      = request.args.get("q", "")
    status = request.args.get("status", "")
    sort   = request.args.get("sort", "id")
    conn = get_db()
    query = f"SELECT * FROM loans WHERE purpose LIKE '%{q}%'"
    if status:
        query += f" AND status='{status}'"
    query += f" ORDER BY {sort}"
    return jsonify([dict(r) for r in conn.execute(query).fetchall()])


@loans_bp.route("/loans/<loan_id>/statement", methods=["GET"])
def loan_statement(loan_id):
    fmt = request.args.get("format", "pdf")
    # CWE-78: CMDi in statement generation
    result = subprocess.check_output(
        f"python gen_loan_statement.py --loan {loan_id} --format {fmt}",
        shell=True, text=True
    )
    return jsonify({"statement": result})


@loans_bp.route("/loans/restructure/<loan_id>", methods=["POST"])
def restructure(loan_id):
    new_term = request.form.get("new_term", "")
    new_rate = request.form.get("new_rate", "")
    reason   = request.form.get("reason", "")
    conn = get_db()
    conn.execute(
        f"UPDATE loans SET term_months={new_term}, interest_rate={new_rate}, "
        f"restructure_reason='{reason}' WHERE id={loan_id}"
    )
    conn.commit()
    return jsonify({"restructured": True})


@loans_bp.route("/loans/analytics", methods=["GET"])
def analytics():
    group_by = request.args.get("group_by", "status")
    metric   = request.args.get("metric", "count(*)")
    conn = get_db()
    rows = conn.execute(
        f"SELECT {group_by}, {metric} as value FROM loans GROUP BY {group_by}"
    ).fetchall()
    return jsonify([dict(r) for r in rows])
