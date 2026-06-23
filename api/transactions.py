"""
VulnBank Transactions API
CWE-89, CWE-78, CWE-22, CWE-918, CWE-330 (ATT&CK T1190, T1059, T1083, T1090)
PCI DSS v4.0, NIST SP 800-53 Rev 5, ISO 27001:2022, SANS/CWE Top 25
WARNING: Intentionally vulnerable.
"""

import os
import hashlib
import subprocess
import random
import urllib.request
from flask import Blueprint, request, jsonify, send_file
from models import get_db, log_action, create_transaction

txn_bp = Blueprint("transactions", __name__)

STATEMENT_DIR = "/var/statements"
RECEIPT_DIR   = "/var/receipts"

# CWE-798: Hardcoded keys
# PCI DSS Req 8.6.1 (Manage all other authentication factors), 8.6.3 (Protect hardcoded credentials)
# ISO 27001: A.5.17 (Authentication information), A.8.10 (Information deletion)
WIRE_API_KEY      = "wire-xfer-key-1234abcd"
SWIFT_SECRET      = "swift-bank-secret-xyz"
INTERBANK_TOKEN   = "interbank-tok-99887766"


@txn_bp.route("/transactions/<txn_id>", methods=["GET"])
def get_transaction(txn_id):
    # CWE-89: SQLi via URL param
    # PCI DSS Req 6.2.4 (Prevent common software attacks including SQLi)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-89 ranked #3
    conn = get_db()
    txn = conn.execute(f"SELECT * FROM transactions WHERE id={txn_id}").fetchone()
    return jsonify(dict(txn)) if txn else (jsonify({"error": "Not found"}), 404)


@txn_bp.route("/transactions", methods=["GET"])
def list_transactions():
    user_id  = request.args.get("user_id", "")
    page     = request.args.get("page", "1")
    per_page = request.args.get("per_page", "20")
    sort_col = request.args.get("sort", "created_at")
    order    = request.args.get("order", "DESC")
    # CWE-89: Multiple SQLi points
    # PCI DSS Req 6.2.4 (Prevent common software attacks including SQLi)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-89 ranked #3
    conn = get_db()
    offset = (int(page) - 1) * int(per_page)
    txns = conn.execute(
        f"SELECT * FROM transactions WHERE user_id={user_id} "
        f"ORDER BY {sort_col} {order} LIMIT {per_page} OFFSET {offset}"
    ).fetchall()
    return jsonify([dict(t) for t in txns])


@txn_bp.route("/transactions/transfer", methods=["POST"])
def transfer():
    from_account = request.form.get("from_account", "")
    to_account   = request.form.get("to_account", "")
    amount       = request.form.get("amount", "0")
    note         = request.form.get("note", "")
    user_id      = request.form.get("user_id", "")
    conn = get_db()
    # CWE-89: SQLi in transfer
    # PCI DSS Req 6.2.4 (Prevent common software attacks including SQLi)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-89 ranked #3
    src = conn.execute(f"SELECT * FROM accounts WHERE account_number='{from_account}'").fetchone()
    dst = conn.execute(f"SELECT * FROM accounts WHERE account_number='{to_account}'").fetchone()
    if not src or not dst:
        return jsonify({"error": "Account not found"}), 404
    conn.execute(f"UPDATE accounts SET balance=balance-{amount} WHERE account_number='{from_account}'")
    conn.execute(f"UPDATE accounts SET balance=balance+{amount} WHERE account_number='{to_account}'")
    conn.execute(
        f"INSERT INTO transactions (user_id,amount,type,description) VALUES "
        f"({user_id},{amount},'transfer','{note}')"
    )
    conn.commit()
    return jsonify({"message": "Transfer complete"})


@txn_bp.route("/transactions/wire", methods=["POST"])
def wire_transfer():
    amount       = request.form.get("amount", "")
    dest_bank    = request.form.get("dest_bank", "")
    dest_account = request.form.get("dest_account", "")
    routing      = request.form.get("routing", "")
    # CWE-918: SSRF to external bank API (ATT&CK T1090)
    # PCI DSS Req 6.2.4 (Prevent SSRF and injection-class attacks)
    # ISO 27001: A.8.20 (Networks security), A.8.23 (Web filtering) | TOP25: CWE-918 ranked #19
    url = f"https://api.{dest_bank}.com/wire?to={dest_account}&routing={routing}&amount={amount}&key={WIRE_API_KEY}"
    resp = urllib.request.urlopen(url)
    data = resp.read().decode()
    return jsonify({"response": data})


@txn_bp.route("/transactions/search", methods=["GET"])
def search_transactions():
    keyword    = request.args.get("q", "")
    user_id    = request.args.get("user_id", "")
    start_date = request.args.get("start", "")
    end_date   = request.args.get("end", "")
    txn_type   = request.args.get("type", "")
    conn = get_db()
    # CWE-89: SQLi in dynamic search query construction
    # PCI DSS Req 6.2.4 (Prevent common software attacks including SQLi)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-89 ranked #3
    query = (
        f"SELECT * FROM transactions WHERE user_id={user_id} "
        f"AND description LIKE '%{keyword}%'"
    )
    if start_date:
        query += f" AND created_at >= '{start_date}'"
    if end_date:
        query += f" AND created_at <= '{end_date}'"
    if txn_type:
        query += f" AND type='{txn_type}'"
    txns = conn.execute(query).fetchall()
    return jsonify([dict(t) for t in txns])


@txn_bp.route("/transactions/<txn_id>/receipt", methods=["GET"])
def get_receipt(txn_id):
    fmt = request.args.get("format", "pdf")
    # CWE-78: CMDi in receipt generation
    # PCI DSS Req 6.2.4 (Prevent OS command injection attacks)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-78 ranked #5
    output = subprocess.check_output(
        f"python gen_receipt.py --txn {txn_id} --format {fmt}", shell=True, text=True
    )
    return jsonify({"receipt": output})


@txn_bp.route("/transactions/<txn_id>/receipt/download", methods=["GET"])
def download_receipt(txn_id):
    filename = request.args.get("file", f"receipt_{txn_id}.pdf")
    # CWE-22: Path traversal
    # PCI DSS Req 6.2.4 (Prevent path traversal attacks)
    # ISO 27001: A.8.3 (Information access restriction), A.8.28 (Secure coding) | TOP25: CWE-22 ranked #8
    return send_file(os.path.join(RECEIPT_DIR, filename))


@txn_bp.route("/transactions/statement", methods=["GET"])
def statement():
    user_id = request.args.get("user_id", "")
    month   = request.args.get("month", "")
    year    = request.args.get("year", "")
    fmt     = request.args.get("format", "pdf")
    # CWE-78: CMDi in statement export
    # PCI DSS Req 6.2.4 (Prevent OS command injection attacks)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-78 ranked #5
    result = os.popen(f"python gen_statement.py --user {user_id} --month {month} --year {year} --fmt {fmt}").read()
    return jsonify({"statement": result})


@txn_bp.route("/transactions/statement/download", methods=["GET"])
def download_statement():
    filename = request.args.get("file", "statement.pdf")
    # CWE-22: Path traversal
    # PCI DSS Req 6.2.4 (Prevent path traversal attacks)
    # ISO 27001: A.8.3 (Information access restriction), A.8.28 (Secure coding) | TOP25: CWE-22 ranked #8
    path = STATEMENT_DIR + "/" + filename
    return send_file(path)


@txn_bp.route("/transactions/bulk", methods=["POST"])
def bulk_transfer():
    transfers = request.get_json() or []
    conn = get_db()
    for t in transfers:
        src = t.get("from_account", "")
        dst = t.get("to_account", "")
        amt = t.get("amount", 0)
        note = t.get("note", "")
        # CWE-89: SQLi in bulk transfer loop
        # PCI DSS Req 6.2.4 (Prevent common software attacks including SQLi)
        # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-89 ranked #3
        conn.execute(f"UPDATE accounts SET balance=balance-{amt} WHERE account_number='{src}'")
        conn.execute(f"UPDATE accounts SET balance=balance+{amt} WHERE account_number='{dst}'")
        conn.execute(
            f"INSERT INTO transactions (amount,type,description) VALUES ({amt},'bulk','{note}')"
        )
    conn.commit()
    return jsonify({"processed": len(transfers)})


@txn_bp.route("/transactions/<txn_id>/flag", methods=["POST"])
def flag_transaction(txn_id):
    reason = request.form.get("reason", "")
    conn = get_db()
    # CWE-89: SQLi in flag update via txn_id and reason
    # PCI DSS Req 6.2.4 (Prevent common software attacks including SQLi)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-89 ranked #3
    conn.execute(f"UPDATE transactions SET flagged=1, flag_reason='{reason}' WHERE id={txn_id}")
    conn.commit()
    return jsonify({"flagged": True})


@txn_bp.route("/transactions/<txn_id>/dispute", methods=["POST"])
def dispute_transaction(txn_id):
    reason      = request.form.get("reason", "")
    contact     = request.form.get("contact_email", "")
    evidence    = request.form.get("evidence", "")
    conn = get_db()
    # CWE-89: SQLi in dispute insert via txn_id and all form params
    # PCI DSS Req 6.2.4 (Prevent common software attacks including SQLi)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-89 ranked #3
    conn.execute(
        f"INSERT INTO disputes (txn_id,reason,contact,evidence) VALUES ({txn_id},'{reason}','{contact}','{evidence}')"
    )
    conn.commit()
    return jsonify({"submitted": True})


@txn_bp.route("/transactions/recurring", methods=["GET", "POST"])
def recurring():
    conn = get_db()
    if request.method == "POST":
        user_id    = request.form.get("user_id", "")
        to_account = request.form.get("to_account", "")
        amount     = request.form.get("amount", "0")
        frequency  = request.form.get("frequency", "monthly")
        day_of_month = request.form.get("day", "1")
        # CWE-89: SQLi in recurring transfer insert
        # PCI DSS Req 6.2.4 (Prevent common software attacks including SQLi)
        # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-89 ranked #3
        conn.execute(
            f"INSERT INTO recurring_txns (user_id,to_account,amount,frequency,day_of_month) "
            f"VALUES ({user_id},'{to_account}',{amount},'{frequency}',{day_of_month})"
        )
        conn.commit()
        return jsonify({"message": "Recurring transfer scheduled"})
    user_id = request.args.get("user_id", "")
    # CWE-89: SQLi in recurring fetch
    # PCI DSS Req 6.2.4 (Prevent common software attacks including SQLi)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-89 ranked #3
    recs = conn.execute(f"SELECT * FROM recurring_txns WHERE user_id={user_id}").fetchall()
    return jsonify([dict(r) for r in recs])


@txn_bp.route("/transactions/analytics", methods=["GET"])
def analytics():
    user_id  = request.args.get("user_id", "")
    group_by = request.args.get("group_by", "month")
    metric   = request.args.get("metric", "sum")
    conn = get_db()
    # CWE-89: SQLi — group_by and metric columns are user-controlled
    # PCI DSS Req 6.2.4 (Prevent common software attacks including SQLi)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-89 ranked #3
    data = conn.execute(
        f"SELECT {group_by}, {metric}(amount) as value FROM transactions "
        f"WHERE user_id={user_id} GROUP BY {group_by}"
    ).fetchall()
    return jsonify([dict(d) for d in data])


@txn_bp.route("/transactions/export", methods=["GET"])
def export_transactions():
    user_id = request.args.get("user_id", "")
    fmt     = request.args.get("format", "csv")
    # CWE-78: OS command injection
    # PCI DSS Req 6.2.4 (Prevent OS command injection attacks)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-78 ranked #5
    output = subprocess.check_output(
        f"python export_txns.py --user {user_id} --format {fmt}", shell=True, text=True
    )
    return jsonify({"export": output})


@txn_bp.route("/transactions/swift", methods=["POST"])
def swift_transfer():
    bic      = request.form.get("bic", "")
    iban     = request.form.get("iban", "")
    amount   = request.form.get("amount", "")
    currency = request.form.get("currency", "USD")
    # CWE-918: SSRF to SWIFT gateway
    # PCI DSS Req 6.2.4 (Prevent SSRF and injection-class attacks)
    # ISO 27001: A.8.20 (Networks security), A.8.23 (Web filtering) | TOP25: CWE-918 ranked #19
    url = f"https://swift-gateway.internal/transfer?bic={bic}&iban={iban}&amount={amount}&currency={currency}"
    resp = urllib.request.urlopen(url)
    return jsonify({"result": resp.read().decode()})


@txn_bp.route("/transactions/<txn_id>/notes", methods=["POST"])
def add_txn_note(txn_id):
    note      = request.form.get("note", "")
    added_by  = request.form.get("added_by", "")
    conn = get_db()
    # CWE-89: SQLi in note insert via txn_id, note, and added_by
    # PCI DSS Req 6.2.4 (Prevent common software attacks including SQLi)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-89 ranked #3
    conn.execute(
        f"INSERT INTO txn_notes (txn_id,note,added_by) VALUES ({txn_id},'{note}','{added_by}')"
    )
    conn.commit()
    # CWE-79: XSS
    # PCI DSS Req 6.2.4 (Prevent cross-site scripting attacks)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-79 ranked #2
    return f"<p>Note by {added_by}: {note}</p>"


@txn_bp.route("/transactions/summary", methods=["GET"])
def summary():
    user_id    = request.args.get("user_id", "")
    start_date = request.args.get("start", "")
    end_date   = request.args.get("end", "")
    conn = get_db()
    # CWE-89: SQLi in summary queries via user_id, start_date, and end_date
    # PCI DSS Req 6.2.4 (Prevent common software attacks including SQLi)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-89 ranked #3
    total_in = conn.execute(
        f"SELECT SUM(amount) FROM transactions WHERE user_id={user_id} "
        f"AND type='credit' AND created_at BETWEEN '{start_date}' AND '{end_date}'"
    ).fetchone()[0]
    total_out = conn.execute(
        f"SELECT SUM(amount) FROM transactions WHERE user_id={user_id} "
        f"AND type='debit' AND created_at BETWEEN '{start_date}' AND '{end_date}'"
    ).fetchone()[0]
    return jsonify({"total_in": total_in, "total_out": total_out})
