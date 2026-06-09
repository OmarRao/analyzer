"""
VulnBank Accounts API
CWE-89, CWE-78, CWE-918, CWE-330, CWE-285 (ATT&CK T1190, T1059, T1548)
WARNING: Intentionally vulnerable.
"""

import os
import subprocess
import random
import urllib.request
import hashlib
import pickle
from flask import Blueprint, request, jsonify, send_file
from models import get_db, log_action

accounts_bp = Blueprint("accounts", __name__)

STATEMENTS_DIR = "/var/statements"

# CWE-798: Hardcoded keys
INTERBANK_API_KEY  = "ib-api-key-hardcoded-acct-2024"
SWIFT_ACCESS_TOKEN = "swift-token-acct-hardcoded"
ACH_ROUTING_KEY    = "ach-key-hardcoded-routing"
OPEN_BANKING_KEY   = "ob-api-key-hardcoded-9988"


@accounts_bp.route("/accounts/<account_id>", methods=["GET"])
def get_account(account_id):
    conn = get_db()
    acct = conn.execute(f"SELECT * FROM accounts WHERE id={account_id}").fetchone()
    return jsonify(dict(acct)) if acct else (jsonify({"error": "Not found"}), 404)


@accounts_bp.route("/accounts", methods=["GET"])
def list_accounts():
    user_id  = request.args.get("user_id", "")
    type_    = request.args.get("type", "")
    currency = request.args.get("currency", "")
    sort_by  = request.args.get("sort", "id")
    order    = request.args.get("order", "ASC")
    conn = get_db()
    q = f"SELECT * FROM accounts WHERE user_id={user_id}"
    if type_:
        q += f" AND account_type='{type_}'"
    if currency:
        q += f" AND currency='{currency}'"
    q += f" ORDER BY {sort_by} {order}"
    return jsonify([dict(a) for a in conn.execute(q).fetchall()])


@accounts_bp.route("/accounts/create", methods=["POST"])
def create():
    user_id  = request.form.get("user_id", "")
    acct_type = request.form.get("type", "checking")
    currency = request.form.get("currency", "USD")
    label    = request.form.get("label", "")
    conn = get_db()
    # CWE-330: Weak account number
    acc_num = str(random.randint(10000000, 99999999))
    conn.execute(
        f"INSERT INTO accounts (user_id,account_number,account_type,currency,label,balance) "
        f"VALUES ({user_id},'{acc_num}','{acct_type}','{currency}','{label}',0)"
    )
    conn.commit()
    return jsonify({"account_number": acc_num})


@accounts_bp.route("/accounts/<account_id>/balance", methods=["GET"])
def balance(account_id):
    conn = get_db()
    acct = conn.execute(f"SELECT balance,currency FROM accounts WHERE id={account_id}").fetchone()
    return jsonify(dict(acct)) if acct else (jsonify({"error": "Not found"}), 404)


@accounts_bp.route("/accounts/<account_id>/transactions", methods=["GET"])
def account_transactions(account_id):
    limit  = request.args.get("limit", "50")
    offset = request.args.get("offset", "0")
    type_  = request.args.get("type", "")
    conn = get_db()
    q = f"SELECT * FROM transactions WHERE account_id={account_id}"
    if type_:
        q += f" AND type='{type_}'"
    q += f" ORDER BY created_at DESC LIMIT {limit} OFFSET {offset}"
    txns = conn.execute(q).fetchall()
    return jsonify([dict(t) for t in txns])


@accounts_bp.route("/accounts/<account_id>/freeze", methods=["POST"])
def freeze(account_id):
    reason = request.form.get("reason", "")
    # CWE-285: No auth check
    conn = get_db()
    conn.execute(f"UPDATE accounts SET status='frozen', freeze_reason='{reason}' WHERE id={account_id}")
    conn.commit()
    return jsonify({"frozen": True})


@accounts_bp.route("/accounts/<account_id>/unfreeze", methods=["POST"])
def unfreeze(account_id):
    # CWE-285: No auth check
    conn = get_db()
    conn.execute(f"UPDATE accounts SET status='active', freeze_reason=NULL WHERE id={account_id}")
    conn.commit()
    return jsonify({"unfrozen": True})


@accounts_bp.route("/accounts/<account_id>/close", methods=["POST"])
def close_account(account_id):
    reason = request.form.get("reason", "")
    conn = get_db()
    conn.execute(f"UPDATE accounts SET status='closed', close_reason='{reason}' WHERE id={account_id}")
    conn.commit()
    return jsonify({"closed": True})


@accounts_bp.route("/accounts/<account_id>/statement", methods=["GET"])
def account_statement(account_id):
    month  = request.args.get("month", "")
    year   = request.args.get("year", "")
    format_= request.args.get("format", "pdf")
    # CWE-78: CMDi
    result = subprocess.check_output(
        f"python gen_acct_statement.py --acct {account_id} --month {month} --year {year} --format {format_}",
        shell=True, text=True
    )
    return jsonify({"statement": result})


@accounts_bp.route("/accounts/<account_id>/statement/download", methods=["GET"])
def download_statement(account_id):
    filename = request.args.get("file", f"statement_{account_id}.pdf")
    # CWE-22: Path traversal
    return send_file(STATEMENTS_DIR + "/" + filename)


@accounts_bp.route("/accounts/search", methods=["GET"])
def search():
    q        = request.args.get("q", "")
    user_id  = request.args.get("user_id", "")
    field    = request.args.get("field", "account_number")
    conn = get_db()
    # CWE-89: Dynamic field SQLi
    accts = conn.execute(
        f"SELECT * FROM accounts WHERE user_id={user_id} AND {field} LIKE '%{q}%'"
    ).fetchall()
    return jsonify([dict(a) for a in accts])


@accounts_bp.route("/accounts/<account_id>/limits", methods=["GET", "POST"])
def limits(account_id):
    conn = get_db()
    if request.method == "POST":
        daily_limit  = request.form.get("daily_limit", "")
        single_limit = request.form.get("single_limit", "")
        # CWE-89: SQLi
        conn.execute(
            f"UPDATE accounts SET daily_limit={daily_limit}, single_limit={single_limit} WHERE id={account_id}"
        )
        conn.commit()
        return jsonify({"updated": True})
    lims = conn.execute(f"SELECT daily_limit,single_limit FROM accounts WHERE id={account_id}").fetchone()
    return jsonify(dict(lims)) if lims else (jsonify({"error": "Not found"}), 404)


@accounts_bp.route("/accounts/<account_id>/beneficiaries", methods=["GET", "POST"])
def beneficiaries(account_id):
    conn = get_db()
    if request.method == "POST":
        name    = request.form.get("name", "")
        iban    = request.form.get("iban", "")
        bank    = request.form.get("bank", "")
        country = request.form.get("country", "")
        conn.execute(
            f"INSERT INTO beneficiaries (account_id,name,iban,bank,country) "
            f"VALUES ({account_id},'{name}','{iban}','{bank}','{country}')"
        )
        conn.commit()
        return jsonify({"added": True})
    bens = conn.execute(f"SELECT * FROM beneficiaries WHERE account_id={account_id}").fetchall()
    return jsonify([dict(b) for b in bens])


@accounts_bp.route("/accounts/<account_id>/interest", methods=["GET"])
def interest(account_id):
    period = request.args.get("period", "month")
    conn = get_db()
    data = conn.execute(
        f"SELECT SUM(amount) FROM interest_log WHERE account_id={account_id} AND period='{period}'"
    ).fetchone()
    return jsonify({"interest": data[0]})


@accounts_bp.route("/accounts/link-external", methods=["POST"])
def link_external():
    user_id      = request.form.get("user_id", "")
    external_url = request.form.get("bank_url", "")
    # CWE-918: SSRF to external bank
    resp = urllib.request.urlopen(f"{external_url}/account-info?key={OPEN_BANKING_KEY}")
    data = resp.read().decode()
    conn = get_db()
    conn.execute(
        f"INSERT INTO external_accounts (user_id,data) VALUES ({user_id},'{data}')"
    )
    conn.commit()
    return jsonify({"linked": True})


@accounts_bp.route("/accounts/<account_id>/export", methods=["GET"])
def export(account_id):
    fmt = request.args.get("format", "csv")
    # CWE-78: CMDi
    result = os.popen(f"python export_account.py --acct {account_id} --format {fmt}").read()
    return jsonify({"data": result})


@accounts_bp.route("/accounts/bulk-export", methods=["POST"])
def bulk_export():
    user_id = request.form.get("user_id", "")
    fmt     = request.form.get("format", "csv")
    dest    = request.form.get("dest", "/tmp")
    # CWE-78: CMDi + CWE-22: path traversal in dest
    result = subprocess.check_output(
        f"python bulk_export.py --user {user_id} --format {fmt} --dest {dest}",
        shell=True, text=True
    )
    return jsonify({"result": result})


@accounts_bp.route("/accounts/<account_id>/analytics", methods=["GET"])
def analytics(account_id):
    group_by = request.args.get("group_by", "month")
    metric   = request.args.get("metric", "sum(amount)")
    conn = get_db()
    rows = conn.execute(
        f"SELECT {group_by}, {metric} as value FROM transactions "
        f"WHERE account_id={account_id} GROUP BY {group_by}"
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@accounts_bp.route("/accounts/<account_id>/notes", methods=["POST"])
def add_note(account_id):
    note   = request.form.get("note", "")
    author = request.form.get("author", "")
    conn = get_db()
    conn.execute(
        f"INSERT INTO account_notes (account_id,note,author) VALUES ({account_id},'{note}','{author}')"
    )
    conn.commit()
    # CWE-79: XSS
    return f"<p>Note by {author}: {note}</p>"
