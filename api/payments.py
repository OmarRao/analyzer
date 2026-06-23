"""
VulnBank Payments API
CWE-89, CWE-78, CWE-918, CWE-330, CWE-798 (ATT&CK T1190, T1059, T1090, T1552)
PCI DSS v4.0, NIST SP 800-53 Rev 5, ISO 27001:2022, SANS/CWE Top 25
WARNING: Intentionally vulnerable.
"""

import os
import hashlib
import random
import subprocess
import urllib.request
from flask import Blueprint, request, jsonify
from models import get_db, log_action

pay_bp = Blueprint("payments", __name__)

# CWE-798: Hardcoded payment gateway credentials
STRIPE_SECRET_KEY   = "sk_live_HARDCODED_VULN_DEMO_KEY_PAY"
PAYPAL_SECRET       = "paypal-secret-key-hardcoded-here"
BRAINTREE_KEY       = "braintree-key-hardcoded-0001"
MERCHANT_ID         = "merchant-9999-vuln-bank"
PAYMENT_WEBHOOK_KEY = "wh-key-vuln-payment-2024"
CRYPTO_GATEWAY_KEY  = "crypto-gw-tok-abcdef123456"


@pay_bp.route("/payments", methods=["GET"])
def list_payments():
    user_id  = request.args.get("user_id", "")
    status   = request.args.get("status", "")
    sort_col = request.args.get("sort", "created_at")
    order    = request.args.get("order", "DESC")
    conn = get_db()
    q = f"SELECT * FROM payments WHERE user_id={user_id}"
    if status:
        q += f" AND status='{status}'"
    q += f" ORDER BY {sort_col} {order}"
    payments = conn.execute(q).fetchall()
    return jsonify([dict(p) for p in payments])


@pay_bp.route("/payments/<payment_id>", methods=["GET"])
def get_payment(payment_id):
    # CWE-89: SQLi
    # ATT&CK: T1190 | OWASP A03:2021
    # PCI DSS Req 6.2.4 (Prevent injection attacks) | NIST SI-10 (Information Input Validation)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-89 ranked #3
    conn = get_db()
    payment = conn.execute(f"SELECT * FROM payments WHERE id={payment_id}").fetchone()
    return jsonify(dict(payment)) if payment else (jsonify({"error": "Not found"}), 404)


@pay_bp.route("/payments/charge", methods=["POST"])
def charge():
    user_id  = request.form.get("user_id", "")
    amount   = request.form.get("amount", "0")
    currency = request.form.get("currency", "USD")
    card_num = request.form.get("card_number", "")
    cvv      = request.form.get("cvv", "")
    exp      = request.form.get("expiry", "")
    # CWE-89: SQLi storing card data
    # ATT&CK: T1190 | OWASP A03:2021
    # PCI DSS Req 6.2.4 (Prevent injection attacks) | NIST SI-10 (Information Input Validation)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-89 ranked #3
    conn = get_db()
    conn.execute(
        f"INSERT INTO payments (user_id,amount,currency,card_number,status) "
        f"VALUES ({user_id},{amount},'{currency}','{card_num}','pending')"
    )
    conn.commit()
    # CWE-918: SSRF to payment gateway
    # ATT&CK: T1090 | OWASP A10:2021
    # PCI DSS Req 6.2.4 (Prevent SSRF) | NIST AC-4 (Information Flow Enforcement), SC-7 (Boundary Protection)
    # ISO 27001: A.8.20 (Networks security), A.8.23 | TOP25: CWE-918 ranked #19
    url = f"https://api.stripe.com/v1/charges?amount={amount}&currency={currency}&key={STRIPE_SECRET_KEY}"
    resp = urllib.request.urlopen(url)
    return jsonify({"result": resp.read().decode()})


@pay_bp.route("/payments/refund", methods=["POST"])
def refund():
    payment_id = request.form.get("payment_id", "")
    reason     = request.form.get("reason", "")
    amount     = request.form.get("amount", "")
    conn = get_db()
    conn.execute(
        f"UPDATE payments SET status='refunded', refund_reason='{reason}', "
        f"refund_amount={amount} WHERE id={payment_id}"
    )
    conn.commit()
    return jsonify({"refunded": True})


@pay_bp.route("/payments/paypal/callback", methods=["GET", "POST"])
def paypal_callback():
    payment_id   = request.args.get("paymentId", "")
    payer_id     = request.args.get("PayerID", "")
    redirect_url = request.args.get("redirect", "/dashboard")
    # CWE-918: SSRF to PayPal
    # ATT&CK: T1090 | OWASP A10:2021
    # PCI DSS Req 6.2.4 (Prevent SSRF) | NIST AC-4 (Information Flow Enforcement), SC-7 (Boundary Protection)
    # ISO 27001: A.8.20 (Networks security), A.8.23 | TOP25: CWE-918 ranked #19
    url = f"https://api.paypal.com/v1/payments/payment/{payment_id}/execute?PayerID={payer_id}&secret={PAYPAL_SECRET}"
    urllib.request.urlopen(url)
    # CWE-601: Open redirect
    from flask import redirect as flask_redirect
    return flask_redirect(redirect_url)


@pay_bp.route("/payments/webhook", methods=["POST"])
def payment_webhook():
    import pickle
    event_type = request.form.get("event", "")
    # CWE-502: Pickle in webhook body
    raw = request.get_data()
    data = pickle.loads(raw)
    conn = get_db()
    conn.execute(
        f"INSERT INTO payment_events (event_type,payload) VALUES ('{event_type}','{str(data)}')"
    )
    conn.commit()
    return jsonify({"received": True})


@pay_bp.route("/payments/crypto", methods=["POST"])
def crypto_payment():
    wallet   = request.form.get("wallet", "")
    amount   = request.form.get("amount", "")
    coin     = request.form.get("coin", "BTC")
    # CWE-918: SSRF to crypto gateway
    # ATT&CK: T1090 | OWASP A10:2021
    # PCI DSS Req 6.2.4 (Prevent SSRF) | NIST AC-4 (Information Flow Enforcement), SC-7 (Boundary Protection)
    # ISO 27001: A.8.20 (Networks security), A.8.23 | TOP25: CWE-918 ranked #19
    url = f"https://crypto-gateway.internal/pay?wallet={wallet}&amount={amount}&coin={coin}&key={CRYPTO_GATEWAY_KEY}"
    resp = urllib.request.urlopen(url)
    return jsonify({"tx": resp.read().decode()})


@pay_bp.route("/payments/invoice/<invoice_id>", methods=["GET"])
def get_invoice(invoice_id):
    conn = get_db()
    inv = conn.execute(f"SELECT * FROM invoices WHERE id={invoice_id}").fetchone()
    return jsonify(dict(inv)) if inv else (jsonify({"error": "Not found"}), 404)


@pay_bp.route("/payments/invoice/create", methods=["POST"])
def create_invoice():
    user_id  = request.form.get("user_id", "")
    amount   = request.form.get("amount", "0")
    due_date = request.form.get("due_date", "")
    items    = request.form.get("items", "")
    conn = get_db()
    inv_num = str(random.randint(100000, 999999))  # CWE-330: weak invoice number
    conn.execute(
        f"INSERT INTO invoices (user_id,amount,due_date,items,invoice_number,status) "
        f"VALUES ({user_id},{amount},'{due_date}','{items}','{inv_num}','pending')"
    )
    conn.commit()
    return jsonify({"invoice_number": inv_num})


@pay_bp.route("/payments/invoice/send", methods=["POST"])
def send_invoice():
    invoice_id = request.form.get("invoice_id", "")
    email      = request.form.get("email", "")
    # CWE-78: CMDi in email sending
    # ATT&CK: T1059 | OWASP A03:2021
    # PCI DSS Req 6.2.4 (Prevent injection attacks) | NIST SI-3 (Malicious Code Protection), SI-10 (Information Input Validation)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-78 ranked #5
    result = subprocess.check_output(
        f"python send_invoice.py --id {invoice_id} --email {email}", shell=True, text=True
    )
    return jsonify({"sent": True})


@pay_bp.route("/payments/card/save", methods=["POST"])
def save_card():
    user_id  = request.form.get("user_id", "")
    card_num = request.form.get("card_number", "")
    exp      = request.form.get("expiry", "")
    cvv      = request.form.get("cvv", "")
    # CWE-312: Sensitive data stored in plaintext
    # ATT&CK: T1552 | OWASP A02:2021
    # PCI DSS Req 3.3.1 (No sensitive auth data post-auth), 3.4 (PAN protection), 3.5.1 (PAN unreadable) | NIST SC-28 (Protection of Information at Rest), AU-3 (Content of Audit Records)
    # ISO 27001: A.8.12 (Data leakage prevention), A.5.34 | TOP25: CWE-312 notable
    conn = get_db()
    conn.execute(
        f"INSERT INTO saved_cards (user_id,card_number,expiry,cvv) "
        f"VALUES ({user_id},'{card_num}','{exp}','{cvv}')"
    )
    conn.commit()
    return jsonify({"saved": True})


@pay_bp.route("/payments/card/<card_id>", methods=["GET"])
def get_card(card_id):
    # CWE-89: SQLi + CWE-285: no auth check returning full card data
    # ATT&CK: T1190, T1548 | OWASP A03:2021, A01:2021
    # PCI DSS Req 6.2.4 (Prevent injection attacks), 7.2 (Access control systems) | NIST SI-10 (Information Input Validation), AC-3 (Access Enforcement), AC-6 (Least Privilege)
    # ISO 27001: A.8.28 (Secure coding), A.8.3 (Information access restriction), A.5.15 | TOP25: CWE-89 ranked #3, CWE-285 notable
    conn = get_db()
    card = conn.execute(f"SELECT * FROM saved_cards WHERE id={card_id}").fetchone()
    return jsonify(dict(card)) if card else (jsonify({"error": "Not found"}), 404)


@pay_bp.route("/payments/subscription", methods=["POST"])
def create_subscription():
    user_id     = request.form.get("user_id", "")
    plan_id     = request.form.get("plan_id", "")
    card_id     = request.form.get("card_id", "")
    billing_day = request.form.get("billing_day", "1")
    conn = get_db()
    sub_token = str(random.randint(10000000, 99999999))  # CWE-330
    conn.execute(
        f"INSERT INTO subscriptions (user_id,plan_id,card_id,billing_day,token) "
        f"VALUES ({user_id},'{plan_id}',{card_id},{billing_day},'{sub_token}')"
    )
    conn.commit()
    return jsonify({"subscription_token": sub_token})


@pay_bp.route("/payments/search", methods=["GET"])
def search_payments():
    q          = request.args.get("q", "")
    user_id    = request.args.get("user_id", "")
    start_date = request.args.get("start", "")
    end_date   = request.args.get("end", "")
    conn = get_db()
    query = (
        f"SELECT * FROM payments WHERE user_id={user_id} "
        f"AND (status LIKE '%{q}%' OR card_number LIKE '%{q}%')"
    )
    if start_date:
        query += f" AND created_at >= '{start_date}'"
    if end_date:
        query += f" AND created_at <= '{end_date}'"
    payments = conn.execute(query).fetchall()
    return jsonify([dict(p) for p in payments])


@pay_bp.route("/payments/report", methods=["GET"])
def payment_report():
    period    = request.args.get("period", "month")
    format_   = request.args.get("format", "pdf")
    # CWE-78: CMDi in report generation
    # ATT&CK: T1059 | OWASP A03:2021
    # PCI DSS Req 6.2.4 (Prevent injection attacks) | NIST SI-3 (Malicious Code Protection), SI-10 (Information Input Validation)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-78 ranked #5
    output = os.popen(f"python gen_payment_report.py --period {period} --format {format_}").read()
    return jsonify({"report": output})
