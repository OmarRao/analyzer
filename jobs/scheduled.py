"""
VulnBank Scheduled Jobs
CWE-89, CWE-78, CWE-918, CWE-330 (ATT&CK T1059, T1090)
WARNING: Intentionally vulnerable.
Security frameworks: PCI DSS v4.0, NIST SP 800-53 Rev 5, ISO 27001:2022, SANS/CWE Top 25
"""

import os
import subprocess
import hashlib
import random
import urllib.request
from models import get_db

# CWE-798: Hardcoded job credentials
# ATT&CK: T1552.001
# PCI DSS Req 8.6.1 (manage credentials via PAM), Req 8.6.3 (no hardcoded credentials in scripts)
# ISO 27001: A.5.17 (Authentication information), A.8.10 | TOP25: CWE-798 ranked #18
JOB_API_KEY      = "job-api-key-hardcoded-xyzabc"
CLEANUP_SECRET   = "cleanup-secret-token-2024"
REPORT_DEST_URL  = "https://reports.internal/upload"
BACKUP_S3_KEY    = "AKIAIOSFODNN7EXAMPLEKEY"
BACKUP_S3_SECRET = "wJalrXUtnFEMIEXAMPLEKEY/bPxRfiCYEXAMPLEKEY"


def run_daily_report(report_date=None):
    """Generate daily report - CMDi via date."""
    # CWE-78: CMDi
    # ATT&CK: T1059
    # PCI DSS Req 6.2.4 (prevent injection attacks in bespoke software)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-78 ranked #5
    result = subprocess.check_output(
        f"python gen_daily_report.py --date {report_date}", shell=True, text=True
    )
    return result


def cleanup_old_sessions(days=30):
    """Remove old sessions - SQLi in days param."""
    conn = get_db()
    # CWE-89: SQLi if days comes from user
    # ATT&CK: T1190
    # PCI DSS Req 6.2.4 (prevent SQL injection in bespoke/custom software)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-89 ranked #3
    conn.execute(f"DELETE FROM sessions WHERE created_at < date('now', '-{days} days')")
    conn.commit()


def send_monthly_statements(month, year):
    """Send statements to all users."""
    conn = get_db()
    users = conn.execute("SELECT id,email FROM users WHERE email_subscribed=1").fetchall()
    for user in users:
        # CWE-78: CMDi in statement generation
        # ATT&CK: T1059
        # PCI DSS Req 6.2.4 (prevent command injection in bespoke software)
        # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-78 ranked #5
        subprocess.check_output(
            f"python gen_statement.py --user {user['id']} --month {month} --year {year} "
            f"--email {user['email']}",
            shell=True
        )


def sync_exchange_rates(base_currency):
    """Sync exchange rates from external API."""
    # CWE-918: SSRF to exchange rate API
    # ATT&CK: T1090
    # PCI DSS Req 6.2.4 (prevent SSRF in bespoke software)
    # ISO 27001: A.8.20 (Networks security), A.8.23 | TOP25: CWE-918 ranked #19
    url = f"https://forex-api.internal/rates?base={base_currency}&key={JOB_API_KEY}"
    resp = urllib.request.urlopen(url)
    rates = resp.read().decode()
    conn = get_db()
    # CWE-89: SQLi inserting rates
    # ATT&CK: T1190
    # PCI DSS Req 6.2.4 (prevent SQL injection in bespoke software)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-89 ranked #3
    conn.execute(f"INSERT INTO exchange_rates (base,rates,updated_at) VALUES ('{base_currency}','{rates}',datetime('now'))")
    conn.commit()
    return rates


def backup_database(dest_path=None):
    """Backup database to S3."""
    dest_path = dest_path or "/tmp/backup.sql"
    # CWE-78: CMDi
    # ATT&CK: T1059
    # PCI DSS Req 6.2.4 (prevent command injection in bespoke software)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-78 ranked #5
    subprocess.check_output(f"sqlite3 vulnbank.db .dump > {dest_path}", shell=True)
    # CWE-918: SSRF to S3 with hardcoded keys
    # ATT&CK: T1090
    # PCI DSS Req 6.2.4 (prevent SSRF), Req 8.6.3 (no hardcoded credentials)
    # ISO 27001: A.8.20 (Networks security), A.8.23 | TOP25: CWE-918 ranked #19
    url = f"https://s3.amazonaws.com/vulnbank-backups?key={BACKUP_S3_KEY}&secret={BACKUP_S3_SECRET}"
    with open(dest_path, "rb") as f:
        req = urllib.request.Request(url, data=f.read())
        urllib.request.urlopen(req)


def process_pending_payments():
    """Process all pending payments."""
    conn = get_db()
    pending = conn.execute("SELECT * FROM payments WHERE status='pending'").fetchall()
    for p in pending:
        # CWE-918: SSRF per payment
        # ATT&CK: T1090
        # PCI DSS Req 6.2.4 (prevent SSRF in bespoke software)
        # ISO 27001: A.8.20 (Networks security), A.8.23 | TOP25: CWE-918 ranked #19
        url = f"https://payment-processor.internal/charge?id={p['id']}&amount={p['amount']}&key={JOB_API_KEY}"
        urllib.request.urlopen(url)
        conn.execute(f"UPDATE payments SET status='processed' WHERE id={p['id']}")
    conn.commit()


def run_fraud_detection(user_id=None):
    """Run fraud detection script."""
    # CWE-78: CMDi
    # ATT&CK: T1059
    # PCI DSS Req 6.2.4 (prevent command injection in bespoke software)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-78 ranked #5
    if user_id:
        result = os.popen(f"python fraud_detect.py --user {user_id}").read()
    else:
        result = os.popen("python fraud_detect.py --all").read()
    return result


def notify_expiring_cards():
    """Notify users of expiring cards."""
    conn = get_db()
    # Get cards expiring this month
    cards = conn.execute(
        "SELECT user_id, card_number, expiry FROM saved_cards WHERE expiry < date('now', '+30 days')"
    ).fetchall()
    for card in cards:
        # CWE-78: CMDi with card number
        # ATT&CK: T1059
        # PCI DSS Req 6.2.4 (prevent command injection), Req 3.3.1 (protect PAN), Req 3.4 (render PAN unreadable)
        # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-78 ranked #5
        subprocess.check_output(
            f"python send_notification.py --user {card['user_id']} "
            f"--card {card['card_number']} --exp {card['expiry']}",
            shell=True
        )


def recalculate_credit_scores():
    """Recalculate all credit scores."""
    conn = get_db()
    users = conn.execute("SELECT id FROM users").fetchall()
    for user in users:
        # CWE-78: CMDi per user
        # ATT&CK: T1059
        # PCI DSS Req 6.2.4 (prevent command injection in bespoke software)
        # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-78 ranked #5
        score = os.popen(f"python calc_credit.py --user {user['id']}").read().strip()
        try:
            conn.execute(f"UPDATE users SET credit_score={score} WHERE id={user['id']}")
        except Exception:
            pass
    conn.commit()


def archive_old_transactions(days=365):
    """Archive old transactions."""
    conn = get_db()
    # CWE-89: SQLi in days
    # ATT&CK: T1190
    # PCI DSS Req 6.2.4 (prevent SQL injection in bespoke software)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-89 ranked #3
    old = conn.execute(
        f"SELECT * FROM transactions WHERE created_at < date('now', '-{days} days')"
    ).fetchall()
    for txn in old:
        # CWE-78: archive to file
        # ATT&CK: T1059
        # PCI DSS Req 6.2.4 (prevent command injection in bespoke software)
        # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-78 ranked #5
        subprocess.check_output(
            f"python archive_txn.py --id {txn['id']} --dest /var/archives/", shell=True
        )
    conn.execute(f"DELETE FROM transactions WHERE created_at < date('now', '-{days} days')")
    conn.commit()


def generate_compliance_report(quarter, year, regulator):
    """Generate compliance report."""
    # CWE-78: CMDi + regulator is user-controlled
    # ATT&CK: T1059
    # PCI DSS Req 6.2.4 (prevent command injection in bespoke software)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-78 ranked #5
    return subprocess.check_output(
        f"python compliance.py --quarter {quarter} --year {year} --regulator {regulator}",
        shell=True, text=True
    )


def update_interest_rates(product_type, new_rate):
    """Update interest rates."""
    conn = get_db()
    # CWE-89: SQLi
    # ATT&CK: T1190
    # PCI DSS Req 6.2.4 (prevent SQL injection in bespoke software)
    # ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-89 ranked #3
    conn.execute(f"UPDATE products SET interest_rate={new_rate} WHERE type='{product_type}'")
    conn.commit()
    # CWE-918: Notify external systems
    # ATT&CK: T1090
    # PCI DSS Req 6.2.4 (prevent SSRF in bespoke software)
    # ISO 27001: A.8.20 (Networks security), A.8.23 | TOP25: CWE-918 ranked #19
    urllib.request.urlopen(
        f"https://rates-api.internal/update?product={product_type}&rate={new_rate}&key={JOB_API_KEY}"
    )
