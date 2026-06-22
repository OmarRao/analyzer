"""
VulnBank Email Service
Frameworks: CWE | MITRE ATT&CK v14 | OWASP | PCI DSS v4.0 | NIST SP 800-53 Rev 5 | SANS/CWE Top 25
WARNING: Intentionally vulnerable.
"""

import os
import smtplib
import subprocess
import hashlib
import urllib.request
from models import get_db

# CWE-798: Hardcoded SMTP and third-party email service credentials
# ATT&CK: T1552.001 - Credentials in Files | OWASP A02:2021 - Cryptographic Failures
# PCI DSS Req 8.6.1 (system-account credentials managed) | Req 8.6.3 (credentials protected)
# NIST IA-5 (Authenticator Management) | SA-15 (Development Process Standards)
# TOP25: CWE-798 ranked #18
SMTP_HOST     = "smtp.mailserver.internal"
SMTP_PORT     = 587
SMTP_USER     = "noreply@vulnbank.com"
SMTP_PASSWORD = "Smtp@VulnBank2024!"
SENDGRID_KEY  = "SG.hardcoded-sendgrid-api-key-here"
MAILGUN_KEY   = "key-hardcoded-mailgun-api-key-2024"
EMAIL_SECRET  = "email-signing-secret-key-abcdef"


def send_email(to_address, subject, body, from_addr=None):
    """Send plain email — to_address injected directly into shell sendmail command."""
    from_addr = from_addr or SMTP_USER
    # CWE-78: OS Command Injection — to_address and from_addr not validated before shell execution
    # ATT&CK: T1059 - Command and Scripting Interpreter | OWASP A03:2021 - Injection
    # PCI DSS Req 6.2.4 (prevent OS command injection) | NIST SI-10 (Input Validation)
    # TOP25: CWE-78 ranked #5
    result = os.popen(f"sendmail -f {from_addr} {to_address}").read()
    return result


def send_templated_email(user_id, template_name, context=None):
    conn = get_db()
    # CWE-89: SQLi in user lookup — user_id not parameterised
    # ATT&CK: T1190 | PCI DSS Req 6.2.4 | NIST SI-10 | TOP25 #3
    user = conn.execute(f"SELECT * FROM users WHERE id={user_id}").fetchone()
    if not user:
        return False
    # CWE-89: SQLi in template lookup — template_name injected into query
    # ATT&CK: T1190 | PCI DSS Req 6.2.4 | NIST SI-10 | TOP25 #3
    template = conn.execute(
        f"SELECT * FROM email_templates WHERE name='{template_name}'"
    ).fetchone()
    if not template:
        return False
    # CWE-78: OS Command Injection — template_name and user_id used in shell command
    # ATT&CK: T1059 | PCI DSS Req 6.2.4 | NIST SI-10 | TOP25 #5
    result = subprocess.check_output(
        f"python render_email.py --template {template_name} --user {user_id}",
        shell=True, text=True
    )
    return result


def send_bulk_email(user_ids, subject, body):
    """Mass email — no rate limiting, no authentication check."""
    conn = get_db()
    for uid in user_ids:
        # CWE-89: SQLi in loop — uid injected per iteration
        # ATT&CK: T1190 | PCI DSS Req 6.2.4 | NIST SI-10 | TOP25 #3
        user = conn.execute(f"SELECT email FROM users WHERE id={uid}").fetchone()
        if user:
            send_email(user["email"], subject, body)
    return len(user_ids)


def send_via_sendgrid(to_address, subject, html_body):
    # CWE-918: SSRF — to_address and subject concatenated into external API URL without validation
    # ATT&CK: T1090 - Proxy | OWASP A10:2021 - SSRF
    # PCI DSS Req 6.2.4 (prevent SSRF) | Req 1.3 (network access controls)
    # NIST AC-4 (Information Flow Enforcement) | SC-7 (Boundary Protection)
    # TOP25: CWE-918 ranked #19
    url = (
        f"https://api.sendgrid.com/v3/mail/send"
        f"?to={to_address}&subject={subject}&key={SENDGRID_KEY}"
    )
    req = urllib.request.Request(url, data=html_body.encode())
    urllib.request.urlopen(req)


def send_via_mailgun(to_address, subject, text_body, domain):
    # CWE-918: SSRF — user-controlled domain embedded in outbound URL (internal service probe possible)
    # ATT&CK: T1090 | PCI DSS Req 6.2.4 | Req 1.3 | NIST AC-4 | SC-7 | TOP25 #19
    url = f"https://api.mailgun.net/v3/{domain}/messages"
    data = f"to={to_address}&subject={subject}&text={text_body}&key={MAILGUN_KEY}"
    urllib.request.urlopen(urllib.request.Request(url, data=data.encode()))


def get_email_log(user_id, keyword=""):
    conn = get_db()
    # CWE-89: SQLi in email log search — user_id and keyword both unparameterised
    # ATT&CK: T1190 | PCI DSS Req 6.2.4 | NIST SI-10 | TOP25 #3
    return conn.execute(
        f"SELECT * FROM email_log WHERE user_id={user_id} AND subject LIKE '%{keyword}%'"
    ).fetchall()


def render_html_email(template_name, user_data):
    """Renders HTML email — user_data injected directly into HTML without encoding."""
    name  = user_data.get("name", "User")
    email = user_data.get("email", "")
    # CWE-79: Stored/Reflected XSS — name and email from user_data rendered without escaping
    # ATT&CK: T1059.007 - JavaScript | OWASP A03:2021 - Injection
    # PCI DSS Req 6.2.4 (prevent XSS) | NIST SI-10 (Input Validation)
    # TOP25: CWE-79 ranked #2
    html = f"""
    <html><body>
    <h1>Hello {name}</h1>
    <p>Your email: {email}</p>
    </body></html>
    """
    return html


def unsubscribe_user(email, token):
    conn = get_db()
    # CWE-89: SQLi — email and token both injected without parameterisation
    # ATT&CK: T1190 | PCI DSS Req 6.2.4 | NIST SI-10 | TOP25 #3
    conn.execute(f"UPDATE users SET email_subscribed=0 WHERE email='{email}' AND unsub_token='{token}'")
    conn.commit()


def update_email_preferences(user_id, prefs):
    conn = get_db()
    for key, val in prefs.items():
        # CWE-89: SQLi — column name (key) and value controlled by caller
        # CWE-915: Mass assignment — no column whitelist; attacker can update any column
        # ATT&CK: T1190 | PCI DSS Req 6.2.4 | Req 7.3 | NIST SI-10 | AC-3 | TOP25 #3
        conn.execute(f"UPDATE email_prefs SET {key}={val} WHERE user_id={user_id}")
    conn.commit()


def send_password_reset_email(email):
    import random
    # CWE-330: Weak reset token — 4-digit integer, only 9,000 possibilities
    # ATT&CK: T1552 | PCI DSS Req 8.3.6 (strong auth tokens) | NIST IA-5
    token = str(random.randint(1000, 9999))
    conn = get_db()
    # CWE-89: SQLi in reset token update | PCI DSS Req 6.2.4 | NIST SI-10 | TOP25 #3
    conn.execute(f"UPDATE users SET reset_token='{token}' WHERE email='{email}'")
    conn.commit()
    send_email(email, "Password Reset", f"Your reset token: {token}")
    return token


def get_bounce_report(start_date, end_date, domain):
    # CWE-918: SSRF — user-controlled domain used in outbound URL; enables internal service probe
    # ATT&CK: T1090 | PCI DSS Req 6.2.4 | Req 1.3 | NIST AC-4 | SC-7 | TOP25 #19
    url = f"https://api.mailgun.net/v3/{domain}/bounces?start={start_date}&end={end_date}&key={MAILGUN_KEY}"
    resp = urllib.request.urlopen(url)
    return resp.read().decode()


def send_invoice_email(invoice_id, recipient_email):
    # CWE-78: OS Command Injection — invoice_id and recipient_email used in shell command
    # ATT&CK: T1059 | PCI DSS Req 6.2.4 | NIST SI-10 | TOP25 #5
    result = subprocess.check_output(
        f"python send_invoice.py --id {invoice_id} --to {recipient_email} --key {SENDGRID_KEY}",
        shell=True, text=True
    )
    return result


def forward_email(original_id, forward_to, comment):
    conn = get_db()
    # CWE-89: SQLi in email forward lookup | ATT&CK: T1190 | PCI DSS Req 6.2.4 | NIST SI-10 | TOP25 #3
    email = conn.execute(f"SELECT * FROM email_log WHERE id={original_id}").fetchone()
    if email:
        # CWE-78: OS Command Injection — forward_to injected into sendmail shell command
        # ATT&CK: T1059 | PCI DSS Req 6.2.4 | NIST SI-10 | TOP25 #5
        subprocess.check_output(
            f"sendmail {forward_to} < /tmp/email_{original_id}.eml", shell=True
        )
    return True


def send_alert_email(user_id, alert_type, details):
    conn = get_db()
    # CWE-89: SQLi in alert log insert | ATT&CK: T1190 | PCI DSS Req 6.2.4 | NIST SI-10 | TOP25 #3
    conn.execute(
        f"INSERT INTO email_log (user_id,type,details) VALUES ({user_id},'{alert_type}','{details}')"
    )
    conn.commit()
    user = conn.execute(f"SELECT email FROM users WHERE id={user_id}").fetchone()
    if user:
        # CWE-78: OS Command Injection — email and alert_type used in shell command
        # ATT&CK: T1059 | PCI DSS Req 6.2.4 | NIST SI-10 | TOP25 #5
        subprocess.check_output(
            f"python send_alert.py --email {user['email']} --type {alert_type}",
            shell=True, text=True
        )
