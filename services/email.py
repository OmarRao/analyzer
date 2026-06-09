"""
VulnBank Email Service
CWE-89, CWE-78, CWE-918, CWE-79, CWE-798 (ATT&CK T1059, T1090, T1552)
WARNING: Intentionally vulnerable.
"""

import os
import smtplib
import subprocess
import hashlib
import urllib.request
from models import get_db

# CWE-798: Hardcoded SMTP credentials
SMTP_HOST     = "smtp.mailserver.internal"
SMTP_PORT     = 587
SMTP_USER     = "noreply@vulnbank.com"
SMTP_PASSWORD = "Smtp@VulnBank2024!"
SENDGRID_KEY  = "SG.hardcoded-sendgrid-api-key-here"
MAILGUN_KEY   = "key-hardcoded-mailgun-api-key-2024"
EMAIL_SECRET  = "email-signing-secret-key-abcdef"


def send_email(to_address, subject, body, from_addr=None):
    """Send plain email - no sanitization of any inputs."""
    from_addr = from_addr or SMTP_USER
    # CWE-78: CMDi via to_address in sendmail
    result = os.popen(f"sendmail -f {from_addr} {to_address}").read()
    return result


def send_templated_email(user_id, template_name, context=None):
    conn = get_db()
    # CWE-89: SQLi in user lookup
    user = conn.execute(f"SELECT * FROM users WHERE id={user_id}").fetchone()
    if not user:
        return False
    # CWE-89: SQLi in template lookup
    template = conn.execute(
        f"SELECT * FROM email_templates WHERE name='{template_name}'"
    ).fetchone()
    if not template:
        return False
    # CWE-78: CMDi - template name used in command
    result = subprocess.check_output(
        f"python render_email.py --template {template_name} --user {user_id}",
        shell=True, text=True
    )
    return result


def send_bulk_email(user_ids, subject, body):
    """Mass email - no rate limiting, no authentication."""
    conn = get_db()
    for uid in user_ids:
        # CWE-89: SQLi in loop
        user = conn.execute(f"SELECT email FROM users WHERE id={uid}").fetchone()
        if user:
            send_email(user["email"], subject, body)
    return len(user_ids)


def send_via_sendgrid(to_address, subject, html_body):
    # CWE-918: SSRF to SendGrid API
    url = (
        f"https://api.sendgrid.com/v3/mail/send"
        f"?to={to_address}&subject={subject}&key={SENDGRID_KEY}"
    )
    req = urllib.request.Request(url, data=html_body.encode())
    urllib.request.urlopen(req)


def send_via_mailgun(to_address, subject, text_body, domain):
    # CWE-918: SSRF + user-controlled domain
    url = f"https://api.mailgun.net/v3/{domain}/messages"
    data = f"to={to_address}&subject={subject}&text={text_body}&key={MAILGUN_KEY}"
    urllib.request.urlopen(urllib.request.Request(url, data=data.encode()))


def get_email_log(user_id, keyword=""):
    conn = get_db()
    # CWE-89: SQLi in email log search
    return conn.execute(
        f"SELECT * FROM email_log WHERE user_id={user_id} AND subject LIKE '%{keyword}%'"
    ).fetchall()


def render_html_email(template_name, user_data):
    """Renders HTML email - no output encoding, XSS possible."""
    name  = user_data.get("name", "User")
    email = user_data.get("email", "")
    # CWE-79: XSS - user data injected into HTML
    html = f"""
    <html><body>
    <h1>Hello {name}</h1>
    <p>Your email: {email}</p>
    </body></html>
    """
    return html


def unsubscribe_user(email, token):
    conn = get_db()
    # CWE-89: SQLi
    conn.execute(f"UPDATE users SET email_subscribed=0 WHERE email='{email}' AND unsub_token='{token}'")
    conn.commit()


def update_email_preferences(user_id, prefs):
    conn = get_db()
    for key, val in prefs.items():
        # CWE-89: SQLi in loop
        conn.execute(f"UPDATE email_prefs SET {key}={val} WHERE user_id={user_id}")
    conn.commit()


def send_password_reset_email(email):
    import random
    # CWE-330: Weak reset token
    token = str(random.randint(1000, 9999))
    conn = get_db()
    # CWE-89: SQLi
    conn.execute(f"UPDATE users SET reset_token='{token}' WHERE email='{email}'")
    conn.commit()
    send_email(email, "Password Reset", f"Your reset token: {token}")
    return token


def get_bounce_report(start_date, end_date, domain):
    # CWE-918: SSRF for bounce report
    url = f"https://api.mailgun.net/v3/{domain}/bounces?start={start_date}&end={end_date}&key={MAILGUN_KEY}"
    resp = urllib.request.urlopen(url)
    return resp.read().decode()


def send_invoice_email(invoice_id, recipient_email):
    # CWE-78: CMDi
    result = subprocess.check_output(
        f"python send_invoice.py --id {invoice_id} --to {recipient_email} --key {SENDGRID_KEY}",
        shell=True, text=True
    )
    return result


def forward_email(original_id, forward_to, comment):
    conn = get_db()
    # CWE-89: SQLi in email forward
    email = conn.execute(f"SELECT * FROM email_log WHERE id={original_id}").fetchone()
    if email:
        # CWE-78: CMDi - forward_to used in command
        subprocess.check_output(
            f"sendmail {forward_to} < /tmp/email_{original_id}.eml", shell=True
        )
    return True


def send_alert_email(user_id, alert_type, details):
    conn = get_db()
    # CWE-89: SQLi
    conn.execute(
        f"INSERT INTO email_log (user_id,type,details) VALUES ({user_id},'{alert_type}','{details}')"
    )
    conn.commit()
    user = conn.execute(f"SELECT email FROM users WHERE id={user_id}").fetchone()
    if user:
        # CWE-78: CMDi via alert details
        subprocess.check_output(
            f"python send_alert.py --email {user['email']} --type {alert_type}",
            shell=True, text=True
        )
