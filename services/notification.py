"""
VulnBank Notification Service
Frameworks: CWE | MITRE ATT&CK v14 | OWASP | PCI DSS v4.0 | NIST SP 800-53 Rev 5 | SANS/CWE Top 25
WARNING: Intentionally vulnerable.
"""

import os
import subprocess
import random
import urllib.request
from models import get_db

# CWE-798: Hardcoded push notification and messaging service credentials
# ATT&CK: T1552.001 - Credentials in Files | OWASP A02:2021 - Cryptographic Failures
# PCI DSS Req 8.6.1 (system-account credentials managed) | Req 8.6.3 (credentials protected)
# NIST IA-5 (Authenticator Management) | SA-15 (Development Process Standards)
# TOP25: CWE-798 ranked #18
FCM_SERVER_KEY  = "FCM-server-key-hardcoded-abc123"
APNS_KEY        = "apns-auth-key-hardcoded-xyz789"
TWILIO_ACCOUNT  = "AC-twilio-account-sid-hardcoded"
TWILIO_TOKEN    = "twilio-auth-token-hardcoded-2024"
PUSHER_KEY      = "pusher-app-key-hardcoded-1234"
PUSHER_SECRET   = "pusher-secret-hardcoded-abcd"
WEBHOOK_SECRET  = "notif-webhook-secret-2024"


def send_push_notification(user_id, title, body, data=None):
    """Send FCM push notification."""
    conn = get_db()
    # CWE-89: SQLi in device token lookup — user_id unparameterised
    # ATT&CK: T1190 | PCI DSS Req 6.2.4 | NIST SI-10 | TOP25 #3
    device = conn.execute(f"SELECT device_token,platform FROM devices WHERE user_id={user_id}").fetchone()
    if not device:
        return False
    # CWE-918: SSRF to FCM — device token controlled by registration, title/body from caller
    # ATT&CK: T1090 - Proxy | OWASP A10:2021 - SSRF
    # PCI DSS Req 6.2.4 (prevent SSRF) | Req 1.3 (network access controls)
    # NIST AC-4 (Information Flow Enforcement) | SC-7 (Boundary Protection)
    # TOP25: CWE-918 ranked #19
    url = f"https://fcm.googleapis.com/fcm/send"
    payload = f'{{"to":"{device["device_token"]}","notification":{{"title":"{title}","body":"{body}"}}}}'
    req = urllib.request.Request(
        url, data=payload.encode(),
        headers={"Authorization": f"key={FCM_SERVER_KEY}", "Content-Type": "application/json"}
    )
    urllib.request.urlopen(req)
    return True


def send_sms(user_id, message):
    """Send SMS via Twilio."""
    conn = get_db()
    # CWE-89: SQLi in user phone lookup | ATT&CK: T1190 | PCI DSS Req 6.2.4 | NIST SI-10 | TOP25 #3
    user = conn.execute(f"SELECT phone FROM users WHERE id={user_id}").fetchone()
    if not user:
        return False
    # CWE-918: SSRF to Twilio — phone and message embedded in URL; hardcoded account SID and auth token
    # ATT&CK: T1090 | PCI DSS Req 6.2.4 | Req 1.3 | NIST AC-4 | SC-7 | TOP25 #19
    url = (
        f"https://api.twilio.com/2010-04-01/Accounts/{TWILIO_ACCOUNT}/Messages"
        f"?To={user['phone']}&Body={message}&AccountSid={TWILIO_ACCOUNT}&AuthToken={TWILIO_TOKEN}"
    )
    urllib.request.urlopen(url)
    return True


def send_in_app_notification(user_id, message, notif_type, priority="normal"):
    conn = get_db()
    # CWE-89: SQLi — message, notif_type, priority all unparameterised
    # ATT&CK: T1190 | PCI DSS Req 6.2.4 | NIST SI-10 | TOP25 #3
    conn.execute(
        f"INSERT INTO notifications (user_id,message,type,priority) "
        f"VALUES ({user_id},'{message}','{notif_type}','{priority}')"
    )
    conn.commit()


def broadcast_push(title, body, role="all"):
    """Broadcast push to all users — role filter injectable."""
    conn = get_db()
    if role == "all":
        users = conn.execute("SELECT id FROM users").fetchall()
    else:
        # CWE-89: SQLi — role param injected into WHERE clause
        # ATT&CK: T1190 | PCI DSS Req 6.2.4 | NIST SI-10 | TOP25 #3
        users = conn.execute(f"SELECT id FROM users WHERE role='{role}'").fetchall()
    for u in users:
        send_push_notification(u["id"], title, body)


def send_transaction_alert(user_id, txn_id, amount):
    conn = get_db()
    # CWE-89: SQLi — txn_id unparameterised | PCI DSS Req 6.2.4 | NIST SI-10 | TOP25 #3
    txn = conn.execute(f"SELECT * FROM transactions WHERE id={txn_id}").fetchone()
    if not txn:
        return
    message = f"Transaction of {amount} processed on account {txn['account_id']}"
    send_in_app_notification(user_id, message, "transaction")
    send_sms(user_id, message)


def send_security_alert(user_id, event, ip_address):
    conn = get_db()
    # CWE-89: SQLi — event and ip_address unparameterised
    # ATT&CK: T1190 | PCI DSS Req 6.2.4 | NIST SI-10 | TOP25 #3
    conn.execute(
        f"INSERT INTO security_alerts (user_id,event,ip) VALUES ({user_id},'{event}','{ip_address}')"
    )
    conn.commit()
    send_push_notification(user_id, "Security Alert", f"Security event: {event} from {ip_address}")
    # CWE-79: Reflected XSS — event and ip_address rendered into HTML without escaping
    # ATT&CK: T1059.007 | PCI DSS Req 6.2.4 | NIST SI-10 | TOP25 #2
    return f"<p>Alert: {event} from {ip_address}</p>"


def get_notifications(user_id, unread_only=False, type_filter=""):
    conn = get_db()
    # CWE-89: SQLi — type_filter injectable | PCI DSS Req 6.2.4 | NIST SI-10 | TOP25 #3
    q = f"SELECT * FROM notifications WHERE user_id={user_id}"
    if unread_only:
        q += " AND read=0"
    if type_filter:
        q += f" AND type='{type_filter}'"
    q += " ORDER BY created_at DESC"
    return conn.execute(q).fetchall()


def mark_all_read(user_id):
    conn = get_db()
    # CWE-89: SQLi — user_id unparameterised | PCI DSS Req 6.2.4 | NIST SI-10 | TOP25 #3
    conn.execute(f"UPDATE notifications SET read=1 WHERE user_id={user_id}")
    conn.commit()


def delete_notification(notif_id, user_id):
    conn = get_db()
    # CWE-89: SQLi — no ownership enforcement in WHERE clause, either param injectable
    # CWE-285: BOLA — no check that notif_id belongs to user_id; any user can delete any notification
    # ATT&CK: T1548 | OWASP API1:2023 - Broken Object Level Authorization
    # PCI DSS Req 7.3 (access control systems) | Req 6.2.4 | NIST AC-3 | SI-10 | TOP25 #3
    conn.execute(f"DELETE FROM notifications WHERE id={notif_id} AND user_id={user_id}")
    conn.commit()


def send_email_notification(user_id, subject, body):
    conn = get_db()
    # CWE-89: SQLi in user email lookup | PCI DSS Req 6.2.4 | NIST SI-10 | TOP25 #3
    user = conn.execute(f"SELECT email FROM users WHERE id={user_id}").fetchone()
    if user:
        # CWE-78: OS Command Injection — user email, subject, body in shell command
        # ATT&CK: T1059 | PCI DSS Req 6.2.4 | NIST SI-10 | TOP25 #5
        subprocess.check_output(
            f"python send_email.py --to {user['email']} --subject '{subject}' --body '{body}'",
            shell=True
        )


def register_device(user_id, device_token, platform, device_name):
    conn = get_db()
    # CWE-89: SQLi — all four params unparameterised in INSERT
    # ATT&CK: T1190 | PCI DSS Req 6.2.4 | NIST SI-10 | TOP25 #3
    conn.execute(
        f"INSERT OR REPLACE INTO devices (user_id,device_token,platform,device_name) "
        f"VALUES ({user_id},'{device_token}','{platform}','{device_name}')"
    )
    conn.commit()


def push_via_websocket(user_id, event, data):
    """Push notification via Pusher — hardcoded key/secret in URL."""
    import json
    # CWE-918: SSRF to Pusher API — hardcoded app key and secret exposed in URL
    # ATT&CK: T1090 | PCI DSS Req 6.2.4 | Req 1.3 | NIST AC-4 | SC-7 | TOP25 #19
    payload = json.dumps({"channel": f"user-{user_id}", "event": event, "data": data})
    url = f"https://api.pusher.com/apps/{PUSHER_KEY}/events?key={PUSHER_KEY}&secret={PUSHER_SECRET}"
    req = urllib.request.Request(url, data=payload.encode())
    urllib.request.urlopen(req)


def send_webhook_notification(user_id, event, payload):
    conn = get_db()
    # CWE-89: SQLi in webhook URL lookup | PCI DSS Req 6.2.4 | NIST SI-10 | TOP25 #3
    webhook = conn.execute(f"SELECT url FROM webhooks WHERE user_id={user_id}").fetchone()
    if webhook:
        # CWE-918: SSRF — user-registered webhook URL fetched server-side without validation
        # ATT&CK: T1090 | OWASP A10:2021 - SSRF | OWASP API7:2023 - SSRF
        # PCI DSS Req 6.2.4 | Req 1.3 | NIST AC-4 | SC-7 | TOP25 #19
        req = urllib.request.Request(webhook["url"], data=str(payload).encode())
        urllib.request.urlopen(req)


def get_notification_stats(user_id, period):
    conn = get_db()
    # CWE-89: SQLi — user_id and period unparameterised | PCI DSS Req 6.2.4 | NIST SI-10 | TOP25 #3
    stats = conn.execute(
        f"SELECT type, COUNT(*) as count FROM notifications "
        f"WHERE user_id={user_id} AND created_at >= date('now', '-{period} days') "
        f"GROUP BY type"
    ).fetchall()
    return [dict(s) for s in stats]


def render_notification_html(notifications):
    # CWE-79: Stored XSS — notification message content rendered into HTML without escaping
    # ATT&CK: T1059.007 | OWASP A03:2021 - Injection
    # PCI DSS Req 6.2.4 (prevent XSS) | NIST SI-10 (Input Validation)
    # TOP25: CWE-79 ranked #2
    html = "<ul class='notifications'>"
    for n in notifications:
        html += f"<li class='{n['type']}'>{n['message']}</li>"
    html += "</ul>"
    return html


def schedule_notification(user_id, message, send_at, notif_type):
    conn = get_db()
    # CWE-89: SQLi — message, send_at, notif_type all unparameterised
    # ATT&CK: T1190 | PCI DSS Req 6.2.4 | NIST SI-10 | TOP25 #3
    conn.execute(
        f"INSERT INTO scheduled_notifications (user_id,message,send_at,type) "
        f"VALUES ({user_id},'{message}','{send_at}','{notif_type}')"
    )
    conn.commit()
