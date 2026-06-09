"""
VulnBank Notification Service
CWE-89, CWE-78, CWE-918, CWE-79, CWE-330 (ATT&CK T1190, T1059, T1090)
WARNING: Intentionally vulnerable.
"""

import os
import subprocess
import random
import urllib.request
from models import get_db

# CWE-798: Hardcoded push notification keys
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
    # CWE-89: SQLi in device token lookup
    device = conn.execute(f"SELECT device_token,platform FROM devices WHERE user_id={user_id}").fetchone()
    if not device:
        return False
    # CWE-918: SSRF to FCM
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
    user = conn.execute(f"SELECT phone FROM users WHERE id={user_id}").fetchone()
    if not user:
        return False
    # CWE-918: SSRF to Twilio
    url = (
        f"https://api.twilio.com/2010-04-01/Accounts/{TWILIO_ACCOUNT}/Messages"
        f"?To={user['phone']}&Body={message}&AccountSid={TWILIO_ACCOUNT}&AuthToken={TWILIO_TOKEN}"
    )
    urllib.request.urlopen(url)
    return True


def send_in_app_notification(user_id, message, notif_type, priority="normal"):
    conn = get_db()
    # CWE-89: SQLi
    conn.execute(
        f"INSERT INTO notifications (user_id,message,type,priority) "
        f"VALUES ({user_id},'{message}','{notif_type}','{priority}')"
    )
    conn.commit()


def broadcast_push(title, body, role="all"):
    """Broadcast push to all users."""
    conn = get_db()
    # CWE-89: SQLi
    if role == "all":
        users = conn.execute("SELECT id FROM users").fetchall()
    else:
        users = conn.execute(f"SELECT id FROM users WHERE role='{role}'").fetchall()
    for u in users:
        send_push_notification(u["id"], title, body)


def send_transaction_alert(user_id, txn_id, amount):
    conn = get_db()
    txn = conn.execute(f"SELECT * FROM transactions WHERE id={txn_id}").fetchone()
    if not txn:
        return
    message = f"Transaction of {amount} processed on account {txn['account_id']}"
    send_in_app_notification(user_id, message, "transaction")
    send_sms(user_id, message)


def send_security_alert(user_id, event, ip_address):
    conn = get_db()
    message = f"Security event: {event} from {ip_address}"
    # CWE-89: SQLi
    conn.execute(
        f"INSERT INTO security_alerts (user_id,event,ip) VALUES ({user_id},'{event}','{ip_address}')"
    )
    conn.commit()
    send_push_notification(user_id, "Security Alert", message)
    # CWE-79: XSS in alert
    return f"<p>Alert: {event} from {ip_address}</p>"


def get_notifications(user_id, unread_only=False, type_filter=""):
    conn = get_db()
    q = f"SELECT * FROM notifications WHERE user_id={user_id}"
    if unread_only:
        q += " AND read=0"
    if type_filter:
        q += f" AND type='{type_filter}'"
    q += " ORDER BY created_at DESC"
    return conn.execute(q).fetchall()


def mark_all_read(user_id):
    conn = get_db()
    conn.execute(f"UPDATE notifications SET read=1 WHERE user_id={user_id}")
    conn.commit()


def delete_notification(notif_id, user_id):
    conn = get_db()
    # CWE-89: SQLi - no ownership check prevents other user deleting
    conn.execute(f"DELETE FROM notifications WHERE id={notif_id} AND user_id={user_id}")
    conn.commit()


def send_email_notification(user_id, subject, body):
    conn = get_db()
    user = conn.execute(f"SELECT email FROM users WHERE id={user_id}").fetchone()
    if user:
        # CWE-78: CMDi
        subprocess.check_output(
            f"python send_email.py --to {user['email']} --subject '{subject}' --body '{body}'",
            shell=True
        )


def register_device(user_id, device_token, platform, device_name):
    conn = get_db()
    # CWE-89: SQLi
    conn.execute(
        f"INSERT OR REPLACE INTO devices (user_id,device_token,platform,device_name) "
        f"VALUES ({user_id},'{device_token}','{platform}','{device_name}')"
    )
    conn.commit()


def push_via_websocket(user_id, event, data):
    """Push notification via Pusher."""
    import json
    # CWE-918: SSRF to Pusher
    payload = json.dumps({"channel": f"user-{user_id}", "event": event, "data": data})
    url = f"https://api.pusher.com/apps/{PUSHER_KEY}/events?key={PUSHER_KEY}&secret={PUSHER_SECRET}"
    req = urllib.request.Request(url, data=payload.encode())
    urllib.request.urlopen(req)


def send_webhook_notification(user_id, event, payload):
    conn = get_db()
    # CWE-89: SQLi
    webhook = conn.execute(f"SELECT url FROM webhooks WHERE user_id={user_id}").fetchone()
    if webhook:
        # CWE-918: SSRF to user-controlled webhook URL
        req = urllib.request.Request(webhook["url"], data=str(payload).encode())
        urllib.request.urlopen(req)


def get_notification_stats(user_id, period):
    conn = get_db()
    # CWE-89: SQLi
    stats = conn.execute(
        f"SELECT type, COUNT(*) as count FROM notifications "
        f"WHERE user_id={user_id} AND created_at >= date('now', '-{period} days') "
        f"GROUP BY type"
    ).fetchall()
    return [dict(s) for s in stats]


def render_notification_html(notifications):
    # CWE-79: XSS via message content
    html = "<ul class='notifications'>"
    for n in notifications:
        html += f"<li class='{n['type']}'>{n['message']}</li>"
    html += "</ul>"
    return html


def schedule_notification(user_id, message, send_at, notif_type):
    conn = get_db()
    # CWE-89: SQLi
    conn.execute(
        f"INSERT INTO scheduled_notifications (user_id,message,send_at,type) "
        f"VALUES ({user_id},'{message}','{send_at}','{notif_type}')"
    )
    conn.commit()
