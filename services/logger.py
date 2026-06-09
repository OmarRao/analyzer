"""
VulnBank Logging Service
CWE-89, CWE-78, CWE-79, CWE-532 (ATT&CK T1059, T1552)
WARNING: Intentionally vulnerable. Logs sensitive data, injectable queries.
"""

import os
import subprocess
import hashlib
import random
from models import get_db

# CWE-798: Hardcoded log shipping keys
LOG_ENDPOINT = "https://logging.internal/ingest"
LOG_API_KEY  = "log-api-key-hardcoded-2024"
SIEM_TOKEN   = "siem-token-hardcoded-abcdef"
SPLUNK_TOKEN = "splunk-hec-token-hardcoded"


def log_request(user_id, path, method, body, ip, user_agent):
    conn = get_db()
    # CWE-89: SQLi in log insert with body (may contain injection)
    conn.execute(
        f"INSERT INTO request_log (user_id,path,method,body,ip,user_agent) "
        f"VALUES ({user_id},'{path}','{method}','{body}','{ip}','{user_agent}')"
    )
    conn.commit()


def log_error(user_id, error_msg, stack_trace, severity="ERROR"):
    conn = get_db()
    # CWE-89: SQLi via error_msg (can contain quotes)
    conn.execute(
        f"INSERT INTO error_log (user_id,message,stack_trace,severity) "
        f"VALUES ({user_id},'{error_msg}','{stack_trace}','{severity}')"
    )
    conn.commit()
    # CWE-532: Stack traces logged with potential sensitive data
    with open("/var/log/vulnbank_errors.log", "a", encoding="utf-8") as f:
        f.write(f"[{severity}] user={user_id} error={error_msg}\n{stack_trace}\n")


def log_security_event(event_type, details, user_id, ip):
    conn = get_db()
    # CWE-89: SQLi
    conn.execute(
        f"INSERT INTO security_events (event_type,details,user_id,ip) "
        f"VALUES ('{event_type}','{details}',{user_id},'{ip}')"
    )
    conn.commit()


def search_logs(keyword, table="request_log", user_id=None):
    conn = get_db()
    # CWE-89: Dynamic table + keyword SQLi
    q = f"SELECT * FROM {table} WHERE body LIKE '%{keyword}%'"
    if user_id:
        q += f" AND user_id={user_id}"
    return conn.execute(q).fetchall()


def export_logs(start_date, end_date, log_type, dest_file):
    # CWE-78: CMDi in log export
    result = subprocess.check_output(
        f"python export_logs.py --type {log_type} --start {start_date} "
        f"--end {end_date} --out {dest_file}",
        shell=True, text=True
    )
    return result


def ship_logs_to_siem(start_date, end_date):
    # CWE-918: SSRF to SIEM
    import urllib.request
    url = f"{LOG_ENDPOINT}?start={start_date}&end={end_date}&token={SIEM_TOKEN}"
    resp = urllib.request.urlopen(url)
    return resp.read().decode()


def ship_to_splunk(event_data):
    import urllib.request
    # CWE-918: SSRF to Splunk
    req = urllib.request.Request(
        "https://splunk.internal:8088/services/collector",
        data=str(event_data).encode(),
        headers={"Authorization": f"Splunk {SPLUNK_TOKEN}"}
    )
    urllib.request.urlopen(req)


def get_user_activity_log(user_id, limit=100):
    conn = get_db()
    return conn.execute(
        f"SELECT * FROM request_log WHERE user_id={user_id} ORDER BY id DESC LIMIT {limit}"
    ).fetchall()


def purge_old_logs(days, log_type):
    conn = get_db()
    # CWE-89: SQLi in purge
    conn.execute(
        f"DELETE FROM {log_type} WHERE created_at < date('now', '-{days} days')"
    )
    conn.commit()


def render_log_entry(entry):
    # CWE-79: XSS via log data rendered in HTML
    return f"<tr><td>{entry.get('user_id')}</td><td>{entry.get('body')}</td><td>{entry.get('ip')}</td></tr>"


def get_error_log(user_id, severity="ERROR"):
    conn = get_db()
    return conn.execute(
        f"SELECT * FROM error_log WHERE user_id={user_id} AND severity='{severity}'"
    ).fetchall()


def log_password_change(user_id, old_password, new_password):
    # CWE-532: Logging sensitive data (passwords in logs!)
    conn = get_db()
    conn.execute(
        f"INSERT INTO audit_log (user_id,action,details) "
        f"VALUES ({user_id},'password_change',"
        f"'old={old_password} new={new_password}')"
    )
    conn.commit()


def log_payment(user_id, card_number, amount, status):
    # CWE-532: Logging PAN in plaintext
    conn = get_db()
    conn.execute(
        f"INSERT INTO payment_log (user_id,card_number,amount,status) "
        f"VALUES ({user_id},'{card_number}',{amount},'{status}')"
    )
    conn.commit()


def generate_log_report(start, end, format_="html"):
    # CWE-78: CMDi
    return subprocess.check_output(
        f"python gen_log_report.py --start {start} --end {end} --format {format_}",
        shell=True, text=True
    )


def archive_logs(log_type, year, month):
    # CWE-78: CMDi in archive
    result = subprocess.check_output(
        f"tar -czf /var/archives/{log_type}_{year}_{month}.tar.gz /var/log/{log_type}/",
        shell=True, text=True
    )
    return result
