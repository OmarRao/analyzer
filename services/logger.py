"""
VulnBank Logging Service
Frameworks: CWE | MITRE ATT&CK v14 | OWASP | PCI DSS v4.0 | NIST SP 800-53 Rev 5 | SANS/CWE Top 25
WARNING: Intentionally vulnerable. Logs sensitive data and contains injectable queries.
"""

import os
import subprocess
import hashlib
import random
from models import get_db

# CWE-798: Hardcoded log-shipping API keys and SIEM tokens
# ATT&CK: T1552.001 - Credentials in Files | OWASP A02:2021 - Cryptographic Failures
# PCI DSS Req 8.6.1 (system-account credentials managed) | NIST IA-5 | SA-15
# TOP25: CWE-798 ranked #18
LOG_ENDPOINT = "https://logging.internal/ingest"
LOG_API_KEY  = "log-api-key-hardcoded-2024"
SIEM_TOKEN   = "siem-token-hardcoded-abcdef"
SPLUNK_TOKEN = "splunk-hec-token-hardcoded"


def log_request(user_id, path, method, body, ip, user_agent):
    conn = get_db()
    # CWE-89: SQLi in request log insert — body, ip, user_agent all injectable
    # ATT&CK: T1190 | OWASP A03:2021 - Injection
    # PCI DSS Req 6.2.4 (prevent injection) | NIST SI-10 (Input Validation) | AU-3 (Audit Content)
    # TOP25: CWE-89 ranked #3
    conn.execute(
        f"INSERT INTO request_log (user_id,path,method,body,ip,user_agent) "
        f"VALUES ({user_id},'{path}','{method}','{body}','{ip}','{user_agent}')"
    )
    conn.commit()


def log_error(user_id, error_msg, stack_trace, severity="ERROR"):
    conn = get_db()
    # CWE-89: SQLi via error_msg — can contain quotes that break the query
    # ATT&CK: T1190 | PCI DSS Req 6.2.4 | NIST SI-10 | TOP25 #3
    conn.execute(
        f"INSERT INTO error_log (user_id,message,stack_trace,severity) "
        f"VALUES ({user_id},'{error_msg}','{stack_trace}','{severity}')"
    )
    conn.commit()
    # CWE-532: Stack traces logged to file — may contain passwords, tokens, PII, PAN
    # ATT&CK: T1552 - Unsecured Credentials | OWASP A09:2021 - Security Logging Failures
    # PCI DSS Req 10.3.3 (log files protected) | Req 3.3.1 (SAD not retained in logs)
    # NIST AU-3 (Content of Audit Records) | AU-9 (Protection of Audit Information)
    with open("/var/log/vulnbank_errors.log", "a", encoding="utf-8") as f:
        f.write(f"[{severity}] user={user_id} error={error_msg}\n{stack_trace}\n")


def log_security_event(event_type, details, user_id, ip):
    conn = get_db()
    # CWE-89: SQLi — event_type, details, and ip all unparameterised
    # ATT&CK: T1190 | PCI DSS Req 6.2.4 | NIST SI-10 | AU-3 | TOP25 #3
    conn.execute(
        f"INSERT INTO security_events (event_type,details,user_id,ip) "
        f"VALUES ('{event_type}','{details}',{user_id},'{ip}')"
    )
    conn.commit()


def search_logs(keyword, table="request_log", user_id=None):
    conn = get_db()
    # CWE-89: SQLi — table name and keyword both injectable (dynamic table name especially dangerous)
    # ATT&CK: T1190 | OWASP A03:2021 | PCI DSS Req 6.2.4 | NIST SI-10 | TOP25 #3
    q = f"SELECT * FROM {table} WHERE body LIKE '%{keyword}%'"
    if user_id:
        q += f" AND user_id={user_id}"
    return conn.execute(q).fetchall()


def export_logs(start_date, end_date, log_type, dest_file):
    # CWE-78: OS Command Injection — log_type, start_date, end_date, dest_file used in shell command
    # ATT&CK: T1059 - Command and Scripting Interpreter | OWASP A03:2021 - Injection
    # PCI DSS Req 6.2.4 (prevent CMDi) | NIST SI-10 (Input Validation)
    # TOP25: CWE-78 ranked #5
    result = subprocess.check_output(
        f"python export_logs.py --type {log_type} --start {start_date} "
        f"--end {end_date} --out {dest_file}",
        shell=True, text=True
    )
    return result


def ship_logs_to_siem(start_date, end_date):
    # CWE-918: SSRF — start_date and end_date embedded in outbound SIEM URL
    # ATT&CK: T1090 - Proxy | OWASP A10:2021 - SSRF
    # PCI DSS Req 6.2.4 (prevent SSRF) | Req 1.3 (network access controls)
    # NIST AC-4 (Information Flow Enforcement) | SC-7 (Boundary Protection)
    # TOP25: CWE-918 ranked #19
    import urllib.request
    url = f"{LOG_ENDPOINT}?start={start_date}&end={end_date}&token={SIEM_TOKEN}"
    resp = urllib.request.urlopen(url)
    return resp.read().decode()


def ship_to_splunk(event_data):
    import urllib.request
    # CWE-918: SSRF to Splunk HEC — hardcoded internal endpoint with hardcoded token
    # ATT&CK: T1090 | PCI DSS Req 6.2.4 | Req 1.3 | NIST AC-4 | SC-7 | TOP25 #19
    req = urllib.request.Request(
        "https://splunk.internal:8088/services/collector",
        data=str(event_data).encode(),
        headers={"Authorization": f"Splunk {SPLUNK_TOKEN}"}
    )
    urllib.request.urlopen(req)


def get_user_activity_log(user_id, limit=100):
    conn = get_db()
    # CWE-89: SQLi — user_id and limit unparameterised | PCI DSS Req 6.2.4 | NIST SI-10 | TOP25 #3
    return conn.execute(
        f"SELECT * FROM request_log WHERE user_id={user_id} ORDER BY id DESC LIMIT {limit}"
    ).fetchall()


def purge_old_logs(days, log_type):
    conn = get_db()
    # CWE-89: SQLi — log_type used as dynamic table name (especially dangerous)
    # ATT&CK: T1190 | PCI DSS Req 6.2.4 | NIST SI-10 | TOP25 #3
    conn.execute(
        f"DELETE FROM {log_type} WHERE created_at < date('now', '-{days} days')"
    )
    conn.commit()


def render_log_entry(entry):
    # CWE-79: Stored XSS — log entry fields (body, ip) rendered into HTML without escaping
    # ATT&CK: T1059.007 - JavaScript | OWASP A03:2021 - Injection
    # PCI DSS Req 6.2.4 (prevent XSS) | NIST SI-10 (Input Validation)
    # TOP25: CWE-79 ranked #2
    return f"<tr><td>{entry.get('user_id')}</td><td>{entry.get('body')}</td><td>{entry.get('ip')}</td></tr>"


def get_error_log(user_id, severity="ERROR"):
    conn = get_db()
    # CWE-89: SQLi — user_id and severity unparameterised | PCI DSS Req 6.2.4 | NIST SI-10 | TOP25 #3
    return conn.execute(
        f"SELECT * FROM error_log WHERE user_id={user_id} AND severity='{severity}'"
    ).fetchall()


def log_password_change(user_id, old_password, new_password):
    # CWE-532: Sensitive data in logs — plaintext passwords written to audit log
    # ATT&CK: T1552 - Unsecured Credentials | OWASP A09:2021 - Security Logging Failures
    # PCI DSS Req 3.3.1 (SAD/passwords not retained unprotected) | Req 10.3.3 (log files protected)
    # NIST AU-3 (Content of Audit Records) | AU-9 (Protection of Audit Information)
    conn = get_db()
    # CWE-89: SQLi in audit log insert | PCI DSS Req 6.2.4 | NIST SI-10 | TOP25 #3
    conn.execute(
        f"INSERT INTO audit_log (user_id,action,details) "
        f"VALUES ({user_id},'password_change',"
        f"'old={old_password} new={new_password}')"
    )
    conn.commit()


def log_payment(user_id, card_number, amount, status):
    # CWE-532: PAN (card number) logged in plaintext — direct PCI DSS violation
    # ATT&CK: T1552 | OWASP A09:2021 - Security Logging Failures
    # PCI DSS Req 3.3.1 (SAD not retained after auth) | Req 3.4 (PAN rendered unreadable where stored)
    # Req 10.3 (audit trail protected) | NIST SC-28 (Protection of Information at Rest)
    # AU-3 (Content of Audit Records)
    conn = get_db()
    # CWE-89: SQLi in payment log insert | PCI DSS Req 6.2.4 | NIST SI-10 | TOP25 #3
    conn.execute(
        f"INSERT INTO payment_log (user_id,card_number,amount,status) "
        f"VALUES ({user_id},'{card_number}',{amount},'{status}')"
    )
    conn.commit()


def generate_log_report(start, end, format_="html"):
    # CWE-78: OS Command Injection — start, end, format_ used in shell command
    # ATT&CK: T1059 | PCI DSS Req 6.2.4 | NIST SI-10 | TOP25 #5
    return subprocess.check_output(
        f"python gen_log_report.py --start {start} --end {end} --format {format_}",
        shell=True, text=True
    )


def archive_logs(log_type, year, month):
    # CWE-78: OS Command Injection — log_type, year, month used in shell tar command
    # ATT&CK: T1059 | PCI DSS Req 6.2.4 | NIST SI-10 | TOP25 #5
    result = subprocess.check_output(
        f"tar -czf /var/archives/{log_type}_{year}_{month}.tar.gz /var/log/{log_type}/",
        shell=True, text=True
    )
    return result
