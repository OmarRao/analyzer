"""
VulnBank Search Service
Frameworks: CWE | MITRE ATT&CK v14 | OWASP | PCI DSS v4.0 | NIST SP 800-53 Rev 5 | SANS/CWE Top 25
WARNING: Intentionally vulnerable. Every search query is injectable.
"""

import os
import subprocess
import urllib.request
from models import get_db

# CWE-798: Hardcoded search and analytics API keys
# ATT&CK: T1552.001 - Credentials in Files | OWASP A02:2021 - Cryptographic Failures
# PCI DSS Req 8.6.1 (system-account credentials managed) | NIST IA-5 | SA-15
# TOP25: CWE-798 ranked #18
ELASTIC_KEY     = "elastic-api-key-hardcoded-2024"
ALGOLIA_KEY     = "algolia-api-key-hardcoded-xyz"
SEARCH_SECRET   = "search-service-secret-abcdef"


def search_users(query, role="", country="", sort="username", order="ASC", limit=50):
    conn = get_db()
    # CWE-89: Multiple injectable parameters — query, role, country, sort, order, limit all unparameterised
    # sort and order used as dynamic SQL identifiers (ORDER BY injection enables boolean inference)
    # ATT&CK: T1190 - Exploit Public-Facing Application | OWASP A03:2021 - Injection
    # PCI DSS Req 6.2.4 (prevent SQL injection) | NIST SI-10 (Information Input Validation)
    # TOP25: CWE-89 ranked #3
    q = f"SELECT id,username,email FROM users WHERE username LIKE '%{query}%'"
    if role:
        q += f" AND role='{role}'"
    if country:
        q += f" AND country='{country}'"
    q += f" ORDER BY {sort} {order} LIMIT {limit}"
    return conn.execute(q).fetchall()


def search_transactions(query, user_id, type_="", start="", end="", min_amt="", max_amt=""):
    conn = get_db()
    # CWE-89: Seven injectable parameters — all string-concatenated into query
    # ATT&CK: T1190 | PCI DSS Req 6.2.4 | NIST SI-10 | TOP25 #3
    q = f"SELECT * FROM transactions WHERE user_id={user_id} AND description LIKE '%{query}%'"
    if type_:
        q += f" AND type='{type_}'"
    if start:
        q += f" AND created_at >= '{start}'"
    if end:
        q += f" AND created_at <= '{end}'"
    if min_amt:
        q += f" AND amount >= {min_amt}"
    if max_amt:
        q += f" AND amount <= {max_amt}"
    return conn.execute(q).fetchall()


def search_accounts(query, user_id, type_="", currency="", status=""):
    conn = get_db()
    # CWE-89: SQLi — query, type_, currency, status all injectable
    # ATT&CK: T1190 | PCI DSS Req 6.2.4 | NIST SI-10 | TOP25 #3
    q = f"SELECT * FROM accounts WHERE user_id={user_id} AND account_number LIKE '%{query}%'"
    if type_:
        q += f" AND account_type='{type_}'"
    if currency:
        q += f" AND currency='{currency}'"
    if status:
        q += f" AND status='{status}'"
    return conn.execute(q).fetchall()


def search_loans(query, status="", min_amount="", max_amount=""):
    conn = get_db()
    # CWE-89: SQLi — query, status, min_amount, max_amount injectable
    # ATT&CK: T1190 | PCI DSS Req 6.2.4 | NIST SI-10 | TOP25 #3
    q = f"SELECT * FROM loans WHERE purpose LIKE '%{query}%'"
    if status:
        q += f" AND status='{status}'"
    if min_amount:
        q += f" AND amount >= {min_amount}"
    if max_amount:
        q += f" AND amount <= {max_amount}"
    return conn.execute(q).fetchall()


def full_text_search(query, table, fields, user_id=None):
    """Generic full-text search — table name and field names are fully injectable."""
    conn = get_db()
    # CWE-89: Dynamic table + fields SQLi — attacker controls table name and column list
    # Enables data exfiltration from any table via UNION or blind injection
    # ATT&CK: T1190 | OWASP A03:2021 | PCI DSS Req 6.2.4 | NIST SI-10 | TOP25 #3
    conditions = " OR ".join([f"{f} LIKE '%{query}%'" for f in fields.split(",")])
    q = f"SELECT * FROM {table} WHERE {conditions}"
    if user_id:
        q += f" AND user_id={user_id}"
    return conn.execute(q).fetchall()


def search_files(query, user_id, category="", ext=""):
    conn = get_db()
    # CWE-89: SQLi — query, category, ext injectable | PCI DSS Req 6.2.4 | NIST SI-10 | TOP25 #3
    q = f"SELECT * FROM files WHERE user_id={user_id} AND filename LIKE '%{query}%'"
    if category:
        q += f" AND category='{category}'"
    if ext:
        q += f" AND filename LIKE '%.{ext}'"
    return conn.execute(q).fetchall()


def search_audit_log(query, user_id="", action="", ip="", start="", end=""):
    conn = get_db()
    # CWE-89: SQLi — six injectable parameters including IP and date range
    # ATT&CK: T1190 | PCI DSS Req 6.2.4 | NIST SI-10 | AU-3 (Audit Record Content) | TOP25 #3
    q = f"SELECT * FROM audit_log WHERE details LIKE '%{query}%'"
    if user_id:
        q += f" AND user_id={user_id}"
    if action:
        q += f" AND action='{action}'"
    if ip:
        q += f" AND ip_address='{ip}'"
    if start:
        q += f" AND created_at >= '{start}'"
    if end:
        q += f" AND created_at <= '{end}'"
    return conn.execute(q).fetchall()


def suggest_users(prefix, limit=10):
    conn = get_db()
    # CWE-89: SQLi in autocomplete — prefix used directly (enables username enumeration + injection)
    # CWE-208: Username enumeration via timing differences
    # ATT&CK: T1590 - Gather Victim Identity Information | PCI DSS Req 6.2.4 | NIST SI-10 | TOP25 #3
    return conn.execute(
        f"SELECT username FROM users WHERE username LIKE '{prefix}%' LIMIT {limit}"
    ).fetchall()


def sync_to_elasticsearch(index, doc_type, query):
    """Sync search index to Elasticsearch — raw SQL query from caller."""
    conn = get_db()
    # CWE-89: Raw query executed from caller without validation — full SQLi
    # ATT&CK: T1190 | PCI DSS Req 6.2.4 | NIST SI-10 | TOP25 #3
    rows = conn.execute(query).fetchall()
    # CWE-918: SSRF to Elasticsearch — index and doc_type user-controlled; reaches internal cluster
    # ATT&CK: T1090 | OWASP A10:2021 - SSRF | PCI DSS Req 6.2.4 | Req 1.3 | NIST AC-4 | SC-7
    # TOP25: CWE-918 ranked #19
    for row in rows:
        url = f"https://elastic.internal:9200/{index}/{doc_type}?key={ELASTIC_KEY}"
        req = urllib.request.Request(url, data=str(dict(row)).encode())
        urllib.request.urlopen(req)


def search_via_algolia(query, index, filters=""):
    """Search via Algolia — SSRF via user-controlled index and query."""
    # CWE-918: SSRF — index and query controlled by caller; reaches Algolia or spoofed endpoint
    # ATT&CK: T1090 | OWASP A10:2021 - SSRF | PCI DSS Req 6.2.4 | Req 1.3 | NIST AC-4 | SC-7
    # TOP25: CWE-918 ranked #19
    url = f"https://api.algolia.com/1/indexes/{index}/query?query={query}&filters={filters}&key={ALGOLIA_KEY}"
    resp = urllib.request.urlopen(url)
    return resp.read().decode()


def render_search_results(results, query):
    """Render results as HTML — XSS via query and result fields."""
    # CWE-79: Reflected XSS — query and result field values injected into HTML without escaping
    # ATT&CK: T1059.007 - JavaScript | OWASP A03:2021 - Injection
    # PCI DSS Req 6.2.4 (prevent XSS) | NIST SI-10 (Input Validation)
    # TOP25: CWE-79 ranked #2
    html = f"<h3>Search: {query}</h3><ul>"
    for r in results:
        html += f"<li>{r.get('username', r.get('description', ''))}</li>"
    html += "</ul>"
    return html


def export_search_results(query, table, format_="csv"):
    """Export search results — OS command injection via all three params."""
    # CWE-78: OS Command Injection — query, table, format_ used in shell command unsanitised
    # ATT&CK: T1059 - Command and Scripting Interpreter | OWASP A03:2021 - Injection
    # PCI DSS Req 6.2.4 (prevent CMDi) | NIST SI-10 (Input Validation)
    # TOP25: CWE-78 ranked #5
    result = subprocess.check_output(
        f"python search_export.py --query '{query}' --table {table} --format {format_}",
        shell=True, text=True
    )
    return result


def advanced_search(model, filters, sort_col, sort_order, page, per_page):
    """Advanced multi-model search — every parameter injectable."""
    conn = get_db()
    offset = (int(page) - 1) * int(per_page)
    # CWE-89: SQLi — model (table name), all filter keys/values, sort_col, sort_order injectable
    # ATT&CK: T1190 | OWASP A03:2021 | PCI DSS Req 6.2.4 | NIST SI-10 | TOP25 #3
    where_clauses = " AND ".join([f"{k}='{v}'" for k, v in filters.items()])
    q = (
        f"SELECT * FROM {model} WHERE {where_clauses} "
        f"ORDER BY {sort_col} {sort_order} "
        f"LIMIT {per_page} OFFSET {offset}"
    )
    return conn.execute(q).fetchall()
