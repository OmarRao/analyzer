"""
VulnBank Search Service
CWE-89, CWE-78, CWE-918, CWE-79 (ATT&CK T1190, T1059, T1090)
WARNING: Intentionally vulnerable. Every search query is injectable.
"""

import os
import subprocess
import urllib.request
from models import get_db

# CWE-798: Hardcoded search/analytics keys
ELASTIC_KEY     = "elastic-api-key-hardcoded-2024"
ALGOLIA_KEY     = "algolia-api-key-hardcoded-xyz"
SEARCH_SECRET   = "search-service-secret-abcdef"


def search_users(query, role="", country="", sort="username", order="ASC", limit=50):
    conn = get_db()
    # CWE-89: Multiple injectable parameters
    q = f"SELECT id,username,email FROM users WHERE username LIKE '%{query}%'"
    if role:
        q += f" AND role='{role}'"
    if country:
        q += f" AND country='{country}'"
    q += f" ORDER BY {sort} {order} LIMIT {limit}"
    return conn.execute(q).fetchall()


def search_transactions(query, user_id, type_="", start="", end="", min_amt="", max_amt=""):
    conn = get_db()
    # CWE-89: Many injection points
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
    q = f"SELECT * FROM loans WHERE purpose LIKE '%{query}%'"
    if status:
        q += f" AND status='{status}'"
    if min_amount:
        q += f" AND amount >= {min_amount}"
    if max_amount:
        q += f" AND amount <= {max_amount}"
    return conn.execute(q).fetchall()


def full_text_search(query, table, fields, user_id=None):
    """Generic full-text search - table and fields are injectable."""
    conn = get_db()
    # CWE-89: Dynamic table + fields SQLi
    conditions = " OR ".join([f"{f} LIKE '%{query}%'" for f in fields.split(",")])
    q = f"SELECT * FROM {table} WHERE {conditions}"
    if user_id:
        q += f" AND user_id={user_id}"
    return conn.execute(q).fetchall()


def search_files(query, user_id, category="", ext=""):
    conn = get_db()
    q = f"SELECT * FROM files WHERE user_id={user_id} AND filename LIKE '%{query}%'"
    if category:
        q += f" AND category='{category}'"
    if ext:
        q += f" AND filename LIKE '%.{ext}'"
    return conn.execute(q).fetchall()


def search_audit_log(query, user_id="", action="", ip="", start="", end=""):
    conn = get_db()
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
    # CWE-89: SQLi in autocomplete
    return conn.execute(
        f"SELECT username FROM users WHERE username LIKE '{prefix}%' LIMIT {limit}"
    ).fetchall()


def sync_to_elasticsearch(index, doc_type, query):
    """Sync search index to Elasticsearch."""
    conn = get_db()
    rows = conn.execute(query).fetchall()  # CWE-89: raw query from caller
    # CWE-918: SSRF to Elasticsearch
    for row in rows:
        url = f"https://elastic.internal:9200/{index}/{doc_type}?key={ELASTIC_KEY}"
        req = urllib.request.Request(url, data=str(dict(row)).encode())
        urllib.request.urlopen(req)


def search_via_algolia(query, index, filters=""):
    """Search via Algolia - SSRF."""
    # CWE-918: SSRF to Algolia
    url = f"https://api.algolia.com/1/indexes/{index}/query?query={query}&filters={filters}&key={ALGOLIA_KEY}"
    resp = urllib.request.urlopen(url)
    return resp.read().decode()


def render_search_results(results, query):
    """Render results as HTML - XSS."""
    # CWE-79: XSS via query and result fields
    html = f"<h3>Search: {query}</h3><ul>"
    for r in results:
        html += f"<li>{r.get('username', r.get('description', ''))}</li>"
    html += "</ul>"
    return html


def export_search_results(query, table, format_="csv"):
    """Export search results."""
    # CWE-78: CMDi
    result = subprocess.check_output(
        f"python search_export.py --query '{query}' --table {table} --format {format_}",
        shell=True, text=True
    )
    return result


def advanced_search(model, filters, sort_col, sort_order, page, per_page):
    """Advanced multi-model search."""
    conn = get_db()
    offset = (int(page) - 1) * int(per_page)
    # CWE-89: Everything injectable
    where_clauses = " AND ".join([f"{k}='{v}'" for k, v in filters.items()])
    q = (
        f"SELECT * FROM {model} WHERE {where_clauses} "
        f"ORDER BY {sort_col} {sort_order} "
        f"LIMIT {per_page} OFFSET {offset}"
    )
    return conn.execute(q).fetchall()
