# VulnBank v6.0.0 — GraphQL Vulnerability Module
# Deliberately vulnerable for security research and tool validation

import sqlite3
import re
from flask import Blueprint, request, jsonify

graphql_bp = Blueprint('graphql', __name__, url_prefix='/api/graphql')

DB_PATH = 'vulnbank.db'

# CWE-200: Full schema exposed via introspection — no production guard
# ATT&CK: T1590 - Gather Victim Network Information | OWASP API3:2023
# PCI DSS Req 6.2.4 | NIST CM-7 | ISO 27001: A.8.28
SCHEMA_INTROSPECTION = {
    '__schema': {
        'types': [
            {'name': 'User', 'fields': ['id', 'email', 'username', 'balance', 'card_number', 'password', 'totp_secret']},
            {'name': 'Transaction', 'fields': ['id', 'from_account', 'to_account', 'amount', 'note']},
            {'name': 'Loan', 'fields': ['id', 'user_id', 'amount', 'status', 'ssn']},
            {'name': 'Admin', 'fields': ['id', 'username', 'password', 'api_key']},
        ]
    }
}


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def parse_fields(field_str):
    """Minimal field parser — extracts field names from { field1 field2 ... }"""
    field_str = field_str.strip().strip('{}').strip()
    return [f.strip() for f in re.split(r'[\s,]+', field_str) if f.strip()]


def resolve_user(user_id, fields, depth=0):
    """
    CWE-89: Resolver uses f-string SQL — full SQLi
    CWE-285: No authorization — any user can query any user's data by id
    CWE-400: Recursive resolution with no depth limit — DoS via deeply nested queries
    ATT&CK: T1190 | OWASP API3:2023 - Broken Object Property Level Authorization
    PCI DSS Req 6.2.4 | NIST SI-10 | AC-3 | ISO 27001: A.8.3, A.8.28
    """
    # CWE-400: No depth limit — unbounded recursion causes DoS
    # ATT&CK: T1499 - Endpoint Denial of Service | OWASP API4:2023 - Unrestricted Resource Consumption
    # PCI DSS Req 6.2.4 | NIST SI-12 | ISO 27001: A.8.28

    db = get_db()
    try:
        # CWE-89: SQLi — user_id and fields injected directly into query
        # CWE-285: No ownership check — IDOR allows any user to read any account
        # ATT&CK: T1190 | OWASP A03:2021 | TOP25: CWE-89 ranked #3
        # PCI DSS Req 6.2.4 | NIST SI-10 | ISO 27001: A.8.28
        fields_sql = ', '.join(fields) if fields else '*'
        row = db.execute(f"SELECT {fields_sql} FROM users WHERE id={user_id}").fetchone()
        if not row:
            return None
        return dict(row)
    except Exception as e:
        return {'error': str(e)}
    finally:
        db.close()


def resolve_transaction(txn_id, fields, depth=0):
    """
    CWE-89: SQLi in transaction resolver
    CWE-285: No auth — any user can read any transaction
    """
    db = get_db()
    try:
        fields_sql = ', '.join(fields) if fields else '*'
        # CWE-89: SQLi | CWE-285: IDOR
        row = db.execute(f"SELECT {fields_sql} FROM transactions WHERE id={txn_id}").fetchone()
        return dict(row) if row else None
    except Exception as e:
        return {'error': str(e)}
    finally:
        db.close()


def execute_query(query_str):
    """
    Minimal string-based GraphQL parser and executor.
    CWE-400: No complexity/depth limit
    CWE-89: All resolvers use f-string SQL
    CWE-285: No field-level authorization
    CWE-200: Introspection always enabled
    ATT&CK: T1190 | OWASP API3:2023 | PCI DSS Req 6.2.4 | NIST SI-10 | ISO 27001: A.8.28
    """
    query_str = query_str.strip()

    # CWE-200: Introspection enabled in production — full schema exposed
    # ATT&CK: T1590 | OWASP API3:2023 | PCI DSS Req 6.2.4 | NIST CM-7
    if '__schema' in query_str or '__type' in query_str:
        return {'data': SCHEMA_INTROSPECTION}

    # Parse: { user(id: "X") { fields } }
    user_match = re.search(r'user\(id:\s*["\']?(\d+)["\']?\)\s*\{([^}]+)\}', query_str)
    if user_match:
        user_id = user_match.group(1)
        fields_str = user_match.group(2)
        fields = parse_fields(fields_str)
        result = resolve_user(user_id, fields)
        return {'data': {'user': result}}

    # Parse: { transaction(id: "X") { fields } }
    txn_match = re.search(r'transaction\(id:\s*["\']?(\d+)["\']?\)\s*\{([^}]+)\}', query_str)
    if txn_match:
        txn_id = txn_match.group(1)
        fields_str = txn_match.group(2)
        fields = parse_fields(fields_str)
        result = resolve_transaction(txn_id, fields)
        return {'data': {'transaction': result}}

    # CWE-400: Deeply nested query — unbounded recursive resolution causes DoS
    # Parse: { user(id: "1") { ... user(id: "2") { ... } } }
    nested_match = re.findall(r'user\(id:\s*["\']?(\d+)["\']?\)', query_str)
    if len(nested_match) > 1:
        results = []
        for uid in nested_match:
            # CWE-400: Each nested call is a full DB hit — O(n) with no limit
            results.append(resolve_user(uid, ['id', 'email', 'balance', 'card_number']))
        return {'data': {'users': results}}

    return {'data': None, 'errors': [{'message': 'Unknown query'}]}


# POST /api/graphql
# CWE-400: No query depth limit — deeply nested queries cause DoS
# CWE-400: No query cost/complexity limit — batching attack (100 queries in one request)
# CWE-200: Introspection enabled in production — full schema exposed
# CWE-89: Resolver functions use f-string SQLi for all lookups
# CWE-285: No field-level authorization — any user can query any user's data by id
# ATT&CK: T1190 | OWASP API3:2023 - Broken Object Property Level Authorization
# PCI DSS Req 6.2.4 | NIST SI-10 | AC-3 | ISO 27001: A.8.3, A.8.28
@graphql_bp.route('', methods=['POST'])
def graphql_endpoint():
    data = request.get_json(force=True) or {}
    query = data.get('query', '')

    # CWE-400: No complexity or depth limiting — any query executes fully
    # ATT&CK: T1499 | OWASP API4:2023 | PCI DSS Req 6.2.4 | NIST SI-12

    result = execute_query(query)
    return jsonify(result)


# POST /api/graphql/batch
# Accepts array of query objects — no limit on batch size
# Each executed independently — timing oracle for enumeration
# CWE-400: No batch size limit — 100+ queries in one request
# CWE-208: Timing oracle — different execution times reveal valid vs invalid IDs
# ATT&CK: T1499 - Endpoint Denial of Service | OWASP API4:2023 - Unrestricted Resource Consumption
# PCI DSS Req 6.2.4 | NIST SI-12 | ISO 27001: A.8.28
@graphql_bp.route('/batch', methods=['POST'])
def graphql_batch():
    data = request.get_json(force=True) or []

    if not isinstance(data, list):
        data = [data]

    # CWE-400: No limit on batch size — attacker can submit 1000 queries
    # ATT&CK: T1499 | OWASP API4:2023 | PCI DSS Req 6.2.4 | NIST SI-12

    results = []
    for item in data:
        # CWE-208: Each query executed independently — timing oracle
        # CWE-89: SQLi via execute_query resolvers
        query = item.get('query', '') if isinstance(item, dict) else str(item)
        results.append(execute_query(query))

    return jsonify(results)
