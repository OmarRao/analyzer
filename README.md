# VulnBank v6.0.0 — Deliberately Vulnerable Banking Application

> **Purpose:** A purpose-built, intentionally insecure banking application used as the primary test target for [SecureScope](https://github.com/OmarRao/secure-scope) — an AI-powered GitHub security scanner with MITRE ATT&CK mapping, ransomware detection, and multi-LLM fix advisory.

---

## ⚠�? Security Warning

**THIS APPLICATION CONTAINS INTENTIONAL SECURITY VULNERABILITIES.**

- **DO NOT** deploy to any public-facing or production environment
- **DO NOT** use real credentials, personal data, or financial information
- **DO NOT** run on a network accessible outside your local machine
- Intended for: security research, scanner validation, education, and CTF-style exercises only

---

## What Is VulnBank?

VulnBank is a multi-module Python/Flask banking simulation containing **500+ deliberately introduced security findings** across **28 CWE categories**, **14 MITRE ATT&CK techniques**, **PCI DSS v4.0 requirements**, **NIST SP 800-53 Rev 5 controls**, **ISO 27001:2022 Annex A controls**, and **SANS/CWE Top 25 rankings**. Every vulnerability is annotated with all applicable framework identifiers in comments, making it ideal for:

- Validating static analysis tools (Semgrep, CodeQL, Bandit, Snyk)
- Benchmarking AI security scanners like [SecureScope](https://github.com/OmarRao/secure-scope)
- Security training and purple-team exercises
- Demonstrating real-world attack patterns in a safe sandbox

---

## Architecture

```
VulnBank/
├── app.py                    # Core Flask app — auth, dashboard, admin, transfers
├── config.py                 # Hardcoded secrets, weak JWT config
├── models.py                 # ORM-style models with injection-prone raw SQL
├── utils.py                  # Shared utilities — XXE, weak crypto, path traversal
│
├── api/
│   ├── auth.py               # Login, register, MFA bypass, SAML XXE, OAuth SSRF
│   ├── accounts.py           # Account management — IDOR, CMDi, SSRF
│   ├── admin.py              # Admin panel — unauthenticated, mass SQLi, pickle RCE
│   ├── files.py              # File upload/download — unrestricted upload, traversal
│   ├── loans.py              # Loan API — business logic abuse, injection
│   ├── payments.py           # Payment processing — CSRF, race conditions
│   ├── reports.py            # Reporting — CSV injection, XSS, path traversal
│   ├── transactions.py       # Transaction history — IDOR, injection
│   ├── users.py              # User management — mass assignment, enumeration
│   ├── oauth.py              # OAuth misconfig — open redirect, SSRF, hardcoded secret
│   ├── mfa.py                # 2FA bypass — master code, no lockout, weak entropy
│   ├── passwordreset.py      # Reset poisoning — Host header injection, token replay
│   ├── graphql_api.py        # GraphQL — SQLi resolvers, introspection, DoS, IDOR
│   ├── jwt_auth.py           # JWT confusion — alg:none, HS256/RS256 swap, kid SQLi
│   └── ldap.py               # LDAP injection — filter bypass, anonymous search
│
├── services/
│   ├── crypto_service.py     # Encryption — MD5, weak keys, ECB mode, hardcoded IV
│   ├── email.py              # Email service — header injection, SSRF
│   ├── logger.py             # Logging — log injection, sensitive data in logs
│   ├── notification.py       # Push notifications — SSRF, template injection
│   └── search.py             # Search — SQL injection, SSRF, XXE
│
├── middleware/
│   └── auth.py               # Auth middleware — JWT confusion, bypass, weak secret
│
├── jobs/
│   └── scheduled.py          # Cron jobs — command injection, path traversal
│
└── utils/
    ├── formatters.py          # Output formatters — XSS, CSV injection, SSTI
    └── validators.py          # Input validators — bypass patterns, regex DoS
```

---

## Vulnerability Coverage

### Injection

| CWE | Name | MITRE ATT&CK | Files |
|-----|------|--------------|-------|
| CWE-89 | SQL Injection | T1190 | app.py, api/auth.py, api/accounts.py, api/admin.py, api/transactions.py, services/search.py |
| CWE-78 | OS Command Injection | T1059 | app.py, api/accounts.py, api/admin.py, api/files.py, jobs/scheduled.py |
| CWE-79 | Cross-Site Scripting (XSS) | T1059.007 | app.py, api/admin.py, api/files.py, utils/formatters.py |
| CWE-94 | Code Injection / SSTI (Jinja2) | T1059 | app.py, utils/formatters.py |
| CWE-611 | XML External Entity (XXE) | T1190 | app.py, utils.py, api/auth.py, services/search.py |
| CWE-1236 | CSV / Formula Injection | T1059 | api/reports.py, utils/formatters.py |
| CWE-113 | HTTP Response Splitting | T1566 | app.py, api/auth.py |

### Authentication & Access Control

| CWE | Name | MITRE ATT&CK | Files |
|-----|------|--------------|-------|
| CWE-798 | Hardcoded Credentials / API Keys | T1552.001 | app.py, config.py, api/auth.py, api/accounts.py, api/admin.py, api/files.py |
| CWE-285 | Improper Authorization / BOLA (IDOR) | T1548 | app.py, api/accounts.py, api/admin.py, api/files.py, api/users.py |
| CWE-347 | JWT Algorithm Confusion / Signature Bypass | T1552 | app.py, middleware/auth.py |
| CWE-284 | Missing Authentication on Admin | T1548 | api/admin.py |
| CWE-208 | Timing Attack / Username Enumeration | T1590 | api/auth.py |
| CWE-915 | Mass Assignment (Unrestricted Object Update) | T1548 | app.py, api/users.py |

### Cryptography

| CWE | Name | MITRE ATT&CK | Files |
|-----|------|--------------|-------|
| CWE-327 | Weak Cryptography (MD5, ECB) | T1600 | utils.py, api/auth.py, services/crypto_service.py |
| CWE-916 | Insufficient Password Hashing | T1600 | app.py, api/auth.py |
| CWE-330 | Weak Randomness / Predictable Tokens | T1552 | app.py, api/auth.py, config.py |
| CWE-312 | Cleartext Storage of Sensitive Data | T1552 | api/auth.py, services/logger.py |

### Server-Side & Network

| CWE | Name | MITRE ATT&CK | Files |
|-----|------|--------------|-------|
| CWE-918 | Server-Side Request Forgery (SSRF) | T1090 | app.py, api/accounts.py, api/admin.py, api/auth.py, services/email.py |
| CWE-22 | Path Traversal | T1083 | app.py, api/accounts.py, api/admin.py, api/files.py, jobs/scheduled.py |
| CWE-601 | Open Redirect | T1566 | app.py, api/auth.py |
| CWE-434 | Unrestricted File Upload | T1190 | api/files.py |
| CWE-942 | Permissive CORS (Wildcard + Credentials) | T1090 | app.py |

### Application Logic

| CWE | Name | MITRE ATT&CK | Files |
|-----|------|--------------|-------|
| CWE-352 | Missing CSRF Protection | T1562 | app.py |
| CWE-502 | Insecure Deserialization (Pickle RCE) | T1059 | app.py, api/admin.py |
| CWE-532 | Sensitive Data in Logs | T1552 | services/logger.py |
| CWE-209 | Verbose Error Messages / Prompt Leak | T1590 | app.py, multiple |
| CWE-1321 | Prototype Pollution / Object Injection | T1059 | app.py |
| CWE-1333 | ReDoS — Catastrophic Regex Backtracking | T1499 | app.py, utils/validators.py |

### Emerging / Latest Threat Classes

| Category | Vulnerability | Standard | Files |
|----------|--------------|----------|-------|
| **LLM Security** | Prompt Injection — user input concatenated into LLM system prompt | OWASP LLM01:2025 | app.py |
| **API Security** | BOLA / IDOR — no ownership check on transaction objects | OWASP API1:2023 | app.py |
| **API Security** | Mass Assignment — unrestricted JSON field merge escalates role | OWASP API3:2023 | app.py |
| **API Security** | JWT Algorithm Confusion — `"alg":"none"` accepted for token forgery | OWASP API2:2023 | app.py |
| **DoS** | ReDoS — nested quantifier regex causes catastrophic backtracking | CWE-1333 | app.py |

### v6.0.0 New Vulnerability Classes

| Category | CWE | Vulnerability | File |
|----------|-----|--------------|------|
| LDAP Injection | CWE-90 | Filter string injection — `uid={username}` bypass with `*)(&` | api/ldap.py |
| LDAP Injection | CWE-200 | Anonymous search returns passwordHash attribute | api/ldap.py |
| OAuth Misconfiguration | CWE-601 | `redirect_uri` not validated — auth code sent to attacker domain | api/oauth.py |
| OAuth Misconfiguration | CWE-918 | SSRF via `token_endpoint` parameter in callback | api/oauth.py |
| OAuth Misconfiguration | CWE-798 | Hardcoded `client_secret` = `oauth-client-secret-2024` | api/oauth.py |
| OAuth Misconfiguration | CWE-285 | Any user can revoke any token (no auth on /revoke) | api/oauth.py |
| 2FA Bypass | CWE-798 | Hardcoded master bypass code `000000` always accepted | api/mfa.py |
| 2FA Bypass | CWE-307 | No brute-force lockout on MFA verify endpoint | api/mfa.py |
| 2FA Bypass | CWE-285 | Unauthenticated access to backup codes endpoint | api/mfa.py |
| Password Reset Poisoning | CWE-20 | Host header injection — reset URL built from `request.headers.get('Host')` | api/passwordreset.py |
| Password Reset Poisoning | CWE-330 | Token = `random.randint(100000, 999999)` — only 900k possibilities | api/passwordreset.py |
| Password Reset Poisoning | CWE-208 | Timing oracle — 500ms sleep for valid email reveals account existence | api/passwordreset.py |
| GraphQL | CWE-400 | No depth or complexity limit — deeply nested queries cause DoS | api/graphql_api.py |
| GraphQL | CWE-200 | Introspection enabled in production — full schema exposed | api/graphql_api.py |
| GraphQL | CWE-89 | Resolver uses `f"SELECT {fields} FROM users WHERE id={id}"` — SQLi + field injection | api/graphql_api.py |
| GraphQL | CWE-285 | No field-level authorization — any user reads any user's card_number | api/graphql_api.py |
| JWT Algorithm Confusion | CWE-347 | `alg:none` accepted without signature verification | api/jwt_auth.py |
| JWT Algorithm Confusion | CWE-347 | HS256 verified with RSA public key as HMAC secret (algorithm confusion) | api/jwt_auth.py |
| JWT Algorithm Confusion | CWE-918 | SSRF — `kid` header starting with `http` fetches remote JWKS | api/jwt_auth.py |
| JWT Algorithm Confusion | CWE-613 | Expired JWTs accepted indefinitely — no expiry enforcement on refresh | api/jwt_auth.py |

---

## MITRE ATT&CK Coverage

| Technique | Name | Examples in VulnBank |
|-----------|------|----------------------|
| T1190 | Exploit Public-Facing Application | SQLi login, XXE, file upload |
| T1059 | Command and Scripting Interpreter | OS command injection, pickle RCE |
| T1059.007 | JavaScript Execution (XSS) | Reflected XSS in search, admin echo |
| T1548 | Abuse Elevation Control Mechanism | No-auth admin endpoints, IDOR |
| T1552 | Unsecured Credentials | Hardcoded keys in config, cleartext logs |
| T1552.001 | Credentials in Files | API keys, DB password, AWS secret in source |
| T1083 | File and Directory Discovery | Path traversal in log read, file download |
| T1090 | Proxy | SSRF to internal services, webhook SSRF |
| T1562 | Impair Defenses | Missing CSRF, auth bypass |
| T1566 | Phishing (Redirect) | Open redirect in OAuth callback |
| T1600 | Weaken Encryption | MD5 passwords, ECB cipher mode |
| T1021.004 | Remote Services: SSH | CMDi via SSH in admin panel |
| T1499 | Endpoint Denial of Service | ReDoS via catastrophic regex backtracking |
| T1059.001 | Scripting (LLM Abuse) | Prompt injection in AI financial advice endpoint |

---

## Running VulnBank

### Docker Compose (recommended)

```bash
docker-compose up
# App:    http://localhost:5000
# MailHog (catches reset emails): http://localhost:8025
```

### Local (without Docker)

```bash
# Clone
git clone https://github.com/OmarRao/analyzer.git
cd analyzer

# Install dependencies
pip install -r requirements.txt

# Run (binds to 0.0.0.0:5000 — LOCAL ONLY)
python app.py
```

Default test credentials (hardcoded intentionally):

| User | Password | Role |
|------|----------|------|
| admin | admin123 | admin |
| alice | password1 | user |
| bob | letmein | user |

---

## CI/CD Integration

VulnBank ships with a GitHub Actions workflow (`.github/workflows/secscope-scan.yml`) that automatically runs [SecureScope](https://github.com/OmarRao/secure-scope) on every push and pull request to `main`:

- Installs Semgrep, pip-audit, and SecureScope
- Runs the full scan with `--sarif --sbom --compliance` flags
- Uploads SARIF results directly to the **GitHub Security tab** (requires `security-events: write` permission)
- Archives all reports as workflow artifacts

The workflow uses `continue-on-error: true` so it never blocks merges — it only surfaces findings.

---

## Postman Collection

Import `vulnbank.postman_collection.json` into Postman to access **35 pre-built exploit requests** across 11 vulnerability folders (Auth, SQL Injection, OAuth, MFA Bypass, Password Reset, GraphQL, JWT, LDAP, Admin, Payments, File Upload).

**Import steps:**
1. Open Postman → Import → Upload Files
2. Select `vulnbank.postman_collection.json`
3. Set the `base_url` variable to `http://localhost:5000`
4. Each request includes pre-configured exploit payloads and CWE descriptions

---

## Use with SecureScope

VulnBank is the canonical test target for [SecureScope](https://github.com/OmarRao/secure-scope). To scan it:

1. Start [SecureScope](https://github.com/OmarRao/secure-scope) (`python -m ui.server`)
2. Enter `https://github.com/OmarRao/analyzer` in the scan wizard
3. Select your preferred LLM for fix advisory
4. View the generated report — it maps every finding to MITRE ATT&CK v14, CWE, and OWASP

A pre-generated sample report is available at:  
**[docs/sample_report.pdf](https://github.com/OmarRao/secure-scope/blob/main/docs/sample_report.pdf)**

---

## Releases

| Version | Date | Notes |
|---------|------|-------|
| [v6.0.0](https://github.com/OmarRao/analyzer/releases/tag/v6.0.0) | 2026-06-24 | LDAP injection, OAuth misconfig, 2FA bypass, password reset poisoning, GraphQL vulns, JWT algorithm confusion, Docker Compose, GitHub Actions CI, Postman collection |
| [v5.0.0](https://github.com/OmarRao/analyzer/releases/tag/v5.0.0) | 2026-06-23 | Complete 6-framework coverage — ISO 27001:2022 Annex A added to all 14 api/utils/jobs/config/models files; new CWE-362 race-condition endpoints and CWE-840 negative-transfer business logic flaw |
| [v4.0.0](https://github.com/OmarRao/analyzer/releases/tag/v4.0.0) | 2026-06-22 | Multi-framework annotations — PCI DSS v4.0, NIST SP 800-53 Rev 5, SANS/CWE Top 25 added to all vulnerabilities; README framework mapping tables |
| [v3.0.0](https://github.com/OmarRao/analyzer/releases/tag/v3.0.0) | 2026-06-17 | Latest Threat Classes — SSTI, Prompt Injection, Mass Assignment, JWT Algorithm Confusion, BOLA, ReDoS, XXE, CORS, HTTP Response Splitting, Prototype Pollution |
| [v2.0.0](https://github.com/OmarRao/analyzer/releases/tag/v2.0.0) | 2026-06-15 | Multi-module expansion — 400+ findings, API layer, services, middleware, jobs |
| [v1.0.0](https://github.com/OmarRao/analyzer/releases/tag/v1.0.0) | 2026-06-09 | Initial release — core Flask app, 12 CWE types |

---

## PCI DSS v4.0 Coverage

VulnBank maps 13+ vulnerabilities to PCI DSS v4.0 requirements — particularly relevant because it simulates a payment-processing banking application.

| PCI DSS Requirement | Scope | Vulnerabilities Demonstrated |
|---------------------|-------|------------------------------|
| Req 2.2.1 — Secure default config | System hardening | Debug mode in production (CWE-94/209) |
| Req 3.3.1 — Sensitive auth data not retained | Data storage | Plaintext password storage (CWE-916) |
| Req 4.2.1 — Strong cryptography in transit | Cryptographic controls | Weak MD5 hashing (CWE-327), permissive CORS (CWE-942) |
| Req 6.2.4 — Prevent common software attacks | Secure development | SQLi, XSS, CMDi, SSTI, XXE, SSRF, CSRF, Path Traversal, ReDoS, Open Redirect, Pickle RCE |
| Req 6.3.2 — Software inventory integrity | Supply chain | Insecure deserialization (CWE-502), SSTI (CWE-94) |
| Req 7.2 — Least privilege | Access control | BOLA/IDOR (CWE-285), Mass Assignment (CWE-915) |
| Req 7.3 — Access control systems | Authorisation | Missing auth on admin (CWE-284), BOLA (CWE-285), Mass Assignment |
| Req 8.3.6 — Strong passphrase requirements | Authentication | MD5 passwords (CWE-916), JWT algorithm confusion (CWE-347) |
| Req 8.6.1 — System-account credentials managed | Credential hygiene | Hardcoded API keys & DB passwords (CWE-798) |
| Req 8.6.3 — Credentials protected from misuse | Credential protection | JWT `alg:none` bypass (CWE-347) |
| Req 1.3 / SC-7 — Network access controls | Network boundary | SSRF to internal services (CWE-918) |
| Req 12.3.2 — Risk-based vulnerability management | Governance | ReDoS (CWE-1333), debug mode |
| Req 12.6.1/2 — Security awareness | Training | Prompt injection (LLM01), phishing via open redirect |

---

## NIST SP 800-53 Rev 5 Coverage

| Control Family | Control ID | Description | Vulnerabilities |
|---------------|------------|-------------|-----------------|
| Access Control | AC-3 | Access Enforcement | BOLA/IDOR (CWE-285), Mass Assignment (CWE-915) |
| Access Control | AC-4 | Information Flow Enforcement | SSRF (CWE-918), Open Redirect (CWE-601) |
| Access Control | AC-6 | Least Privilege | BOLA (CWE-285), Mass Assignment (CWE-915) |
| Audit & Accountability | AU-3 | Content of Audit Records | Sensitive data in logs (CWE-532) |
| Configuration Management | CM-6 | Configuration Settings | Debug mode enabled, hardcoded secrets |
| Configuration Management | CM-7 | Least Functionality | Debug mode, unnecessary admin endpoints |
| Identification & Authentication | IA-5 | Authenticator Management | Hardcoded credentials (CWE-798), weak hashing |
| Identification & Authentication | IA-5(1) | Password-based Authentication | MD5 hashing (CWE-916) |
| Identification & Authentication | IA-8 | Non-Org User Authentication | JWT confusion (CWE-347) |
| System & Communications | SC-5 | DoS Protection | ReDoS (CWE-1333) |
| System & Communications | SC-7 | Boundary Protection | SSRF (CWE-918), XXE (CWE-611) |
| System & Communications | SC-8 | Transmission Confidentiality | Permissive CORS (CWE-942), CSRF (CWE-352) |
| System & Communications | SC-13 | Cryptographic Protection | MD5 (CWE-327), JWT `alg:none` (CWE-347) |
| System & Communications | CA-3 | Information Exchange | CORS misconfiguration (CWE-942) |
| System & Info Integrity | SI-3 | Malicious Code Protection | Pickle RCE (CWE-502), SSTI (CWE-94) |
| System & Info Integrity | SI-10 | Information Input Validation | SQLi, XSS, CMDi, XXE, Path Traversal, ReDoS, SSRF |
| System & Acquisition | SA-15 | Development Process Standards | Hardcoded secrets (CWE-798) |

---

## SANS / CWE Top 25 (2023) Coverage

VulnBank deliberately includes 10 of the SANS Top 25 most dangerous software weaknesses.

| Rank | CWE | Name | Endpoint in VulnBank |
|------|-----|------|----------------------|
| #2 | CWE-79 | Cross-Site Scripting | `/search` (reflected XSS in results) |
| #3 | CWE-89 | SQL Injection | `/login`, `/search`, `/profile/<u>`, `/transfer`, `/dashboard` |
| #5 | CWE-78 | OS Command Injection | `/admin/ping`, `/admin/run` |
| #8 | CWE-22 | Path Traversal | `/admin/logs` |
| #9 | CWE-352 | CSRF | `/transfer` |
| #18 | CWE-798 | Hardcoded Credentials | `app.py` module globals |
| #19 | CWE-918 | SSRF | `/api/fetch` |
| #23 | CWE-611 | XML External Entity | `/api/import/statement` |
| — | CWE-502 | Insecure Deserialization | `/api/restore` (OWASP A08 critical) |
| — | CWE-347 | Improper Crypto Signature Verification | `/api/token/verify` |
| — | CWE-601 | Open Redirect | `/api/redirect` |
| — | CWE-916 | Insufficient Password Hashing | `/reset-password` |
| — | CWE-1333 | ReDoS | `/api/validate/email` |

---

## ISO 27001:2022 Coverage

| Annex A Control | Control Name | Vulnerability Types Demonstrated |
|----------------|--------------|----------------------------------|
| A.5.15 | Access control | IDOR/BOLA (CWE-285), Mass Assignment (CWE-915), Missing authentication (CWE-284) |
| A.5.17 | Authentication information | Hardcoded credentials and API keys (CWE-798), JWT weak secret |
| A.5.34 | Privacy and protection of PII | Sensitive PII/PAN in audit logs (CWE-532), cleartext card storage (CWE-312) |
| A.8.3 | Information access restriction | Path traversal (CWE-22), IDOR (CWE-285), unrestricted file download |
| A.8.10 | Information deletion | Hardcoded credentials never rotated (CWE-798) |
| A.8.12 | Data leakage prevention | Sensitive data in logs — passwords, tokens, card numbers (CWE-532) |
| A.8.15 | Logging | Unrestricted file upload bypasses audit controls (CWE-434) |
| A.8.20 | Networks security | SSRF to internal network services (CWE-918), XXE SSRF (CWE-611) |
| A.8.23 | Web filtering | SSRF via OAuth callback, webhook, and payment-processor URLs (CWE-918) |
| A.8.24 | Use of cryptography | MD5 password hashing (CWE-916/327), weak random tokens (CWE-330), ECB mode |
| A.8.28 | Secure coding | SQLi (CWE-89), XSS (CWE-79), CMDi (CWE-78), SSTI (CWE-94), Pickle RCE (CWE-502), Race Condition (CWE-362), Business Logic (CWE-840) |

---

## Contributing

Found a vulnerability pattern that's missing? PRs welcome — every new vuln must include:
- CWE comment annotation with all applicable framework IDs:
  `# CWE-XXX: Description (ATT&CK: TXXXX | OWASP AXX | PCI DSS Req X.X.X | NIST XX-X | TOP25 #N)`
- Entry in the README vulnerability table and relevant framework tables

---

---

**Built by [Omar Rao](https://github.com/OmarRao)**  
Engineer — Data Resilience, Cybersecurity and Privacy  
[LinkedIn](https://www.linkedin.com/in/omarrao/) &nbsp;·&nbsp; [Substack](https://omarrao.substack.com/)

