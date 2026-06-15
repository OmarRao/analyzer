# VulnBank — Deliberately Vulnerable Banking Application

> **Purpose:** A purpose-built, intentionally insecure banking application used as the primary test target for [SecureScope](https://github.com/OmarRao/secure-scope) — an AI-powered GitHub security scanner with MITRE ATT&CK mapping, ransomware detection, and multi-LLM fix advisory.

---

## ⚠️ Security Warning

**THIS APPLICATION CONTAINS INTENTIONAL SECURITY VULNERABILITIES.**

- **DO NOT** deploy to any public-facing or production environment
- **DO NOT** use real credentials, personal data, or financial information
- **DO NOT** run on a network accessible outside your local machine
- Intended for: security research, scanner validation, education, and CTF-style exercises only

---

## What Is VulnBank?

VulnBank is a multi-module Python/Flask banking simulation containing **400+ deliberately introduced security findings** across **22 CWE categories** and **12 MITRE ATT&CK techniques**. Every vulnerability is annotated with CWE and ATT&CK identifiers in comments, making it ideal for:

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
│   └── users.py              # User management — mass assignment, enumeration
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
| CWE-94 | Code Injection | T1059 | app.py |
| CWE-611 | XML External Entity (XXE) | T1190 | utils.py, api/auth.py, services/search.py |
| CWE-1236 | CSV / Formula Injection | T1059 | api/reports.py, utils/formatters.py |

### Authentication & Access Control

| CWE | Name | MITRE ATT&CK | Files |
|-----|------|--------------|-------|
| CWE-798 | Hardcoded Credentials / API Keys | T1552.001 | app.py, config.py, api/auth.py, api/accounts.py, api/admin.py, api/files.py |
| CWE-285 | Improper Authorization (IDOR) | T1548 | api/accounts.py, api/admin.py, api/files.py, api/users.py |
| CWE-347 | JWT Signature Not Verified | T1190 | middleware/auth.py |
| CWE-284 | Missing Authentication on Admin | T1548 | api/admin.py |
| CWE-208 | Timing Attack / Username Enumeration | T1590 | api/auth.py |

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
| CWE-601 | Open Redirect | T1566 | api/auth.py |
| CWE-434 | Unrestricted File Upload | T1190 | api/files.py |

### Application Logic

| CWE | Name | MITRE ATT&CK | Files |
|-----|------|--------------|-------|
| CWE-352 | Missing CSRF Protection | T1562 | app.py |
| CWE-502 | Insecure Deserialization (Pickle RCE) | T1059 | app.py, api/admin.py |
| CWE-532 | Sensitive Data in Logs | T1552 | services/logger.py |
| CWE-209 | Verbose Error Messages | T1590 | Multiple |

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

---

## Quick Start

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
| [v2.0.0](https://github.com/OmarRao/analyzer/releases/tag/v2.0.0) | 2026-06-15 | Multi-module expansion — 400+ findings, API layer, services, middleware, jobs |
| [v1.0.0](https://github.com/OmarRao/analyzer/releases/tag/v1.0.0) | 2026-06-09 | Initial release — core Flask app, 12 CWE types |

---

## Contributing

Found a vulnerability pattern that's missing? PRs welcome — every new vuln must include:
- CWE comment annotation: `# CWE-XXX: Description (ATT&CK: TXXXX)`
- Entry in the README vulnerability table

---

---

**Built by [Omar Rao](https://github.com/OmarRao)**  
Engineer — Data Resilience, Cybersecurity and Privacy  
[LinkedIn](https://www.linkedin.com/in/omarrao/) &nbsp;·&nbsp; [Substack](https://omarrao.substack.com/)
