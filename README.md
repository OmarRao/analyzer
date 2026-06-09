# VulnBank

A deliberately vulnerable Python/Flask banking demo application used for security scanner testing.

## ⚠️ WARNING
This application contains **intentional security vulnerabilities**. DO NOT deploy to production.

## Vulnerabilities Present

| Vulnerability | CWE | MITRE ATT&CK | Location |
|--------------|-----|--------------|----------|
| SQL Injection | CWE-89 | T1190 | app.py: login, search, transfer, profile |
| Reflected XSS | CWE-79 | T1059.007 | app.py: search |
| OS Command Injection | CWE-78 | T1059 | app.py: admin_ping, admin_run, utils.py |
| Path Traversal | CWE-22 | T1083 | app.py: admin_logs, utils.py |
| Hardcoded Credentials | CWE-798 | T1552.001 | app.py, config.py, ci.yml |
| Insecure Deserialization | CWE-502 | T1059 | app.py: restore_session |
| Weak Cryptography (MD5) | CWE-327 | T1600 | utils.py, app.py |
| SSRF | CWE-918 | T1090 | app.py: fetch_url |
| XXE Injection | CWE-611 | T1190 | utils.py: parse_user_xml |
| Missing CSRF | CWE-352 | T1562 | app.py: transfer |
| Weak Randomness | CWE-330 | T1552 | config.py, utils.py |
| CI/CD Injection | CWE-78 | T1059 | .github/workflows/ci.yml |

## Run locally
```bash
pip install -r requirements.txt
python app.py
```
