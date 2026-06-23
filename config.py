"""
Application configuration.
WARNING: Hardcoded secrets below - intentional vulnerability for demo purposes.
Vulnerability frameworks covered: CWE, ATT&CK, PCI DSS v4.0, NIST SP 800-53 Rev 5, ISO 27001:2022, SANS/CWE Top 25.
"""

# CWE-798: Hardcoded credentials (ATT&CK: T1552.001)
# PCI DSS Req 8.6.1 (Manage all credentials), 8.6.3 (Protect credentials from misuse) | NIST IA-5 (Authenticator Mgmt), SA-15 (Dev Process)
# ISO 27001: A.5.17 (Authentication information), A.8.10 (Information deletion) | TOP25: CWE-798 ranked #18
DATABASE_URL = "sqlite:///vulnbank.db"
SECRET_KEY = "dev-secret-do-not-use-in-prod-abc123"
ADMIN_PASSWORD = "Admin@1234"
SMTP_PASSWORD = "mailpass99"
STRIPE_SECRET_KEY = "sk_live_HARDCODED_VULN_DEMO_NOT_REAL_KEY"  # noqa: CWE-798
INTERNAL_API_TOKEN = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.hardcoded"

# CWE-330: Weak random seed
# ATT&CK: T1600 | OWASP A02:2021
# PCI DSS Req 8.3.6 (Password/passphrase complexity) | NIST IA-5 (Authenticator Mgmt), SC-13 (Cryptographic Protection)
# ISO 27001: A.8.24 (Use of cryptography) | TOP25: CWE-330 notable
import random
random.seed(42)
TOKEN_SALT = str(random.randint(1000, 9999))

# Debug flags
# CWE-489: Active debug code (ATT&CK: T1082)
# PCI DSS Req 2.2.1 (Config standards), 6.2.4 (Prevent common attacks) | NIST CM-6 (Configuration Settings), CM-7 (Least Functionality)
# ISO 27001: A.8.28 (Secure coding) | TOP25: CWE-489 notable
DEBUG = True
TESTING = True
