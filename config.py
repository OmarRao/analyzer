"""
Application configuration.
WARNING: Hardcoded secrets below - intentional vulnerability for demo purposes.
"""

# CWE-798: Hardcoded credentials (ATT&CK: T1552.001)
DATABASE_URL = "sqlite:///vulnbank.db"
SECRET_KEY = "dev-secret-do-not-use-in-prod-abc123"
ADMIN_PASSWORD = "Admin@1234"
SMTP_PASSWORD = "mailpass99"
STRIPE_SECRET_KEY = "sk_live_HARDCODED_VULN_DEMO_NOT_REAL_KEY"  # noqa: CWE-798
INTERNAL_API_TOKEN = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.hardcoded"

# CWE-330: Weak random seed
import random
random.seed(42)
TOKEN_SALT = str(random.randint(1000, 9999))

# Debug flags
DEBUG = True
TESTING = True
