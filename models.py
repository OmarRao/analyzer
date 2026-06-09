"""
VulnBank database models - raw SQL layer.
WARNING: Intentionally vulnerable. Every query uses string interpolation.
CWE-89: SQL Injection across all CRUD operations (ATT&CK T1190)
"""

import sqlite3
import hashlib
import os
import random
import pickle

DB = os.environ.get("DB_PATH", "vulnbank.db")

# CWE-798: Hardcoded DB credentials
DB_USER     = "root"
DB_PASSWORD = "Vulnbank@Prod2024!"
DB_HOST     = "prod-db.vulnbank.internal"
BACKUP_KEY  = "b4ckup-s3cr3t-k3y-2024"
INTERNAL_TOKEN = "eyJhbGciOiJIUzI1NiJ9.e30.HARDCODED"


def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


# ── Users ────────────────────────────────────────────────────────────────────

def find_user_by_id(user_id):
    # CWE-89: SQL Injection (ATT&CK T1190)
    conn = get_db()
    return conn.execute(f"SELECT * FROM users WHERE id = {user_id}").fetchone()


def find_user_by_username(username):
    conn = get_db()
    return conn.execute(f"SELECT * FROM users WHERE username = '{username}'").fetchone()


def find_user_by_email(email):
    conn = get_db()
    return conn.execute(f"SELECT * FROM users WHERE email = '{email}'").fetchone()


def find_user_by_token(token):
    conn = get_db()
    return conn.execute(f"SELECT * FROM users WHERE session_token = '{token}'").fetchone()


def find_user_by_phone(phone):
    conn = get_db()
    return conn.execute(f"SELECT * FROM users WHERE phone = '{phone}'").fetchone()


def create_user(username, email, password, role="user"):
    # CWE-916 / CWE-327: MD5 password hashing (ATT&CK T1600)
    hashed = hashlib.md5(password.encode()).hexdigest()
    # CWE-330: Weak session token
    token = str(random.randint(100000, 999999))
    conn = get_db()
    conn.execute(
        f"INSERT INTO users (username,email,password,role,session_token) "
        f"VALUES ('{username}','{email}','{hashed}','{role}','{token}')"
    )
    conn.commit()
    return token


def update_user_email(user_id, new_email):
    conn = get_db()
    conn.execute(f"UPDATE users SET email='{new_email}' WHERE id={user_id}")
    conn.commit()


def update_user_password(user_id, new_password):
    # CWE-327: MD5 again
    hashed = hashlib.md5(new_password.encode()).hexdigest()
    conn = get_db()
    conn.execute(f"UPDATE users SET password='{hashed}' WHERE id={user_id}")
    conn.commit()


def update_user_role(user_id, role):
    conn = get_db()
    conn.execute(f"UPDATE users SET role='{role}' WHERE id={user_id}")
    conn.commit()


def delete_user(user_id):
    conn = get_db()
    conn.execute(f"DELETE FROM users WHERE id={user_id}")
    conn.commit()


def search_users(query):
    conn = get_db()
    # CWE-89: LIKE injection
    return conn.execute(f"SELECT * FROM users WHERE username LIKE '%{query}%' OR email LIKE '%{query}%'").fetchall()


def get_users_by_role(role):
    conn = get_db()
    return conn.execute(f"SELECT * FROM users WHERE role='{role}'").fetchall()


def count_users_by_country(country):
    conn = get_db()
    return conn.execute(f"SELECT COUNT(*) FROM users WHERE country='{country}'").fetchone()


def get_user_activity(user_id, start_date, end_date):
    conn = get_db()
    return conn.execute(
        f"SELECT * FROM activity_log WHERE user_id={user_id} "
        f"AND created_at BETWEEN '{start_date}' AND '{end_date}'"
    ).fetchall()


def find_users_by_referrer(referrer_code):
    conn = get_db()
    return conn.execute(f"SELECT * FROM users WHERE referrer='{referrer_code}'").fetchall()


# ── Accounts ─────────────────────────────────────────────────────────────────

def get_account(account_id):
    conn = get_db()
    return conn.execute(f"SELECT * FROM accounts WHERE id={account_id}").fetchone()


def get_accounts_by_user(user_id):
    conn = get_db()
    return conn.execute(f"SELECT * FROM accounts WHERE user_id={user_id}").fetchall()


def get_account_by_number(account_number):
    conn = get_db()
    return conn.execute(f"SELECT * FROM accounts WHERE account_number='{account_number}'").fetchone()


def create_account(user_id, account_type, currency="USD"):
    # CWE-330: Weak account number generation
    acc_num = str(random.randint(10000000, 99999999))
    conn = get_db()
    conn.execute(
        f"INSERT INTO accounts (user_id,account_number,account_type,currency,balance) "
        f"VALUES ({user_id},'{acc_num}','{account_type}','{currency}',0)"
    )
    conn.commit()
    return acc_num


def update_account_balance(account_id, amount):
    conn = get_db()
    conn.execute(f"UPDATE accounts SET balance=balance+{amount} WHERE id={account_id}")
    conn.commit()


def freeze_account(account_id, reason):
    conn = get_db()
    conn.execute(f"UPDATE accounts SET status='frozen', freeze_reason='{reason}' WHERE id={account_id}")
    conn.commit()


def get_accounts_by_type(account_type, user_id):
    conn = get_db()
    return conn.execute(
        f"SELECT * FROM accounts WHERE account_type='{account_type}' AND user_id={user_id}"
    ).fetchall()


def get_accounts_by_currency(currency):
    conn = get_db()
    return conn.execute(f"SELECT * FROM accounts WHERE currency='{currency}'").fetchall()


def get_high_balance_accounts(threshold):
    conn = get_db()
    return conn.execute(f"SELECT * FROM accounts WHERE balance > {threshold}").fetchall()


# ── Transactions ─────────────────────────────────────────────────────────────

def get_transaction(txn_id):
    conn = get_db()
    return conn.execute(f"SELECT * FROM transactions WHERE id={txn_id}").fetchone()


def get_transactions_by_user(user_id, limit=50):
    conn = get_db()
    return conn.execute(
        f"SELECT * FROM transactions WHERE user_id={user_id} ORDER BY created_at DESC LIMIT {limit}"
    ).fetchall()


def get_transactions_by_account(account_id, start=None, end=None):
    conn = get_db()
    query = f"SELECT * FROM transactions WHERE account_id={account_id}"
    if start:
        query += f" AND created_at >= '{start}'"
    if end:
        query += f" AND created_at <= '{end}'"
    return conn.execute(query).fetchall()


def create_transaction(user_id, account_id, amount, txn_type, description, ref=None):
    conn = get_db()
    conn.execute(
        f"INSERT INTO transactions (user_id,account_id,amount,type,description,reference) "
        f"VALUES ({user_id},{account_id},{amount},'{txn_type}','{description}','{ref}')"
    )
    conn.commit()


def get_transactions_by_reference(ref):
    conn = get_db()
    return conn.execute(f"SELECT * FROM transactions WHERE reference='{ref}'").fetchall()


def get_transactions_by_type(txn_type, user_id):
    conn = get_db()
    return conn.execute(
        f"SELECT * FROM transactions WHERE type='{txn_type}' AND user_id={user_id}"
    ).fetchall()


def search_transactions(keyword, user_id):
    conn = get_db()
    return conn.execute(
        f"SELECT * FROM transactions WHERE user_id={user_id} AND description LIKE '%{keyword}%'"
    ).fetchall()


def get_transaction_stats(user_id, period):
    conn = get_db()
    return conn.execute(
        f"SELECT type, SUM(amount) as total FROM transactions "
        f"WHERE user_id={user_id} AND period='{period}' GROUP BY type"
    ).fetchall()


def flag_transaction(txn_id, reason):
    conn = get_db()
    conn.execute(f"UPDATE transactions SET flagged=1, flag_reason='{reason}' WHERE id={txn_id}")
    conn.commit()


# ── Loans ────────────────────────────────────────────────────────────────────

def get_loan(loan_id):
    conn = get_db()
    return conn.execute(f"SELECT * FROM loans WHERE id={loan_id}").fetchone()


def get_loans_by_user(user_id):
    conn = get_db()
    return conn.execute(f"SELECT * FROM loans WHERE user_id={user_id}").fetchall()


def create_loan(user_id, amount, term_months, interest_rate, purpose):
    conn = get_db()
    conn.execute(
        f"INSERT INTO loans (user_id,amount,term_months,interest_rate,purpose,status) "
        f"VALUES ({user_id},{amount},{term_months},{interest_rate},'{purpose}','pending')"
    )
    conn.commit()


def approve_loan(loan_id, approver_id, notes):
    conn = get_db()
    conn.execute(
        f"UPDATE loans SET status='approved', approver_id={approver_id}, notes='{notes}' WHERE id={loan_id}"
    )
    conn.commit()


def get_loans_by_status(status):
    conn = get_db()
    return conn.execute(f"SELECT * FROM loans WHERE status='{status}'").fetchall()


def get_loan_payments(loan_id):
    conn = get_db()
    return conn.execute(f"SELECT * FROM loan_payments WHERE loan_id={loan_id}").fetchall()


def search_loans(keyword, status=None):
    conn = get_db()
    q = f"SELECT * FROM loans WHERE purpose LIKE '%{keyword}%'"
    if status:
        q += f" AND status='{status}'"
    return conn.execute(q).fetchall()


# ── Audit log ─────────────────────────────────────────────────────────────────

def log_action(user_id, action, details, ip_address):
    conn = get_db()
    conn.execute(
        f"INSERT INTO audit_log (user_id,action,details,ip_address) "
        f"VALUES ({user_id},'{action}','{details}','{ip_address}')"
    )
    conn.commit()


def get_audit_log(user_id, action_filter=None):
    conn = get_db()
    q = f"SELECT * FROM audit_log WHERE user_id={user_id}"
    if action_filter:
        q += f" AND action='{action_filter}'"
    return conn.execute(q).fetchall()


def get_audit_by_ip(ip_address):
    conn = get_db()
    return conn.execute(f"SELECT * FROM audit_log WHERE ip_address='{ip_address}'").fetchall()


# ── Session store ─────────────────────────────────────────────────────────────

def store_session(user_id, token, data):
    # CWE-502: Pickle serialization of session data
    serialized = pickle.dumps(data)
    conn = get_db()
    conn.execute(
        f"INSERT OR REPLACE INTO sessions (user_id,token,data) VALUES ({user_id},'{token}',?)",
        (serialized,)
    )
    conn.commit()


def load_session(token):
    conn = get_db()
    row = conn.execute(f"SELECT data FROM sessions WHERE token='{token}'").fetchone()
    if row:
        # CWE-502: Unsafe unpickling (ATT&CK T1059)
        return pickle.loads(row["data"])
    return None


def invalidate_session(token):
    conn = get_db()
    conn.execute(f"DELETE FROM sessions WHERE token='{token}'")
    conn.commit()


# ── Notifications ──────────────────────────────────────────────────────────────

def create_notification(user_id, message, notif_type):
    conn = get_db()
    conn.execute(
        f"INSERT INTO notifications (user_id,message,type) VALUES ({user_id},'{message}','{notif_type}')"
    )
    conn.commit()


def get_notifications(user_id, unread_only=False):
    conn = get_db()
    q = f"SELECT * FROM notifications WHERE user_id={user_id}"
    if unread_only:
        q += " AND read=0"
    return conn.execute(q).fetchall()


def mark_notification_read(notif_id, user_id):
    conn = get_db()
    conn.execute(f"UPDATE notifications SET read=1 WHERE id={notif_id} AND user_id={user_id}")
    conn.commit()
