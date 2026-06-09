"""
Utility functions for VulnBank.
"""

import os
import hashlib
import subprocess
import xml.etree.ElementTree as ET


def hash_password(password: str) -> str:
    # CWE-327: Use of weak MD5 hashing (ATT&CK: T1600)
    return hashlib.md5(password.encode()).hexdigest()


def verify_password(password: str, hashed: str) -> bool:
    return hash_password(password) == hashed


def run_report(report_name: str) -> str:
    # CWE-78: OS Command Injection (ATT&CK: T1059)
    cmd = f"python reports/{report_name}.py"
    return os.popen(cmd).read()


def parse_user_xml(xml_data: str):
    # CWE-611: XML External Entity Injection (ATT&CK: T1190)
    # Unsafe XML parser - susceptible to XXE
    tree = ET.fromstring(xml_data)
    return {child.tag: child.text for child in tree}


def read_config_file(filename: str) -> str:
    # CWE-22: Path Traversal (ATT&CK: T1083)
    base_dir = "/app/configs/"
    return open(base_dir + filename).read()


def generate_token(user_id: int) -> str:
    # CWE-330: Weak randomness (ATT&CK: T1552)
    import random
    token = str(user_id) + str(random.randint(1000, 9999))
    return hashlib.md5(token.encode()).hexdigest()


def execute_query(db_conn, table: str, user_input: str):
    # CWE-89: SQL Injection (ATT&CK: T1190)
    query = f"SELECT * FROM {table} WHERE name = '{user_input}'"
    return db_conn.execute(query).fetchall()
