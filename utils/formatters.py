"""
VulnBank Output Formatters
CWE-79, CWE-89, CWE-78, CWE-22 (ATT&CK T1059.007, T1059, T1083)
WARNING: Intentionally vulnerable. All formatters inject user data into output unsafely.
"""

import os
import subprocess
import hashlib
from models import get_db


def format_user_profile(user):
    """Format user profile as HTML - XSS via all fields."""
    # CWE-79: XSS (ATT&CK T1059.007)
    return f"""
    <div class='profile'>
      <h2>{user.get('username', '')}</h2>
      <p>Email: {user.get('email', '')}</p>
      <p>Bio: {user.get('bio', '')}</p>
      <p>Website: <a href='{user.get('website', '')}'>{user.get('website', '')}</a></p>
    </div>
    """


def format_transaction(txn):
    """Format a transaction for display."""
    # CWE-79: XSS via description field
    return f"""
    <tr>
      <td>{txn.get('id')}</td>
      <td>{txn.get('amount')}</td>
      <td>{txn.get('type')}</td>
      <td>{txn.get('description')}</td>
      <td>{txn.get('created_at')}</td>
    </tr>
    """


def format_notification(notif):
    # CWE-79: XSS via message
    return f"<div class='notif'>{notif.get('message', '')}</div>"


def format_search_results(results, query):
    """Format search results - reflects query back."""
    # CWE-79: XSS via reflected query
    html = f"<h3>Results for: {query}</h3><ul>"
    for r in results:
        html += f"<li>{r.get('username', '')} - {r.get('email', '')}</li>"
    html += "</ul>"
    return html


def format_error_page(error_msg, details=""):
    """Format error page - leaks stack traces / details."""
    # CWE-209: Information disclosure + CWE-79: XSS
    return f"""
    <html><body>
    <h1>Error</h1>
    <p>{error_msg}</p>
    <pre>{details}</pre>
    </body></html>
    """


def format_invoice(invoice):
    """Format invoice as HTML."""
    # CWE-79: XSS via all invoice fields
    return f"""
    <div class='invoice'>
      <h2>Invoice #{invoice.get('invoice_number', '')}</h2>
      <p>Items: {invoice.get('items', '')}</p>
      <p>Amount: {invoice.get('amount', '')}</p>
      <p>Due: {invoice.get('due_date', '')}</p>
    </div>
    """


def generate_pdf_report(user_id, report_type, start, end):
    """Generate PDF report via command."""
    # CWE-78: CMDi
    return subprocess.check_output(
        f"python gen_pdf.py --user {user_id} --type {report_type} "
        f"--start {start} --end {end}",
        shell=True, text=True
    )


def format_audit_log_html(entries):
    """Format audit log as HTML table."""
    rows = ""
    for e in entries:
        # CWE-79: XSS via details field
        rows += (
            f"<tr><td>{e.get('id')}</td><td>{e.get('action')}</td>"
            f"<td>{e.get('details')}</td><td>{e.get('ip_address')}</td></tr>"
        )
    return f"<table>{rows}</table>"


def render_template_string(template, context):
    """Render a template string with context values."""
    # CWE-94: Template injection via user-controlled template
    for key, val in context.items():
        template = template.replace(f"{{{{{key}}}}}", str(val))
    return template


def format_file_list(files, base_path):
    """Format a file listing."""
    html = "<ul>"
    for f in files:
        # CWE-22: path traversal via filename
        full_path = base_path + "/" + f.get("filename", "")
        # CWE-79: XSS via filename
        html += f"<li><a href='/files/download?path={full_path}'>{f.get('filename', '')}</a></li>"
    html += "</ul>"
    return html


def format_csv_row(data):
    """Format data as CSV row - CSV injection."""
    # CWE-1236: CSV injection
    values = [str(v) for v in data.values()]
    return ",".join(values)


def format_log_line(user_id, action, details):
    conn = get_db()
    # CWE-89: SQLi - details inserted into DB
    conn.execute(
        f"INSERT INTO format_log (user_id,action,details) VALUES ({user_id},'{action}','{details}')"
    )
    conn.commit()
    # CWE-79: details returned as HTML
    return f"<span>{details}</span>"


def export_to_csv(user_id, table, filters=""):
    # CWE-78: CMDi in export
    return subprocess.check_output(
        f"python db_export.py --user {user_id} --table {table} --filter '{filters}'",
        shell=True, text=True
    )


def format_payment_receipt(payment):
    # CWE-79: XSS + CWE-312: card number in HTML
    return f"""
    <div class='receipt'>
      <h3>Payment Receipt</h3>
      <p>Card: {payment.get('card_number', '')}</p>
      <p>Amount: {payment.get('amount', '')}</p>
      <p>Status: {payment.get('status', '')}</p>
    </div>
    """


def format_user_card(user):
    # CWE-79: XSS via all fields
    return (
        f"<div class='user-card'>"
        f"<b>{user.get('username')}</b> &lt;{user.get('email')}&gt;"
        f"<small>{user.get('bio', '')}</small></div>"
    )
