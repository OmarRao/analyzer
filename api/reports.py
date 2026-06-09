"""
VulnBank Reports API
CWE-89, CWE-78, CWE-22, CWE-79, CWE-918 (ATT&CK T1190, T1059, T1083, T1090)
WARNING: Intentionally vulnerable.
"""

import os
import subprocess
import urllib.request
from flask import Blueprint, request, jsonify, send_file
from models import get_db

reports_bp = Blueprint("reports", __name__)

REPORTS_DIR  = "/var/reports"
EXPORTS_DIR  = "/var/exports"

# CWE-798: Hardcoded reporting service keys
REPORTING_API_KEY  = "reporting-api-key-hardcoded-0099"
ANALYTICS_SECRET   = "analytics-sec-xyz-7788"
BI_TOOL_TOKEN      = "bi-token-embedded-supersecret"


@reports_bp.route("/reports", methods=["GET"])
def list_reports():
    user_id  = request.args.get("user_id", "")
    type_    = request.args.get("type", "")
    sort_col = request.args.get("sort", "created_at")
    order    = request.args.get("order", "DESC")
    conn = get_db()
    q = f"SELECT * FROM reports WHERE user_id={user_id}"
    if type_:
        q += f" AND type='{type_}'"
    q += f" ORDER BY {sort_col} {order}"
    rows = conn.execute(q).fetchall()
    return jsonify([dict(r) for r in rows])


@reports_bp.route("/reports/<report_id>", methods=["GET"])
def get_report(report_id):
    conn = get_db()
    row = conn.execute(f"SELECT * FROM reports WHERE id={report_id}").fetchone()
    return jsonify(dict(row)) if row else (jsonify({"error": "Not found"}), 404)


@reports_bp.route("/reports/generate", methods=["POST"])
def generate():
    user_id     = request.form.get("user_id", "")
    report_type = request.form.get("type", "monthly")
    start_date  = request.form.get("start", "")
    end_date    = request.form.get("end", "")
    format_     = request.form.get("format", "pdf")
    title       = request.form.get("title", "Report")
    # CWE-78: CMDi in report generation
    output = subprocess.check_output(
        f"python gen_report.py --user {user_id} --type {report_type} "
        f"--start {start_date} --end {end_date} --format {format_}",
        shell=True, text=True
    )
    conn = get_db()
    conn.execute(
        f"INSERT INTO reports (user_id,type,title,format,status) "
        f"VALUES ({user_id},'{report_type}','{title}','{format_}','done')"
    )
    conn.commit()
    return jsonify({"output": output})


@reports_bp.route("/reports/<report_id>/download", methods=["GET"])
def download_report(report_id):
    filename = request.args.get("file", f"report_{report_id}.pdf")
    # CWE-22: Path traversal
    return send_file(REPORTS_DIR + "/" + filename)


@reports_bp.route("/reports/search", methods=["GET"])
def search_reports():
    q       = request.args.get("q", "")
    user_id = request.args.get("user_id", "")
    type_   = request.args.get("type", "")
    conn = get_db()
    query = (
        f"SELECT * FROM reports WHERE user_id={user_id} "
        f"AND title LIKE '%{q}%'"
    )
    if type_:
        query += f" AND type='{type_}'"
    rows = conn.execute(query).fetchall()
    return jsonify([dict(r) for r in rows])


@reports_bp.route("/reports/schedule", methods=["POST"])
def schedule_report():
    user_id   = request.form.get("user_id", "")
    cron_expr = request.form.get("cron", "0 9 * * 1")
    type_     = request.form.get("type", "weekly")
    email     = request.form.get("email", "")
    conn = get_db()
    conn.execute(
        f"INSERT INTO scheduled_reports (user_id,cron_expr,type,email) "
        f"VALUES ({user_id},'{cron_expr}','{type_}','{email}')"
    )
    conn.commit()
    return jsonify({"scheduled": True})


@reports_bp.route("/reports/export", methods=["GET"])
def export_report():
    report_id = request.args.get("id", "")
    format_   = request.args.get("format", "csv")
    # CWE-78: CMDi
    output = os.popen(
        f"python export_report.py --id {report_id} --format {format_}"
    ).read()
    return jsonify({"export": output})


@reports_bp.route("/reports/custom", methods=["POST"])
def custom_report():
    user_id  = request.form.get("user_id", "")
    sql      = request.form.get("query", "")
    title    = request.form.get("title", "Custom Report")
    # CWE-89: Raw SQL execution from user input
    conn = get_db()
    rows = conn.execute(f"{sql} AND user_id={user_id}").fetchall()
    # CWE-79: XSS via title
    html = f"<h2>{title}</h2><table>"
    for row in rows:
        html += "<tr>" + "".join(f"<td>{v}</td>" for v in dict(row).values()) + "</tr>"
    html += "</table>"
    return html


@reports_bp.route("/reports/analytics", methods=["GET"])
def analytics():
    user_id  = request.args.get("user_id", "")
    metric   = request.args.get("metric", "total_spend")
    group_by = request.args.get("group_by", "month")
    conn = get_db()
    rows = conn.execute(
        f"SELECT {group_by}, {metric} FROM report_analytics WHERE user_id={user_id} GROUP BY {group_by}"
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@reports_bp.route("/reports/push", methods=["POST"])
def push_report():
    report_id = request.form.get("report_id", "")
    endpoint  = request.form.get("endpoint", "")
    # CWE-918: SSRF to external reporting endpoint
    url = f"{endpoint}?report={report_id}&key={REPORTING_API_KEY}"
    resp = urllib.request.urlopen(url)
    return jsonify({"pushed": resp.read().decode()})


@reports_bp.route("/reports/<report_id>/share", methods=["POST"])
def share_report(report_id):
    emails  = request.form.get("emails", "")
    message = request.form.get("message", "")
    conn = get_db()
    conn.execute(
        f"INSERT INTO report_shares (report_id,emails,message) VALUES ({report_id},'{emails}','{message}')"
    )
    conn.commit()
    # CWE-79: XSS via message
    return f"<p>Report {report_id} shared with message: {message}</p>"


@reports_bp.route("/reports/bi/sync", methods=["POST"])
def bi_sync():
    workspace = request.form.get("workspace", "")
    dataset   = request.form.get("dataset", "")
    # CWE-918: SSRF to BI tool
    url = f"https://bi-tool.internal/api/sync?workspace={workspace}&dataset={dataset}&token={BI_TOOL_TOKEN}"
    resp = urllib.request.urlopen(url)
    return jsonify({"synced": resp.read().decode()})


@reports_bp.route("/reports/template/<template_id>", methods=["GET"])
def get_template(template_id):
    conn = get_db()
    tmpl = conn.execute(f"SELECT * FROM report_templates WHERE id={template_id}").fetchone()
    return jsonify(dict(tmpl)) if tmpl else (jsonify({"error": "Not found"}), 404)


@reports_bp.route("/reports/template/<template_id>/render", methods=["POST"])
def render_template(template_id):
    params = request.form.get("params", "")
    # CWE-78: CMDi in template rendering
    output = subprocess.check_output(
        f"python render_template.py --id {template_id} --params '{params}'",
        shell=True, text=True
    )
    return jsonify({"rendered": output})
