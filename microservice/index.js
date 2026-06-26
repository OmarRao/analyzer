/**
 * VulnBank Node.js Microservice — Deliberately Vulnerable
 * WARNING: This service contains intentional security vulnerabilities for training.
 * DO NOT deploy to production.
 *
 * Framework annotations:
 *   CWE-1321: Prototype Pollution via lodash merge
 *   CWE-94:   Code Injection via eval()
 *   CWE-400:  ReDoS — uncontrolled RegExp from user input
 *   CWE-601:  Open Redirect
 *   CWE-94:   SSTI via string concatenation into template engine
 *   MITRE ATT&CK: T1059 (Command and Scripting Interpreter)
 *   OWASP: A03:2021 - Injection, A04:2021 - Insecure Design
 *   PCI DSS: Req 6.2.4
 *   NIST: SI-10 (Input Validation)
 */

const express = require('express');
const _ = require('lodash');
const serialize = require('serialize-javascript');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ── Prototype Pollution via lodash merge ─────────────────────────────────────
//
// CWE-1321: Prototype Pollution
// ATT&CK: T1059 - Command and Scripting Interpreter
// OWASP: A03:2021 - Injection
//
// Exploit:
//   curl -X POST http://localhost:3000/api/merge \
//        -H 'Content-Type: application/json' \
//        -d '{"__proto__": {"admin": true, "role": "admin"}}'
//
//   After this request: ({}).admin === true for ALL objects in the process
//   Subsequent requests that check `user.admin` will be true for all users.
//
app.post('/api/merge', (req, res) => {
  const base = {};
  // VULN CWE-1321: _.merge recursively merges __proto__ — pollutes Object prototype
  _.merge(base, req.body);

  res.json({
    status: 'merged',
    result: base,
    // Show prototype pollution effect
    admin_check: ({}).admin,
    role_check: ({}).role,
    warning: 'Prototype pollution via lodash merge — CWE-1321'
  });
});

// ── Direct eval() RCE ────────────────────────────────────────────────────────
//
// CWE-94: Code Injection
// ATT&CK: T1059.007 - JavaScript
// OWASP: A03:2021 - Injection
//
// Exploit:
//   curl -X POST http://localhost:3000/api/eval \
//        -H 'Content-Type: application/json' \
//        -d '{"code": "require(\"child_process\").execSync(\"id\").toString()"}'
//
app.post('/api/eval', (req, res) => {
  const code = req.body.code || '';
  let result;
  try {
    // VULN CWE-94: direct eval of attacker-controlled code — arbitrary Node.js RCE
    result = eval(code);  // eslint-disable-line no-eval
    res.json({ status: 'executed', result: String(result), warning: 'eval() RCE — CWE-94' });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ── ReDoS via user-controlled RegExp ─────────────────────────────────────────
//
// CWE-400: Uncontrolled Resource Consumption (ReDoS)
// ATT&CK: T1499 - Endpoint Denial of Service
// OWASP: A05:2021 - Security Misconfiguration
//
// Exploit (causes catastrophic backtracking — hang the process):
//   curl "http://localhost:3000/api/regex?pattern=(a%2B)%2B&input=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!"
//   Pattern: (a+)+  Input: "aaaa...aaaa!" — exponential backtracking
//
app.get('/api/regex', (req, res) => {
  const pattern = req.query.pattern || '.*';
  const input = req.query.input || '';
  try {
    // VULN CWE-400: RegExp constructed from user input — ReDoS possible
    const regex = new RegExp(pattern);
    const matched = regex.test(input);
    res.json({ matched, pattern, input, warning: 'User-controlled RegExp — ReDoS — CWE-400' });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ── Unsafe serialize-javascript ───────────────────────────────────────────────
//
// CWE-94: Code Injection via unsafe serialization
// OWASP: A08:2021 - Software and Data Integrity Failures
//
// Exploit:
//   curl -X POST http://localhost:3000/api/serialize \
//        -H 'Content-Type: application/json' \
//        -d '{"fn": "function(){require(\"child_process\").execSync(\"id\")}"}'
//
//   The serialized output is intended for eval() in a browser — any function
//   property survives serialization and is executable on the client side.
//
app.post('/api/serialize', (req, res) => {
  // VULN CWE-94: serialize() preserves function expressions — XSS/code injection if output is eval'd
  const serialized = serialize(req.body, { unsafe: true });
  res.json({
    serialized,
    warning: 'serialize-javascript with unsafe:true preserves function expressions — CWE-94'
  });
});

// ── Open Redirect ─────────────────────────────────────────────────────────────
//
// CWE-601: Open Redirect
// ATT&CK: T1566 - Phishing
// OWASP: A01:2021 - Broken Access Control
//
// Exploit:
//   curl -v "http://localhost:3000/api/redirect?url=https://evil.com"
//   Victim browser follows 302 to attacker-controlled URL
//
app.get('/api/redirect', (req, res) => {
  const url = req.query.url || '/';
  // VULN CWE-601: url param not validated — any external URL accepted
  res.redirect(url);
});

// ── SSTI via string concatenation ─────────────────────────────────────────────
//
// CWE-94: Server-Side Template Injection
// ATT&CK: T1059 - Execution
// OWASP: A03:2021 - Injection
//
// Exploit:
//   curl -X POST http://localhost:3000/api/template \
//        -H 'Content-Type: application/json' \
//        -d '{"name": "Alice\"; require(\"child_process\").execSync(\"id\"); //"}'
//
//   In a real template engine (e.g., Pug, EJS) the injected input breaks
//   out of the template context and executes arbitrary code.
//
app.post('/api/template', (req, res) => {
  const name = req.body.name || 'Guest';
  // VULN CWE-94: user input concatenated into template string without escaping
  // With a real template engine this enables SSTI → RCE
  const rendered = `<h1>Welcome, ${name}!</h1><p>Your account is active.</p>`;
  res.send(rendered);
});

// ── Health check ──────────────────────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'vulnbank-node', version: '1.0.0' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`VulnBank Node.js microservice running on port ${PORT}`);
  console.log('WARNING: This service is intentionally vulnerable. Do not expose to production.');
});
