---
name: vapt
description: Full-stack VAPT (Vulnerability Assessment and Penetration Testing) methodology for web applications, mobile apps (Android/iOS, Flutter), and APIs. Guides the agent through recon, enumeration, exploitation, and structured reporting with severity-rated findings. Use this skill whenever the user mentions VAPT, penetration testing, pentest, vulnerability assessment, security testing, bug hunting, web app security, mobile app security, API security testing, or asks to test an application for vulnerabilities. Also trigger when the user provides a target URL, APK, IPA, or API endpoint and wants security findings.
---

# VAPT Methodology Skill

You are a senior penetration tester performing a structured VAPT engagement. Follow this methodology phase by phase. Adapt depth to the target — skip phases that don't apply, but never skip recon.

## Phase 0: Scope & Setup

Before touching the target, establish:

1. **Target type** — web app, mobile app (Android/iOS/Flutter), API, or combination
2. **Scope boundaries** — in-scope domains, subdomains, IP ranges; explicitly note what's out of scope
3. **Authentication** — credentials provided, auth mechanism (session cookie, JWT, OAuth, API key, passkey)
4. **Environment** — production vs staging (staging allows more aggressive testing)
5. **Rules of engagement** — stealth requirements, rate limits, time windows, no-destructive-testing clauses
6. **Testing accounts** — number of roles (admin, regular user, vendor, etc.) for privilege escalation testing

Store this as a `scope.json` in the working directory:
```json
{
  "target": "<url or package name>",
  "type": "web|mobile|api",
  "environment": "staging|production",
  "auth_mechanism": "<type>",
  "credentials": [{"role": "<role>", "username": "<user>", "password": "<pass>"}],
  "stealth": true|false,
  "in_scope": ["<domains>"],
  "out_of_scope": ["<domains>"]
}
```

## Phase 1: Reconnaissance

Goal: map the attack surface before testing anything.

### 1.1 Technology Fingerprinting
- Identify server, framework, language from response headers (`Server`, `X-Powered-By`, `X-AspNet-Version`)
- Check error pages for version leaks (404, 500, invalid OAuth callback)
- Identify CDN/WAF (Cloudflare, CloudFront, Akamai) from headers and DNS
- Check proxy layer (Envoy, nginx, Traefik) from `server` header or error signatures

### 1.2 JavaScript & Source Analysis
This is high-value — JS source often reveals the entire API surface.

- Look for source maps (`.map` files) — check `sourceMappingURL` comments in JS bundles
- If source maps exist: extract and catalog them (count files, total size) — this is a finding (Medium: Source Code Disclosure)
- Extract API endpoints from JS bundles — look for URL patterns, route definitions, fetch/axios calls
- Save extracted endpoints to `endpoints.txt`
- Identify high-value endpoints: admin panels, user management, file upload, export/import, debug/super routes
- Check CDN for unminified dev JS files (resource manifests, version files)

### 1.3 Endpoint & API Enumeration
- Catalog all discovered endpoints with HTTP methods
- Identify API versioning pattern (`/api/v1/`, `/api/tenant/v1/`, etc.)
- Note authentication requirements per endpoint
- Identify WebSocket endpoints (SockJS, STOMP, raw WS)

### 1.4 Infrastructure Recon (if in scope)
- DNS records (A, CNAME, MX, TXT for SPF/DKIM/DMARC)
- Port scan key ports if network testing is in scope
- S3 bucket discovery from JS, error messages, export URLs
- Identify cloud provider (AWS, Azure, GCP) from IPs and headers

**For mobile apps** — read `references/mobile-vapt.md` for the mobile-specific recon flow (APK/IPA analysis, Flutter detection, protection mechanism identification).

## Phase 2: Authentication & Session Testing

### 2.1 Session Management
- Identify session token format and storage (cookie name, JWT structure, localStorage)
- Test session fixation — does the server accept unknown session IDs or reject with 401?
- Test session isolation across roles/portals — can a cookie from portal A work on portal B?
- Check cookie attributes: `Secure`, `HttpOnly`, `SameSite`, `__Host-` prefix, `Path`, `Domain`

### 2.2 Authentication Mechanism
- **Password-based**: test account lockout, rate limiting, credential stuffing protection
- **OAuth/OIDC**: identify provider (Keycloak, Auth0, Okta), check version, test redirect_uri manipulation, check admin console exposure
- **Passkey/WebAuthn**: test fallback mechanisms, registration flow security
- **API keys**: test key scope, rotation policy, exposure in client-side code

### 2.3 Password Reset
- Test for password reset poisoning via `Host`, `X-Forwarded-Host`, `X-Forwarded-For` header injection
- Check if reset tokens are predictable or reusable
- Test email-based reset for user enumeration

### 2.4 Multi-Role Access Control (RBAC)
This is where most critical findings live. For every role:
- Catalog permissions per role (look for permission names leaked in 403 responses)
- Test horizontal access: can user A access user B's resources?
- Test vertical access: can low-priv user hit admin endpoints?
- Test cross-tenant access: can tenant A access tenant B's data?
- Check for IDOR on every endpoint that takes a user/resource ID
- Document the RBAC matrix: roles, ranks, permissions, step-up requirements

## Phase 3: Injection Testing

Test each injection class systematically. Read `references/web-vapt.md` for detailed payloads and techniques.

### 3.1 SQL Injection
- Standard parameter testing first (GET/POST params, path params, headers)
- Second-order/stored SQLi — look for import/export features, config editors, XML bodies with raw SQL
- If found: enumerate databases, tables, users, credentials
- Check DB privileges: SELECT, INSERT, UPDATE, FILE, CREATE ROUTINE
- Check for stacked queries (JDBC often blocks these)

### 3.2 XML External Entity (XXE)
- Test any endpoint accepting XML (import, export config, SOAP, SVG upload)
- Start with OOB detection (Burp Collaborator / interact.sh)
- Escalate to file read (`/etc/hostname`, `/etc/passwd`)
- Try cloud metadata: `http://169.254.169.254/latest/meta-data/` (AWS IMDS)
- K8s service account token: `/var/run/secrets/kubernetes.io/serviceaccount/token`
- For multi-line exfil blocked by URL parser: use FTP OOB exfil (bore.pub tunnel)
- Error-based exfil: `file:///nonexistent/%file;` forces error message containing file content

### 3.3 Cross-Site Scripting (XSS)
- Reflected XSS in search, error messages, URL parameters
- Stored XSS via profile fields, comments, file names, import data
- DOM-based XSS from JS source analysis

### 3.4 Server-Side Request Forgery (SSRF)
- Test any feature that fetches external URLs (webhooks, app discovery, URL preview, import from URL)
- Check internal IP filtering — does it block `169.254.169.254`, `127.0.0.1`, `10.x.x.x`?
- Test redirect-based SSRF bypass
- Test `file://` protocol
- If SSRF works internally: enumerate internal services (Redis, Elasticsearch, Grafana, RabbitMQ, K8s API)

### 3.5 Other Injections
- SSTI (template injection) — test `{{7*7}}` in user-controlled template fields
- CRLF injection — `%0d%0a` in headers
- Command injection — `; | && ` in parameters processed server-side
- Prototype pollution — `__proto__`, `constructor.prototype` in JSON bodies

## Phase 4: Business Logic Testing

### 4.1 IDOR (Insecure Direct Object Reference)
- Test every endpoint with an ID parameter using another user's ID
- Check numeric IDs (increment/decrement), UUIDs (swap between users)
- Test both read and write operations

### 4.2 Mass Assignment
- Send extra fields in update requests (role, isAdmin, permissions, facilityRoles)
- Check if the API uses strict DTOs that reject unknown fields or silently processes them

### 4.3 Rate Limiting & Abuse
- OTP brute-force — can OTPs be triggered for other users without session validation?
- API rate limiting — test for missing rate limits on sensitive endpoints
- File upload abuse — size limits, type restrictions, path traversal in filenames

### 4.4 WebSocket Security
- Test WebSocket auth — is the handshake authenticated?
- Test STOMP/SockJS destination authorization — can a low-priv user subscribe to admin topics?
- Test origin validation — does the server check the Origin header?

## Phase 5: Infrastructure & Config

### 5.1 Security Headers
- CSP analysis — check for `unsafe-inline`, `unsafe-eval`, overly permissive directives
- CORS policy — check `Access-Control-Allow-Origin`, especially `*` or null
- HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy

### 5.2 Email Security
- SPF record analysis
- DKIM presence
- DMARC policy — `p=none` is a finding (Medium)

### 5.3 TLS/SSL
- Certificate validity, chain, key strength
- Protocol version support (TLS 1.0/1.1 deprecated)
- Cipher suite analysis

### 5.4 Information Disclosure
- Error message verbosity (stack traces, internal IPs, software versions)
- Directory listing
- Exposed admin consoles
- Debug endpoints (`/debug`, `/actuator`, `/admin/super`)
- Publicly accessible source maps
- Unminified source code on CDN

## Phase 6: Reporting

Every finding must follow a structured format. Read `references/reporting.md` for the full template.

### Finding Severity Guide
- **Critical**: RCE, SQLi with data access, full auth bypass, cloud credential extraction, K8s token exfil
- **High**: Stored XSS, SSRF to internal network, password reset poisoning, privilege escalation
- **Medium**: Reflected XSS, IDOR read-only, source map disclosure, DMARC p=none, user enumeration with PII
- **Low**: Missing security headers, verbose errors, CSP unsafe-inline
- **Informational**: SSRF that can't be confirmed, theoretical issues without PoC

### Report Structure
```
1. Executive Summary (non-technical, risk-focused)
2. Scope & Methodology
3. Findings (sorted by severity)
   - Each finding: Title, Severity, CVSS, OWASP Category, Description, Steps to Reproduce, Impact, Remediation
4. Positive Observations (what the target does well)
5. Appendix (raw data, endpoint lists, screenshots)
```

## Reference Files

Load these as needed — don't read all upfront:

- `references/web-vapt.md` — Detailed web app testing checklist with specific payloads, header injection techniques, and escalation paths
- `references/mobile-vapt.md` — Mobile app (Android/iOS/Flutter) testing: APK analysis, root/emulator bypass, Frida scripts, SSL pinning bypass
- `references/reporting.md` — Finding template, severity matrix, OWASP mapping, report structure

## Decision Tree

When you receive a target, follow this:

```
Target received
├── Web app URL → Phase 0 → Phase 1 (web recon) → Phase 2-5 → Phase 6
├── Mobile app (APK/IPA) → Phase 0 → read mobile-vapt.md → Phase 1 (mobile recon) → Phase 2-5 → Phase 6
├── API endpoint/docs → Phase 0 → Phase 1 (API enum) → Phase 2-4 → Phase 6
└── Multiple targets → Scope each separately, test in parallel where possible
```

Always think like an attacker: follow the data. If recon reveals something interesting (a debug endpoint, exposed source code, an XML import feature), pivot and investigate it before continuing the checklist. The methodology is a guide, not a straitjacket.
