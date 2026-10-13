# VAPT Reporting Reference

Structured templates for findings and final reports.

---

## Individual Finding Template

Every vulnerability must be documented with this structure:

```markdown
### [FINDING_ID] - [Title]

**Severity:** Critical | High | Medium | Low | Informational
**CVSS Score:** X.X (use CVSS v3.1 calculator)
**OWASP Category:** [e.g., A03:2021 - Injection]
**CWE:** [e.g., CWE-89: SQL Injection]
**Status:** Open | Remediated | Accepted Risk

#### Description
[2-3 sentences explaining what the vulnerability is and where it exists. Be specific about the affected endpoint, parameter, or component.]

#### Affected Component
- **URL/Endpoint:** `POST /api/v1/admin/export/edit`
- **Parameter:** `queryString` in XML body
- **Authentication Required:** Yes (Admin role)
- **Module:** Export Job Configuration

#### Steps to Reproduce
1. [Exact step with request details]
2. [Include HTTP request/response snippets]
3. [Include tool-specific steps (Burp, curl)]

**Request:**
```http
POST /api/v1/admin/export/edit HTTP/1.1
Host: target.com
Cookie: JSESSIONID=<session>
Content-Type: application/xml

<exportConfig>
  <queryString>SELECT @@version</queryString>
</exportConfig>
```

**Response / Evidence:**
[What confirmed the vulnerability — response body, Collaborator interaction, downloaded file content, etc.]

#### Impact
[What an attacker can achieve. Be specific:]
- Data exfiltration (user PII, credentials, tokens)
- Privilege escalation (low-priv to admin)
- Remote code execution
- Internal network access
- Cloud credential theft

#### Remediation
[Specific, actionable fix — not just "validate input":]
- Use parameterized queries / prepared statements for all SQL operations
- Disable external entity processing in XML parser: `factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`
- Implement server-side RBAC check on WebSocket STOMP destinations

#### References
- [OWASP Testing Guide link]
- [CWE link]
- [Relevant advisory if applicable]
```

---

## Severity Classification Matrix

### Critical (CVSS 9.0-10.0)
Immediate risk of significant data breach or system compromise.
- Remote Code Execution (RCE)
- SQL Injection with data access (read/write to DB)
- Authentication bypass (full access without credentials)
- Cloud credential extraction (AWS IAM keys, K8s tokens)
- XXE with internal file read + cloud metadata access
- Password reset poisoning (confirmed token delivery to attacker)
- Privilege escalation from unauthenticated to admin

### High (CVSS 7.0-8.9)
Significant security impact requiring prompt remediation.
- Stored XSS (especially in admin panels)
- SSRF to internal network with confirmed access
- IDOR with write access (modify other users' data)
- Insecure deserialization
- Vertical privilege escalation (user to admin)
- Hardcoded credentials granting significant access
- Broken session management (session fixation with exploitation)

### Medium (CVSS 4.0-6.9)
Moderate risk, exploitable under certain conditions.
- Reflected XSS
- IDOR read-only (view other users' data)
- Source code disclosure (source maps, unminified JS)
- DMARC policy set to `p=none`
- User enumeration with PII exposure
- Cross-tenant data leakage (read-only)
- Missing rate limiting on sensitive operations
- Information disclosure (software versions, internal IPs)
- CORS misconfiguration without credential reflection

### Low (CVSS 0.1-3.9)
Minor security concern, defense-in-depth improvement.
- Missing security headers (CSP unsafe-inline, missing HSTS)
- Verbose error messages without sensitive data
- Cookie attributes missing (Secure, HttpOnly, SameSite)
- SPF softfail (`~all`)
- Clickjacking (no X-Frame-Options) on non-sensitive pages
- Autocomplete enabled on sensitive forms
- Lack of CAPTCHA on non-critical forms

### Informational (CVSS 0.0)
Observations and recommendations, no exploitable risk confirmed.
- Theoretical vulnerabilities without PoC
- SSRF where execution can't be confirmed
- Best practice recommendations
- Defense-in-depth suggestions
- Technology version disclosures (if no known CVE)

---

## OWASP Top 10 (2021) Mapping

| ID | Category | Common Findings |
|----|----------|----------------|
| A01 | Broken Access Control | IDOR, privilege escalation, RBAC bypass, missing function-level access control |
| A02 | Cryptographic Failures | Hardcoded keys, weak algorithms, cleartext transmission |
| A03 | Injection | SQLi, XXE, XSS, SSTI, command injection, CRLF |
| A04 | Insecure Design | Business logic flaws, missing rate limits, insufficient anti-automation |
| A05 | Security Misconfiguration | Default configs, unnecessary features, missing headers, source maps |
| A06 | Vulnerable Components | Outdated libraries, known CVEs in dependencies |
| A07 | Auth Failures | Credential stuffing, weak passwords, session management issues |
| A08 | Data Integrity Failures | Insecure deserialization, CI/CD issues, unsigned updates |
| A09 | Logging Failures | Insufficient logging, sensitive data in logs |
| A10 | SSRF | Server-side request forgery to internal/cloud resources |

---

## Final Report Structure

```markdown
# Vulnerability Assessment & Penetration Testing Report

## Document Information
| Field | Value |
|-------|-------|
| Client | [Client Name] |
| Application | [App Name + URL/Package] |
| Assessment Type | Web Application / Mobile Application / API |
| Environment | Staging / Production |
| Testing Period | [Start Date] - [End Date] |
| Tester | [Name] |
| Report Version | 1.0 |
| Classification | Confidential |

## Executive Summary
[3-5 sentences for non-technical stakeholders. Overall risk posture, critical issues count, key recommendation.]

**Finding Summary:**
| Severity | Count |
|----------|-------|
| Critical | X |
| High | X |
| Medium | X |
| Low | X |
| Informational | X |
| **Total** | **X** |

## Scope & Methodology
- Testing approach (black-box / gray-box / white-box)
- Tools used (Burp Suite, Frida, custom scripts, etc.)
- Standards followed (OWASP Testing Guide, OWASP MASVS for mobile)
- Testing account details (roles tested, not actual credentials)
- Out-of-scope items

## Findings
[Sorted by severity: Critical → High → Medium → Low → Informational]
[Each finding uses the Individual Finding Template above]

## Positive Observations
[Things the target does well — proper RBAC on HTTP endpoints, session isolation between portals, parameterized queries on standard endpoints, strict DTO validation, etc. This builds credibility and acknowledges defensive wins.]

## Appendix
- A: Full endpoint list
- B: Tool configuration
- C: Raw scan results (if applicable)
- D: Screenshots / evidence gallery
```

---

## Writing Tips

1. **Be specific, not generic.** "SQL injection in the export config endpoint" not "SQL injection was found."
2. **Show, don't tell.** Include request/response snippets. A finding without a PoC is a guess.
3. **Write remediation the developer can act on.** "Use `PreparedStatement` with parameterized queries" not "sanitize input."
4. **Note positive findings.** "Session isolation is properly enforced between admin, tenant, and user portals" — this prevents the team from breaking what already works.
5. **Distinguish confirmed vs. theoretical.** If you can't confirm exploitation, mark it Informational and explain what's missing.
6. **Chain findings.** Show how SQLi + XXE + SSRF combines for cloud credential extraction — the chain impact is greater than individual findings.
