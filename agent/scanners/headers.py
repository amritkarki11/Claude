"""Security Headers Scanner — checks HTTP response headers for misconfigurations.

Maps to:
  - OWASP Top 10 A05:2021 Security Misconfiguration
  - OTG-CONFIG-002  Test Application Platform Configuration
  - OTG-CONFIG-006  Test HTTP Methods
  - CWE-16          Configuration
  - CWE-693         Protection Mechanism Failure

Checks all security-relevant headers on every response:
  Strict-Transport-Security, Content-Security-Policy, X-Frame-Options,
  X-Content-Type-Options, Referrer-Policy, Permissions-Policy,
  X-XSS-Protection, Cache-Control, Set-Cookie flags, CORS, Server info leak.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

from ..http import HttpClient, Session
from ..recipes.schema import Recipe
from .base import Scanner, Candidate

logger = logging.getLogger(__name__)


@dataclass
class HeaderFinding:
    """One header misconfiguration."""
    header: str
    status: str        # missing | misconfigured | info-leak
    severity: str      # critical | high | medium | low | info
    detail: str        # why it's bad
    recommendation: str
    owasp_ref: str = ""
    current_value: str = ""


@dataclass
class HeaderScanResult:
    """Full result of header analysis on one URL."""
    url: str = ""
    findings: list[HeaderFinding] = field(default_factory=list)
    raw_headers: dict = field(default_factory=dict)

    @property
    def score(self) -> str:
        """Quick A–F grade based on findings."""
        crits = sum(1 for f in self.findings if f.severity in ("critical", "high"))
        meds = sum(1 for f in self.findings if f.severity == "medium")
        if crits >= 3:
            return "F"
        if crits >= 2:
            return "D"
        if crits >= 1 or meds >= 3:
            return "C"
        if meds >= 1:
            return "B"
        return "A"


class HeaderScanner(Scanner):
    """Checks security headers on target responses."""

    vuln_classes = ["security-headers", "misconfiguration"]

    def __init__(self, client: HttpClient, session: Session):
        super().__init__(client)
        self.session = session

    async def _detect(self, target: str, recipe: Recipe, **context: Any) -> list[Candidate]:
        """Fetch target and check all security headers."""
        try:
            resp = await self.client.get(target, session=self.session, follow_redirects=True)
        except Exception as e:
            logger.warning("Header scan failed for %s: %s", target, e)
            return []

        headers = {k.lower(): v for k, v in resp.headers.items()}
        findings = []
        is_https = target.startswith("https://")

        # ── 1. Strict-Transport-Security (HSTS) ──
        hsts = headers.get("strict-transport-security", "")
        if not hsts:
            findings.append(HeaderFinding(
                header="Strict-Transport-Security",
                status="missing",
                severity="high",
                detail="HSTS header is missing. Browser will not enforce HTTPS, allowing SSL stripping attacks (MITM).",
                recommendation="Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                owasp_ref="A05:2021 / CWE-319",
            ))
        else:
            max_age_m = re.search(r"max-age=(\d+)", hsts)
            if max_age_m:
                max_age = int(max_age_m.group(1))
                if max_age < 15768000:  # < 6 months
                    findings.append(HeaderFinding(
                        header="Strict-Transport-Security",
                        status="misconfigured",
                        severity="medium",
                        detail=f"HSTS max-age is {max_age}s ({max_age//86400} days) — too short. Should be at least 1 year (31536000).",
                        recommendation="Set max-age=31536000; includeSubDomains; preload",
                        owasp_ref="A05:2021",
                        current_value=hsts,
                    ))
            if "includesubdomains" not in hsts.lower():
                findings.append(HeaderFinding(
                    header="Strict-Transport-Security",
                    status="misconfigured",
                    severity="low",
                    detail="HSTS does not include subdomains. Subdomains can still be accessed over HTTP.",
                    recommendation="Add includeSubDomains directive",
                    owasp_ref="A05:2021",
                    current_value=hsts,
                ))

        # ── 2. Content-Security-Policy (CSP) ──
        csp = headers.get("content-security-policy", "")
        if not csp:
            findings.append(HeaderFinding(
                header="Content-Security-Policy",
                status="missing",
                severity="high",
                detail="CSP header is missing. No restrictions on script sources — XSS attacks have no browser-level mitigation.",
                recommendation="Add a restrictive CSP. At minimum: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'self'",
                owasp_ref="A05:2021 / CWE-693",
            ))
        else:
            csp_lower = csp.lower()
            csp_issues = []
            if "'unsafe-inline'" in csp_lower and "script-src" in csp_lower:
                csp_issues.append("script-src allows 'unsafe-inline' — inline scripts can execute (XSS bypass)")
            if "'unsafe-eval'" in csp_lower:
                csp_issues.append("'unsafe-eval' allowed — eval()/Function() can execute attacker code")
            if "default-src *" in csp_lower or "script-src *" in csp_lower:
                csp_issues.append("Wildcard (*) source — effectively no protection, any domain can serve scripts")
            if "data:" in csp_lower and "script-src" in csp_lower:
                csp_issues.append("data: URI allowed in script-src — can inject scripts via data: scheme")
            if "object-src" not in csp_lower and "default-src" not in csp_lower:
                csp_issues.append("object-src not restricted — Flash/Java plugins can be embedded")
            if "frame-ancestors" not in csp_lower:
                csp_issues.append("frame-ancestors not set — page can be framed (clickjacking)")
            if "base-uri" not in csp_lower:
                csp_issues.append("base-uri not restricted — <base> tag injection can redirect relative URLs")
            if csp_issues:
                findings.append(HeaderFinding(
                    header="Content-Security-Policy",
                    status="misconfigured",
                    severity="high" if any("unsafe" in i or "Wildcard" in i for i in csp_issues) else "medium",
                    detail="CSP is present but has weaknesses: " + "; ".join(csp_issues),
                    recommendation="Tighten CSP: remove 'unsafe-inline', 'unsafe-eval', wildcards. Use nonces or hashes for inline scripts.",
                    owasp_ref="A05:2021 / CWE-693",
                    current_value=csp[:300],
                ))

        # ── 3. X-Frame-Options ──
        xfo = headers.get("x-frame-options", "")
        has_frame_ancestors = "frame-ancestors" in csp.lower() if csp else False
        if not xfo and not has_frame_ancestors:
            findings.append(HeaderFinding(
                header="X-Frame-Options",
                status="missing",
                severity="medium",
                detail="X-Frame-Options header is missing and CSP frame-ancestors not set. Page can be embedded in an iframe — vulnerable to clickjacking attacks.",
                recommendation="Add: X-Frame-Options: DENY (or SAMEORIGIN). Better: use CSP frame-ancestors 'self'",
                owasp_ref="A05:2021 / CWE-1021",
            ))
        elif xfo and xfo.upper() not in ("DENY", "SAMEORIGIN"):
            if not xfo.upper().startswith("ALLOW-FROM"):
                findings.append(HeaderFinding(
                    header="X-Frame-Options",
                    status="misconfigured",
                    severity="medium",
                    detail=f"X-Frame-Options has invalid value '{xfo}'. Only DENY and SAMEORIGIN are valid.",
                    recommendation="Set to DENY or SAMEORIGIN",
                    owasp_ref="CWE-1021",
                    current_value=xfo,
                ))

        # ── 4. X-Content-Type-Options ──
        xcto = headers.get("x-content-type-options", "")
        if not xcto:
            findings.append(HeaderFinding(
                header="X-Content-Type-Options",
                status="missing",
                severity="medium",
                detail="X-Content-Type-Options header is missing. Browser may MIME-sniff responses, treating uploaded files as executable scripts.",
                recommendation="Add: X-Content-Type-Options: nosniff",
                owasp_ref="A05:2021 / CWE-16",
            ))
        elif xcto.lower() != "nosniff":
            findings.append(HeaderFinding(
                header="X-Content-Type-Options",
                status="misconfigured",
                severity="medium",
                detail=f"X-Content-Type-Options should be 'nosniff', got '{xcto}'.",
                recommendation="Set to: nosniff",
                owasp_ref="CWE-16",
                current_value=xcto,
            ))

        # ── 5. Referrer-Policy ──
        rp = headers.get("referrer-policy", "")
        if not rp:
            findings.append(HeaderFinding(
                header="Referrer-Policy",
                status="missing",
                severity="low",
                detail="Referrer-Policy header is missing. Full URL including query parameters and tokens may leak to third-party sites via Referer header.",
                recommendation="Add: Referrer-Policy: strict-origin-when-cross-origin (or no-referrer for sensitive pages)",
                owasp_ref="CWE-200",
            ))
        elif rp.lower() in ("unsafe-url",):
            findings.append(HeaderFinding(
                header="Referrer-Policy",
                status="misconfigured",
                severity="medium",
                detail="Referrer-Policy is 'unsafe-url' — full URL with path and query is sent to ALL origins, leaking tokens and sensitive paths.",
                recommendation="Use: strict-origin-when-cross-origin or no-referrer",
                owasp_ref="CWE-200",
                current_value=rp,
            ))

        # ── 6. Permissions-Policy (formerly Feature-Policy) ──
        pp = headers.get("permissions-policy", headers.get("feature-policy", ""))
        if not pp:
            findings.append(HeaderFinding(
                header="Permissions-Policy",
                status="missing",
                severity="low",
                detail="Permissions-Policy header is missing. Browser features (camera, microphone, geolocation, payment) are not restricted — malicious embedded content can request them.",
                recommendation="Add: Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()",
                owasp_ref="A05:2021",
            ))

        # ── 7. X-XSS-Protection ──
        xxss = headers.get("x-xss-protection", "")
        if not xxss:
            findings.append(HeaderFinding(
                header="X-XSS-Protection",
                status="missing",
                severity="low",
                detail="X-XSS-Protection header is missing. While deprecated in modern browsers, older browsers (IE) won't activate their XSS filter.",
                recommendation="Add: X-XSS-Protection: 0 (to disable, since CSP is preferred) or 1; mode=block for legacy browsers",
                owasp_ref="CWE-79",
            ))
        elif xxss.strip() == "0" and not csp:
            findings.append(HeaderFinding(
                header="X-XSS-Protection",
                status="misconfigured",
                severity="medium",
                detail="X-XSS-Protection is disabled (0) but no CSP is set — no XSS protection at browser level.",
                recommendation="Either enable X-XSS-Protection: 1; mode=block OR add a Content-Security-Policy",
                owasp_ref="CWE-79",
                current_value=xxss,
            ))

        # ── 8. Cache-Control (for sensitive pages) ──
        cc = headers.get("cache-control", "")
        pragma = headers.get("pragma", "")
        # Only flag for pages that likely have sensitive content
        body_lower = resp.text[:3000].lower() if resp.text else ""
        has_sensitive = any(kw in body_lower for kw in (
            "password", "account", "profile", "dashboard", "session",
            "credit", "payment", "balance", "ssn", "social security",
        ))
        if has_sensitive and "no-store" not in cc.lower():
            findings.append(HeaderFinding(
                header="Cache-Control",
                status="misconfigured",
                severity="medium",
                detail="Page contains sensitive content but Cache-Control does not include 'no-store'. Sensitive data may be cached by browser or proxy.",
                recommendation="Add: Cache-Control: no-store, no-cache, must-revalidate, private",
                owasp_ref="A05:2021 / CWE-524",
                current_value=cc or "(not set)",
            ))

        # ── 9. Set-Cookie flags ──
        cookies = [v for k, v in resp.headers.multi_items() if k.lower() == "set-cookie"]
        # Fallback: try raw
        if not cookies:
            cookies = [v for k, v in resp.headers.items() if k.lower() == "set-cookie"]

        for cookie_str in cookies:
            cookie_lower = cookie_str.lower()
            cookie_name = cookie_str.split("=")[0].strip()
            issues = []
            if "httponly" not in cookie_lower:
                issues.append("HttpOnly flag missing — cookie accessible via JavaScript (XSS can steal it)")
            if is_https and "secure" not in cookie_lower:
                issues.append("Secure flag missing — cookie sent over unencrypted HTTP")
            if "samesite" not in cookie_lower:
                issues.append("SameSite attribute missing — cookie sent with cross-site requests (CSRF)")
            elif "samesite=none" in cookie_lower:
                issues.append("SameSite=None — cookie sent with ALL cross-site requests (CSRF risk)")
            if issues:
                findings.append(HeaderFinding(
                    header=f"Set-Cookie ({cookie_name})",
                    status="misconfigured",
                    severity="medium" if "httponly" in " ".join(issues).lower() or "secure" in " ".join(issues).lower() else "low",
                    detail="; ".join(issues),
                    recommendation=f"Set cookie with: {cookie_name}=value; HttpOnly; Secure; SameSite=Strict; Path=/",
                    owasp_ref="A05:2021 / CWE-614 / CWE-1004",
                    current_value=cookie_str[:200],
                ))

        # ── 10. Server / X-Powered-By info leak ──
        server = headers.get("server", "")
        xpb = headers.get("x-powered-by", "")
        if server and re.search(r"\d+\.\d+", server):
            findings.append(HeaderFinding(
                header="Server",
                status="info-leak",
                severity="low",
                detail=f"Server header discloses software version: '{server}'. Attackers can look up known CVEs for this exact version.",
                recommendation="Remove version from Server header or suppress it entirely",
                owasp_ref="CWE-200",
                current_value=server,
            ))
        if xpb:
            findings.append(HeaderFinding(
                header="X-Powered-By",
                status="info-leak",
                severity="low",
                detail=f"X-Powered-By header exposes technology: '{xpb}'. Aids attackers in choosing targeted exploits.",
                recommendation="Remove X-Powered-By header entirely",
                owasp_ref="CWE-200",
                current_value=xpb,
            ))

        # ── 11. CORS misconfiguration ──
        acao = headers.get("access-control-allow-origin", "")
        acac = headers.get("access-control-allow-credentials", "")
        if acao == "*" and acac.lower() == "true":
            findings.append(HeaderFinding(
                header="CORS",
                status="misconfigured",
                severity="critical",
                detail="CORS allows any origin (*) WITH credentials. Any website can make authenticated requests and read responses — complete authentication bypass for API calls.",
                recommendation="Never combine Access-Control-Allow-Origin: * with Allow-Credentials: true. Whitelist specific origins.",
                owasp_ref="A05:2021 / CWE-942",
                current_value=f"Allow-Origin: {acao}, Allow-Credentials: {acac}",
            ))
        elif acao == "*":
            findings.append(HeaderFinding(
                header="CORS",
                status="misconfigured",
                severity="medium",
                detail="CORS allows any origin (*). While credentials aren't included, response data is readable by any website.",
                recommendation="Restrict Access-Control-Allow-Origin to specific trusted origins",
                owasp_ref="CWE-942",
                current_value=f"Allow-Origin: {acao}",
            ))

        # ── 12. X-Permitted-Cross-Domain-Policies ──
        xpcdp = headers.get("x-permitted-cross-domain-policies", "")
        if not xpcdp:
            findings.append(HeaderFinding(
                header="X-Permitted-Cross-Domain-Policies",
                status="missing",
                severity="info",
                detail="X-Permitted-Cross-Domain-Policies not set. Flash/Acrobat cross-domain policy files may be honored.",
                recommendation="Add: X-Permitted-Cross-Domain-Policies: none",
                owasp_ref="CWE-16",
            ))

        # ── 13. Cross-Origin headers (COEP/COOP/CORP) ──
        coep = headers.get("cross-origin-embedder-policy", "")
        coop = headers.get("cross-origin-opener-policy", "")
        corp = headers.get("cross-origin-resource-policy", "")
        if not coop:
            findings.append(HeaderFinding(
                header="Cross-Origin-Opener-Policy",
                status="missing",
                severity="low",
                detail="COOP not set. Window can be referenced by cross-origin documents, enabling Spectre-type side-channel attacks.",
                recommendation="Add: Cross-Origin-Opener-Policy: same-origin",
                owasp_ref="CWE-16",
            ))

        # Convert all findings to Candidate objects
        if not findings:
            return []

        candidates = []
        for hf in findings:
            if hf.severity == "info":
                continue  # Skip informational for scanner output
            candidates.append(self._make_candidate(
                recipe=recipe,
                endpoint=target,
                method="GET",
                evidence={
                    "technique": "header-check",
                    "header": hf.header,
                    "status": hf.status,
                    "detail": hf.detail,
                    "recommendation": hf.recommendation,
                    "owasp_ref": hf.owasp_ref,
                    "current_value": hf.current_value,
                },
                confidence="high" if hf.severity in ("critical", "high") else "medium",
                request_data={
                    "param": "N/A",
                    "payload": "N/A",
                    "technique": "security-header-check",
                    "id_location": "header",
                },
                response_data={
                    "status": resp.status_code,
                    "body_snippet": f"{hf.header}: {hf.current_value}" if hf.current_value else f"{hf.header}: (missing)",
                },
            ))

        return candidates

    async def full_audit(self, target: str) -> HeaderScanResult:
        """Run a full header audit and return structured result (for direct use)."""
        result = HeaderScanResult(url=target)
        try:
            resp = await self.client.get(target, session=self.session, follow_redirects=True)
            result.raw_headers = dict(resp.headers)
        except Exception as e:
            logger.warning("Header audit failed: %s", e)
            return result

        # Use a dummy recipe for _detect
        from ..recipes.schema import Recipe
        dummy = Recipe(
            id="header-audit",
            applies_to=("web",),
            tech_signals=("any",),
            preconditions=("target reachable",),
            detect=({"step": "check security headers"},),
            signal="missing or misconfigured security header",
            verify="header value confirms misconfiguration",
            severity="medium",
            remediation="Add recommended security headers",
            source="OWASP Secure Headers Project",
        )
        candidates = await self._detect(target, dummy)

        for c in candidates:
            ev = c.evidence
            result.findings.append(HeaderFinding(
                header=ev.get("header", ""),
                status=ev.get("status", ""),
                severity="high" if c.confidence == "high" else "medium",
                detail=ev.get("detail", ""),
                recommendation=ev.get("recommendation", ""),
                owasp_ref=ev.get("owasp_ref", ""),
                current_value=ev.get("current_value", ""),
            ))

        return result
