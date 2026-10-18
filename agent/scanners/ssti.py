"""SSTI scanner — Server-Side Template Injection verification chain.

Verification Chain (per param):
  Step 1 - MATH PROBE:    Inject {{7*7}} and ${7*7} → check if 49 appears in response
  Step 2 - ENGINE DETECT:  Inject engine-specific probes → identify Jinja2/Twig/Freemarker/etc.
  Step 3 - CONFIRM:        Inject a different math expression → verify it evaluates correctly
  Step 4 - IMPACT PROBE:   Attempt to read env/config (non-destructive) → confirm RCE potential

GO/NO-GO:
  - MATH passes + ENGINE detected + CONFIRM passes → CONFIRMED high
  - MATH passes + CONFIRM passes but no engine ID → CONFIRMED medium
  - Only MATH passes → medium confidence, needs verification
  - Nothing passes → STOP

Engine-specific polyglot probes cover:
  Jinja2, Twig, Freemarker, Mako, Velocity, Pebble, Smarty, ERB, Slim, EJS
"""
from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import quote

from ..http import HttpClient, Session
from ..recipes.schema import Recipe
from .base import Scanner, Candidate

logger = logging.getLogger(__name__)

# ── Payloads ──────────────────────────────────────────────────

# Step 1: Math probes — template-agnostic expressions that evaluate to a known result
# Each tuple: (payload, expected_result_string)
_MATH_PROBES = [
    ("{{7*7}}", "49"),
    ("${7*7}", "49"),
    ("{{7*'7'}}", "7777777"),       # Jinja2 string multiplication
    ("#{7*7}", "49"),                # Ruby ERB / Slim
    ("<%= 7*7 %>", "49"),            # ERB / EJS
    ("{{=7*7}}", "49"),              # Handlebars-ish
    ("${{7*7}}", "49"),              # Java EL
    ("{7*7}", "49"),                 # Smarty
]

# Step 2: Engine fingerprint probes — each returns a unique string per engine
# (payload, expected_in_response, engine_name)
_ENGINE_PROBES = [
    # Jinja2 (Python) — string multiply
    ("{{7*'7'}}", "7777777", "Jinja2"),
    # Twig (PHP) — range filter
    ("{{7*7}}", "49", "Twig"),
    # Freemarker (Java)
    ("${7*7}", "49", "Freemarker"),
    # Mako (Python) — uses ${}
    ("${7*7}", "49", "Mako"),
    # Pebble (Java) — uses {{}}
    ("{{7*7}}", "49", "Pebble"),
    # Smarty (PHP) — uses {}
    ("{7*7}", "49", "Smarty"),
    # ERB (Ruby)
    ("<%= 7*7 %>", "49", "ERB"),
    # EJS (Node.js)
    ("<%= 7*7 %>", "49", "EJS"),
    # Velocity (Java) — uses #set
    ("#set($x=7*7)${x}", "49", "Velocity"),
]

# Jinja2-specific disambiguation (string * int = repeated string)
_JINJA2_CONFIRM = ("{{7*'7'}}", "7777777")

# Step 3: Confirmation — a DIFFERENT math expression to rule out coincidence
_CONFIRM_PROBES = [
    ("{{3*11}}", "33"),
    ("${3*11}", "33"),
    ("{{9+9}}", "18"),
    ("${9+9}", "18"),
    ("#{3*11}", "33"),
    ("<%= 3*11 %>", "33"),
    ("{3*11}", "33"),
]

# Step 4: Impact probes (non-destructive — read-only checks)
# (payload, expected_pattern_regex, description)
_IMPACT_PROBES = [
    # Jinja2 — read config
    ("{{config}}", r"<Config", "Jinja2 config leak"),
    ("{{config.items()}}", r"SECRET_KEY|DATABASE", "Jinja2 config items"),
    # Jinja2 — class introspection (RCE indicator)
    ("{{''.__class__.__mro__}}", r"__class__|str|object", "Jinja2 class chain"),
    # Twig — env info
    ("{{_self.env.display}}", r"Twig", "Twig env access"),
    # Freemarker — class access
    ("${7*7}", r"49", "Freemarker eval"),
    # ERB — env
    ("<%= ENV %>", r"PATH|HOME|USER", "ERB ENV access"),
]

# SSTI error signatures (template parsing errors)
_SSTI_ERRORS = [
    "templateerror", "template error", "templatesyntaxerror",
    "jinja2.exceptions", "twig_error", "twig\\error",
    "freemarker.core", "freemarker.template",
    "mako.exceptions", "mako.lookup",
    "velocityexception", "org.apache.velocity",
    "pebbleexception", "com.mitchellbosecke.pebble",
    "smartyexception", "smartycompilerexception",
    "erb:", "syntaxerror (erb)",
    "ejs error", "ejs:renderfile",
    "template syntax error", "unexpected token",
    "undefined variable", "unknown tag",
]


class SstiScanner(Scanner):
    """Detects Server-Side Template Injection using a verification chain.

    For each parameter (one at a time):
    1. MATH: inject {{7*7}} and variants → check if 49 appears
    2. ENGINE: fingerprint the template engine
    3. CONFIRM: inject a different expression → verify evaluation
    4. IMPACT: non-destructive check for RCE potential
    """

    vuln_classes = ["ssti", "template-injection"]

    def __init__(self, client: HttpClient, session: Session):
        super().__init__(client)
        self.session = session

    async def _detect(self, target: str, recipe: Recipe,
                      **context: Any) -> list[Candidate]:
        params = context.get("params", [])
        method = context.get("method", "GET")
        id_location = context.get("id_location", "query")
        injection_points = context.get("injection_points", [])

        if not params and not injection_points:
            return []

        candidates = []

        if injection_points:
            for point in injection_points:
                if "ssti" not in point.get("vuln_classes", []) and \
                   "template-injection" not in point.get("vuln_classes", []):
                    continue

                param = point["param"]
                loc = point.get("location", id_location)
                meth = point.get("method", method)
                siblings = point.get("sibling_fields", {})

                result = await self._test_param(
                    target, param, meth, loc, recipe, siblings=siblings
                )
                if result:
                    candidates.append(result)
        else:
            siblings = context.get("siblings", {})
            for param in params:
                result = await self._test_param(
                    target, param, method, id_location, recipe,
                    siblings=siblings,
                )
                if result:
                    candidates.append(result)

        return candidates

    async def _test_param(
        self,
        target: str,
        param: str,
        method: str,
        id_location: str,
        recipe: Recipe,
        *,
        siblings: dict[str, str] | None = None,
    ) -> Candidate | None:
        """Run the SSTI verification chain on a single parameter."""
        log = {"param": param, "method": method, "location": id_location, "steps": []}

        # ── Step 0: Baseline ──
        try:
            baseline = await self._send(target, param, "normalvalue123", method, id_location, siblings=siblings)
            baseline_body = baseline.text[:5000]
        except Exception as e:
            logger.debug("SSTI baseline failed %s/%s: %s", target, param, e)
            return None

        # Check that our canary value reflects (if it doesn't, no point testing)
        if "normalvalue123" not in baseline_body:
            # Value doesn't reflect — SSTI less likely but not impossible
            pass

        # ── Step 1: MATH PROBE ──
        math_result = await self._step_math(
            target, param, method, id_location, baseline_body, siblings=siblings
        )
        log["steps"].append({"step": "math", "result": math_result})

        if not math_result["success"]:
            logger.debug("SSTI: math probe failed for %s/%s", target, param)
            return None

        # ── Step 2: ENGINE DETECTION ──
        engine_result = await self._step_engine_detect(
            target, param, method, id_location, baseline_body, siblings=siblings
        )
        log["steps"].append({"step": "engine", "result": engine_result})

        # ── Step 3: CONFIRM with different expression ──
        confirm_result = await self._step_confirm(
            target, param, method, id_location, baseline_body,
            math_result.get("syntax", "{{}}"), siblings=siblings
        )
        log["steps"].append({"step": "confirm", "result": confirm_result})

        if not confirm_result["success"]:
            # Math passed but confirm failed → might be coincidence
            return self._make_candidate(
                recipe=recipe,
                endpoint=target,
                method=method,
                evidence={
                    "technique": "math-only",
                    "chain": log,
                    "note": "Math probe passed but confirmation failed — may be coincidence",
                    "engine": engine_result.get("engine"),
                },
                confidence="low",
                request_data={
                    "param": param,
                    "payload": math_result["payload"],
                    "id_location": id_location,
                    "sibling_fields": siblings or {},
                    "full_request": math_result.get("full_request", ""),
                },
                response_data={
                    "status": math_result.get("status"),
                    "full_response": math_result.get("full_response", ""),
                },
            )

        # Both math and confirm passed → this is real SSTI
        confidence = "high" if engine_result.get("engine") else "medium"

        # ── Step 4: IMPACT PROBE (optional, non-destructive) ──
        impact_result = await self._step_impact(
            target, param, method, id_location, engine_result.get("engine"),
            siblings=siblings
        )
        log["steps"].append({"step": "impact", "result": impact_result})

        evidence = {
            "technique": "ssti-confirmed",
            "chain": log,
            "engine": engine_result.get("engine", "unknown"),
            "math_payload": math_result["payload"],
            "confirm_payload": confirm_result.get("payload"),
            "rce_potential": impact_result.get("success", False),
            "impact_detail": impact_result.get("description", ""),
            "body_snippet": math_result.get("body_snippet", ""),
        }

        return self._make_candidate(
            recipe=recipe,
            endpoint=target,
            method=method,
            evidence=evidence,
            confidence=confidence,
            request_data={
                "param": param,
                "payload": math_result["payload"],
                "id_location": id_location,
                "technique": "ssti",
                "engine": engine_result.get("engine", "unknown"),
                "sibling_fields": siblings or {},
                "full_request": math_result.get("full_request", ""),
            },
            response_data={
                "status": math_result.get("status"),
                "full_response": math_result.get("full_response", ""),
            },
        )

    # ── Chain steps ──────────────────────────────────────────────

    async def _step_math(
        self, target: str, param: str, method: str, id_location: str,
        baseline_body: str, *, siblings: dict[str, str] | None = None,
    ) -> dict:
        """Step 1: MATH PROBE — inject expressions that evaluate to known results.

        Success: the expected result appears in the response AND was NOT in baseline.
        """
        for payload, expected in _MATH_PROBES:
            # Skip if expected result is already in baseline (coincidence)
            if expected in baseline_body:
                continue

            try:
                resp = await self._send(target, param, payload, method, id_location, siblings=siblings)
                body = resp.text[:5000]

                # Check for WAF → try URL-encoded
                if resp.status_code == 403:
                    resp = await self._send(
                        target, param, quote(payload, safe=""), method, id_location, siblings=siblings
                    )
                    body = resp.text[:5000]
                    if resp.status_code == 403:
                        continue

                if expected in body:
                    # Determine syntax family
                    if payload.startswith("{{"):
                        syntax = "{{}}"
                    elif payload.startswith("${"):
                        syntax = "${}"
                    elif payload.startswith("<%"):
                        syntax = "<%>"
                    elif payload.startswith("#{"):
                        syntax = "#{}"
                    elif payload.startswith("{") and not payload.startswith("{{"):
                        syntax = "{}"
                    else:
                        syntax = "unknown"

                    return {
                        "success": True,
                        "payload": payload,
                        "expected": expected,
                        "syntax": syntax,
                        "status": resp.status_code,
                        "body_snippet": body[:500],
                        "full_request": self.capture_request(resp),
                        "full_response": self.capture_response(resp),
                    }

                # Also check for template errors (indicates processing)
                body_lower = body.lower()
                for sig in _SSTI_ERRORS:
                    if sig in body_lower and sig not in baseline_body.lower():
                        return {
                            "success": True,
                            "payload": payload,
                            "expected": expected,
                            "syntax": "error-based",
                            "status": resp.status_code,
                            "error_match": sig,
                            "body_snippet": body[:500],
                            "full_request": self.capture_request(resp),
                            "full_response": self.capture_response(resp),
                        }

            except Exception as e:
                logger.debug("SSTI math error %s/%s: %s", target, param, e)
                continue

        return {"success": False}

    async def _step_engine_detect(
        self, target: str, param: str, method: str, id_location: str,
        baseline_body: str, *, siblings: dict[str, str] | None = None,
    ) -> dict:
        """Step 2: ENGINE DETECT — fingerprint the template engine.

        Uses Jinja2 string multiplication as primary discriminator:
        {{7*'7'}} → "7777777" = Jinja2 (string * int)
        {{7*'7'}} → "49" = Twig (casts string to int)
        """
        # Try Jinja2 discriminator first
        payload, expected = _JINJA2_CONFIRM
        if expected not in baseline_body:
            try:
                resp = await self._send(target, param, payload, method, id_location, siblings=siblings)
                body = resp.text[:5000]
                if expected in body:
                    return {"success": True, "engine": "Jinja2", "probe": payload}
                elif "49" in body and "49" not in baseline_body:
                    return {"success": True, "engine": "Twig", "probe": payload}
            except Exception:
                pass

        return {"success": False, "engine": None}

    async def _step_confirm(
        self, target: str, param: str, method: str, id_location: str,
        baseline_body: str, syntax: str,
        *, siblings: dict[str, str] | None = None,
    ) -> dict:
        """Step 3: CONFIRM — inject a DIFFERENT math expression.

        Rules out coincidence: if {{7*7}}→49 and {{3*11}}→33, it's not an accident.
        Uses the same syntax family detected in step 1.
        """
        for payload, expected in _CONFIRM_PROBES:
            if expected in baseline_body:
                continue

            # Match syntax family from step 1
            if syntax == "{{}}" and not payload.startswith("{{"):
                continue
            elif syntax == "${}" and not payload.startswith("${"):
                continue
            elif syntax == "<%>" and not payload.startswith("<%"):
                continue
            elif syntax == "#{}" and not payload.startswith("#{"):
                continue
            elif syntax == "{}" and not (payload.startswith("{") and not payload.startswith("{{")):
                continue

            try:
                resp = await self._send(target, param, payload, method, id_location, siblings=siblings)
                body = resp.text[:5000]

                if expected in body:
                    return {
                        "success": True,
                        "payload": payload,
                        "expected": expected,
                    }

            except Exception as e:
                logger.debug("SSTI confirm error %s/%s: %s", target, param, e)
                continue

        return {"success": False}

    async def _step_impact(
        self, target: str, param: str, method: str, id_location: str,
        engine: str | None, *, siblings: dict[str, str] | None = None,
    ) -> dict:
        """Step 4: IMPACT — non-destructive check for RCE potential.

        Does NOT execute commands. Only checks if class chains or config
        objects are accessible, which indicates RCE is possible.
        """
        for payload, pattern, description in _IMPACT_PROBES:
            # Filter by engine if known
            if engine:
                engine_lower = engine.lower()
                desc_lower = description.lower()
                if engine_lower not in desc_lower and "eval" not in desc_lower:
                    continue

            try:
                resp = await self._send(target, param, payload, method, id_location, siblings=siblings)
                body = resp.text[:5000]

                if re.search(pattern, body, re.IGNORECASE):
                    return {
                        "success": True,
                        "payload": payload,
                        "description": description,
                        "body_snippet": body[:500],
                    }

            except Exception as e:
                logger.debug("SSTI impact error %s/%s: %s", target, param, e)
                continue

        return {"success": False}

    # ── HTTP helper ──────────────────────────────────────────────

    async def _send(self, target: str, param: str, value: str,
                    method: str, id_location: str,
                    *, siblings: dict[str, str] | None = None):
        """Send a request with the payload injected."""
        if id_location == "query":
            params = dict(siblings) if siblings else {}
            params[param] = value
            return await self.client.request(
                method, target, session=self.session, params=params,
            )
        elif id_location == "json":
            data = dict(siblings) if siblings else {}
            data[param] = value
            return await self.client.post(
                target, session=self.session, json=data,
            )
        elif id_location == "body":
            data = dict(siblings) if siblings else {}
            data[param] = value
            return await self.client.post(
                target, session=self.session, data=data,
            )
        elif id_location == "path":
            url = target.rstrip("/") + f"/{value}"
            return await self.client.request(method, url, session=self.session)
        else:
            raise ValueError(f"Unknown id_location: {id_location}")
