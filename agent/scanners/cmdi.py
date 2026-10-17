"""OS Command Injection scanner — structured verification chain.

Verification Chain (per param, one at a time):
  Step 1 - CANARY:    Inject a unique canary string via command substitution
                      (e.g., `echo CANARY`) → check if canary appears in response
  Step 2 - MATH:      Inject `expr 39821 + 10234` → check if 50055 appears
                      (rules out the canary being coincidentally in the page)
  Step 3 - TIME:      Inject `sleep 5` / `ping -c 5 127.0.0.1` → measure
                      response time delta (confirms code execution even when
                      output is not reflected)
  Step 4 - BLIND OOB: Only if time fails — attempt DNS canary (optional, not
                      implemented here since it requires OOB infra)

GO/NO-GO logic:
  - CANARY pass + MATH pass → CONFIRMED (high confidence)
  - CANARY pass + MATH fail → medium (might be false positive)
  - CANARY fail + TIME pass → CONFIRMED blind command injection (high)
  - All fail → STOP, not injectable

Separator strategies (try in order):
  - Inline: `; <cmd>`
  - Newline: `\n<cmd>`
  - Pipe: `| <cmd>`
  - Backtick: `` `<cmd>` ``
  - Dollar-paren: `$(<cmd>)`
  - And-chain: `&& <cmd>`
  - Double-pipe: `|| <cmd>`

Rules:
  - One parameter at a time
  - Include sibling fields with default values
  - Encode on WAF block (403 → URL-encode ONCE, then move on)
  - Non-destructive payloads ONLY (echo, expr, sleep, id, whoami)
  - No rm, no wget to attacker infra, no reverse shells
"""
from __future__ import annotations

import logging
import random
import string
import time
from typing import Any
from urllib.parse import quote

from ..http import HttpClient, Session
from ..recipes.schema import Recipe
from .base import Scanner, Candidate

logger = logging.getLogger(__name__)

# ── Payload generation ────────────────────────────────────────


def _random_canary(length: int = 12) -> str:
    """Generate a random canary string unlikely to appear naturally."""
    return "CMDI" + "".join(random.choices(string.ascii_uppercase + string.digits, k=length))


def _random_math() -> tuple[int, int, int]:
    """Generate a random math expression (a + b = result)."""
    a = random.randint(10000, 49999)
    b = random.randint(10000, 49999)
    return a, b, a + b


# ── Separators ────────────────────────────────────────────────

# Each separator has: (prefix, suffix) where the command goes between them.
# The prefix terminates the previous command context and the suffix starts
# ours. We prepend a benign value so the original param has something.
_SEPARATORS = [
    # name, format_string — {cmd} is replaced with the command
    ("semicolon",     "test;{cmd}"),
    ("newline",       "test\n{cmd}"),
    ("pipe",          "test|{cmd}"),
    ("backtick",      "test`{cmd}`"),
    ("dollar_paren",  "test$({cmd})"),
    ("and_chain",     "test&&{cmd}"),
    ("or_chain",      "test||{cmd}"),
]

# Windows-specific separators (tried after Unix ones)
_WIN_SEPARATORS = [
    ("win_and",       "test&{cmd}"),
    ("win_pipe",      "test|{cmd}"),
    ("win_newline",   "test\n{cmd}"),
]

# ── Commands ──────────────────────────────────────────────────

# Step 1: Canary echo commands (Unix and Windows)
def _canary_commands(canary: str) -> list[tuple[str, str]]:
    """Return (os_type, command) pairs for echoing the canary."""
    return [
        ("unix",    f"echo {canary}"),
        ("unix",    f"echo '{canary}'"),
        ("windows", f"echo {canary}"),
    ]


# Step 2: Math commands
def _math_commands(a: int, b: int) -> list[tuple[str, str]]:
    """Return (os_type, command) pairs for math verification."""
    return [
        ("unix",    f"expr {a} + {b}"),
        ("unix",    f"echo $(({a}+{b}))"),
        ("windows", f"set /a {a}+{b}"),
    ]


# Step 3: Time delay commands
_TIME_COMMANDS_UNIX = [
    "sleep 5",
    "ping -c 5 127.0.0.1",
]

_TIME_COMMANDS_WIN = [
    "ping -n 6 127.0.0.1",       # ~5 seconds on Windows
    "timeout /t 5 /nobreak",
]

# Time-based detection threshold (seconds)
_TIME_THRESHOLD = 4.0


# ── Error / output signatures ────────────────────────────────

# If these appear in the response after injection (but NOT in baseline),
# they hint at command execution or shell error exposure.
_SHELL_ERROR_SIGS = [
    "sh:",
    "bash:",
    "/bin/sh:",
    "/bin/bash:",
    "command not found",
    "not recognized as an internal or external command",
    "cannot execute",
    "permission denied",
    "syntax error near unexpected token",
    "no such file or directory",
    "is not recognized",
    # PowerShell
    "is not recognized as the name of a cmdlet",
    "the term",
]

# Output markers from commands like `id` or `whoami`
_EXEC_MARKERS = [
    "uid=",           # id command output: uid=0(root)
    "gid=",
    "groups=",
]


class CmdiScanner(Scanner):
    """Detects OS Command Injection using a structured verification chain.

    For each parameter (one at a time):
    1. CANARY:  inject `echo RANDOM_STRING` via each separator → check reflection
    2. MATH:    inject `expr a + b` → check if sum appears in response
    3. TIME:    inject `sleep 5` → measure response time delta

    Special handling:
    - WAF: URL-encode on 403, try once more
    - Both Unix and Windows command variants
    - Full sibling fields support
    """

    vuln_classes = ["cmdi", "command-injection", "os-command-injection"]

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
                vuln_classes = point.get("vuln_classes", [])
                if not any(vc in vuln_classes for vc in self.vuln_classes):
                    continue  # Skip params not flagged for command injection

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

        Chain: CANARY → MATH → TIME
        GO/NO-GO at each step.
        """
        log = {"param": param, "method": method, "location": id_location, "steps": []}

        # ── Step 0: Get baseline response ──
        try:
            baseline = await self._send(
                target, param, "normalvalue123", method, id_location,
                siblings=siblings,
            )
            baseline_status = baseline.status_code
            baseline_body = baseline.text[:5000].lower()
            baseline_len = len(baseline.text)
        except Exception as e:
            logger.debug("Baseline request failed for %s/%s: %s", target, param, e)
            return None

        # ── Step 1: CANARY ──
        canary = _random_canary()
        canary_result = await self._step_canary(
            target, param, method, id_location, canary,
            baseline_status, baseline_body,
            siblings=siblings,
        )
        log["steps"].append({"step": "canary", "result": canary_result})

        if canary_result["success"]:
            # Canary reflected! Now verify it's real with MATH.
            # ── Step 2: MATH ──
            math_result = await self._step_math(
                target, param, method, id_location,
                canary_result["separator"],
                canary_result.get("os_type", "unix"),
                baseline_body,
                siblings=siblings,
            )
            log["steps"].append({"step": "math", "result": math_result})

            if math_result["success"]:
                # CANARY + MATH confirmed → CONFIRMED command injection
                return self._make_candidate(
                    recipe=recipe,
                    endpoint=target,
                    method=method,
                    evidence={
                        "technique": "output-based",
                        "chain": log,
                        "os_type": canary_result.get("os_type"),
                        "separator": canary_result["separator"],
                        "canary": canary,
                        "math_expression": math_result.get("expression"),
                        "math_result": math_result.get("expected"),
                    },
                    confidence="high",
                    request_data={
                        "param": param,
                        "canary_payload": canary_result["payload"],
                        "math_payload": math_result.get("payload", ""),
                        "separator": canary_result["separator"],
                        "id_location": id_location,
                        "technique": "output-based",
                        "sibling_fields": siblings or {},
                    },
                    response_data={
                        "canary_status": canary_result.get("status"),
                        "math_status": math_result.get("status"),
                    },
                )
            else:
                # Canary passed but math failed — might be a coincidence
                # Don't report to avoid false positives
                logger.debug(
                    "CANARY passed but MATH failed for %s/%s — "
                    "possible false positive, skipping", target, param
                )

        # ── Step 3: TIME (blind detection) ──
        # If canary didn't work, try time-based (blind command injection)
        time_result = await self._step_time(
            target, param, method, id_location,
            baseline_body, siblings=siblings,
        )
        log["steps"].append({"step": "time", "result": time_result})

        if time_result["success"]:
            # Verify time-based with a second measurement to reduce false positives
            verify_result = await self._step_time_verify(
                target, param, method, id_location,
                time_result["separator"],
                time_result["command"],
                siblings=siblings,
            )
            log["steps"].append({"step": "time_verify", "result": verify_result})

            if verify_result["success"]:
                return self._make_candidate(
                    recipe=recipe,
                    endpoint=target,
                    method=method,
                    evidence={
                        "technique": "time-based-blind",
                        "chain": log,
                        "separator": time_result["separator"],
                        "command": time_result["command"],
                        "elapsed": time_result.get("elapsed"),
                        "baseline_time": time_result.get("baseline_time"),
                        "verify_elapsed": verify_result.get("elapsed"),
                    },
                    confidence="high",
                    request_data={
                        "param": param,
                        "payload": time_result["payload"],
                        "separator": time_result["separator"],
                        "id_location": id_location,
                        "technique": "time-based-blind",
                        "sibling_fields": siblings or {},
                    },
                    response_data={
                        "status": time_result.get("status"),
                        "elapsed": time_result.get("elapsed"),
                    },
                )

        # ── Step 4: Shell error signature check ──
        # If we saw shell errors during canary step, that's a hint but not
        # enough on its own for zero-FP. Only report if we also have canary.
        if canary_result.get("shell_error_found"):
            # Shell error without canary or time = weak signal → skip
            logger.debug(
                "Shell error detected for %s/%s but no execution confirmed — "
                "not reporting to avoid false positive", target, param
            )

        return None

    # ── Chain steps ──────────────────────────────────────────────

    async def _step_canary(
        self, target: str, param: str, method: str, id_location: str,
        canary: str, baseline_status: int, baseline_body: str,
        *, siblings: dict[str, str] | None = None,
    ) -> dict:
        """Step 1: CANARY — inject echo command, check for reflection.

        Success: canary string appears in response body but NOT in baseline.
        """
        canary_lower = canary.lower()

        # Make sure canary isn't already in the page
        if canary_lower in baseline_body:
            # Extremely unlikely with random canary, but regenerate
            canary = _random_canary()
            canary_lower = canary.lower()

        shell_error_found = False

        for sep_name, sep_fmt in _SEPARATORS + _WIN_SEPARATORS:
            for os_type, cmd in _canary_commands(canary):
                payload = sep_fmt.format(cmd=cmd)

                try:
                    resp = await self._send(
                        target, param, payload, method, id_location,
                        siblings=siblings,
                    )
                    status = resp.status_code
                    body = resp.text[:5000].lower()

                    # WAF check → try URL-encoded once
                    if status == 403:
                        encoded = quote(payload, safe="")
                        resp = await self._send(
                            target, param, encoded, method, id_location,
                            siblings=siblings,
                        )
                        status = resp.status_code
                        body = resp.text[:5000].lower()
                        if status == 403:
                            continue

                    # Check for shell errors (evidence of reaching shell)
                    for sig in _SHELL_ERROR_SIGS:
                        if sig in body and sig not in baseline_body:
                            shell_error_found = True
                            break

                    # Check for canary in response
                    if canary_lower in body:
                        return {
                            "success": True,
                            "payload": payload,
                            "separator": sep_name,
                            "os_type": os_type,
                            "status": status,
                            "shell_error_found": shell_error_found,
                        }

                except Exception as e:
                    logger.debug("CANARY error for %s/%s sep=%s: %s",
                                 target, param, sep_name, e)
                    continue

        return {"success": False, "shell_error_found": shell_error_found}

    async def _step_math(
        self, target: str, param: str, method: str, id_location: str,
        separator: str, os_type: str, baseline_body: str,
        *, siblings: dict[str, str] | None = None,
    ) -> dict:
        """Step 2: MATH — inject arithmetic expression, check for result.

        Success: computed result appears in response but NOT in baseline.
        Uses the same separator that worked for the canary step.
        """
        a, b, expected = _random_math()

        # Find the separator format string
        sep_fmt = None
        for name, fmt in _SEPARATORS + _WIN_SEPARATORS:
            if name == separator:
                sep_fmt = fmt
                break
        if not sep_fmt:
            return {"success": False, "reason": "separator_not_found"}

        expected_str = str(expected)

        # Skip if the expected result already appears in baseline (unlikely)
        if expected_str in baseline_body:
            a, b, expected = _random_math()
            expected_str = str(expected)
            if expected_str in baseline_body:
                return {"success": False, "reason": "math_result_in_baseline"}

        for os_t, cmd in _math_commands(a, b):
            # Use same OS type that worked for canary
            if os_type == "windows" and os_t != "windows":
                continue
            if os_type == "unix" and os_t == "windows":
                continue

            payload = sep_fmt.format(cmd=cmd)

            try:
                resp = await self._send(
                    target, param, payload, method, id_location,
                    siblings=siblings,
                )
                body = resp.text[:5000]
                status = resp.status_code

                # WAF check
                if status == 403:
                    encoded = quote(payload, safe="")
                    resp = await self._send(
                        target, param, encoded, method, id_location,
                        siblings=siblings,
                    )
                    body = resp.text[:5000]
                    status = resp.status_code
                    if status == 403:
                        continue

                if expected_str in body:
                    return {
                        "success": True,
                        "payload": payload,
                        "expression": f"{a} + {b}",
                        "expected": expected_str,
                        "status": status,
                    }

            except Exception as e:
                logger.debug("MATH error for %s/%s: %s", target, param, e)
                continue

        return {"success": False}

    async def _step_time(
        self, target: str, param: str, method: str, id_location: str,
        baseline_body: str, *, siblings: dict[str, str] | None = None,
    ) -> dict:
        """Step 3: TIME — inject sleep/ping, measure response time.

        Success: response takes >= threshold seconds longer than baseline.
        """
        # Get baseline timing
        try:
            t0 = time.monotonic()
            await self._send(
                target, param, "normalvalue123", method, id_location,
                siblings=siblings,
            )
            baseline_time = time.monotonic() - t0
        except Exception:
            baseline_time = 1.0

        all_commands = (
            [(cmd, "unix") for cmd in _TIME_COMMANDS_UNIX] +
            [(cmd, "windows") for cmd in _TIME_COMMANDS_WIN]
        )

        for sep_name, sep_fmt in _SEPARATORS + _WIN_SEPARATORS:
            for cmd, os_type in all_commands:
                payload = sep_fmt.format(cmd=cmd)

                try:
                    t0 = time.monotonic()
                    resp = await self._send(
                        target, param, payload, method, id_location,
                        siblings=siblings,
                    )
                    elapsed = time.monotonic() - t0
                    status = resp.status_code

                    # WAF check
                    if status == 403:
                        t0 = time.monotonic()
                        resp = await self._send(
                            target, param, quote(payload, safe=""),
                            method, id_location, siblings=siblings,
                        )
                        elapsed = time.monotonic() - t0
                        status = resp.status_code
                        if status == 403:
                            continue

                    delta = elapsed - baseline_time
                    if delta >= _TIME_THRESHOLD:
                        return {
                            "success": True,
                            "payload": payload,
                            "separator": sep_name,
                            "command": cmd,
                            "os_type": os_type,
                            "elapsed": round(elapsed, 2),
                            "baseline_time": round(baseline_time, 2),
                            "delta": round(delta, 2),
                            "status": status,
                        }

                except Exception as e:
                    logger.debug("TIME error for %s/%s sep=%s: %s",
                                 target, param, sep_name, e)
                    continue

        return {"success": False}

    async def _step_time_verify(
        self, target: str, param: str, method: str, id_location: str,
        separator: str, command: str,
        *, siblings: dict[str, str] | None = None,
    ) -> dict:
        """Verify time-based finding with a second measurement.

        This reduces false positives from network jitter. We re-send the
        same payload and check that the delay is consistent. Then we send
        a non-sleeping payload with the same separator and check that it's
        fast — confirming the delay comes from our injected command.
        """
        # Find separator format
        sep_fmt = None
        for name, fmt in _SEPARATORS + _WIN_SEPARATORS:
            if name == separator:
                sep_fmt = fmt
                break
        if not sep_fmt:
            return {"success": False, "reason": "separator_not_found"}

        # Re-measure with the same payload
        payload = sep_fmt.format(cmd=command)
        try:
            t0 = time.monotonic()
            resp = await self._send(
                target, param, payload, method, id_location,
                siblings=siblings,
            )
            elapsed = time.monotonic() - t0

            if elapsed < _TIME_THRESHOLD:
                # First time might have been jitter
                return {"success": False, "reason": "not_reproducible",
                        "elapsed": round(elapsed, 2)}
        except Exception as e:
            return {"success": False, "error": str(e)}

        # Control: send with a benign command via same separator
        control_payload = sep_fmt.format(cmd="echo 1")
        try:
            t0 = time.monotonic()
            await self._send(
                target, param, control_payload, method, id_location,
                siblings=siblings,
            )
            control_elapsed = time.monotonic() - t0
        except Exception:
            control_elapsed = 0.5

        # Confirm: sleep payload is slow, control is fast
        if elapsed >= _TIME_THRESHOLD and control_elapsed < _TIME_THRESHOLD:
            return {
                "success": True,
                "elapsed": round(elapsed, 2),
                "control_elapsed": round(control_elapsed, 2),
            }

        return {
            "success": False,
            "reason": "control_also_slow",
            "elapsed": round(elapsed, 2),
            "control_elapsed": round(control_elapsed, 2),
        }

    # ── HTTP helper ──────────────────────────────────────────────

    async def _send(self, target: str, param: str, value: str,
                    method: str, id_location: str,
                    *, siblings: dict[str, str] | None = None):
        """Send a request with the payload injected at the right location."""
        if id_location == "query":
            params = dict(siblings) if siblings else {}
            params[param] = value
            return await self.client.request(
                method, target, session=self.session,
                params=params,
            )
        elif id_location == "body":
            data = dict(siblings) if siblings else {}
            data[param] = value
            return await self.client.post(
                target, session=self.session,
                data=data,
            )
        elif id_location == "path":
            url = target.rstrip("/") + f"/{value}"
            return await self.client.request(method, url, session=self.session)
        else:
            raise ValueError(f"Unknown id_location: {id_location}")
