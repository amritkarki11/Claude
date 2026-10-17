"""SQLi verifier — replays the verification chain to confirm findings.

For each technique:
  - error-based: re-runs BREAK+FIX chain and checks consistency
  - redirect-based: re-sends true/false pair and checks redirect differs
  - error-based-partial: replays BREAK only (FIX already failed in scan)
  - boolean-only: replays true/false comparison
  - time-based: replays sleep injection and checks timing

Follows the same GO/NO-GO logic as the scanner.
"""
from __future__ import annotations

import logging
import time
from typing import Any
from urllib.parse import quote

from ..http import HttpClient, Session
from ..scanners.base import Candidate
from .base import Verifier, Verdict, VerifyResult

logger = logging.getLogger(__name__)

# DB error signatures (same as scanner)
_DB_ERRORS = [
    "sql syntax", "mysql", "mariadb", "postgresql", "sqlite",
    "ora-", "oracle", "microsoft sql", "mssql", "unclosed quotation",
    "quoted string not properly terminated", "syntax error",
    "unexpected end of sql", "sqlexception", "jdbc", "odbc",
    "you have an error in your sql",
    "warning: mysql", "valid mysql result",
    "pg_query", "pg_exec", "unterminated quoted string",
]

_FIX_MAP = {
    "'": "''",
    "\"": "\"\"",
    "' OR '": "'' OR ''",
    "1'": "1''",
    "1\"": "1\"\"",
}

_TIME_THRESHOLD = 4.0


class SqliVerifier(Verifier):
    """Deterministic SQLi verification via chain replay."""

    def __init__(self, client: HttpClient, session: Session):
        super().__init__(client)
        self.session = session

    async def _verify(self, candidate: Candidate, replays: int,
                      **context: Any) -> VerifyResult:
        req = candidate.request_data
        technique = req.get("technique", "error-based")

        if technique == "error-based":
            return await self._verify_error_chain(candidate, replays)
        elif technique == "redirect-based":
            return await self._verify_redirect(candidate, replays)
        elif technique == "error-based-partial":
            return await self._verify_error_partial(candidate, replays)
        elif technique == "auth-bypass":
            return await self._verify_auth_bypass(candidate, replays)
        elif technique == "boolean-blind":
            return await self._verify_boolean_blind(candidate, replays)
        elif technique == "time-blind":
            return await self._verify_time_blind(candidate, replays)
        else:
            return self._result(
                candidate=candidate,
                verdict=Verdict.NEEDS_HUMAN,
                replays=0,
                evidence={"reason": f"Unknown technique: {technique}"},
                reason=f"Cannot verify technique '{technique}' automatically",
            )

    async def _verify_error_chain(self, candidate: Candidate, replays: int) -> VerifyResult:
        """Replay the full BREAK+FIX chain for error-based SQLi.

        For each replay:
        1. Send BREAK payload → expect DB error / 500
        2. Send FIX payload → expect normal response restored
        Both must pass for the replay to count as success.
        """
        req = candidate.request_data
        param = req.get("param", "id")
        break_payload = req.get("payload", "'")
        fix_payload = req.get("fix_payload", _FIX_MAP.get(break_payload, "''"))
        id_location = req.get("id_location", "query")
        method = candidate.method
        expected_error = candidate.response_data.get("error_match", "")
        siblings = req.get("sibling_fields") or None

        successes = 0
        responses = []

        # Get baseline for FIX comparison
        try:
            baseline = await self._send(
                candidate.endpoint, param, "normalvalue123", method, id_location,
                siblings=siblings,
            )
            baseline_status = baseline.status_code
            baseline_body = baseline.text[:3000].lower()
        except Exception:
            baseline_status = 200
            baseline_body = ""

        for i in range(replays):
            try:
                # BREAK step
                break_resp = await self._send(
                    candidate.endpoint, param, break_payload, method, id_location,
                    siblings=siblings,
                )
                break_body = break_resp.text[:3000].lower()
                break_status = break_resp.status_code

                break_ok = False
                if expected_error and expected_error != "status_500":
                    break_ok = expected_error.lower() in break_body
                elif expected_error == "status_500":
                    break_ok = break_status == 500
                else:
                    break_ok = any(sig in break_body for sig in _DB_ERRORS)

                # FIX step
                fix_resp = await self._send(
                    candidate.endpoint, param, fix_payload, method, id_location,
                    siblings=siblings,
                )
                fix_body = fix_resp.text[:3000].lower()
                fix_status = fix_resp.status_code

                fix_ok = (
                    (fix_status == baseline_status or
                     (200 <= fix_status < 300 and 200 <= baseline_status < 300))
                    and not any(sig in fix_body for sig in _DB_ERRORS)
                )

                replay_ok = break_ok and fix_ok
                responses.append({
                    "replay": i + 1,
                    "break_status": break_status,
                    "break_error_found": break_ok,
                    "fix_status": fix_status,
                    "fix_restored": fix_ok,
                    "chain_passed": replay_ok,
                })
                if replay_ok:
                    successes += 1

            except Exception as e:
                responses.append({"replay": i + 1, "error": str(e)})

        return self._make_verdict(candidate, replays, successes, responses,
                                  "SQLi (error-based, BREAK+FIX chain)")

    async def _verify_error_partial(self, candidate: Candidate, replays: int) -> VerifyResult:
        """Verify partial error-based finding (BREAK passed, FIX failed).

        Only replays the BREAK step. Verdict is NEEDS_HUMAN at best (never CONFIRMED)
        since the FIX step failed during scanning.
        """
        req = candidate.request_data
        param = req.get("param", "id")
        payload = req.get("payload", "'")
        id_location = req.get("id_location", "query")
        method = candidate.method
        expected_error = candidate.response_data.get("error_match", "")
        siblings = req.get("sibling_fields") or None

        successes = 0
        responses = []

        for i in range(replays):
            try:
                resp = await self._send(
                    candidate.endpoint, param, payload, method, id_location,
                    siblings=siblings,
                )
                body = resp.text[:3000].lower()
                matched = False

                if expected_error and expected_error != "status_500":
                    matched = expected_error.lower() in body
                elif expected_error == "status_500":
                    matched = resp.status_code == 500
                else:
                    matched = any(sig in body for sig in _DB_ERRORS)

                responses.append({
                    "replay": i + 1,
                    "status": resp.status_code,
                    "error_found": matched,
                })
                if matched:
                    successes += 1

            except Exception as e:
                responses.append({"replay": i + 1, "error": str(e)})

        # Cap verdict at NEEDS_HUMAN since FIX step failed
        if successes == replays:
            verdict = Verdict.NEEDS_HUMAN
            reason = (f"All {replays} BREAK replays succeeded but FIX step failed "
                      f"during scan — needs manual verification")
        elif successes == 0:
            verdict = Verdict.FALSE
            reason = f"None of {replays} BREAK replays reproduced — likely false positive"
        else:
            verdict = Verdict.NEEDS_HUMAN
            reason = f"{successes}/{replays} BREAK replays succeeded — inconsistent"

        return self._result(
            candidate=candidate,
            verdict=verdict,
            replays=replays,
            evidence={"responses": responses, "successes": successes},
            reason=reason,
        )

    async def _verify_redirect(self, candidate: Candidate, replays: int) -> VerifyResult:
        """Verify redirect-based auth bypass SQLi."""
        req = candidate.request_data
        param = req.get("param", "id")
        payload_true = req.get("payload_true", "' OR '1'='1' --")
        payload_false = req.get("payload_false", "' OR '1'='2' --")
        id_location = req.get("id_location", "query")
        method = candidate.method
        expected_true_loc = candidate.response_data.get("true_location", "")
        siblings = req.get("sibling_fields") or None

        successes = 0
        responses = []

        for i in range(replays):
            try:
                true_resp = await self._send(
                    candidate.endpoint, param, payload_true, method, id_location,
                    siblings=siblings,
                )
                false_resp = await self._send(
                    candidate.endpoint, param, payload_false, method, id_location,
                    siblings=siblings,
                )
                true_loc = true_resp.headers.get("location", "")
                false_loc = false_resp.headers.get("location", "")

                matched = (
                    true_loc.lower() != false_loc.lower()
                    and true_loc.lower() == expected_true_loc.lower()
                )
                responses.append({
                    "replay": i + 1,
                    "true_status": true_resp.status_code,
                    "false_status": false_resp.status_code,
                    "true_location": true_loc,
                    "false_location": false_loc,
                    "redirect_differs": true_loc.lower() != false_loc.lower(),
                })
                if matched:
                    successes += 1

            except Exception as e:
                responses.append({"replay": i + 1, "error": str(e)})

        return self._make_verdict(candidate, replays, successes, responses,
                                  "SQLi (redirect-based / auth bypass)")

    async def _verify_auth_bypass(self, candidate: Candidate, replays: int) -> VerifyResult:
        """Verify auth bypass SQLi by re-sending true/false payloads and comparing body lengths."""
        req = candidate.request_data
        param = req.get("param", "uid")
        payload_true = req.get("payload_true", "' OR '1'='1' --")
        payload_false = req.get("payload_false", "' OR '1'='2' --")
        id_location = req.get("id_location", "body")
        method = candidate.method
        siblings = req.get("sibling_fields") or None

        successes = 0
        responses = []

        for i in range(replays):
            try:
                true_resp = await self._send(candidate.endpoint, param, payload_true, method, id_location, siblings=siblings)
                false_resp = await self._send(candidate.endpoint, param, payload_false, method, id_location, siblings=siblings)

                true_len = len(true_resp.text)
                false_len = len(false_resp.text)
                diff = abs(true_len - false_len)

                matched = diff > 200 and true_resp.status_code < 400
                responses.append({"replay": i + 1, "true_len": true_len, "false_len": false_len, "diff": diff, "matched": matched})
                if matched:
                    successes += 1
            except Exception as e:
                responses.append({"replay": i + 1, "error": str(e)})

        return self._make_verdict(candidate, replays, successes, responses, "SQLi (auth bypass — response body diff)", majority_ok=True)

    async def _verify_boolean_blind(self, candidate: Candidate, replays: int) -> VerifyResult:
        """Verify boolean blind SQLi by re-sending true/false and checking length diff."""
        req = candidate.request_data
        param = req.get("param", "id")
        payload = req.get("payload", "' OR '1'='1' --")
        id_location = req.get("id_location", "query")
        method = candidate.method
        siblings = req.get("sibling_fields") or None

        # Derive true/false pair from the payload
        true_payload = payload
        false_payload = payload.replace("1'='1", "1'='2").replace("1=1", "1=2")

        successes = 0
        responses = []

        for i in range(replays):
            try:
                true_resp = await self._send(candidate.endpoint, param, true_payload, method, id_location, siblings=siblings)
                false_resp = await self._send(candidate.endpoint, param, false_payload, method, id_location, siblings=siblings)

                diff = abs(len(true_resp.text) - len(false_resp.text))
                matched = diff > 50
                responses.append({"replay": i + 1, "diff": diff, "matched": matched})
                if matched:
                    successes += 1
            except Exception as e:
                responses.append({"replay": i + 1, "error": str(e)})

        return self._make_verdict(candidate, replays, successes, responses, "SQLi (boolean-blind)", majority_ok=True)

    async def _verify_time_blind(self, candidate: Candidate, replays: int) -> VerifyResult:
        """Verify time-based blind SQLi by re-running sleep payload."""
        req = candidate.request_data
        param = req.get("param", "id")
        payload = req.get("payload", "' OR SLEEP(5) --")
        id_location = req.get("id_location", "query")
        method = candidate.method
        siblings = req.get("sibling_fields") or None

        successes = 0
        responses = []

        for i in range(replays):
            try:
                t0 = time.monotonic()
                await self._send(candidate.endpoint, param, "normalvalue123", method, id_location, siblings=siblings)
                baseline_time = time.monotonic() - t0

                t0 = time.monotonic()
                await self._send(candidate.endpoint, param, payload, method, id_location, siblings=siblings)
                elapsed = time.monotonic() - t0

                delta = elapsed - baseline_time
                matched = delta >= _TIME_THRESHOLD
                responses.append({"replay": i + 1, "elapsed": round(elapsed, 2), "baseline": round(baseline_time, 2), "delta": round(delta, 2), "matched": matched})
                if matched:
                    successes += 1
            except Exception as e:
                responses.append({"replay": i + 1, "error": str(e)})

        return self._make_verdict(candidate, replays, successes, responses, "SQLi (time-based blind)", majority_ok=True)

    def _make_verdict(self, candidate, replays, successes, responses, label,
                       *, majority_ok: bool = False):
        if successes == replays:
            verdict = Verdict.CONFIRMED
            reason = f"All {replays} replays confirmed — {label} confirmed"
        elif successes == 0:
            verdict = Verdict.FALSE
            reason = f"None of {replays} replays reproduced — likely false positive"
        elif majority_ok and successes > replays // 2:
            verdict = Verdict.CONFIRMED
            reason = f"{successes}/{replays} replays confirmed — {label} confirmed (majority)"
        else:
            verdict = Verdict.NEEDS_HUMAN
            reason = f"{successes}/{replays} replays succeeded — inconsistent"

        return self._result(
            candidate=candidate,
            verdict=verdict,
            replays=replays,
            evidence={"responses": responses, "successes": successes},
            reason=reason,
        )

    async def _send(self, endpoint, param, value, method, id_location,
                    *, siblings: dict[str, str] | None = None):
        if id_location == "query":
            params = dict(siblings) if siblings else {}
            params[param] = value
            return await self.client.request(
                method, endpoint, session=self.session,
                params=params,
            )
        elif id_location == "body":
            data = dict(siblings) if siblings else {}
            data[param] = value
            return await self.client.post(
                endpoint, session=self.session,
                data=data,
            )
        elif id_location == "path":
            url = endpoint.rstrip("/") + f"/{value}"
            return await self.client.request(method, url, session=self.session)
        else:
            raise ValueError(f"Unknown id_location: {id_location}")
