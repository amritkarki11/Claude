"""SQLi verifier — replays injection to confirm it's not a false positive.

For error-based: re-sends the payload and checks the same DB error appears.
For boolean-based: re-sends true/false pair and checks length difference persists.
"""
from __future__ import annotations

from typing import Any

from ..http import HttpClient, Session
from ..scanners.base import Candidate
from .base import Verifier, Verdict, VerifyResult


class SqliVerifier(Verifier):
    """Deterministic SQLi verification via payload replay."""

    def __init__(self, client: HttpClient, session: Session):
        super().__init__(client)
        self.session = session

    async def _verify(self, candidate: Candidate, replays: int,
                      **context: Any) -> VerifyResult:
        req = candidate.request_data
        technique = req.get("technique", "error-based")

        if technique == "error-based":
            return await self._verify_error(candidate, replays)
        elif technique == "boolean-based":
            return await self._verify_boolean(candidate, replays)
        else:
            return self._result(
                candidate=candidate,
                verdict=Verdict.NEEDS_HUMAN,
                replays=0,
                evidence={"reason": f"Unknown technique: {technique}"},
                reason=f"Cannot verify technique '{technique}' automatically",
            )

    async def _verify_error(self, candidate: Candidate, replays: int) -> VerifyResult:
        req = candidate.request_data
        param = req.get("param", "id")
        payload = req.get("payload", "'")
        id_location = req.get("id_location", "query")
        expected_error = candidate.response_data.get("error_match", "")

        successes = 0
        responses = []

        for i in range(replays):
            try:
                resp = await self._send(
                    candidate.endpoint, param, payload,
                    candidate.method, id_location
                )
                body = resp.text[:2000].lower()
                matched = expected_error.lower() in body if expected_error else False
                responses.append({
                    "replay": i + 1,
                    "status": resp.status_code,
                    "error_found": matched,
                })
                if matched:
                    successes += 1
            except Exception as e:
                responses.append({"replay": i + 1, "error": str(e)})

        return self._make_verdict(candidate, replays, successes, responses,
                                  "SQLi (error-based)")

    async def _verify_boolean(self, candidate: Candidate, replays: int) -> VerifyResult:
        req = candidate.request_data
        param = req.get("param", "id")
        payload_true = req.get("payload_true", "' OR '1'='1' --")
        payload_false = req.get("payload_false", "' OR '1'='2' --")
        id_location = req.get("id_location", "query")

        successes = 0
        responses = []

        for i in range(replays):
            try:
                true_resp = await self._send(
                    candidate.endpoint, param, payload_true,
                    candidate.method, id_location
                )
                false_resp = await self._send(
                    candidate.endpoint, param, payload_false,
                    candidate.method, id_location
                )
                diff = abs(len(true_resp.text) - len(false_resp.text))
                responses.append({
                    "replay": i + 1,
                    "true_len": len(true_resp.text),
                    "false_len": len(false_resp.text),
                    "diff": diff,
                })
                if diff > 50:
                    successes += 1
            except Exception as e:
                responses.append({"replay": i + 1, "error": str(e)})

        return self._make_verdict(candidate, replays, successes, responses,
                                  "SQLi (boolean-based)")

    def _make_verdict(self, candidate, replays, successes, responses, label):
        if successes == replays:
            verdict = Verdict.CONFIRMED
            reason = f"All {replays} replays confirmed — {label} confirmed"
        elif successes == 0:
            verdict = Verdict.FALSE
            reason = f"None of {replays} replays reproduced — likely false positive"
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

    async def _send(self, endpoint, param, value, method, id_location):
        if id_location == "query":
            return await self.client.request(
                method, endpoint, session=self.session,
                params={param: value},
            )
        elif id_location == "body":
            return await self.client.post(
                endpoint, session=self.session,
                json={param: value},
                headers={"Content-Type": "application/json"},
            )
        elif id_location == "path":
            url = endpoint.rstrip("/") + f"/{value}"
            return await self.client.request(method, url, session=self.session)
        else:
            raise ValueError(f"Unknown id_location: {id_location}")
