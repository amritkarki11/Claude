"""SSRF verifier — replays SSRF probe to confirm it's not a false positive.

Re-sends the internal URL and checks the same signature appears in the response,
while confirming it doesn't appear in a baseline request.
"""
from __future__ import annotations

from typing import Any

from ..http import HttpClient, Session
from ..scanners.base import Candidate
from .base import Verifier, Verdict, VerifyResult


class SsrfVerifier(Verifier):
    """Deterministic SSRF verification via probe replay."""

    def __init__(self, client: HttpClient, session: Session):
        super().__init__(client)
        self.session = session

    async def _verify(self, candidate: Candidate, replays: int,
                      **context: Any) -> VerifyResult:
        req = candidate.request_data
        param = req.get("param", "url")
        ssrf_url = req.get("ssrf_url", "http://127.0.0.1")
        id_location = req.get("id_location", "query")
        expected_sig = candidate.response_data.get("signature_match", "")

        # Get baseline to ensure signature isn't always present
        baseline_body = ""
        try:
            baseline_resp = await self._send(
                candidate.endpoint, param, "https://www.example.com",
                candidate.method, id_location
            )
            baseline_body = baseline_resp.text[:3000].lower()
        except Exception:
            pass

        # If signature is in baseline, it's not SSRF-specific
        if expected_sig and expected_sig.lower() in baseline_body:
            return self._result(
                candidate=candidate,
                verdict=Verdict.FALSE,
                replays=0,
                evidence={"reason": "Signature present in baseline response"},
                reason="Signature appears in baseline — false positive",
            )

        successes = 0
        responses = []

        for i in range(replays):
            try:
                resp = await self._send(
                    candidate.endpoint, param, ssrf_url,
                    candidate.method, id_location
                )
                body = resp.text[:3000].lower()
                matched = (expected_sig.lower() in body) if expected_sig else False
                responses.append({
                    "replay": i + 1,
                    "status": resp.status_code,
                    "signature_found": matched,
                })
                if matched:
                    successes += 1
            except Exception as e:
                responses.append({"replay": i + 1, "error": str(e)})

        return self._make_verdict(candidate, replays, successes, responses)

    def _make_verdict(self, candidate, replays, successes, responses):
        if successes == replays:
            verdict = Verdict.CONFIRMED
            reason = f"All {replays} replays confirmed signature — SSRF confirmed"
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
                data={param: value},
            )
        else:
            raise ValueError(f"Unknown id_location: {id_location}")
