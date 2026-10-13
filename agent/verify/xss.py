"""XSS verifier — replays reflected XSS payload to confirm it's not a false positive.

Re-sends the payload and checks the same reflection appears unencoded.
"""
from __future__ import annotations

from typing import Any

from ..http import HttpClient, Session
from ..scanners.base import Candidate
from .base import Verifier, Verdict, VerifyResult

# Markers that indicate unencoded reflection
_REFLECTION_MARKERS = [
    "<script>", "<img ", "<svg", "onerror=", "onload=",
    "javascript:", "alert(1)",
]


class XssVerifier(Verifier):
    """Deterministic XSS verification via payload replay."""

    def __init__(self, client: HttpClient, session: Session):
        super().__init__(client)
        self.session = session

    async def _verify(self, candidate: Candidate, replays: int,
                      **context: Any) -> VerifyResult:
        req = candidate.request_data
        param = req.get("param", "q")
        payload = req.get("payload", "<script>alert(1)</script>")
        id_location = req.get("id_location", "query")

        successes = 0
        responses = []

        for i in range(replays):
            try:
                resp = await self._send(
                    candidate.endpoint, param, payload,
                    candidate.method, id_location
                )
                body = resp.text
                reflected = self._is_reflected(payload, body)
                responses.append({
                    "replay": i + 1,
                    "status": resp.status_code,
                    "reflected": reflected,
                })
                if reflected:
                    successes += 1
            except Exception as e:
                responses.append({"replay": i + 1, "error": str(e)})

        return self._make_verdict(candidate, replays, successes, responses)

    def _make_verdict(self, candidate, replays, successes, responses):
        if successes == replays:
            verdict = Verdict.CONFIRMED
            reason = f"All {replays} replays reflected payload — XSS confirmed"
        elif successes == 0:
            verdict = Verdict.FALSE
            reason = f"None of {replays} replays reflected — likely false positive"
        else:
            verdict = Verdict.NEEDS_HUMAN
            reason = f"{successes}/{replays} replays reflected — inconsistent"

        return self._result(
            candidate=candidate,
            verdict=verdict,
            replays=replays,
            evidence={"responses": responses, "successes": successes},
            reason=reason,
        )

    @staticmethod
    def _is_reflected(payload: str, body: str) -> bool:
        """Check if payload appears unencoded in response."""
        if payload in body:
            return True
        lower_body = body.lower()
        for marker in _REFLECTION_MARKERS:
            if marker.lower() in payload.lower() and marker.lower() in lower_body:
                return True
        return False

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
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        else:
            raise ValueError(f"Unknown id_location: {id_location}")
