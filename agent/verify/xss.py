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
        siblings = req.get("siblings", {})

        successes = 0
        responses = []
        csp_blocks = False

        for i in range(replays):
            try:
                resp = await self._send(
                    candidate.endpoint, param, payload,
                    candidate.method, id_location, siblings=siblings
                )
                body = resp.text
                reflected = self._is_reflected(payload, body)

                # Check CSP on first replay
                if i == 0:
                    csp = resp.headers.get("content-security-policy", "")
                    if csp and self._csp_blocks_inline(csp):
                        csp_blocks = True

                responses.append({
                    "replay": i + 1,
                    "status": resp.status_code,
                    "reflected": reflected,
                })
                if reflected:
                    successes += 1
            except Exception as e:
                responses.append({"replay": i + 1, "error": str(e)})

        return self._make_verdict(candidate, replays, successes, responses,
                                  csp_blocks=csp_blocks)

    def _make_verdict(self, candidate, replays, successes, responses,
                      *, csp_blocks: bool = False):
        if csp_blocks:
            # CSP blocks inline scripts — reflected but not exploitable
            verdict = Verdict.FALSE
            reason = (f"Payload reflected in {successes}/{replays} replays but "
                      "CSP script-src blocks inline script execution")
        elif successes == replays:
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
            evidence={"responses": responses, "successes": successes,
                      "csp_blocks_inline": csp_blocks},
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

    @staticmethod
    def _csp_blocks_inline(csp: str) -> bool:
        """Check if CSP blocks inline script execution."""
        if not csp:
            return False
        csp_lower = csp.lower()
        directives = {}
        for part in csp_lower.split(";"):
            part = part.strip()
            if not part:
                continue
            tokens = part.split()
            if tokens:
                directives[tokens[0]] = tokens[1:]
        sources = directives.get("script-src", directives.get("default-src", []))
        if not sources:
            return False
        if "'unsafe-inline'" in sources:
            return False
        if "'none'" in sources:
            return True
        return True  # Sources listed without unsafe-inline = blocks inline

    async def _send(self, endpoint, param, value, method, id_location,
                    *, siblings: dict | None = None):
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
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        else:
            raise ValueError(f"Unknown id_location: {id_location}")
