"""IDOR verifier — deterministic replay to confirm IDOR candidates.

Re-sends the exact request from the candidate (attacker session + victim id)
multiple times and checks that the response consistently indicates success.
A one-off 200 could be a cache hit or race condition; consistent success
across replays confirms the IDOR.
"""
from __future__ import annotations

from typing import Any

from ..http import HttpClient, Session
from ..scanners.base import Candidate
from .base import Verifier, Verdict, VerifyResult


class IdorVerifier(Verifier):
    """Deterministic IDOR verification via request replay."""

    def __init__(self, client: HttpClient, attacker_session: Session):
        super().__init__(client)
        self.attacker = attacker_session

    async def _verify(self, candidate: Candidate, replays: int,
                      **context: Any) -> VerifyResult:
        """Replay the IDOR request and check for consistent success.

        Confirmation requires ALL replays to return a success status with
        a body that doesn't indicate authorization failure.
        """
        req = candidate.request_data
        id_param = req.get("id_param", "id")
        id_value = req.get("id_value", "")
        id_location = req.get("id_location", "body")

        successes = 0
        responses = []

        for i in range(replays):
            try:
                resp = await self._replay(
                    candidate.endpoint, id_param, id_value, id_location
                )
                status = resp.status_code
                body = resp.text[:500]
                responses.append({"replay": i + 1, "status": status, "body_snippet": body})

                if 200 <= status < 300 and not self._looks_like_authz_fail(body):
                    successes += 1
            except Exception as e:
                responses.append({"replay": i + 1, "error": str(e)})

        # Verdict logic
        if successes == replays:
            verdict = Verdict.CONFIRMED
            reason = (
                f"All {replays} replays returned success with attacker session "
                f"using victim id '{id_value}' — IDOR confirmed"
            )
        elif successes == 0:
            verdict = Verdict.FALSE
            reason = (
                f"None of {replays} replays succeeded — likely false positive "
                f"(original may have been a cache hit or race condition)"
            )
        else:
            verdict = Verdict.NEEDS_HUMAN
            reason = (
                f"{successes}/{replays} replays succeeded — inconsistent; "
                f"may be timing-dependent or rate-limited"
            )

        return self._result(
            candidate=candidate,
            verdict=verdict,
            replays=replays,
            evidence={"responses": responses, "successes": successes},
            reason=reason,
        )

    async def _replay(self, endpoint: str, id_param: str,
                      id_value: str, id_location: str):
        """Send one replay request."""
        if id_location == "body":
            return await self.client.post(
                endpoint,
                session=self.attacker,
                json={id_param: id_value},
                headers={"Content-Type": "application/json"},
            )
        elif id_location == "query":
            return await self.client.get(
                endpoint,
                session=self.attacker,
                params={id_param: id_value},
            )
        elif id_location == "path":
            url = endpoint.rstrip("/") + f"/{id_value}"
            return await self.client.get(url, session=self.attacker)
        else:
            raise ValueError(f"Unknown id_location: {id_location}")

    @staticmethod
    def _looks_like_authz_fail(body: str) -> bool:
        """Quick heuristic: does the response body suggest authorization failure?"""
        fail_signals = [
            "unauthorized", "forbidden", "access denied",
            "not allowed", "permission denied", "403",
            "invalid session", "login required",
        ]
        lower = body.lower()
        return any(signal in lower for signal in fail_signals)
