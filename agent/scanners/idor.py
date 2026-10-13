"""IDOR scanner — detects Insecure Direct Object Reference vulnerabilities.

Strategy: replay a request using the attacker's session but substituting
the victim's identifier. If the response indicates success (the foreign
resource is accessed/mutated), that's a candidate IDOR.

This scanner handles:
  - IDOR on OTP/action trigger endpoints (idor-otp-trigger recipe)
  - Generic IDOR on REST resources (idor-* recipes)
"""
from __future__ import annotations

from typing import Any

from ..http import HttpClient, Session
from ..recipes.schema import Recipe
from .base import Scanner, Candidate


class IdorScanner(Scanner):
    """Detects IDOR by replaying requests with cross-account identifiers."""

    vuln_classes = ["idor", "bola"]

    def __init__(self, client: HttpClient,
                 attacker_session: Session,
                 victim_session: Session):
        super().__init__(client)
        self.attacker = attacker_session
        self.victim = victim_session

    async def _detect(self, target: str, recipe: Recipe,
                      **context: Any) -> list[Candidate]:
        """Run IDOR detection.

        Expected context kwargs:
            victim_ids: list[str | int] — identifiers belonging to the victim
            id_param: str — the parameter name that carries the identifier
            id_location: str — "body" | "path" | "query" (default: "body")
            content_type: str — request content type (default: "application/json")
        """
        victim_ids = context.get("victim_ids", [])
        id_param = context.get("id_param", "id")
        id_location = context.get("id_location", "body")
        content_type = context.get("content_type", "application/json")

        if not victim_ids:
            return []

        candidates = []

        for vid in victim_ids:
            try:
                result = await self._probe(
                    target, vid, id_param, id_location, content_type
                )
                if result:
                    candidates.append(
                        self._make_candidate(
                            recipe=recipe,
                            endpoint=target,
                            method="POST",
                            evidence=result,
                            confidence=self._assess_confidence(result, len(victim_ids)),
                            request_data={
                                "id_param": id_param,
                                "id_value": str(vid),
                                "id_location": id_location,
                                "session": "attacker",
                            },
                            response_data={
                                "status": result.get("status"),
                                "body_snippet": result.get("body_snippet", ""),
                            },
                        )
                    )
            except Exception:
                # Individual probe failures shouldn't stop the scan
                continue

        return candidates

    async def _probe(self, target: str, victim_id: Any, id_param: str,
                     id_location: str, content_type: str) -> dict | None:
        """Send one request with the attacker's session + victim's identifier.

        Returns evidence dict if the response indicates success, None otherwise.
        """
        if id_location == "body":
            if "json" in content_type:
                resp = await self.client.post(
                    target,
                    session=self.attacker,
                    json={id_param: victim_id},
                    headers={"Content-Type": content_type},
                )
            else:
                resp = await self.client.post(
                    target,
                    session=self.attacker,
                    data={id_param: victim_id},
                    headers={"Content-Type": content_type},
                )
        elif id_location == "query":
            resp = await self.client.get(
                target,
                session=self.attacker,
                params={id_param: victim_id},
            )
        elif id_location == "path":
            # Replace last path segment with victim id
            url = target.rstrip("/") + f"/{victim_id}"
            resp = await self.client.get(url, session=self.attacker)
        else:
            return None

        # Success indicators: 2xx status, or response body suggests action taken
        if 200 <= resp.status_code < 300:
            body = resp.text[:500]
            return {
                "status": resp.status_code,
                "body_snippet": body,
                "victim_id": str(victim_id),
                "indicates_success": True,
            }

        return None

    def _assess_confidence(self, evidence: dict, total_probes: int) -> str:
        """Assess confidence based on the evidence gathered."""
        status = evidence.get("status", 0)
        if status == 200 and total_probes >= 2:
            return "high"
        elif status == 200:
            return "medium"
        else:
            return "low"
