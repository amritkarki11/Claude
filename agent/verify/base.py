"""Verifier base class.

A verifier takes a Candidate and deterministically re-tests it to confirm
or reject. Nothing reaches the human as a "finding" until a verifier says
CONFIRMED. This is the non-negotiable guardrail from BUILD_PLAN.md.

Verdict values:
  CONFIRMED   — deterministic replay confirmed the vulnerability
  FALSE       — replay did NOT reproduce; likely a false positive
  NEEDS_HUMAN — inconclusive; needs manual judgment (e.g. timing-dependent)
"""
from __future__ import annotations

import abc
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from ..http import HttpClient, Session
from ..scanners.base import Candidate


class Verdict(str, Enum):
    CONFIRMED = "CONFIRMED"
    FALSE = "FALSE"
    NEEDS_HUMAN = "NEEDS_HUMAN"


@dataclass
class VerifyResult:
    """Output of a verification pass."""
    candidate: Candidate
    verdict: Verdict
    replays: int              # how many times the request was replayed
    evidence: dict            # verifier-specific confirmation data
    reason: str               # human-readable explanation
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class Verifier(abc.ABC):
    """Base class for vulnerability verifiers.

    Each verifier deterministically re-tests a candidate finding. The
    verify() method replays the exact request from the candidate and
    checks whether the vulnerability reproduces consistently.

    Usage:
        verifier = IdorVerifier(client, attacker_session)
        result = await verifier.verify(candidate)
        if result.verdict == Verdict.CONFIRMED:
            # safe to report
    """

    def __init__(self, client: HttpClient, **kwargs: Any):
        self.client = client

    async def verify(self, candidate: Candidate,
                     replays: int = 2, **context: Any) -> VerifyResult:
        """Verify a candidate finding.

        Args:
            candidate: the unverified finding from a scanner
            replays: number of times to replay for confirmation (min 2)
            **context: verifier-specific context

        Returns:
            VerifyResult with verdict.
        """
        replays = max(replays, 2)  # always at least 2 replays
        return await self._verify(candidate, replays, **context)

    @abc.abstractmethod
    async def _verify(self, candidate: Candidate, replays: int,
                      **context: Any) -> VerifyResult:
        """Subclasses implement the actual verification logic."""
        ...

    def _result(self, candidate: Candidate, verdict: Verdict,
                replays: int, evidence: dict, reason: str) -> VerifyResult:
        """Helper to create a VerifyResult."""
        return VerifyResult(
            candidate=candidate,
            verdict=verdict,
            replays=replays,
            evidence=evidence,
            reason=reason,
        )
