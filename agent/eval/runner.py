"""Eval runner — runs the orchestrator against a fixture and scores results.

Usage (CLI):
    python -m agent.eval --fixture altoro --target http://demo.testfire.net

Usage (programmatic):
    from agent.eval.runner import EvalRunner
    runner = EvalRunner("altoro")
    result = await runner.run()
    print(result.metrics)
"""
from __future__ import annotations

import asyncio
import json
import logging
import pathlib
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any

from .fixtures import get_fixture, TargetFixture
from .metrics import compute_metrics, EvalMetrics

logger = logging.getLogger(__name__)


@dataclass
class EvalRun:
    """Complete result of one eval run."""
    fixture_name: str
    target: str
    started_at: str = ""
    finished_at: str = ""
    duration_s: float = 0.0
    metrics: EvalMetrics | None = None
    confirmed_findings: list[dict] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict:
        d: dict[str, Any] = {
            "fixture_name": self.fixture_name,
            "target": self.target,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_s": self.duration_s,
            "error": self.error,
        }
        if self.metrics:
            d["metrics"] = {
                "precision": self.metrics.precision,
                "recall": self.metrics.recall,
                "f1": self.metrics.f1,
                "true_positives": self.metrics.true_positive_count,
                "false_negatives": self.metrics.false_negative_count,
                "false_positives": self.metrics.false_positive_count,
                "total_expected": self.metrics.total_expected,
                "total_confirmed": self.metrics.total_confirmed,
            }
        d["confirmed_findings"] = self.confirmed_findings
        return d


class EvalRunner:
    """Runs the orchestrator against a fixture and computes metrics."""

    def __init__(
        self,
        fixture_name: str,
        *,
        target_override: str | None = None,
        output_dir: str | pathlib.Path = "outputs/eval",
        recon: bool = True,
        no_nmap: bool = True,
        attacker_cookie: str | None = None,
        victim_cookie: str | None = None,
    ):
        self.fixture = get_fixture(fixture_name)
        self.target = target_override or self.fixture.base_url
        self.output_dir = pathlib.Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.recon = recon
        self.no_nmap = no_nmap
        self.attacker_cookie = attacker_cookie
        self.victim_cookie = victim_cookie

    async def run(self) -> EvalRun:
        """Execute the full eval: orchestrator run + metric computation."""
        from ..orchestrator import Orchestrator, OrchestratorConfig
        from ..http import Session
        from ..scope import add_to_scope

        result = EvalRun(
            fixture_name=self.fixture.name,
            target=self.target,
            started_at=datetime.now(timezone.utc).isoformat(),
        )

        try:
            add_to_scope(self.target)

            attacker_session = Session()
            if self.attacker_cookie:
                for part in self.attacker_cookie.split(";"):
                    part = part.strip()
                    if "=" in part:
                        k, v = part.split("=", 1)
                        attacker_session.cookies[k.strip()] = v.strip()

            victim_session = None
            if self.victim_cookie:
                victim_session = Session()
                for part in self.victim_cookie.split(";"):
                    part = part.strip()
                    if "=" in part:
                        k, v = part.split("=", 1)
                        victim_session.cookies[k.strip()] = v.strip()

            config = OrchestratorConfig(
                attacker_session=attacker_session,
                victim_session=victim_session,
                recon=self.recon,
                no_nmap=self.no_nmap,
                output_dir=str(self.output_dir / "run_output"),
                use_mind=False,
            )

            orch = Orchestrator(config)
            t0 = time.monotonic()
            state = await orch.run(self.target)
            result.duration_s = round(time.monotonic() - t0, 2)

            confirmed = []
            for vr in state.confirmed:
                entry = {
                    "recipe_id": vr.candidate.recipe_id,
                    "scanner": vr.candidate.scanner,
                    "endpoint": vr.candidate.endpoint,
                    "method": vr.candidate.method,
                    "confidence": vr.candidate.confidence,
                    "evidence": vr.candidate.evidence,
                    "request_data": vr.candidate.request_data,
                    "verdict": vr.verdict.value,
                    "reason": vr.reason,
                }
                confirmed.append(entry)

            for vr in state.needs_human:
                entry = {
                    "recipe_id": vr.candidate.recipe_id,
                    "scanner": vr.candidate.scanner,
                    "endpoint": vr.candidate.endpoint,
                    "method": vr.candidate.method,
                    "confidence": vr.candidate.confidence,
                    "evidence": vr.candidate.evidence,
                    "request_data": vr.candidate.request_data,
                    "verdict": vr.verdict.value,
                    "reason": vr.reason,
                }
                confirmed.append(entry)

            result.confirmed_findings = confirmed
            result.metrics = compute_metrics(self.fixture.expected, confirmed)

        except Exception as e:
            logger.exception("Eval run failed")
            result.error = str(e)

        result.finished_at = datetime.now(timezone.utc).isoformat()
        self._save(result)
        return result

    def _save(self, result: EvalRun) -> None:
        """Save eval result to JSON."""
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        outfile = self.output_dir / f"eval_{self.fixture.name}_{ts}.json"
        with outfile.open("w", encoding="utf-8") as f:
            json.dump(result.to_dict(), f, indent=2, default=str)
        logger.info("Eval result saved to %s", outfile)
