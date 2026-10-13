"""Orchestrator — the main agent loop.

Ties together: scope → recon → retrieve recipes → run scanners → verify →
route confirmed findings to the human review queue.

State model:
  - TargetState: holds target info, inventory, and queues
  - candidate_queue: unverified scanner hits
  - confirmed: verified findings (CONFIRMED)
  - human_queue: findings needing human judgment (CONFIRMED + NEEDS_HUMAN)

Usage:
    orch = Orchestrator(config)
    await orch.run("https://target.example.com")
    # results in outputs/human_queue.jsonl
"""
from __future__ import annotations

import json
import logging
import pathlib
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any

from .http import HttpClient, Session
from .scope import check as scope_check, add_to_scope, ScopeError
from .scanners.base import Scanner, Candidate
from .scanners.idor import IdorScanner
from .scanners.sqli import SqliScanner
from .scanners.xss import XssScanner
from .scanners.ssrf import SsrfScanner
from .verify.base import Verifier, Verdict, VerifyResult
from .verify.idor import IdorVerifier
from .verify.sqli import SqliVerifier
from .verify.xss import XssVerifier
from .verify.ssrf import SsrfVerifier
from .kb.retriever import Retriever, RetrievalResult
from .recipes.schema import Recipe

logger = logging.getLogger(__name__)

DEFAULT_OUTPUT_DIR = pathlib.Path(__file__).parent.parent / "outputs"


# ── State model ──────────────────────────────────────────────


@dataclass
class EndpointInfo:
    """Discovered endpoint from recon."""
    url: str
    method: str = "GET"
    params: list[str] = field(default_factory=list)
    tech_signals: list[str] = field(default_factory=list)
    notes: str = ""


@dataclass
class TargetState:
    """Full state for one orchestration run."""
    target: str
    started_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    # Recon inventory
    endpoints: list[EndpointInfo] = field(default_factory=list)
    tech_signals: list[str] = field(default_factory=list)

    # Queues
    candidate_queue: list[Candidate] = field(default_factory=list)
    confirmed: list[VerifyResult] = field(default_factory=list)
    needs_human: list[VerifyResult] = field(default_factory=list)
    false_positives: list[VerifyResult] = field(default_factory=list)

    # Stats
    recipes_matched: int = 0
    scans_run: int = 0
    verifications_run: int = 0

    def summary(self) -> dict:
        return {
            "target": self.target,
            "started_at": self.started_at,
            "endpoints_discovered": len(self.endpoints),
            "tech_signals": self.tech_signals,
            "recipes_matched": self.recipes_matched,
            "candidates_found": len(self.candidate_queue),
            "confirmed": len(self.confirmed),
            "needs_human": len(self.needs_human),
            "false_positives": len(self.false_positives),
            "scans_run": self.scans_run,
            "verifications_run": self.verifications_run,
        }


# ── Human queue writer ───────────────────────────────────────


class HumanQueue:
    """Writes confirmed/needs-human findings to a JSONL file for review."""

    def __init__(self, output_dir: pathlib.Path | str = DEFAULT_OUTPUT_DIR):
        self.output_dir = pathlib.Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.queue_file = self.output_dir / "human_queue.jsonl"
        self.summary_file = self.output_dir / "run_summary.json"

    def add(self, result: VerifyResult) -> None:
        """Append a verified result to the human queue file."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "verdict": result.verdict.value,
            "recipe_id": result.candidate.recipe_id,
            "endpoint": result.candidate.endpoint,
            "method": result.candidate.method,
            "scanner": result.candidate.scanner,
            "confidence": result.candidate.confidence,
            "replays": result.replays,
            "reason": result.reason,
            "evidence": result.evidence,
            "request_data": result.candidate.request_data,
        }
        with self.queue_file.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

    def write_summary(self, state: TargetState) -> None:
        """Write the run summary as JSON."""
        with self.summary_file.open("w", encoding="utf-8") as f:
            json.dump(state.summary(), f, indent=2)

    def read_queue(self) -> list[dict]:
        """Read all entries from the queue file."""
        if not self.queue_file.exists():
            return []
        entries = []
        with self.queue_file.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    entries.append(json.loads(line))
        return entries

    def clear(self) -> None:
        """Clear the queue file (for fresh runs)."""
        if self.queue_file.exists():
            self.queue_file.unlink()


# ── Scanner registry ─────────────────────────────────────────


class ScannerRegistry:
    """Maps recipe vuln classes to scanner constructors."""

    def __init__(self) -> None:
        self._map: dict[str, type[Scanner]] = {}

    def register(self, vuln_class: str, scanner_cls: type[Scanner]) -> None:
        self._map[vuln_class] = scanner_cls

    def get(self, vuln_class: str) -> type[Scanner] | None:
        return self._map.get(vuln_class)

    def get_for_recipe(self, recipe: Recipe) -> type[Scanner] | None:
        """Find scanner by matching recipe id prefix or source to vuln classes."""
        rid = recipe.id.lower()
        for vc, cls in self._map.items():
            if rid.startswith(vc):
                return cls
        # Fall back: check source field (e.g. CWE-639 → idor)
        source = (recipe.source or "").lower()
        if "639" in source or "284" in source:
            return self._map.get("idor")
        return None


# ── Orchestrator ─────────────────────────────────────────────


@dataclass
class OrchestratorConfig:
    """Configuration for a single orchestrator run."""
    # Sessions
    attacker_session: Session
    victim_session: Session | None = None

    # IDOR-specific context
    victim_ids: list[str] = field(default_factory=list)
    id_param: str = "id"
    id_location: str = "body"

    # Recipes
    recipes_dir: pathlib.Path | str | None = None
    recipes: list[Recipe] | None = None

    # Endpoints to scan (manual recon input for now)
    endpoints: list[EndpointInfo] | None = None
    tech_signals: list[str] = field(default_factory=list)

    # Tuning
    verify_replays: int = 3
    output_dir: pathlib.Path | str = DEFAULT_OUTPUT_DIR

    # HTTP client options
    timeout: float = 15.0
    use_proxy: bool = False
    log_path: pathlib.Path | str | None = None


class Orchestrator:
    """Main agent loop: recon → recipes → scan → verify → human queue.

    For Phase 6, recon is manual (endpoints passed in config). Future phases
    will add automated recon (crawling, API schema parsing, etc).
    """

    def __init__(self, config: OrchestratorConfig,
                 client: HttpClient | None = None):
        self.config = config
        self.client = client  # can be injected for testing
        self.state: TargetState | None = None
        self.queue = HumanQueue(config.output_dir)
        self.registry = ScannerRegistry()
        self.retriever = Retriever()

        # Register built-in scanners
        self.registry.register("idor", IdorScanner)
        self.registry.register("bola", IdorScanner)
        self.registry.register("sqli", SqliScanner)
        self.registry.register("sql-injection", SqliScanner)
        self.registry.register("xss", XssScanner)
        self.registry.register("reflected-xss", XssScanner)
        self.registry.register("ssrf", SsrfScanner)

    async def run(self, target: str) -> TargetState:
        """Execute the full orchestration loop on a target.

        Steps:
          1. Scope check
          2. Inventory (manual endpoints for now)
          3. Retrieve matching recipes
          4. Run scanners → candidate queue
          5. Verify candidates → confirmed / false / needs_human
          6. Write human queue
        """
        self.state = TargetState(target=target)
        self.queue.clear()

        # Ensure client
        if self.client is None:
            log_path = self.config.log_path or (
                pathlib.Path(self.config.output_dir) / "http_log.jsonl"
            )
            self.client = HttpClient(
                timeout=self.config.timeout,
                use_proxy=self.config.use_proxy,
                log_path=log_path,
            )

        try:
            # Step 1: scope check
            logger.info("Step 1: Scope check for %s", target)
            scope_check(target)

            # Step 2: inventory
            logger.info("Step 2: Building inventory")
            self._build_inventory()

            # Step 3: retrieve recipes
            logger.info("Step 3: Retrieving matching recipes")
            matched = self._retrieve_recipes()

            # Step 4: scan
            logger.info("Step 4: Running scanners (%d recipes)", len(matched))
            await self._run_scanners(matched)

            # Step 5: verify
            logger.info("Step 5: Verifying %d candidates",
                        len(self.state.candidate_queue))
            await self._verify_candidates()

            # Step 6: write human queue
            logger.info("Step 6: Writing human queue")
            self._write_human_queue()

            logger.info("Run complete: %s", self.state.summary())
            return self.state

        finally:
            # Don't close injected clients
            if self.config.log_path is None and self.client is not None:
                pass  # let caller manage lifecycle

    def _build_inventory(self) -> None:
        """Build endpoint inventory from config.

        Phase 6: manual. Future phases: automated crawl + API schema parse.
        """
        if self.config.endpoints:
            self.state.endpoints = list(self.config.endpoints)

        if self.config.tech_signals:
            self.state.tech_signals = list(self.config.tech_signals)

    def _retrieve_recipes(self) -> list[RetrievalResult]:
        """Retrieve recipes matching the target's tech signals."""
        # Build retriever from config
        if self.config.recipes:
            self.retriever.build(recipes=self.config.recipes)
        elif self.config.recipes_dir:
            self.retriever.build(recipes_dir=self.config.recipes_dir)
        else:
            logger.warning("No recipes configured — scanning skipped")
            return []

        if not self.state.tech_signals:
            # If no signals, return all recipes (small corpus for now)
            results = [
                RetrievalResult(
                    recipe_id=r.id,
                    recipe=r,
                    exact_match=False,
                    vector_score=0.0,
                    combined_rank=i + 1,
                )
                for i, r in enumerate(self.retriever.recipes)
            ]
        else:
            results = self.retriever.retrieve(self.state.tech_signals)

        self.state.recipes_matched = len(results)
        return results

    async def _run_scanners(self, matched: list[RetrievalResult]) -> None:
        """Run the appropriate scanner for each matched recipe × endpoint."""
        for rr in matched:
            recipe = rr.recipe
            scanner_cls = self.registry.get_for_recipe(recipe)
            if scanner_cls is None:
                logger.debug("No scanner for recipe %s — skipped", recipe.id)
                continue

            # Build scanner with appropriate sessions
            scanner = self._build_scanner(scanner_cls)
            if scanner is None:
                continue

            # Scan each endpoint
            endpoints = self.state.endpoints
            if not endpoints:
                logger.debug("No endpoints to scan for recipe %s", recipe.id)
                continue

            for ep in endpoints:
                try:
                    candidates = await scanner.detect(
                        ep.url,
                        recipe,
                        victim_ids=self.config.victim_ids,
                        id_param=self.config.id_param,
                        id_location=self.config.id_location or ep.method,
                        params=ep.params,
                        method=ep.method,
                    )
                    self.state.candidate_queue.extend(candidates)
                    self.state.scans_run += 1
                except Exception as exc:
                    logger.error("Scanner error on %s: %s", ep.url, exc)

    def _build_scanner(self, scanner_cls: type[Scanner]) -> Scanner | None:
        """Instantiate a scanner with the right sessions."""
        if scanner_cls is IdorScanner:
            if self.config.victim_session is None:
                logger.warning("IDOR scanner needs victim_session — skipped")
                return None
            return IdorScanner(
                self.client,
                self.config.attacker_session,
                self.config.victim_session,
            )
        # Single-session scanners (SQLi, XSS, SSRF)
        if scanner_cls in (SqliScanner, XssScanner, SsrfScanner):
            return scanner_cls(self.client, self.config.attacker_session)
        # Generic fallback for future scanners
        return scanner_cls(self.client)

    async def _verify_candidates(self) -> None:
        """Verify each candidate in the queue."""
        for candidate in list(self.state.candidate_queue):
            verifier = self._build_verifier(candidate)
            if verifier is None:
                logger.debug("No verifier for %s — skipped", candidate.scanner)
                continue

            try:
                result = await verifier.verify(
                    candidate,
                    replays=self.config.verify_replays,
                )
                self.state.verifications_run += 1

                if result.verdict == Verdict.CONFIRMED:
                    self.state.confirmed.append(result)
                elif result.verdict == Verdict.NEEDS_HUMAN:
                    self.state.needs_human.append(result)
                else:
                    self.state.false_positives.append(result)

            except Exception as exc:
                logger.error("Verify error for %s: %s",
                             candidate.endpoint, exc)

    def _build_verifier(self, candidate: Candidate) -> Verifier | None:
        """Pick the right verifier for a candidate."""
        if candidate.scanner == "IdorScanner":
            return IdorVerifier(self.client, self.config.attacker_session)
        if candidate.scanner == "SqliScanner":
            return SqliVerifier(self.client, self.config.attacker_session)
        if candidate.scanner == "XssScanner":
            return XssVerifier(self.client, self.config.attacker_session)
        if candidate.scanner == "SsrfScanner":
            return SsrfVerifier(self.client, self.config.attacker_session)
        return None

    def _write_human_queue(self) -> None:
        """Write confirmed + needs_human findings to the queue file."""
        for result in self.state.confirmed:
            self.queue.add(result)
        for result in self.state.needs_human:
            self.queue.add(result)
        self.queue.write_summary(self.state)
