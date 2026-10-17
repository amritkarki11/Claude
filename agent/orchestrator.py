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
from typing import Any, Callable
from urllib.parse import urlparse, urlencode

from .http import HttpClient, Session
from .scope import check as scope_check, add_to_scope, ScopeError
from .scanners.base import Scanner, Candidate
from .scanners.idor import IdorScanner
from .scanners.sqli import SqliScanner
from .scanners.xss import XssScanner
from .scanners.ssrf import SsrfScanner
from .scanners.nosqli import NosqliScanner
from .scanners.ssti import SstiScanner
from .scanners.cmdi import CmdiScanner
from .scanners.lfi import LfiScanner
from .scanners.csrf import CsrfScanner
from .scanners.stored_xss import StoredXssScanner
from .scanners.open_redirect import OpenRedirectScanner
from .scanners.bruteforce import BruteforceScanner
from .scanners.headers import HeaderScanner
from .recon.testcase_mapper import TestCaseMapper
from .verify.base import Verifier, Verdict, VerifyResult
from .verify.idor import IdorVerifier
from .verify.sqli import SqliVerifier
from .verify.xss import XssVerifier
from .verify.ssrf import SsrfVerifier
from .verify.playwright_xss import PlaywrightXssVerifier
from .kb.retriever import Retriever, RetrievalResult
from .recipes.schema import Recipe
from .recon.inventory import InventoryBuilder, ReconInventory
from .recon.auth_bypass import AuthBypassDiscovery, BypassResult
from .scanners.privesc import PrivilegeEscalationScanner
from .mind.core import Mind

logger = logging.getLogger(__name__)

DEFAULT_OUTPUT_DIR = pathlib.Path(__file__).parent.parent / "outputs"


# ── Passthrough verifier for scanners with built-in chains ───


class _PassthroughVerifier(Verifier):
    """Auto-confirms candidates from scanners that already ran verification.

    Scanners like NosqliScanner, SstiScanner, CmdiScanner, LfiScanner,
    CsrfScanner, StoredXssScanner, and OpenRedirectScanner have multi-step
    verification chains built into their _detect() method.
    By the time a candidate is emitted, it's already been verified.

    This verifier simply maps scanner confidence to a Verdict:
      - high   → CONFIRMED
      - medium → NEEDS_HUMAN
      - low    → FALSE (scanner shouldn't emit these, but just in case)
    """

    async def _verify(self, candidate: Candidate, replays: int = 1,
                      **context: Any) -> VerifyResult:
        if candidate.confidence == "high":
            verdict = Verdict.CONFIRMED
            reason = (
                f"Scanner {candidate.scanner} verification chain passed "
                f"with high confidence: {candidate.evidence.get('technique', 'N/A')}"
            )
        elif candidate.confidence == "medium":
            verdict = Verdict.NEEDS_HUMAN
            reason = (
                f"Scanner {candidate.scanner} partial verification — "
                f"manual review recommended"
            )
        else:
            verdict = Verdict.FALSE
            reason = "Low confidence — likely false positive"

        return VerifyResult(
            candidate=candidate,
            verdict=verdict,
            reason=reason,
            replays=0,
            evidence=candidate.evidence,
        )


# ── State model ──────────────────────────────────────────────


@dataclass
class EndpointInfo:
    """Discovered endpoint from recon."""
    url: str
    method: str = "GET"
    params: list[str] = field(default_factory=list)
    tech_signals: list[str] = field(default_factory=list)
    notes: str = ""
    # Functionality classification (from classifier)
    function: str = "unknown"
    relevant_vulns: list[str] = field(default_factory=list)
    injection_points: list[dict] = field(default_factory=list)


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

    # Endpoints to scan (manual or from recon)
    endpoints: list[EndpointInfo] | None = None
    tech_signals: list[str] = field(default_factory=list)

    # Recon options
    recon: bool = False           # enable automated recon pipeline
    crawl_depth: int = 3
    crawl_max_pages: int = 100
    max_js_files: int = 50

    # Nmap options
    nmap_ports: str = "1-10000"
    nmap_scan_type: str = "-sV -sC"
    nmap_timeout: int = 300
    no_nmap: bool = False

    # Tuning
    verify_replays: int = 3
    output_dir: pathlib.Path | str = DEFAULT_OUTPUT_DIR

    # HTTP client options
    timeout: float = 15.0
    use_proxy: bool = False
    log_path: pathlib.Path | str | None = None
    rate_limit: float = 0.0
    stealth: bool = False

    # Mind system
    use_mind: bool = True
    mind_data_dir: pathlib.Path | str | None = None
    nvd_api_key: str | None = None
    github_token: str | None = None


class Orchestrator:
    """Main agent loop: recon → recipes → scan → verify → human queue.

    For Phase 6, recon is manual (endpoints passed in config). Future phases
    will add automated recon (crawling, API schema parsing, etc).
    """

    def __init__(self, config: OrchestratorConfig,
                 client: HttpClient | None = None,
                 on_finding: Callable[[VerifyResult], None] | None = None):
        self.config = config
        self.client = client  # can be injected for testing
        self.state: TargetState | None = None
        self.queue = HumanQueue(config.output_dir)
        self.registry = ScannerRegistry()
        self.retriever = Retriever()
        self._on_finding = on_finding  # real-time callback for confirmed findings
        self.on_recon_phase: Callable | None = None  # set by CLI for display

        # Mind system — persona, memory, learning
        self.mind: Mind | None = None
        if config.use_mind:
            try:
                mind_kwargs: dict[str, Any] = {}
                if config.mind_data_dir:
                    mind_kwargs["data_dir"] = config.mind_data_dir
                if config.nvd_api_key:
                    mind_kwargs["nvd_api_key"] = config.nvd_api_key
                if config.github_token:
                    mind_kwargs["github_token"] = config.github_token
                self.mind = Mind(**mind_kwargs)
                logger.info("Mind system initialized")
            except Exception as e:
                logger.warning("Mind system failed to init: %s — running without it", e)
                self.mind = None

        # Register built-in scanners
        self.registry.register("idor", IdorScanner)
        self.registry.register("bola", IdorScanner)
        self.registry.register("sqli", SqliScanner)
        self.registry.register("sql-injection", SqliScanner)
        self.registry.register("xss", XssScanner)
        self.registry.register("reflected-xss", XssScanner)
        self.registry.register("ssrf", SsrfScanner)
        self.registry.register("nosqli", NosqliScanner)
        self.registry.register("nosql-injection", NosqliScanner)
        self.registry.register("ssti", SstiScanner)
        self.registry.register("template-injection", SstiScanner)
        self.registry.register("cmdi", CmdiScanner)
        self.registry.register("command-injection", CmdiScanner)
        self.registry.register("os-command-injection", CmdiScanner)
        self.registry.register("lfi", LfiScanner)
        self.registry.register("path-traversal", LfiScanner)
        self.registry.register("file-inclusion", LfiScanner)
        self.registry.register("csrf", CsrfScanner)
        self.registry.register("cross-site-request-forgery", CsrfScanner)
        self.registry.register("stored-xss", StoredXssScanner)
        self.registry.register("open-redirect", OpenRedirectScanner)
        self.registry.register("brute-force", BruteforceScanner)
        self.registry.register("weak-credentials", BruteforceScanner)
        self.registry.register("account-lockout", BruteforceScanner)
        self.registry.register("security-headers", HeaderScanner)
        self.registry.register("misconfiguration", HeaderScanner)

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
                rate_limit=self.config.rate_limit,
                stealth=self.config.stealth,
            )

        try:
            # Step 1: scope check
            logger.info("Step 1: Scope check for %s", target)
            scope_check(target)

            # Step 1b: Mind — gather target intelligence
            if self.mind:
                try:
                    tech_stack = list(self.config.tech_signals) if self.config.tech_signals else []
                    intel = await self.mind.prepare_for_target(
                        tech_stack=tech_stack, target_url=target,
                    )
                    logger.info("Mind intel: %d CVEs, %d exploits",
                                len(intel.get("cves", [])),
                                len(intel.get("exploits", [])))
                except Exception as e:
                    logger.warning("Mind prepare_for_target failed: %s", e)

            # Step 2: inventory (recon + manual)
            logger.info("Step 2: Building inventory")
            await self._build_inventory()

            # Step 2b: Test case mapping (profile site → applicable tests)
            if self.config.recon and self._recon_inventory:
                logger.info("Step 2b: Mapping applicable test cases")
                _emit = self.on_recon_phase or (lambda *a, **kw: None)
                _emit("testcase_map_start")
                mapper = TestCaseMapper()
                ri = self._recon_inventory
                site_profile = mapper.profile_site(
                    url=target,
                    fingerprint_result=ri.fingerprint_result,
                    classified_endpoints=[ep.to_dict() for ep in ri.endpoints],
                    js_analysis=ri.js_analysis,
                    dirbrute_result=ri.dirbrute_result,
                    nmap_result=ri.nmap_result,
                )
                test_plan = mapper.get_test_plan(site_profile)
                self._test_plan = test_plan
                _emit("testcase_map", test_plan)
                logger.info("Test plan: %d applicable tests across %d phases",
                            sum(len(v) for v in test_plan.get("phases", {}).values()),
                            len(test_plan.get("phases", {})))
            else:
                self._test_plan = None

            # Step 2c: Mind — prioritize endpoints
            if self.mind and self.state.endpoints:
                try:
                    ep_dicts = [
                        {"url": ep.url, "method": ep.method, "params": ep.params}
                        for ep in self.state.endpoints
                    ]
                    prioritized = self.mind.prioritize_targets(
                        ep_dicts, self.state.tech_signals,
                    )
                    url_order = {ep["url"]: i for i, ep in enumerate(prioritized)}
                    self.state.endpoints.sort(
                        key=lambda ep: url_order.get(ep.url, 999)
                    )
                    logger.info("Mind: reordered %d endpoints by attack priority",
                                len(self.state.endpoints))
                except Exception as e:
                    logger.warning("Mind prioritize_targets failed: %s", e)

            # Step 3: retrieve recipes
            logger.info("Step 3: Retrieving matching recipes")
            matched = self._retrieve_recipes()

            # Step 3b: Security headers audit
            if self.config.recon:
                logger.info("Step 3b: Running security headers audit")
                _emit = self.on_recon_phase or (lambda *a, **kw: None)
                _emit("headers_audit_start")
                header_scanner = HeaderScanner(self.client, self.config.attacker_session)
                header_result = await header_scanner.full_audit(target)
                self._header_audit = header_result
                # Convert header findings to candidates
                for hf in header_result.findings:
                    if hf.status == "fail":
                        candidate = Candidate(
                            recipe_id=f"auto:header-{hf.header.lower()}",
                            scanner="HeaderScanner",
                            endpoint=target,
                            method="GET",
                            evidence={
                                "technique": "security-header-missing",
                                "header": hf.header,
                                "detail": hf.detail,
                                "recommendation": hf.recommendation,
                                "owasp_ref": hf.owasp_ref,
                                "current_value": hf.current_value,
                            },
                            confidence="high" if hf.severity in ("high", "critical") else "medium",
                            request_data={
                                "url": target,
                                "method": "GET",
                                "param": hf.header,
                                "payload": "N/A",
                                "technique": "security-header-missing",
                            },
                            response_data={
                                "status": 200,
                                "body_snippet": f"{hf.header}: {hf.current_value or 'MISSING'}",
                            },
                        )
                        result = VerifyResult(
                            candidate=candidate,
                            verdict=Verdict.CONFIRMED,
                            replays=1,
                            reason=hf.detail,
                            evidence=candidate.evidence,
                        )
                        self.state.confirmed.append(result)
                        self.queue.add(result)
                        if self._on_finding:
                            self._on_finding(result)
                _emit("headers_audit", header_result)
                logger.info("Header audit: grade=%s, %d issues",
                            header_result.score, len([f for f in header_result.findings if f.status == "fail"]))
            else:
                self._header_audit = None

            # Step 4: scan
            logger.info("Step 4: Running scanners (%d recipes)", len(matched))
            _emit = self.on_recon_phase or (lambda *a, **kw: None)
            _emit("scan_start")
            await self._run_scanners(matched)

            # Step 4b: deduplicate candidates
            before = len(self.state.candidate_queue)
            self._dedup_candidates()
            after = len(self.state.candidate_queue)
            if before != after:
                logger.info("Dedup: %d → %d candidates", before, after)

            # Step 5: verify
            logger.info("Step 5: Verifying %d candidates",
                        len(self.state.candidate_queue))
            _emit("verify_start", len(self.state.candidate_queue))
            await self._verify_candidates()

            # Step 6: write human queue
            logger.info("Step 6: Writing human queue")
            self._write_human_queue()

            # Step 7: Mind — record engagement summary for learning
            if self.mind:
                try:
                    scanners_used = list({c.scanner for c in self.state.candidate_queue})
                    self.mind.record_engagement_summary(
                        target=target,
                        findings_count=len(self.state.confirmed),
                        tech_stack=self.state.tech_signals,
                        scanners_used=scanners_used,
                    )
                except Exception as e:
                    logger.warning("Mind record_engagement failed: %s", e)

            logger.info("Run complete: %s", self.state.summary())
            return self.state

        finally:
            # Don't close injected clients
            if self.config.log_path is None and self.client is not None:
                pass  # let caller manage lifecycle

    async def _build_inventory(self) -> None:
        """Build endpoint inventory from recon + config.

        If config.recon is True, runs the full automated recon pipeline
        (fingerprint → crawl → JS extract → param discovery) and merges
        results with any manually specified endpoints/signals.
        """
        if self.config.recon and self.client is not None:
            logger.info("Running automated recon pipeline")
            _emit = self.on_recon_phase or (lambda *a, **kw: None)
            _emit("phase_start", "Running automated recon pipeline")
            builder = InventoryBuilder(
                self.client,
                self.config.attacker_session,
                max_depth=self.config.crawl_depth,
                max_pages=self.config.crawl_max_pages,
                max_js_files=self.config.max_js_files,
                nmap_ports=self.config.nmap_ports,
                nmap_scan_type=self.config.nmap_scan_type,
                nmap_timeout=self.config.nmap_timeout,
                no_nmap=self.config.no_nmap,
                on_phase=_emit,
            )
            recon_inv = await builder.run(self.state.target)
            self._recon_inventory = recon_inv
            _emit("recon_summary", recon_inv)

            # ── Auth bypass discovery ────────────────────────────
            # If attacker session has no auth (unauthenticated scan),
            # try to find and exploit login form SQL injection.
            # On success: upgrade session → re-crawl authenticated →
            # merge new endpoints → scan everything (unauth + auth).
            if self._session_is_empty(self.config.attacker_session):
                logger.info("No auth provided — attempting login bypass discovery")
                _emit("auth_bypass_start")
                bypass = await self._attempt_auth_bypass(
                    recon_inv, self.state.target
                )
                if bypass is not None:
                    logger.info(
                        "AUTH BYPASS SUCCESS via %s on %s — session upgraded",
                        bypass.technique, bypass.login_url,
                    )
                    _emit("auth_bypass_success",
                          f"{bypass.technique} on {bypass.login_url}")
                    self.config.attacker_session = bypass.session
                    # Record as a confirmed finding
                    self._record_bypass_finding(bypass)

                    # ── Re-crawl with authenticated session ──────────
                    # Now that we have auth, re-run the full recon pipeline
                    # to discover post-login endpoints (dashboard, transfer,
                    # admin pages, etc.) that weren't visible unauthenticated.
                    logger.info("Re-running recon pipeline with authenticated session")
                    _emit("auth_recrawl")
                    auth_builder = InventoryBuilder(
                        self.client,
                        self.config.attacker_session,
                        max_depth=self.config.crawl_depth,
                        max_pages=self.config.crawl_max_pages,
                        max_js_files=self.config.max_js_files,
                    )
                    auth_inv = await auth_builder.run(self.state.target)

                    # Merge authenticated endpoints into the main inventory.
                    # Keep unauth endpoints too — some vulns are only on
                    # public pages, others only behind the login.
                    existing_urls = {ep.url for ep in recon_inv.endpoints}
                    new_count = 0
                    for ep in auth_inv.endpoints:
                        if ep.url not in existing_urls:
                            recon_inv.endpoints.append(ep)
                            existing_urls.add(ep.url)
                            new_count += 1

                    # Merge tech signals from authenticated crawl
                    auth_signals = set(auth_inv.tech_signals)
                    existing_signals = set(recon_inv.tech_signals)
                    for sig in auth_signals - existing_signals:
                        recon_inv.tech_signals.append(sig)

                    # Merge high-value params
                    existing_hvp = {p["name"] for p in recon_inv.high_value_params}
                    for p in auth_inv.high_value_params:
                        if p["name"] not in existing_hvp:
                            recon_inv.high_value_params.append(p)

                    logger.info(
                        "Authenticated recon found %d new endpoints "
                        "(total: %d unauth + %d auth = %d merged)",
                        new_count,
                        len(recon_inv.endpoints) - new_count,
                        new_count,
                        len(recon_inv.endpoints),
                    )

                    # ── Privilege escalation check ─────────────────
                    # Now that we have an authenticated session from bypass,
                    # check if it has admin/elevated privileges.
                    _emit("privesc_check")
                    logger.info("Checking for privilege escalation opportunities")
                    privesc = PrivilegeEscalationScanner(
                        self.client, self.config.attacker_session,
                    )
                    all_urls = [ep.url for ep in recon_inv.endpoints]
                    privesc_results = await privesc.check(
                        self.state.target, all_urls,
                    )
                    for pr in privesc_results:
                        logger.info(
                            "PRIVILEGE ESCALATION: %s — %s",
                            pr.escalation_type, pr.detail,
                        )
                        _emit("privesc_found", pr.detail)
                        self._record_privesc_finding(pr, bypass)
                    if not privesc_results:
                        logger.info("No privilege escalation found")

                else:
                    logger.info("Auth bypass discovery found no exploitable login")
                    _emit("auth_bypass_fail")

            # Convert recon endpoints to EndpointInfo (with classification data)
            _seen_eps: set[tuple[str, str]] = set()
            for ep in recon_inv.endpoints:
                for method in ep.methods:
                    if (ep.url, method) in _seen_eps:
                        continue
                    _seen_eps.add((ep.url, method))
                    param_names = [p["name"] for p in ep.params]
                    # Filter injection points for this method
                    method_points = [
                        pt for pt in ep.injection_points
                        if pt.get("method", method) == method
                    ]
                    self.state.endpoints.append(EndpointInfo(
                        url=ep.url,
                        method=method,
                        params=param_names,
                        tech_signals=recon_inv.tech_signals,
                        function=ep.function,
                        relevant_vulns=ep.relevant_vulns,
                        injection_points=method_points,
                    ))

            # Merge tech signals (recon + manual)
            signal_set = set(recon_inv.tech_signals)
            signal_set.update(self.config.tech_signals)
            self.state.tech_signals = sorted(signal_set)

            # Export inventory.json
            out_dir = pathlib.Path(self.config.output_dir)
            out_dir.mkdir(parents=True, exist_ok=True)
            InventoryBuilder.export_json(recon_inv, out_dir / "inventory.json")
            logger.info("Recon inventory exported to %s/inventory.json", out_dir)
        else:
            self._recon_inventory = None

        # Add manual endpoints (may supplement recon-discovered ones)
        if self.config.endpoints:
            for ep in self.config.endpoints:
                # Avoid duplicates by URL+method
                exists = any(
                    e.url == ep.url and e.method == ep.method
                    for e in self.state.endpoints
                )
                if not exists:
                    self.state.endpoints.append(ep)

        if self.config.tech_signals and not self.config.recon:
            self.state.tech_signals = list(self.config.tech_signals)

    # ── Auth bypass helpers ─────────────────────────────────────

    @staticmethod
    def _session_is_empty(session: Session | None) -> bool:
        """Return True if the session carries no authentication material."""
        if session is None:
            return True
        return (
            not session.jwt
            and not session.bearer
            and not session.jsessionid
            and not session.headers
            and not session.cookies
        )

    async def _attempt_auth_bypass(
        self,
        recon_inv: ReconInventory,
        target_url: str,
    ) -> BypassResult | None:
        """Run AuthBypassDiscovery against crawled login forms."""
        if recon_inv.crawl_result is None:
            return None
        discovery = AuthBypassDiscovery(self.client)
        return await discovery.run(recon_inv.crawl_result, target_url)

    def _record_bypass_finding(self, bypass: BypassResult) -> None:
        """Record a successful auth bypass as a confirmed finding."""
        # Build exact request string for the report
        parsed = urlparse(bypass.login_url)
        path = parsed.path or "/"
        form_fields = bypass.evidence.get("form_fields", {})
        # Use the actual field names from the login form
        uid_field = bypass.evidence.get("username_field", "uid")
        pw_field = bypass.evidence.get("password_field", "passw")
        body_data = dict(form_fields)
        body_data[uid_field] = bypass.payload_username
        body_data[pw_field] = bypass.payload_password
        body_str = urlencode(body_data)

        full_request = (
            f"POST {path} HTTP/1.1\n"
            f"Host: {parsed.hostname}\n"
            f"Content-Type: application/x-www-form-urlencoded\n"
            f"Content-Length: {len(body_str)}\n"
            f"\n"
            f"{body_str}"
        )

        # Use exact captured request/response from the bypass attempt
        full_request = bypass.evidence.get("full_request", full_request)
        resp_status = bypass.evidence.get("status_code", 302)
        full_response = bypass.evidence.get("full_response", f"HTTP/1.1 {resp_status}")

        candidate = Candidate(
            recipe_id="auto:auth-bypass",
            scanner="AuthBypassDiscovery",
            endpoint=bypass.login_url,
            method="POST",
            evidence={
                "technique": bypass.technique,
                "payload_username": bypass.payload_username,
                "payload_password": bypass.payload_password,
                "signals": bypass.evidence,
                "confidence": bypass.confidence,
                "uid_field": uid_field,
                "pw_field": pw_field,
            },
            confidence="high",
            request_data={
                "url": bypass.login_url,
                "method": "POST",
                "param": uid_field,
                "payload": bypass.payload_username,
                "id_location": "body",
                "sibling_fields": {pw_field: bypass.payload_password},
                "full_request": full_request,
                "technique": "auth-bypass",
            },
            response_data={
                "status": resp_status,
                "full_response": full_response,
            },
        )
        result = VerifyResult(
            candidate=candidate,
            verdict=Verdict.CONFIRMED,
            replays=1,
            reason=f"Login bypass via {bypass.technique}",
            evidence={
                "technique": bypass.technique,
                "signals": bypass.evidence,
                "session_cookies": (
                    list(bypass.session.cookies.keys())
                    if bypass.session else []
                ),
            },
        )
        self.state.confirmed.append(result)
        self.queue.add(result)
        if self._on_finding:
            self._on_finding(result)
        logger.info(
            "Recorded auth bypass finding: %s on %s",
            bypass.technique, bypass.login_url,
        )

    def _record_privesc_finding(self, pr: Any, bypass: BypassResult) -> None:
        """Record a privilege escalation finding as a confirmed finding."""
        evidence = pr.evidence or {}
        url = evidence.get("url", bypass.login_url)
        status = evidence.get("status", evidence.get("auth_status", 200))

        candidate = Candidate(
            recipe_id=f"auto:privesc-{pr.escalation_type}",
            scanner="PrivilegeEscalationScanner",
            endpoint=url,
            method="GET",
            evidence={
                "escalation_type": pr.escalation_type,
                "detail": pr.detail,
                "bypass_technique": bypass.technique,
                "bypass_login_url": bypass.login_url,
                **evidence,
            },
            confidence=pr.confidence,
            request_data={
                "url": url,
                "method": "GET",
                "via_bypass": bypass.technique,
            },
            response_data={
                "status": status,
                "body_snippet": evidence.get("body_snippet", ""),
            },
        )
        result = VerifyResult(
            candidate=candidate,
            verdict=Verdict.CONFIRMED,
            replays=1,
            reason=pr.detail,
            evidence=evidence,
        )
        self.state.confirmed.append(result)
        self.queue.add(result)
        if self._on_finding:
            self._on_finding(result)
        logger.info("Recorded privesc finding: %s", pr.detail)

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
            # Fallback: if signals exist but nothing matched, use all recipes
            # (small corpus — better to over-scan than miss vulns)
            if not results and self.retriever.recipes:
                logger.info("No exact signal match — falling back to all %d recipes",
                            len(self.retriever.recipes))
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

        self.state.recipes_matched = len(results)
        return results

    async def _run_scanners(self, matched: list[RetrievalResult]) -> None:
        """Run the appropriate scanner for each matched recipe × endpoint.

        Smart routing: if endpoints have classification data, only run
        scanners whose vuln class is relevant to that endpoint's function.
        If no classification, fall back to running all matched scanners.
        """
        for rr in matched:
            recipe = rr.recipe
            scanner_cls = self.registry.get_for_recipe(recipe)
            if scanner_cls is None:
                logger.debug("No scanner for recipe %s — skipped", recipe.id)
                continue

            # Determine the vuln class this scanner handles
            recipe_vuln_class = recipe.id.lower().split("-")[0]  # e.g. "sqli" from "sqli-error"

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
                # Smart routing: skip if endpoint has classification and
                # this vuln class is NOT relevant to it
                if ep.relevant_vulns and recipe_vuln_class not in ep.relevant_vulns:
                    # Also check scanner's vuln_classes list
                    scanner_vulns = getattr(scanner_cls, "vuln_classes", [])
                    if not any(vc in ep.relevant_vulns for vc in scanner_vulns):
                        logger.debug(
                            "Skipping %s on %s — not relevant (function=%s, vulns=%s)",
                            recipe.id, ep.url, ep.function, ep.relevant_vulns
                        )
                        continue

                # Skip static pages entirely
                if ep.function == "static_page":
                    logger.debug("Skipping static page %s", ep.url)
                    continue

                try:
                    candidates = await scanner.detect(
                        ep.url,
                        recipe,
                        victim_ids=self.config.victim_ids,
                        id_param=self.config.id_param,
                        id_location=self.config.id_location or ("body" if ep.method in ("POST", "PUT", "PATCH") else "query"),
                        params=ep.params,
                        method=ep.method,
                        injection_points=ep.injection_points,
                    )
                    self.state.candidate_queue.extend(candidates)
                    self.state.scans_run += 1
                except Exception as exc:
                    logger.error("Scanner error on %s: %s", ep.url, exc)

    def _dedup_candidates(self) -> None:
        """Deduplicate candidates by (base_path, param, scanner).

        Multiple crawled URLs like /index.jsp?content=A and /index.jsp?content=B
        produce separate candidates for the same vuln. Keep only the first
        representative per unique group.
        """
        seen: dict[tuple, int] = {}
        deduped: list[Candidate] = []

        for c in self.state.candidate_queue:
            # Extract base path (without query string)
            parsed = urlparse(c.endpoint)
            base_path = parsed.path or "/"

            # Extract param name from request_data
            param = c.request_data.get("param", c.request_data.get("id_param", ""))

            key = (base_path, param, c.scanner)
            if key not in seen:
                seen[key] = len(deduped)
                deduped.append(c)
            else:
                # Keep the one with higher confidence
                existing = deduped[seen[key]]
                conf_rank = {"high": 3, "medium": 2, "low": 1}
                if conf_rank.get(c.confidence, 0) > conf_rank.get(existing.confidence, 0):
                    deduped[seen[key]] = c

        self.state.candidate_queue = deduped

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
        # Single-session scanners
        if scanner_cls in (SqliScanner, XssScanner, SsrfScanner,
                           NosqliScanner, SstiScanner, CmdiScanner, LfiScanner,
                           CsrfScanner, StoredXssScanner, OpenRedirectScanner,
                           BruteforceScanner, HeaderScanner):
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
                    if self._on_finding:
                        self._on_finding(result)
                    if self.mind:
                        self.mind.record_finding(
                            candidate.scanner, success=True,
                            tech_stack=",".join(self.state.tech_signals[:3]),
                            details={"endpoint": candidate.endpoint,
                                     "method": candidate.method},
                        )
                elif result.verdict == Verdict.NEEDS_HUMAN:
                    self.state.needs_human.append(result)
                    if self._on_finding:
                        self._on_finding(result)
                else:
                    self.state.false_positives.append(result)
                    if self.mind:
                        self.mind.record_finding(
                            candidate.scanner, success=False,
                            tech_stack=",".join(self.state.tech_signals[:3]),
                        )

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
            # Prefer Playwright for XSS verification (real browser = no FP)
            try:
                import playwright  # noqa: F401
                return PlaywrightXssVerifier(self.client)
            except ImportError:
                return XssVerifier(self.client, self.config.attacker_session)
        if candidate.scanner == "SsrfScanner":
            return SsrfVerifier(self.client, self.config.attacker_session)
        # Scanners with built-in verification chains (NoSQLi, SSTI, CMDi, LFI)
        # don't need an external verifier — their detection IS the verification.
        # Return a PassthroughVerifier that confirms based on scanner confidence.
        if candidate.scanner in ("NosqliScanner", "SstiScanner",
                                 "CmdiScanner", "LfiScanner",
                                 "CsrfScanner", "StoredXssScanner",
                                 "OpenRedirectScanner",
                                 "BruteforceScanner", "HeaderScanner"):
            return _PassthroughVerifier(self.client)
        return None

    def _write_human_queue(self) -> None:
        """Write confirmed + needs_human findings to the queue file."""
        for result in self.state.confirmed:
            self.queue.add(result)
        for result in self.state.needs_human:
            self.queue.add(result)
        self.queue.write_summary(self.state)
