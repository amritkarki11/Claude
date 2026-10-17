"""Recon Inventory Builder (Phase 2.5).

Combines output from all recon modules (crawler, JS extractor, param
discovery, fingerprinting) into a single normalized inventory that the
orchestrator consumes. Can also export to inventory.json for external tools.

Usage:
    builder = InventoryBuilder(client, session)
    inventory = await builder.run("https://target.example.com")
    builder.export_json(inventory, "outputs/inventory.json")
"""
from __future__ import annotations

import json
import logging
import pathlib
from dataclasses import dataclass, field, asdict
from typing import Any
from urllib.parse import urljoin

from ..http import HttpClient, Session
from .crawler import Crawler, CrawlResult
from .js_extractor import JsExtractor, JsExtractionResult
from .param_discovery import ParamDiscoverer, ParamInventory
from .fingerprint import Fingerprinter, FingerprintResult
from .classifier import EndpointClassifier, ClassifiedEndpoint, EndpointFunction
from .nmap_scanner import NmapScanner, ExploitLookup, NmapResult
from .js_analyzer import JsAnalyzer, JsAnalysisResult
from .dirbrute import DirBrute, DirbruteResult

logger = logging.getLogger(__name__)


# ── Data classes ──────────────────────────────────────────────


@dataclass
class InventoryEndpoint:
    """A discovered endpoint with params, methods, and metadata."""
    url: str
    methods: list[str] = field(default_factory=list)
    params: list[dict] = field(default_factory=list)  # [{name, type, score, sources}]
    sources: list[str] = field(default_factory=list)   # where discovered
    notes: str = ""
    # Functionality classification
    function: str = "unknown"              # EndpointFunction value
    function_confidence: float = 0.0
    relevant_vulns: list[str] = field(default_factory=list)
    injection_points: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "methods": self.methods,
            "params": self.params,
            "sources": self.sources,
            "notes": self.notes,
            "function": self.function,
            "function_confidence": self.function_confidence,
            "relevant_vulns": self.relevant_vulns,
            "injection_points": self.injection_points,
        }


@dataclass
class ReconInventory:
    """Normalized output from the entire recon pipeline."""
    target: str
    endpoints: list[InventoryEndpoint] = field(default_factory=list)
    tech_signals: list[str] = field(default_factory=list)
    security_headers: list[str] = field(default_factory=list)
    waf_detected: list[str] = field(default_factory=list)
    forms_found: int = 0
    js_files_analyzed: int = 0
    pages_crawled: int = 0
    high_value_params: list[dict] = field(default_factory=list)

    # Raw sub-results (kept for debugging / re-analysis)
    crawl_result: CrawlResult | None = field(default=None, repr=False)
    js_result: JsExtractionResult | None = field(default=None, repr=False)
    js_analysis: JsAnalysisResult | None = field(default=None, repr=False)
    dirbrute_result: DirbruteResult | None = field(default=None, repr=False)
    param_inventory: ParamInventory | None = field(default=None, repr=False)
    fingerprint_result: FingerprintResult | None = field(default=None, repr=False)
    nmap_result: NmapResult | None = field(default=None, repr=False)

    def summary(self) -> dict:
        soft_404s = self.crawl_result.soft_404_count if self.crawl_result else 0
        return {
            "target": self.target,
            "endpoints": len(self.endpoints),
            "tech_signals": self.tech_signals,
            "security_headers": self.security_headers,
            "waf": self.waf_detected,
            "pages_crawled": self.pages_crawled,
            "soft_404s_filtered": soft_404s,
            "forms_found": self.forms_found,
            "js_files_analyzed": self.js_files_analyzed,
            "high_value_params": len(self.high_value_params),
        }

    def to_dict(self) -> dict:
        """Serialize to a JSON-compatible dict (no raw sub-results)."""
        return {
            "target": self.target,
            "endpoints": [ep.to_dict() for ep in self.endpoints],
            "tech_signals": self.tech_signals,
            "security_headers": self.security_headers,
            "waf_detected": self.waf_detected,
            "forms_found": self.forms_found,
            "js_files_analyzed": self.js_files_analyzed,
            "pages_crawled": self.pages_crawled,
            "high_value_params": self.high_value_params,
            "summary": self.summary(),
        }


# ── Inventory Builder ─────────────────────────────────────────


class InventoryBuilder:
    """Runs the full recon pipeline and produces a ReconInventory.

    Pipeline:
      1. Fingerprint (tech detection — informs recipe matching)
      2. Crawl (page discovery, form extraction)
      3. JS extraction (API endpoint discovery)
      4. Param discovery (merge + type inference + scoring)
      5. Normalize into ReconInventory
    """

    def __init__(
        self,
        client: HttpClient,
        session: Session | None = None,
        *,
        max_depth: int = 3,
        max_pages: int = 100,
        max_js_files: int = 50,
        probe_extras: bool = True,
        nmap_ports: str = "1-10000",
        nmap_scan_type: str = "-sV -sC",
        nmap_timeout: int = 300,
        no_nmap: bool = False,
        on_phase: Any = None,
    ):
        self.client = client
        self.session = session
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.max_js_files = max_js_files
        self.probe_extras = probe_extras
        self.nmap_ports = nmap_ports
        self.nmap_scan_type = nmap_scan_type
        self.nmap_timeout = nmap_timeout
        self.no_nmap = no_nmap
        self._emit = on_phase or (lambda *a, **kw: None)

    async def run(self, target_url: str) -> ReconInventory:
        """Execute the full recon pipeline on the target."""
        inventory = ReconInventory(target=target_url)

        # Step 0: Nmap port scan (runs on the hostname)
        from urllib.parse import urlparse as _urlparse
        if not self.no_nmap:
            logger.info("Recon: nmap scan on %s", target_url)
            hostname = _urlparse(target_url).hostname or target_url
            nmap = NmapScanner(hostname, ports=self.nmap_ports,
                               scan_type=self.nmap_scan_type,
                               timeout=self.nmap_timeout)
            nmap_result = await nmap.scan()
            if nmap_result.services:
                ExploitLookup.check_outdated(nmap_result.services)
                await ExploitLookup.searchsploit(nmap_result.services)
            inventory.nmap_result = nmap_result
            logger.info("Nmap: %d open ports found", len(nmap_result.open_ports))
            self._emit("nmap", nmap_result)
        else:
            logger.info("Nmap scanning disabled (--no-nmap)")

        # Step 1: Fingerprint
        logger.info("Recon: fingerprinting %s", target_url)
        fp = Fingerprinter(self.client, self.session)
        fp_result = await fp.fingerprint(target_url, probe_extras=self.probe_extras)
        inventory.fingerprint_result = fp_result
        inventory.tech_signals = fp_result.signal_list
        inventory.security_headers = fp_result.security_headers
        inventory.waf_detected = fp_result.waf_detected
        self._emit("fingerprint", fp_result)

        # Step 2: Crawl
        logger.info("Recon: crawling %s (depth=%d, max=%d)",
                     target_url, self.max_depth, self.max_pages)
        crawler = Crawler(
            self.client, self.session,
            base_url=target_url,
            max_depth=self.max_depth,
            max_pages=self.max_pages,
        )
        crawl_result = await crawler.crawl()
        inventory.crawl_result = crawl_result
        inventory.pages_crawled = crawl_result.urls_visited
        inventory.forms_found = crawl_result.forms_found
        if crawl_result.soft_404_count:
            logger.info("Recon: detected %d soft-404 pages (filtered from inventory)",
                        crawl_result.soft_404_count)
        self._emit("crawl", crawl_result)

        # Step 3: JS extraction
        logger.info("Recon: extracting JS endpoints from %s", target_url)
        js_ext = JsExtractor(
            self.client, self.session,
            max_js_files=self.max_js_files,
        )
        js_result = await js_ext.extract(target_url)
        inventory.js_result = js_result
        inventory.js_files_analyzed = js_result.js_files_fetched
        self._emit("js_extract", js_result)

        # Step 3b: JS sensitive data analysis
        logger.info("Recon: analyzing JS files for secrets & source maps")
        js_urls = [ep.source_file for ep in js_result.endpoints] if js_result.endpoints else None
        # Also grab JS URLs from crawled pages
        if crawl_result and crawl_result.pages:
            crawl_js = []
            for page in crawl_result.pages:
                for link in page.links:
                    if link.endswith(".js") or ".js?" in link:
                        crawl_js.append(link)
            if crawl_js:
                js_urls = list(set((js_urls or []) + crawl_js))
        js_analyzer = JsAnalyzer(self.client, self.session, max_js_files=self.max_js_files)
        js_analysis = await js_analyzer.analyze(target_url, js_urls)
        inventory.js_analysis = js_analysis
        if js_analysis.findings:
            logger.info("JS analysis: %d sensitive findings (%d critical)",
                        len(js_analysis.findings), len(js_analysis.critical_findings()))
        self._emit("js_analysis", js_analysis)

        # Step 3c: Directory bruteforce
        logger.info("Recon: directory bruteforce on %s", target_url)
        dirbrute = DirBrute(self.client, self.session, concurrency=10)
        dirbrute_result = await dirbrute.scan(target_url)
        inventory.dirbrute_result = dirbrute_result
        if dirbrute_result.findings:
            logger.info("Dirbrute: %d paths found", len(dirbrute_result.findings))
        self._emit("dirbrute", dirbrute_result)

        # Step 4: Param discovery
        logger.info("Recon: discovering params")
        discoverer = ParamDiscoverer()
        discoverer.add_crawl_result(crawl_result)
        discoverer.add_js_result(js_result)

        # Also add URLs from crawled pages
        for page in crawl_result.pages:
            for link in page.links:
                discoverer.add_url(link)

        param_inv = discoverer.build_inventory()
        inventory.param_inventory = param_inv

        # Step 5: Normalize into endpoints
        inventory.endpoints = self._build_endpoints(
            crawl_result, js_result, param_inv, target_url
        )
        inventory.high_value_params = [
            {"name": p.name, "type": p.param_type, "score": p.security_score}
            for p in param_inv.high_value_params
        ]
        self._emit("params", param_inv)

        # Step 6: Classify endpoints by functionality
        logger.info("Recon: classifying endpoint functionality")
        self._classify_endpoints(inventory, crawl_result)

        self._emit("classify", inventory.endpoints)
        logger.info("Recon complete: %s", inventory.summary())
        return inventory

    def _build_endpoints(
        self,
        crawl: CrawlResult,
        js: JsExtractionResult,
        params: ParamInventory,
        target_url: str,
    ) -> list[InventoryEndpoint]:
        """Merge crawl + JS + param results into unified endpoint list.

        Filters out soft-404 pages and their forms — endpoints that returned
        200 but whose body indicates 'not found' are ghost endpoints and
        should not enter the scan pipeline.
        """
        ep_map: dict[str, InventoryEndpoint] = {}

        # Build set of soft-404 URLs so we can filter forms sourced from them
        soft_404_urls = {p.url for p in crawl.pages if p.is_soft_404}
        if soft_404_urls:
            logger.info("Filtering %d soft-404 URLs from endpoint inventory",
                        len(soft_404_urls))

        # From crawler: forms and page URLs (skip soft-404 sourced forms)
        for form in crawl.all_forms:
            # Skip forms discovered on soft-404 pages
            if form.source_page in soft_404_urls:
                logger.debug("Skipping form %s from soft-404 page %s",
                             form.action, form.source_page)
                continue
            if form.action in soft_404_urls:
                logger.debug("Skipping form action %s — soft-404 URL", form.action)
                continue

            # Register the form action URL as an endpoint
            key = form.action
            ep = ep_map.get(key)
            if ep is None:
                ep = InventoryEndpoint(url=key, sources=["crawler"])
                ep_map[key] = ep
            elif "crawler" not in ep.sources:
                ep.sources.append("crawler")
            if form.method not in ep.methods:
                ep.methods.append(form.method)

            # Also register the source page (e.g. login.jsp) as an endpoint
            # with the same params — the source page is where the form lives
            # and some apps process the form submission at the same URL
            if form.source_page and form.source_page != form.action:
                src_key = form.source_page
                src_ep = ep_map.get(src_key)
                if src_ep is None:
                    src_ep = InventoryEndpoint(url=src_key, sources=["crawler"])
                    ep_map[src_key] = src_ep
                elif "crawler" not in src_ep.sources:
                    src_ep.sources.append("crawler")
                if "GET" not in src_ep.methods:
                    src_ep.methods.append("GET")

        # From JS extractor
        base = target_url.rstrip("/")
        for js_ep in js.endpoints:
            # JS paths are relative — resolve against target
            url = js_ep.path if js_ep.path.startswith("http") else f"{base}{js_ep.path}"
            key = url
            ep = ep_map.get(key)
            if ep is None:
                ep = InventoryEndpoint(url=key, sources=["js_extractor"])
                ep_map[key] = ep
            elif "js_extractor" not in ep.sources:
                ep.sources.append("js_extractor")
            if js_ep.method not in ep.methods:
                ep.methods.append(js_ep.method)

        # From crawled page links (non-form URLs with query params)
        for page in crawl.pages:
            # Skip soft-404 pages
            if page.is_soft_404:
                continue
            if "?" in page.url:
                key = page.url.split("?")[0]
                ep = ep_map.get(key)
                if ep is None:
                    ep = InventoryEndpoint(url=key, sources=["crawler"])
                    ep_map[key] = ep
                elif "crawler" not in ep.sources:
                    ep.sources.append("crawler")
                if "GET" not in ep.methods:
                    ep.methods.append("GET")

        # Attach params from param inventory
        for ep_params in params.endpoints:
            key = ep_params.url
            ep = ep_map.get(key)
            if ep is None:
                ep = InventoryEndpoint(url=key, sources=[ep_params.source])
                ep_map[key] = ep
            if ep_params.method and ep_params.method not in ep.methods:
                ep.methods.append(ep_params.method)
            for pi in ep_params.params:
                # Check if param already in the list
                if not any(p["name"] == pi.name for p in ep.params):
                    ep.params.append({
                        "name": pi.name,
                        "type": pi.param_type,
                        "score": pi.security_score,
                        "sources": pi.sources,
                    })

        # Default method to GET if none detected
        for ep in ep_map.values():
            if not ep.methods:
                ep.methods.append("GET")

        return sorted(ep_map.values(), key=lambda e: e.url)

    def _classify_endpoints(
        self,
        inventory: ReconInventory,
        crawl: CrawlResult,
    ) -> None:
        """Classify each endpoint by functional role and attach injection points."""
        classifier = EndpointClassifier()

        # Build lookup maps from crawl data
        crawl_pages: dict[str, Any] = {}
        forms_by_action: dict[str, list] = {}
        if crawl:
            for page in crawl.pages:
                # Skip soft-404 pages from classification context
                if page.is_soft_404:
                    continue
                crawl_pages[page.url] = page
                for form in page.forms:
                    forms_by_action.setdefault(form.action, []).append(form)
                    # Also index by source page URL
                    if form.source_page:
                        forms_by_action.setdefault(form.source_page, []).append(form)

        for ep in inventory.endpoints:
            forms = forms_by_action.get(ep.url, [])
            page = crawl_pages.get(ep.url)

            classified = classifier.classify_endpoint(
                ep.url,
                methods=ep.methods,
                params=ep.params,
                forms=forms,
                page=page,
            )

            ep.function = classified.function.value
            ep.function_confidence = classified.confidence
            ep.relevant_vulns = classified.relevant_vulns
            ep.injection_points = classified.injection_points

            logger.debug("Classified %s → %s (%.0f%%) vulns=%s points=%d",
                         ep.url, ep.function, ep.function_confidence * 100,
                         ep.relevant_vulns, len(ep.injection_points))

    @staticmethod
    def export_json(
        inventory: ReconInventory,
        path: str | pathlib.Path,
    ) -> pathlib.Path:
        """Write inventory to a JSON file."""
        p = pathlib.Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("w", encoding="utf-8") as f:
            json.dump(inventory.to_dict(), f, indent=2)
        return p
