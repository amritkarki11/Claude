"""NVD (National Vulnerability Database) feed — CVE intelligence.

Fetches recent CVEs from the NVD 2.0 API, extracts structured data
(severity, affected products, description, references), and stores
them in the agent's memory for tech-stack-aware scanning.

Rate limit: NVD public API allows 5 requests per 30 seconds without
an API key, 50/30s with a key. We respect this with built-in throttling.
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

logger = logging.getLogger(__name__)

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_LOOKBACK_DAYS = 7
MAX_RESULTS_PER_PAGE = 100


@dataclass
class CVERecord:
    """Structured CVE data extracted from NVD."""
    cve_id: str
    description: str
    severity: str              # critical / high / medium / low / unknown
    cvss_score: float | None
    cvss_vector: str
    published: str
    last_modified: str
    affected_products: list[dict[str, str]]  # [{vendor, product, version}]
    references: list[str]
    weaknesses: list[str]      # CWE IDs
    tags: list[str]

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "published": self.published,
            "last_modified": self.last_modified,
            "affected_products": self.affected_products,
            "references": self.references,
            "weaknesses": self.weaknesses,
            "tags": self.tags,
        }


class NVDFeed:
    """Fetches and parses CVEs from the NVD 2.0 API."""

    def __init__(self, api_key: str | None = None):
        self.api_key = api_key
        self._last_request: float = 0.0
        self._min_interval = 6.0 if not api_key else 0.6  # respect rate limits

    async def fetch_recent(self, days: int = DEFAULT_LOOKBACK_DAYS,
                           keyword: str | None = None,
                           max_results: int = 200) -> list[CVERecord]:
        """Fetch CVEs published or modified in the last N days."""
        now = datetime.now(timezone.utc)
        start = now - timedelta(days=days)

        params: dict[str, Any] = {
            "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": min(max_results, MAX_RESULTS_PER_PAGE),
        }
        if keyword:
            params["keywordSearch"] = keyword

        records: list[CVERecord] = []
        start_index = 0

        async with httpx.AsyncClient(timeout=30.0) as client:
            while len(records) < max_results:
                params["startIndex"] = start_index
                await self._throttle()

                headers = {}
                if self.api_key:
                    headers["apiKey"] = self.api_key

                try:
                    resp = await client.get(NVD_API_BASE, params=params, headers=headers)
                    resp.raise_for_status()
                    data = resp.json()
                except (httpx.HTTPError, ValueError) as e:
                    logger.warning("NVD API error: %s", e)
                    break

                vulnerabilities = data.get("vulnerabilities", [])
                if not vulnerabilities:
                    break

                for vuln in vulnerabilities:
                    record = self._parse_cve(vuln.get("cve", {}))
                    if record:
                        records.append(record)

                total_results = data.get("totalResults", 0)
                start_index += len(vulnerabilities)
                if start_index >= total_results:
                    break

        logger.info("NVD: fetched %d CVEs (last %d days)", len(records), days)
        return records

    async def fetch_by_cpe(self, cpe_name: str, max_results: int = 50) -> list[CVERecord]:
        """Fetch CVEs affecting a specific CPE (Common Platform Enumeration)."""
        params: dict[str, Any] = {
            "cpeName": cpe_name,
            "resultsPerPage": min(max_results, MAX_RESULTS_PER_PAGE),
        }
        records: list[CVERecord] = []

        async with httpx.AsyncClient(timeout=30.0) as client:
            await self._throttle()
            headers = {}
            if self.api_key:
                headers["apiKey"] = self.api_key

            try:
                resp = await client.get(NVD_API_BASE, params=params, headers=headers)
                resp.raise_for_status()
                data = resp.json()
            except (httpx.HTTPError, ValueError) as e:
                logger.warning("NVD CPE query error: %s", e)
                return records

            for vuln in data.get("vulnerabilities", []):
                record = self._parse_cve(vuln.get("cve", {}))
                if record:
                    records.append(record)

        return records

    async def fetch_by_keyword(self, keyword: str, days: int = 30,
                               max_results: int = 100) -> list[CVERecord]:
        """Search CVEs by keyword (product name, vuln type, etc.)."""
        return await self.fetch_recent(days=days, keyword=keyword, max_results=max_results)

    def _parse_cve(self, cve: dict) -> CVERecord | None:
        """Parse a raw NVD CVE entry into a structured record."""
        cve_id = cve.get("id", "")
        if not cve_id:
            return None

        # Description (English preferred)
        descriptions = cve.get("descriptions", [])
        desc = ""
        for d in descriptions:
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        if not desc and descriptions:
            desc = descriptions[0].get("value", "")

        # CVSS scoring — try v3.1 first, then v3.0, then v2.0
        severity = "unknown"
        cvss_score = None
        cvss_vector = ""

        metrics = cve.get("metrics", {})
        for version_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            metric_list = metrics.get(version_key, [])
            if metric_list:
                primary = metric_list[0]
                cvss_data = primary.get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_vector = cvss_data.get("vectorString", "")
                severity = primary.get("baseSeverity",
                                       cvss_data.get("baseSeverity", "unknown")).lower()
                break

        # Affected products from CPE matches
        affected = []
        configurations = cve.get("configurations", [])
        for config in configurations:
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    cpe = match.get("criteria", "")
                    parts = cpe.split(":")
                    if len(parts) >= 5:
                        affected.append({
                            "vendor": parts[3],
                            "product": parts[4],
                            "version": parts[5] if len(parts) > 5 else "*",
                        })

        # References
        refs = [r.get("url", "") for r in cve.get("references", []) if r.get("url")]

        # Weaknesses (CWE)
        weaknesses = []
        for w in cve.get("weaknesses", []):
            for wd in w.get("description", []):
                val = wd.get("value", "")
                if val.startswith("CWE-"):
                    weaknesses.append(val)

        # Build tags for searchability
        tags = list(weaknesses)
        for a in affected:
            tags.append(a["vendor"])
            tags.append(a["product"])
        if severity != "unknown":
            tags.append(f"severity:{severity}")
        if cvss_score and cvss_score >= 9.0:
            tags.append("critical-cvss")

        return CVERecord(
            cve_id=cve_id,
            description=desc,
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            published=cve.get("published", ""),
            last_modified=cve.get("lastModified", ""),
            affected_products=affected,
            references=refs,
            weaknesses=weaknesses,
            tags=tags,
        )

    async def _throttle(self) -> None:
        """Respect NVD rate limits."""
        elapsed = time.monotonic() - self._last_request
        if elapsed < self._min_interval:
            await asyncio.sleep(self._min_interval - elapsed)
        self._last_request = time.monotonic()
