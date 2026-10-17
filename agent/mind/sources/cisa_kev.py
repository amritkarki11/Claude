"""CISA KEV (Known Exploited Vulnerabilities) feed.

The KEV catalog lists CVEs that are actively exploited in the wild.
These are highest-priority targets: if the agent finds a tech stack
matching a KEV entry, it should test for that CVE first.

The catalog is a single JSON file updated daily by CISA.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime

import httpx

logger = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


@dataclass
class KEVEntry:
    """One actively-exploited vulnerability from CISA's catalog."""
    cve_id: str
    vendor: str
    product: str
    name: str
    description: str
    date_added: str
    due_date: str
    known_ransomware_use: bool
    notes: str

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "vendor": self.vendor,
            "product": self.product,
            "name": self.name,
            "description": self.description,
            "date_added": self.date_added,
            "due_date": self.due_date,
            "known_ransomware_use": self.known_ransomware_use,
            "notes": self.notes,
            "tags": [
                self.vendor.lower(),
                self.product.lower(),
                "actively-exploited",
                "cisa-kev",
            ] + (["ransomware"] if self.known_ransomware_use else []),
        }


class CISAKEVFeed:
    """Fetches the CISA Known Exploited Vulnerabilities catalog."""

    async def fetch_all(self) -> list[KEVEntry]:
        """Download the full KEV catalog."""
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                resp = await client.get(KEV_URL)
                resp.raise_for_status()
                data = resp.json()
            except (httpx.HTTPError, ValueError) as e:
                logger.warning("CISA KEV fetch error: %s", e)
                return []

        entries = []
        for vuln in data.get("vulnerabilities", []):
            entry = KEVEntry(
                cve_id=vuln.get("cveID", ""),
                vendor=vuln.get("vendorProject", ""),
                product=vuln.get("product", ""),
                name=vuln.get("vulnerabilityName", ""),
                description=vuln.get("shortDescription", ""),
                date_added=vuln.get("dateAdded", ""),
                due_date=vuln.get("dueDate", ""),
                known_ransomware_use=vuln.get("knownRansomwareCampaignUse", "Unknown") == "Known",
                notes=vuln.get("notes", ""),
            )
            if entry.cve_id:
                entries.append(entry)

        logger.info("CISA KEV: fetched %d entries", len(entries))
        return entries

    async def fetch_recent(self, days: int = 7) -> list[KEVEntry]:
        """Fetch KEV entries added in the last N days."""
        all_entries = await self.fetch_all()
        cutoff = datetime.now().strftime("%Y-%m-%d")
        # Simple date string comparison works because format is YYYY-MM-DD
        from datetime import timedelta
        cutoff_date = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
        return [e for e in all_entries if e.date_added >= cutoff_date]

    async def search(self, vendor: str = "", product: str = "") -> list[KEVEntry]:
        """Search KEV by vendor and/or product name."""
        all_entries = await self.fetch_all()
        results = []
        for e in all_entries:
            if vendor and vendor.lower() not in e.vendor.lower():
                continue
            if product and product.lower() not in e.product.lower():
                continue
            results.append(e)
        return results
