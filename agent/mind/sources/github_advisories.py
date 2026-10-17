"""GitHub Security Advisories feed.

GitHub's advisory database covers vulnerabilities in open-source packages
across all ecosystems (npm, PyPI, Maven, Go, Rust, etc.). This is valuable
for identifying vulnerabilities in the target's dependencies.

Uses the public GraphQL API (no auth needed for public advisories).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import httpx

logger = logging.getLogger(__name__)

GITHUB_GRAPHQL_URL = "https://api.github.com/graphql"
# Public REST API fallback (no auth needed)
GITHUB_ADVISORIES_REST = "https://api.github.com/advisories"


@dataclass
class GitHubAdvisory:
    """One security advisory from GitHub."""
    ghsa_id: str
    cve_id: str | None
    summary: str
    description: str
    severity: str
    published_at: str
    updated_at: str
    affected_packages: list[dict[str, str]]  # [{ecosystem, name, vulnerable_versions}]
    references: list[str]
    cwes: list[str]

    def to_dict(self) -> dict:
        tags = [self.severity.lower()] if self.severity else []
        for pkg in self.affected_packages:
            if pkg.get("ecosystem"):
                tags.append(pkg["ecosystem"].lower())
            if pkg.get("name"):
                tags.append(pkg["name"].lower())
        tags.extend(self.cwes)
        if self.cve_id:
            tags.append(self.cve_id.lower())
        return {
            "ghsa_id": self.ghsa_id,
            "cve_id": self.cve_id,
            "summary": self.summary,
            "description": self.description,
            "severity": self.severity,
            "published_at": self.published_at,
            "updated_at": self.updated_at,
            "affected_packages": self.affected_packages,
            "references": self.references,
            "cwes": self.cwes,
            "tags": tags,
            "source": "github-advisories",
        }


class GitHubAdvisoryFeed:
    """Fetches security advisories from GitHub's public API."""

    def __init__(self, token: str | None = None):
        self.token = token

    async def fetch_recent(self, days: int = 7, severity: str = "",
                           ecosystem: str = "",
                           max_results: int = 100) -> list[GitHubAdvisory]:
        """Fetch advisories published in the last N days."""
        since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")

        params: dict[str, str | int] = {
            "per_page": min(max_results, 100),
            "sort": "published",
            "direction": "desc",
        }
        if severity:
            params["severity"] = severity.lower()
        if ecosystem:
            params["ecosystem"] = ecosystem.lower()

        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        advisories: list[GitHubAdvisory] = []

        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                resp = await client.get(GITHUB_ADVISORIES_REST, params=params, headers=headers)
                resp.raise_for_status()
                data = resp.json()
            except (httpx.HTTPError, ValueError) as e:
                logger.warning("GitHub advisories fetch error: %s", e)
                return advisories

            if not isinstance(data, list):
                return advisories

            for item in data:
                advisory = self._parse_advisory(item)
                if advisory and advisory.published_at >= since:
                    advisories.append(advisory)

        logger.info("GitHub advisories: fetched %d (last %d days)", len(advisories), days)
        return advisories

    async def search(self, keyword: str, ecosystem: str = "",
                     limit: int = 50) -> list[GitHubAdvisory]:
        """Search advisories by keyword."""
        # The REST API doesn't have a keyword search, so we fetch recent
        # and filter locally
        all_recent = await self.fetch_recent(days=90, ecosystem=ecosystem, max_results=100)
        keyword_lower = keyword.lower()
        results = [
            a for a in all_recent
            if keyword_lower in a.summary.lower() or keyword_lower in a.description.lower()
        ]
        return results[:limit]

    def _parse_advisory(self, item: dict) -> GitHubAdvisory | None:
        """Parse a raw GitHub advisory response."""
        ghsa_id = item.get("ghsa_id", "")
        if not ghsa_id:
            return None

        # Extract affected packages
        affected = []
        for vuln in item.get("vulnerabilities", []):
            pkg = vuln.get("package", {})
            affected.append({
                "ecosystem": pkg.get("ecosystem", ""),
                "name": pkg.get("name", ""),
                "vulnerable_versions": vuln.get("vulnerable_version_range", ""),
                "patched_versions": vuln.get("first_patched_version", {}).get("identifier", ""),
            })

        # Extract CWEs
        cwes = [c.get("cwe_id", "") for c in item.get("cwes", []) if c.get("cwe_id")]

        # References
        refs = [r.get("url", "") for r in item.get("references", []) if r.get("url")]

        # CVE ID (may be null)
        identifiers = item.get("identifiers", [])
        cve_id = None
        for ident in identifiers:
            if ident.get("type") == "CVE":
                cve_id = ident.get("value")
                break
        if not cve_id:
            cve_id = item.get("cve_id")

        return GitHubAdvisory(
            ghsa_id=ghsa_id,
            cve_id=cve_id,
            summary=item.get("summary", ""),
            description=item.get("description", ""),
            severity=item.get("severity", "unknown"),
            published_at=item.get("published_at", ""),
            updated_at=item.get("updated_at", ""),
            affected_packages=affected,
            references=refs,
            cwes=cwes,
        )
