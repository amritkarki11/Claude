"""Learner — processes raw intelligence into actionable knowledge.

The learner sits between raw feeds (CVEs, exploits, advisories, blog posts)
and the agent's memory. It:
  1. Deduplicates: skips intel the agent already knows
  2. Classifies: maps intel to scanner capabilities (can we test for this?)
  3. Prioritizes: scores by exploitability, recency, and relevance
  4. Generates: creates recipe suggestions for new attack patterns
  5. Correlates: links related CVEs, exploits, and advisories
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

from .memory import Memory, MemoryEntry
from .sources.nvd import CVERecord
from .sources.cisa_kev import KEVEntry
from .sources.exploitdb import ExploitEntry
from .sources.github_advisories import GitHubAdvisory
from .sources.security_feeds import FeedItem

logger = logging.getLogger(__name__)

# Maps CWE IDs to scanner capabilities
CWE_TO_SCANNER: dict[str, str] = {
    "CWE-89": "sqli",          # SQL Injection
    "CWE-79": "xss",           # Cross-site Scripting
    "CWE-918": "ssrf",         # Server-Side Request Forgery
    "CWE-611": "xxe",          # XML External Entity
    "CWE-78": "cmdi",          # OS Command Injection
    "CWE-22": "lfi",           # Path Traversal
    "CWE-94": "ssti",          # Code Injection (includes SSTI)
    "CWE-352": "csrf",         # Cross-Site Request Forgery
    "CWE-639": "idor",         # Authorization Bypass (IDOR)
    "CWE-862": "idor",         # Missing Authorization
    "CWE-863": "idor",         # Incorrect Authorization
    "CWE-287": "auth-bypass",  # Improper Authentication
    "CWE-306": "auth-bypass",  # Missing Authentication
    "CWE-502": "deserialization",
    "CWE-1321": "prototype-pollution",
    "CWE-601": "open-redirect",
    "CWE-943": "nosqli",       # NoSQL Injection
    "CWE-400": "dos",          # Resource Exhaustion
    "CWE-307": "bruteforce",   # Brute Force
}

# Severity weight for prioritization
SEVERITY_WEIGHTS = {
    "critical": 1.0,
    "high": 0.8,
    "medium": 0.5,
    "low": 0.2,
    "unknown": 0.3,
}


@dataclass
class LearningSummary:
    """What the learner processed in one run."""
    new_cves: int = 0
    new_exploits: int = 0
    new_advisories: int = 0
    new_feed_items: int = 0
    recipe_suggestions: int = 0
    skipped_duplicates: int = 0
    correlations_found: int = 0
    high_priority_items: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "new_cves": self.new_cves,
            "new_exploits": self.new_exploits,
            "new_advisories": self.new_advisories,
            "new_feed_items": self.new_feed_items,
            "recipe_suggestions": self.recipe_suggestions,
            "skipped_duplicates": self.skipped_duplicates,
            "correlations_found": self.correlations_found,
            "high_priority_items": self.high_priority_items,
        }


class Learner:
    """Processes raw intelligence and updates the agent's memory."""

    def __init__(self, memory: Memory):
        self.memory = memory

    def process_cves(self, cves: list[CVERecord]) -> int:
        """Process CVE records into memory. Returns count of new entries."""
        count = 0
        for cve in cves:
            entry_id = f"cve:{cve.cve_id}"
            if entry_id in self.memory._entries:
                continue

            data = cve.to_dict()
            data["scanner_mapping"] = self._map_to_scanners(cve.weaknesses)
            data["priority_score"] = self._score_cve(cve)

            self.memory.store_cve(cve.cve_id, data)
            count += 1
        return count

    def process_kev_entries(self, entries: list[KEVEntry]) -> int:
        """Process CISA KEV entries — these get highest priority."""
        count = 0
        for entry in entries:
            entry_id = f"kev:{entry.cve_id}"
            if entry_id in self.memory._entries:
                continue

            data = entry.to_dict()
            data["priority_score"] = 1.0  # KEV = actively exploited = max priority
            data["scanner_mapping"] = []  # will be enriched via CVE correlation

            mem_entry = MemoryEntry(
                id=entry_id,
                category="cve",
                timestamp=time.time(),
                data=data,
                tags=data["tags"] + ["actively-exploited", "kev"],
                source="cisa-kev",
                confidence=1.0,
            )
            self.memory.store(mem_entry)
            count += 1
        return count

    def process_exploits(self, exploits: list[ExploitEntry]) -> int:
        """Process ExploitDB entries."""
        count = 0
        for exploit in exploits:
            entry_id = f"exploit:edb-{exploit.edb_id}"
            if entry_id in self.memory._entries:
                continue

            self.memory.store_exploit(f"edb-{exploit.edb_id}", exploit.to_dict())
            count += 1
        return count

    def process_advisories(self, advisories: list[GitHubAdvisory]) -> int:
        """Process GitHub security advisories."""
        count = 0
        for advisory in advisories:
            entry_id = f"advisory:{advisory.ghsa_id}"
            if entry_id in self.memory._entries:
                continue

            data = advisory.to_dict()
            data["scanner_mapping"] = self._map_to_scanners(advisory.cwes)

            mem_entry = MemoryEntry(
                id=entry_id,
                category="cve",
                timestamp=time.time(),
                data=data,
                tags=data["tags"],
                source="github-advisories",
                confidence=0.9,
            )
            self.memory.store(mem_entry)
            count += 1
        return count

    def process_feed_items(self, items: list[FeedItem]) -> int:
        """Process security feed items (blog posts, research, disclosures)."""
        count = 0
        for item in items:
            item_hash = hashlib.sha256(item.url.encode()).hexdigest()[:16]
            entry_id = f"feed:{item_hash}"
            if entry_id in self.memory._entries:
                continue

            mem_entry = MemoryEntry(
                id=entry_id,
                category="intel",
                timestamp=time.time(),
                data=item.to_dict(),
                tags=item.tags,
                source=item.source,
                confidence=0.7,
                # Feed items expire after 90 days
                expires=time.time() + 90 * 86400,
            )
            self.memory.store(mem_entry)
            count += 1
        return count

    def correlate(self) -> int:
        """Find relationships between stored intel.

        Links CVEs to known exploits, KEV entries to advisories,
        and attack patterns to related CVEs.
        """
        correlations = 0

        # Find CVEs that have known exploits
        cves = self.memory.recall(category="cve", limit=500)
        exploits = self.memory.recall(category="technique", limit=500)

        exploit_cves = {}
        for e in exploits:
            for code in e.data.get("codes", []):
                if code.startswith("CVE-"):
                    exploit_cves.setdefault(code, []).append(e.id)

        for cve in cves:
            cve_id = cve.data.get("cve_id", "")
            if cve_id in exploit_cves and "has_exploit" not in cve.tags:
                cve.tags.append("has_exploit")
                cve.data["linked_exploits"] = exploit_cves[cve_id]
                cve.data["priority_score"] = min(
                    cve.data.get("priority_score", 0.5) + 0.2, 1.0
                )
                correlations += 1

        return correlations

    def generate_recipe_suggestions(self) -> list[dict]:
        """Analyze learned intel and suggest new recipe YAML files.

        Looks for patterns the current scanner set can detect but
        doesn't have specific recipes for.
        """
        suggestions = []

        # Find high-severity CVEs mapped to our scanners but without recipes
        high_cves = self.memory.recall(category="cve", tags=["severity:critical"], limit=100)
        high_cves += self.memory.recall(category="cve", tags=["severity:high"], limit=100)

        for cve in high_cves:
            scanner_mapping = cve.data.get("scanner_mapping", [])
            if not scanner_mapping:
                continue

            for scanner_id in scanner_mapping:
                suggestion = {
                    "based_on": cve.data.get("cve_id", cve.id),
                    "scanner": scanner_id,
                    "description": cve.data.get("description", "")[:200],
                    "severity": cve.data.get("severity", "high"),
                    "affected_products": cve.data.get("affected_products", []),
                    "weaknesses": cve.data.get("weaknesses", []),
                    "suggested_detect": self._suggest_detection(scanner_id, cve.data),
                }
                suggestions.append(suggestion)

        return suggestions[:20]

    def get_priority_intel(self, tech_stack: list[str] | None = None,
                           limit: int = 10) -> list[dict]:
        """Get the highest-priority intel items, optionally filtered by tech stack."""
        all_intel = list(self.memory._entries.values())

        scored = []
        for entry in all_intel:
            score = entry.data.get("priority_score", 0.5) * entry.confidence

            # Boost if matches current tech stack
            if tech_stack:
                for tech in tech_stack:
                    if any(tech.lower() in tag.lower() for tag in entry.tags):
                        score *= 1.5
                        break

            # Boost actively exploited
            if "actively-exploited" in entry.tags or "kev" in entry.tags:
                score *= 2.0

            # Boost if has known exploit
            if "has_exploit" in entry.tags:
                score *= 1.3

            # Recency boost
            age_days = (time.time() - entry.timestamp) / 86400
            recency = 1.0 / (1.0 + age_days / 30)
            score *= (0.7 + 0.3 * recency)

            scored.append((score, entry))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [
            {
                "id": e.id,
                "score": round(s, 3),
                "category": e.category,
                "summary": _summarize_entry(e),
                "tags": e.tags[:10],
            }
            for s, e in scored[:limit]
        ]

    def _map_to_scanners(self, cwes: list[str]) -> list[str]:
        """Map CWE IDs to scanner identifiers."""
        scanners = set()
        for cwe in cwes:
            scanner = CWE_TO_SCANNER.get(cwe)
            if scanner:
                scanners.add(scanner)
        return sorted(scanners)

    def _score_cve(self, cve: CVERecord) -> float:
        """Score a CVE for prioritization (0.0 - 1.0)."""
        score = SEVERITY_WEIGHTS.get(cve.severity, 0.3)

        # CVSS score influence
        if cve.cvss_score:
            score = max(score, cve.cvss_score / 10.0)

        # Boost if it maps to our scanners
        mapped = self._map_to_scanners(cve.weaknesses)
        if mapped:
            score = min(score + 0.1, 1.0)

        # Boost if it has exploit references
        for ref in cve.references:
            if "exploit" in ref.lower() or "poc" in ref.lower():
                score = min(score + 0.15, 1.0)
                break

        return round(score, 3)

    def _suggest_detection(self, scanner_id: str, cve_data: dict) -> list[str]:
        """Suggest detection steps for a scanner based on CVE info."""
        base_steps = {
            "sqli": ["inject single quote", "check for SQL error patterns",
                     "test boolean blind", "test time-based blind"],
            "xss": ["inject HTML tag canary", "check for reflection",
                    "test event handler payloads", "check CSP bypass"],
            "ssrf": ["inject internal IP", "test cloud metadata endpoints",
                     "test redirect-based bypass"],
            "lfi": ["test path traversal sequences", "try encoding bypasses",
                    "check null byte termination"],
            "cmdi": ["inject command separator", "test time-based detection",
                     "verify with math operation"],
            "ssti": ["inject math expression", "identify template engine",
                     "test engine-specific payloads"],
            "idor": ["swap user identifiers", "compare response bodies",
                     "test both read and write"],
            "csrf": ["omit CSRF token", "tamper token value",
                     "check SameSite cookie attribute"],
        }
        return base_steps.get(scanner_id, ["manual testing required"])


def _summarize_entry(entry: MemoryEntry) -> str:
    """Create a one-line summary of a memory entry."""
    data = entry.data
    if entry.category == "cve":
        cve_id = data.get("cve_id", data.get("ghsa_id", entry.id))
        severity = data.get("severity", "?")
        desc = data.get("description", data.get("summary", ""))[:100]
        return f"[{severity.upper()}] {cve_id}: {desc}"
    elif entry.category == "technique":
        return f"Exploit: {data.get('description', entry.id)[:100]}"
    elif entry.category == "intel":
        return f"{data.get('source', '?')}: {data.get('title', '')[:100]}"
    elif entry.category == "pattern":
        return f"Pattern: {data.get('description', entry.id)[:100]}"
    return str(entry.id)[:100]
