"""Persistent Memory — the agent remembers what it learned across engagements.

Stores:
  - Successful attack patterns (what worked on which tech stacks)
  - CVE intelligence (mapped to scanner capabilities)
  - Technique effectiveness scores (updated after each engagement)
  - Engagement history (anonymized — no target data, just patterns)
  - Daily intel digests (processed feed summaries)

All data is stored as append-only JSONL with indexes rebuilt on load.
No pickle, no eval — safe serialization only.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


MIND_DATA_DIR = Path(__file__).parent.parent.parent / "mind_data"


@dataclass
class MemoryEntry:
    """One piece of learned knowledge."""
    id: str
    category: str           # cve | technique | pattern | engagement | intel
    timestamp: float
    data: dict[str, Any]
    tags: list[str] = field(default_factory=list)
    confidence: float = 1.0  # 0.0-1.0, decays over time for unverified intel
    source: str = ""         # where this knowledge came from
    expires: float | None = None  # optional TTL timestamp

    def is_expired(self) -> bool:
        return self.expires is not None and time.time() > self.expires

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "MemoryEntry":
        return cls(**d)


@dataclass
class TechniqueScore:
    """Effectiveness score for an attack technique."""
    technique_id: str
    success_count: int = 0
    attempt_count: int = 0
    last_success: float = 0.0
    tech_stacks: list[str] = field(default_factory=list)

    @property
    def effectiveness(self) -> float:
        if self.attempt_count == 0:
            return 0.5  # unknown = neutral prior
        return self.success_count / self.attempt_count

    def record_attempt(self, success: bool, tech_stack: str = "") -> None:
        self.attempt_count += 1
        if success:
            self.success_count += 1
            self.last_success = time.time()
        if tech_stack and tech_stack not in self.tech_stacks:
            self.tech_stacks.append(tech_stack)


class Memory:
    """Persistent memory store backed by JSONL files.

    Thread-safe for reads; writes append atomically (one JSON line per write).
    Indexes are rebuilt from the JSONL on load — the file is the source of truth.
    """

    def __init__(self, data_dir: Path | str = MIND_DATA_DIR):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self._memory_file = self.data_dir / "memory.jsonl"
        self._scores_file = self.data_dir / "technique_scores.json"

        # In-memory indexes (rebuilt from disk on load)
        self._entries: dict[str, MemoryEntry] = {}
        self._by_category: dict[str, list[str]] = {}
        self._by_tag: dict[str, list[str]] = {}
        self._scores: dict[str, TechniqueScore] = {}

        self._load()

    def _load(self) -> None:
        """Rebuild indexes from the JSONL file."""
        self._entries.clear()
        self._by_category.clear()
        self._by_tag.clear()

        if self._memory_file.exists():
            with self._memory_file.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = MemoryEntry.from_dict(json.loads(line))
                        if not entry.is_expired():
                            self._index(entry)
                    except (json.JSONDecodeError, TypeError, KeyError):
                        continue  # skip corrupt lines

        if self._scores_file.exists():
            try:
                raw = json.loads(self._scores_file.read_text(encoding="utf-8"))
                for tid, sdata in raw.items():
                    self._scores[tid] = TechniqueScore(**sdata)
            except (json.JSONDecodeError, TypeError):
                pass

    def _index(self, entry: MemoryEntry) -> None:
        """Add entry to in-memory indexes."""
        self._entries[entry.id] = entry
        self._by_category.setdefault(entry.category, []).append(entry.id)
        for tag in entry.tags:
            self._by_tag.setdefault(tag, []).append(entry.id)

    def store(self, entry: MemoryEntry) -> None:
        """Persist a new memory entry (append-only)."""
        with self._memory_file.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry.to_dict()) + "\n")
        self._index(entry)

    def recall(self, category: str | None = None, tags: list[str] | None = None,
               limit: int = 50) -> list[MemoryEntry]:
        """Retrieve memories by category and/or tags."""
        ids: set[str] | None = None

        if category and category in self._by_category:
            ids = set(self._by_category[category])
        elif category:
            return []

        if tags:
            tag_ids = set()
            for tag in tags:
                tag_ids.update(self._by_tag.get(tag, []))
            ids = tag_ids if ids is None else ids & tag_ids

        if ids is None:
            ids = set(self._entries.keys())

        results = [self._entries[i] for i in ids if i in self._entries]
        results.sort(key=lambda e: e.timestamp, reverse=True)
        return results[:limit]

    def search(self, query: str, limit: int = 20) -> list[MemoryEntry]:
        """Simple keyword search across memory entries."""
        query_lower = query.lower()
        scored: list[tuple[float, MemoryEntry]] = []

        for entry in self._entries.values():
            text = json.dumps(entry.data).lower()
            if query_lower in text:
                # Score by recency and confidence
                recency = 1.0 / (1.0 + (time.time() - entry.timestamp) / 86400)
                score = entry.confidence * 0.6 + recency * 0.4
                scored.append((score, entry))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [e for _, e in scored[:limit]]

    def get_technique_score(self, technique_id: str) -> TechniqueScore:
        """Get or create a technique effectiveness score."""
        if technique_id not in self._scores:
            self._scores[technique_id] = TechniqueScore(technique_id=technique_id)
        return self._scores[technique_id]

    def record_technique_result(self, technique_id: str, success: bool,
                                tech_stack: str = "") -> None:
        """Record the result of using a technique."""
        score = self.get_technique_score(technique_id)
        score.record_attempt(success, tech_stack)
        self._save_scores()

    def _save_scores(self) -> None:
        """Persist technique scores to disk."""
        data = {tid: asdict(s) for tid, s in self._scores.items()}
        self._scores_file.write_text(
            json.dumps(data, indent=2), encoding="utf-8"
        )

    def store_cve(self, cve_id: str, data: dict) -> None:
        """Store a CVE as a memory entry with standard tags."""
        entry = MemoryEntry(
            id=f"cve:{cve_id}",
            category="cve",
            timestamp=time.time(),
            data=data,
            tags=_extract_cve_tags(data),
            source="nvd",
            confidence=1.0,
        )
        self.store(entry)

    def store_exploit(self, exploit_id: str, data: dict) -> None:
        """Store an exploit technique."""
        entry = MemoryEntry(
            id=f"exploit:{exploit_id}",
            category="technique",
            timestamp=time.time(),
            data=data,
            tags=data.get("tags", []),
            source=data.get("source", "unknown"),
            confidence=0.8,
        )
        self.store(entry)

    def store_attack_pattern(self, pattern_id: str, data: dict) -> None:
        """Store a learned attack pattern from an engagement."""
        entry = MemoryEntry(
            id=f"pattern:{pattern_id}",
            category="pattern",
            timestamp=time.time(),
            data=data,
            tags=data.get("tags", []),
            source="engagement",
            confidence=0.9,
        )
        self.store(entry)

    def get_relevant_cves(self, tech_stack: list[str], limit: int = 20) -> list[MemoryEntry]:
        """Find CVEs relevant to a given tech stack."""
        results = []
        for entry in self._entries.values():
            if entry.category != "cve":
                continue
            if any(tech.lower() in tag.lower() for tech in tech_stack for tag in entry.tags):
                results.append(entry)
        results.sort(key=lambda e: e.timestamp, reverse=True)
        return results[:limit]

    def get_effective_techniques(self, tech_stack: str = "",
                                min_effectiveness: float = 0.3) -> list[TechniqueScore]:
        """Get techniques ranked by effectiveness, optionally filtered by tech stack."""
        scores = list(self._scores.values())
        if tech_stack:
            scores = [s for s in scores if tech_stack.lower() in
                      [t.lower() for t in s.tech_stacks]]
        scores = [s for s in scores if s.effectiveness >= min_effectiveness]
        scores.sort(key=lambda s: s.effectiveness, reverse=True)
        return scores

    def summary(self) -> dict:
        """Return a summary of what the mind knows."""
        return {
            "total_memories": len(self._entries),
            "by_category": {cat: len(ids) for cat, ids in self._by_category.items()},
            "techniques_tracked": len(self._scores),
            "top_techniques": [
                {"id": s.technique_id, "effectiveness": round(s.effectiveness, 2)}
                for s in sorted(self._scores.values(),
                                key=lambda s: s.effectiveness, reverse=True)[:10]
            ],
        }


def _extract_cve_tags(cve_data: dict) -> list[str]:
    """Extract searchable tags from CVE data."""
    tags = []
    desc = cve_data.get("description", "").lower()

    vuln_keywords = {
        "sql injection": "sqli", "xss": "xss", "cross-site scripting": "xss",
        "ssrf": "ssrf", "server-side request": "ssrf",
        "xxe": "xxe", "xml external": "xxe",
        "rce": "rce", "remote code execution": "rce", "command injection": "cmdi",
        "idor": "idor", "insecure direct": "idor",
        "authentication bypass": "auth-bypass", "csrf": "csrf",
        "path traversal": "lfi", "directory traversal": "lfi",
        "deserialization": "deserialization", "ssti": "ssti",
        "prototype pollution": "prototype-pollution",
        "open redirect": "open-redirect",
        "privilege escalation": "privesc",
    }
    for keyword, tag in vuln_keywords.items():
        if keyword in desc:
            tags.append(tag)

    # Extract affected product/vendor names
    for ref in cve_data.get("affected_products", []):
        if isinstance(ref, str):
            tags.append(ref.lower())
        elif isinstance(ref, dict):
            if ref.get("vendor"):
                tags.append(ref["vendor"].lower())
            if ref.get("product"):
                tags.append(ref["product"].lower())

    if cve_data.get("severity"):
        tags.append(f"severity:{cve_data['severity'].lower()}")

    return tags
