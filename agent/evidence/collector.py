"""Evidence collector — captures and hashes request/response pairs.

Every piece of evidence gets a SHA-256 hash at capture time, forming an
immutable chain. The collector writes a JSONL evidence log that can be
verified independently.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any


@dataclass
class EvidenceItem:
    """A single piece of captured evidence with integrity hash."""
    evidence_id: str
    finding_id: str
    timestamp: str
    category: str  # request, response, screenshot, note
    content: dict[str, Any]
    sha256: str = ""
    prev_hash: str = ""  # hash of previous item (chain)

    def __post_init__(self):
        if not self.sha256:
            self.sha256 = self._compute_hash()

    def _compute_hash(self) -> str:
        canonical = json.dumps(
            {
                "evidence_id": self.evidence_id,
                "finding_id": self.finding_id,
                "timestamp": self.timestamp,
                "category": self.category,
                "content": self.content,
                "prev_hash": self.prev_hash,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def verify(self) -> bool:
        """Verify this item's hash matches its content."""
        expected = self._compute_hash()
        return self.sha256 == expected

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class EvidenceChain:
    """Ordered chain of evidence items with hash linking."""
    finding_id: str
    items: list[EvidenceItem] = field(default_factory=list)

    def add(self, category: str, content: dict[str, Any]) -> EvidenceItem:
        prev_hash = self.items[-1].sha256 if self.items else "0" * 64
        item = EvidenceItem(
            evidence_id=f"{self.finding_id}-{len(self.items):03d}",
            finding_id=self.finding_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            category=category,
            content=content,
            prev_hash=prev_hash,
        )
        self.items.append(item)
        return item

    def verify_chain(self) -> tuple[bool, list[str]]:
        """Verify the entire chain. Returns (valid, errors)."""
        errors = []
        for i, item in enumerate(self.items):
            if not item.verify():
                errors.append(f"Item {item.evidence_id}: hash mismatch")
            if i == 0:
                if item.prev_hash != "0" * 64:
                    errors.append(f"Item {item.evidence_id}: first item should have zero prev_hash")
            else:
                if item.prev_hash != self.items[i - 1].sha256:
                    errors.append(f"Item {item.evidence_id}: prev_hash doesn't match previous item")
        return (len(errors) == 0, errors)


class EvidenceCollector:
    """Collects evidence across all findings, writes to JSONL log."""

    def __init__(self, output_dir: pathlib.Path | str):
        self.output_dir = pathlib.Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = self.output_dir / "evidence.jsonl"
        self._chains: dict[str, EvidenceChain] = {}
        self._counter = 0

    def capture_request(
        self,
        finding_id: str,
        method: str,
        url: str,
        headers: dict | None = None,
        body: str = "",
    ) -> EvidenceItem:
        chain = self._get_chain(finding_id)
        item = chain.add("request", {
            "method": method,
            "url": url,
            "headers": headers or {},
            "body": body,
        })
        self._write(item)
        return item

    def capture_response(
        self,
        finding_id: str,
        status: int,
        headers: dict | None = None,
        body: str = "",
        elapsed_ms: float = 0,
    ) -> EvidenceItem:
        chain = self._get_chain(finding_id)
        item = chain.add("response", {
            "status": status,
            "headers": headers or {},
            "body": body[:10000],  # cap body size
            "elapsed_ms": elapsed_ms,
        })
        self._write(item)
        return item

    def capture_note(self, finding_id: str, note: str) -> EvidenceItem:
        chain = self._get_chain(finding_id)
        item = chain.add("note", {"text": note})
        self._write(item)
        return item

    def get_chain(self, finding_id: str) -> EvidenceChain | None:
        return self._chains.get(finding_id)

    def verify_all(self) -> dict[str, tuple[bool, list[str]]]:
        """Verify all chains. Returns {finding_id: (valid, errors)}."""
        results = {}
        for fid, chain in self._chains.items():
            results[fid] = chain.verify_chain()
        return results

    def export(self, output_path: pathlib.Path | str | None = None) -> pathlib.Path:
        """Export all evidence to a single JSON file."""
        path = pathlib.Path(output_path or (self.output_dir / "evidence_export.json"))
        data = {
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "chains": {},
        }
        for fid, chain in self._chains.items():
            valid, errors = chain.verify_chain()
            data["chains"][fid] = {
                "items": [item.to_dict() for item in chain.items],
                "integrity_valid": valid,
                "errors": errors,
            }
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return path

    def _get_chain(self, finding_id: str) -> EvidenceChain:
        if finding_id not in self._chains:
            self._chains[finding_id] = EvidenceChain(finding_id=finding_id)
        return self._chains[finding_id]

    def _write(self, item: EvidenceItem) -> None:
        with self.log_file.open("a", encoding="utf-8") as f:
            f.write(json.dumps(item.to_dict()) + "\n")
