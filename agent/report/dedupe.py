"""Finding deduplication for bug bounty mode.

Prevents submitting the same vuln twice by normalizing findings into
canonical keys and tracking what's been reported.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
from dataclasses import dataclass, field
from urllib.parse import urlparse
from typing import Any


def _normalize_vuln_class(recipe_id: str) -> str:
    """Normalize recipe_id to a canonical vuln class."""
    rid = recipe_id.lower().split(":")[-1]  # strip auto: prefix
    rid = rid.replace("_", "-").replace(" ", "-")
    # Collapse variants: sqli-error, sqli-blind → sqli
    base = rid.split("-")[0]
    return base


def _normalize_endpoint(url: str) -> str:
    """Normalize URL to its path (ignore query params and fragments)."""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.hostname}{parsed.path}".rstrip("/").lower()


def finding_key(finding: dict) -> str:
    """Generate a dedup key for a finding.

    Key = sha256(normalized_vuln_class + normalized_endpoint + param).
    """
    vuln = _normalize_vuln_class(finding.get("recipe_id", ""))
    endpoint = _normalize_endpoint(finding.get("endpoint", ""))
    param = (finding.get("request_data", {}).get("param", "")
             or finding.get("evidence", {}).get("param", "")).lower()

    canonical = f"{vuln}|{endpoint}|{param}"
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]


@dataclass
class DedupeStore:
    """Tracks reported findings to prevent duplicate submissions."""
    _seen: dict[str, dict] = field(default_factory=dict)
    _path: pathlib.Path | None = None

    @classmethod
    def load(cls, path: pathlib.Path | str) -> DedupeStore:
        path = pathlib.Path(path)
        store = cls(_path=path)
        if path.exists():
            data = json.loads(path.read_text())
            store._seen = data.get("seen", {})
        return store

    def save(self) -> None:
        if self._path:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(json.dumps({"seen": self._seen}, indent=2))

    def is_duplicate(self, finding: dict) -> bool:
        key = finding_key(finding)
        return key in self._seen

    def mark_reported(self, finding: dict, platform_id: str = "") -> str:
        key = finding_key(finding)
        self._seen[key] = {
            "recipe_id": finding.get("recipe_id", ""),
            "endpoint": finding.get("endpoint", ""),
            "platform_id": platform_id,
        }
        return key

    def dedupe(self, findings: list[dict]) -> list[dict]:
        """Filter out already-reported findings."""
        return [f for f in findings if not self.is_duplicate(f)]

    @property
    def reported_count(self) -> int:
        return len(self._seen)
