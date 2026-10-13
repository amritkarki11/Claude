"""Frontier token budget tracker.

Tracks usage against the USD cap in config.yaml. The router checks
budget.allow() before every frontier call and logs spend after.
Thread-safe for future async use.
"""
from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# Rough per-token pricing (USD). Update when model changes.
# These are conservative estimates — better to over-count than under.
PRICING = {
    "anthropic/claude-sonnet-5-5": {"input": 3.0 / 1_000_000, "output": 15.0 / 1_000_000},
    "anthropic/claude-sonnet-4-0": {"input": 3.0 / 1_000_000, "output": 15.0 / 1_000_000},
    "anthropic/claude-opus-4-0":  {"input": 15.0 / 1_000_000, "output": 75.0 / 1_000_000},
}

# Fallback pricing if model not in table
DEFAULT_PRICING = {"input": 5.0 / 1_000_000, "output": 20.0 / 1_000_000}


@dataclass
class UsageEntry:
    job: str
    model: str
    input_tokens: int
    output_tokens: int
    cost_usd: float
    timestamp: str = ""


@dataclass
class Budget:
    cap_usd: float
    spent_usd: float = 0.0
    entries: list[UsageEntry] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    log_path: Optional[Path] = None

    def allow(self) -> bool:
        """Check if there's budget remaining for a frontier call."""
        with self._lock:
            return self.spent_usd < self.cap_usd

    def remaining(self) -> float:
        with self._lock:
            return max(0.0, self.cap_usd - self.spent_usd)

    def record(self, job: str, model: str, input_tokens: int,
               output_tokens: int, timestamp: str = "") -> float:
        """Record token usage, return cost of this call."""
        pricing = PRICING.get(model, DEFAULT_PRICING)
        cost = (input_tokens * pricing["input"]) + (output_tokens * pricing["output"])
        entry = UsageEntry(
            job=job, model=model,
            input_tokens=input_tokens, output_tokens=output_tokens,
            cost_usd=round(cost, 6), timestamp=timestamp,
        )
        with self._lock:
            self.spent_usd = round(self.spent_usd + cost, 6)
            self.entries.append(entry)
        if self.log_path:
            self._append_log(entry)
        return cost

    def summary(self) -> dict:
        """Return a summary of budget usage."""
        with self._lock:
            by_job: dict[str, float] = {}
            for e in self.entries:
                by_job[e.job] = by_job.get(e.job, 0.0) + e.cost_usd
            return {
                "cap_usd": self.cap_usd,
                "spent_usd": round(self.spent_usd, 4),
                "remaining_usd": round(self.cap_usd - self.spent_usd, 4),
                "calls": len(self.entries),
                "by_job": {k: round(v, 4) for k, v in by_job.items()},
            }

    def _append_log(self, entry: UsageEntry) -> None:
        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps({
                    "job": entry.job, "model": entry.model,
                    "input_tokens": entry.input_tokens,
                    "output_tokens": entry.output_tokens,
                    "cost_usd": entry.cost_usd,
                    "timestamp": entry.timestamp,
                }) + "\n")
        except OSError:
            pass  # best-effort logging
