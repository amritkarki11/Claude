"""Baseline management — save, load, and compare eval snapshots.

A baseline is a frozen eval result that later runs are compared against
for regression detection. If recall drops or FP count rises, the comparison
flags it.
"""
from __future__ import annotations

import json
import pathlib
from dataclasses import dataclass

BASELINE_DIR = pathlib.Path(__file__).parent.parent.parent / "outputs" / "eval"


@dataclass
class BaselineComparison:
    """Comparison between a new eval run and a stored baseline."""
    baseline_f1: float
    current_f1: float
    baseline_recall: float
    current_recall: float
    baseline_precision: float
    current_precision: float
    baseline_fp: int
    current_fp: int
    recall_regression: bool
    precision_regression: bool
    f1_regression: bool
    fp_increase: bool

    @property
    def any_regression(self) -> bool:
        return self.recall_regression or self.f1_regression or self.fp_increase

    def summary(self) -> str:
        lines = []
        lines.append(f"F1:        {self.baseline_f1:.4f} → {self.current_f1:.4f}"
                      f" {'▼ REGRESSION' if self.f1_regression else '✓'}")
        lines.append(f"Recall:    {self.baseline_recall:.4f} → {self.current_recall:.4f}"
                      f" {'▼ REGRESSION' if self.recall_regression else '✓'}")
        lines.append(f"Precision: {self.baseline_precision:.4f} → {self.current_precision:.4f}"
                      f" {'▼ REGRESSION' if self.precision_regression else '✓'}")
        lines.append(f"FP count:  {self.baseline_fp} → {self.current_fp}"
                      f" {'▲ INCREASE' if self.fp_increase else '✓'}")
        if self.any_regression:
            lines.append("VERDICT: REGRESSION DETECTED")
        else:
            lines.append("VERDICT: OK")
        return "\n".join(lines)


def save_baseline(fixture_name: str, metrics: dict, path: pathlib.Path | None = None) -> pathlib.Path:
    """Save current metrics as the baseline for a fixture."""
    p = path or (BASELINE_DIR / f"baseline_{fixture_name}.json")
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    return p


def load_baseline(fixture_name: str, path: pathlib.Path | None = None) -> dict | None:
    """Load stored baseline for a fixture. Returns None if none exists."""
    p = path or (BASELINE_DIR / f"baseline_{fixture_name}.json")
    if not p.exists():
        return None
    with p.open("r", encoding="utf-8") as f:
        return json.load(f)


def compare(baseline: dict, current: dict) -> BaselineComparison:
    """Compare current metrics against a baseline."""
    return BaselineComparison(
        baseline_f1=baseline.get("f1", 0.0),
        current_f1=current.get("f1", 0.0),
        baseline_recall=baseline.get("recall", 0.0),
        current_recall=current.get("recall", 0.0),
        baseline_precision=baseline.get("precision", 0.0),
        current_precision=current.get("precision", 0.0),
        baseline_fp=baseline.get("false_positives", 0),
        current_fp=current.get("false_positives", 0),
        recall_regression=current.get("recall", 0.0) < baseline.get("recall", 0.0) - 0.01,
        precision_regression=current.get("precision", 0.0) < baseline.get("precision", 0.0) - 0.05,
        f1_regression=current.get("f1", 0.0) < baseline.get("f1", 0.0) - 0.02,
        fp_increase=current.get("false_positives", 0) > baseline.get("false_positives", 0),
    )
