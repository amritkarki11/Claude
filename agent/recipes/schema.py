"""Recipe schema + validation.

A recipe is one unit of vuln KNOWLEDGE (not a scanner): the conditions under
which a check applies, the deterministic steps that look for it, and how a
candidate finding gets verified before it's ever reported. See CLAUDE.md:
"No finding is reported until a deterministic verifier confirms it."

Fields (per CLAUDE.md "Recipe schema"):
  id            unique slug, e.g. "idor-otp-trigger"
  applies_to    list[str] of target classes this recipe is relevant to, e.g.
                ["api", "web"]
  tech_signals  list[str] of recon tech signals that must ALL be present for
                this recipe to be a candidate, e.g. ["rest-api", "session-cookie"]
  preconditions list[str] human-readable conditions that must hold before
                detect[] is attempted (e.g. "two accounts with different
                privilege levels are available")
  detect        list[dict] ordered deterministic steps, each with at least a
                "step" description; richer fields (method/path/etc) are
                recipe-specific and passed through as-is
  signal        str: what a positive result looks like
  verify        str: the deterministic re-check that must confirm a finding
                before it is reported (never model opinion alone)
  severity      one of SEVERITIES
  remediation   str: fix guidance
  source        str: provenance (CWE id, advisory, internal research, etc.)
"""
from __future__ import annotations

from dataclasses import dataclass, field

REQUIRED_FIELDS = (
    "id", "applies_to", "tech_signals", "preconditions",
    "detect", "signal", "verify", "severity", "remediation", "source",
)
SEVERITIES = ("info", "low", "medium", "high", "critical")

_LIST_FIELDS = ("applies_to", "tech_signals", "preconditions", "detect")
_STR_FIELDS = ("id", "signal", "verify", "severity", "remediation", "source")


class SchemaError(ValueError):
    """A recipe dict does not conform to the schema."""


@dataclass(frozen=True)
class Recipe:
    id: str
    applies_to: tuple[str, ...]
    tech_signals: tuple[str, ...]
    preconditions: tuple[str, ...]
    detect: tuple[dict, ...]
    signal: str
    verify: str
    severity: str
    remediation: str
    source: str
    path: str = field(default="", compare=False)


def validate_recipe(data: dict, *, path: str = "") -> Recipe:
    """Validate a raw recipe dict and return a Recipe. Raises SchemaError
    with a message naming the offending field on any problem."""
    where = f" ({path})" if path else ""
    if not isinstance(data, dict):
        raise SchemaError(f"recipe must be a mapping{where}, got {type(data).__name__}")

    missing = [f for f in REQUIRED_FIELDS if f not in data]
    if missing:
        raise SchemaError(f"recipe missing required field(s) {missing}{where}")

    rid = data["id"]
    if not isinstance(rid, str) or not rid.strip():
        raise SchemaError(f"recipe 'id' must be a non-empty string{where}")
    where = where or f" (id={rid!r})"

    for f in _LIST_FIELDS:
        v = data[f]
        if not isinstance(v, list) or not v:
            raise SchemaError(f"recipe '{f}' must be a non-empty list{where}")
    for item in data["applies_to"] + data["tech_signals"] + data["preconditions"]:
        if not isinstance(item, str) or not item.strip():
            raise SchemaError(f"recipe 'applies_to'/'tech_signals'/'preconditions' entries must be non-empty strings{where}")
    for step in data["detect"]:
        if not isinstance(step, dict) or not step:
            raise SchemaError(f"recipe 'detect' entries must be non-empty mappings{where}")

    for f in _STR_FIELDS:
        v = data[f]
        if not isinstance(v, str) or not v.strip():
            raise SchemaError(f"recipe '{f}' must be a non-empty string{where}")

    if data["severity"] not in SEVERITIES:
        raise SchemaError(f"recipe 'severity' must be one of {SEVERITIES}, got {data['severity']!r}{where}")

    return Recipe(
        id=rid,
        applies_to=tuple(data["applies_to"]),
        tech_signals=tuple(data["tech_signals"]),
        preconditions=tuple(data["preconditions"]),
        detect=tuple(data["detect"]),
        signal=data["signal"],
        verify=data["verify"],
        severity=data["severity"],
        remediation=data["remediation"],
        source=data["source"],
        path=path,
    )
