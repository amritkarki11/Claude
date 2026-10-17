"""CVSS v3.1 base score calculator.

Implements the specification from https://www.first.org/cvss/v3.1/specification-document
Only base metrics — temporal and environmental are out of scope for now.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from enum import Enum
from typing import Any


class AttackVector(Enum):
    NETWORK = "N"
    ADJACENT = "A"
    LOCAL = "L"
    PHYSICAL = "P"


class AttackComplexity(Enum):
    LOW = "L"
    HIGH = "H"


class PrivilegesRequired(Enum):
    NONE = "N"
    LOW = "L"
    HIGH = "H"


class UserInteraction(Enum):
    NONE = "N"
    REQUIRED = "R"


class Scope(Enum):
    UNCHANGED = "U"
    CHANGED = "C"


class Impact(Enum):
    NONE = "N"
    LOW = "L"
    HIGH = "H"


_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}  # scope unchanged
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}  # scope changed
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"N": 0.0, "L": 0.22, "H": 0.56}


@dataclass
class CvssVector:
    attack_vector: AttackVector = AttackVector.NETWORK
    attack_complexity: AttackComplexity = AttackComplexity.LOW
    privileges_required: PrivilegesRequired = PrivilegesRequired.NONE
    user_interaction: UserInteraction = UserInteraction.NONE
    scope: Scope = Scope.UNCHANGED
    confidentiality: Impact = Impact.NONE
    integrity: Impact = Impact.NONE
    availability: Impact = Impact.NONE

    def score(self) -> float:
        iss = 1.0 - (
            (1.0 - _CIA[self.confidentiality.value])
            * (1.0 - _CIA[self.integrity.value])
            * (1.0 - _CIA[self.availability.value])
        )
        if iss <= 0:
            return 0.0

        if self.scope == Scope.CHANGED:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
            pr_weights = _PR_C
        else:
            impact = 6.42 * iss
            pr_weights = _PR_U

        exploitability = (
            8.22
            * _AV[self.attack_vector.value]
            * _AC[self.attack_complexity.value]
            * pr_weights[self.privileges_required.value]
            * _UI[self.user_interaction.value]
        )

        if self.scope == Scope.UNCHANGED:
            raw = min(impact + exploitability, 10.0)
        else:
            raw = min(1.08 * (impact + exploitability), 10.0)

        return math.ceil(raw * 10) / 10

    def severity(self) -> str:
        s = self.score()
        if s == 0.0:
            return "none"
        if s <= 3.9:
            return "low"
        if s <= 6.9:
            return "medium"
        if s <= 8.9:
            return "high"
        return "critical"

    def vector_string(self) -> str:
        return (
            f"CVSS:3.1/AV:{self.attack_vector.value}"
            f"/AC:{self.attack_complexity.value}"
            f"/PR:{self.privileges_required.value}"
            f"/UI:{self.user_interaction.value}"
            f"/S:{self.scope.value}"
            f"/C:{self.confidentiality.value}"
            f"/I:{self.integrity.value}"
            f"/A:{self.availability.value}"
        )

    @classmethod
    def from_string(cls, vs: str) -> CvssVector:
        """Parse a CVSS:3.1 vector string."""
        parts = vs.replace("CVSS:3.1/", "").split("/")
        metrics: dict[str, str] = {}
        for part in parts:
            k, v = part.split(":", 1)
            metrics[k] = v

        return cls(
            attack_vector=AttackVector(metrics["AV"]),
            attack_complexity=AttackComplexity(metrics["AC"]),
            privileges_required=PrivilegesRequired(metrics["PR"]),
            user_interaction=UserInteraction(metrics["UI"]),
            scope=Scope(metrics["S"]),
            confidentiality=Impact(metrics["C"]),
            integrity=Impact(metrics["I"]),
            availability=Impact(metrics["A"]),
        )


# Convenience: map common vuln classes to typical CVSS vectors
VULN_CLASS_CVSS: dict[str, CvssVector] = {
    "sqli": CvssVector(
        confidentiality=Impact.HIGH, integrity=Impact.HIGH, availability=Impact.HIGH,
    ),
    "xss": CvssVector(
        user_interaction=UserInteraction.REQUIRED,
        confidentiality=Impact.LOW, integrity=Impact.LOW,
    ),
    "ssrf": CvssVector(
        confidentiality=Impact.HIGH, integrity=Impact.LOW,
    ),
    "idor": CvssVector(
        privileges_required=PrivilegesRequired.LOW,
        confidentiality=Impact.HIGH, integrity=Impact.LOW,
    ),
    "csrf": CvssVector(
        user_interaction=UserInteraction.REQUIRED,
        integrity=Impact.LOW,
    ),
    "lfi": CvssVector(
        confidentiality=Impact.HIGH,
    ),
    "cmdi": CvssVector(
        confidentiality=Impact.HIGH, integrity=Impact.HIGH, availability=Impact.HIGH,
    ),
    "ssti": CvssVector(
        confidentiality=Impact.HIGH, integrity=Impact.HIGH, availability=Impact.HIGH,
    ),
    "open-redirect": CvssVector(
        user_interaction=UserInteraction.REQUIRED,
        confidentiality=Impact.LOW,
    ),
    "security-headers": CvssVector(
        attack_complexity=AttackComplexity.HIGH,
        confidentiality=Impact.LOW,
    ),
}


def cvss_for_finding(finding: dict) -> CvssVector:
    """Return a CVSS vector for a finding, using vuln class defaults."""
    recipe_id = finding.get("recipe_id", "")
    for prefix, vector in VULN_CLASS_CVSS.items():
        if recipe_id.lower().startswith(prefix):
            return vector
    return CvssVector(confidentiality=Impact.LOW)
