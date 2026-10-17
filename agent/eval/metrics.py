"""Precision / recall / F1 computation for eval runs.

Matching logic:
  A confirmed finding matches an expected finding when their vuln_class
  matches (normalized) and the endpoint path is a substring match (the
  scanner may hit a sub-path of the expected endpoint or vice versa).
  Param matching is optional — only checked when the expected finding
  specifies one.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlparse

from .fixtures import ExpectedFinding


@dataclass
class MatchResult:
    """Result of matching confirmed findings against expected."""
    true_positives: list[tuple[ExpectedFinding, dict]] = field(default_factory=list)
    false_negatives: list[ExpectedFinding] = field(default_factory=list)
    false_positives: list[dict] = field(default_factory=list)


@dataclass
class EvalMetrics:
    """Precision, recall, F1 for one eval run."""
    true_positive_count: int
    false_negative_count: int
    false_positive_count: int
    total_expected: int
    total_confirmed: int
    precision: float
    recall: float
    f1: float
    match_detail: MatchResult


def _normalize_class(vuln_class: str) -> str:
    return vuln_class.strip().lower().replace("_", "-").replace(" ", "-")


def _endpoint_path(url_or_path: str) -> str:
    if url_or_path.startswith(("http://", "https://")):
        return urlparse(url_or_path).path.rstrip("/") or "/"
    return url_or_path.rstrip("/") or "/"


def _finding_vuln_class(finding: dict) -> str:
    """Extract vuln class from a confirmed finding dict."""
    rid = finding.get("recipe_id", "")
    scanner = finding.get("scanner", "").lower()
    if "sqli" in rid or "sql" in scanner:
        return "sqli"
    if "xss" in rid or "xss" in scanner:
        return "xss"
    if "idor" in rid or "idor" in scanner:
        return "idor"
    if "header" in rid or "header" in scanner:
        return "security-headers"
    if "csrf" in rid or "csrf" in scanner:
        return "csrf"
    if "ssrf" in rid or "ssrf" in scanner:
        return "ssrf"
    if "privesc" in rid or "privilege" in scanner:
        return "broken-access"
    if "lfi" in rid or "path" in rid:
        return "lfi"
    if "redirect" in rid:
        return "open-redirect"
    if "ssti" in rid:
        return "ssti"
    if "cmdi" in rid or "command" in rid:
        return "cmdi"
    if "nosqli" in rid:
        return "nosqli"
    if "brute" in rid:
        return "bruteforce"
    return _normalize_class(rid.split("-")[0]) if rid else "unknown"


def _matches(expected: ExpectedFinding, finding: dict) -> bool:
    """Check whether a confirmed finding matches an expected one."""
    ec = _normalize_class(expected.vuln_class)
    fc = _normalize_class(_finding_vuln_class(finding))
    if ec != fc:
        return False

    ep = _endpoint_path(expected.endpoint)
    fp = _endpoint_path(finding.get("endpoint", ""))
    if ep not in fp and fp not in ep:
        return False

    if expected.param:
        evidence = finding.get("evidence", {})
        req = finding.get("request_data", {})
        combined = str(evidence) + str(req)
        if expected.param.lower() not in combined.lower():
            return False

    return True


def compute_metrics(
    expected: list[ExpectedFinding],
    confirmed: list[dict],
) -> EvalMetrics:
    """Match confirmed findings against expected and compute metrics."""
    matched_expected: set[int] = set()
    matched_confirmed: set[int] = set()
    tp_pairs: list[tuple[ExpectedFinding, dict]] = []

    for ei, exp in enumerate(expected):
        for ci, conf in enumerate(confirmed):
            if ci in matched_confirmed:
                continue
            if _matches(exp, conf):
                matched_expected.add(ei)
                matched_confirmed.add(ci)
                tp_pairs.append((exp, conf))
                break

    fn = [exp for i, exp in enumerate(expected) if i not in matched_expected]
    fp = [conf for i, conf in enumerate(confirmed) if i not in matched_confirmed]

    tp_count = len(tp_pairs)
    fp_count = len(fp)
    fn_count = len(fn)

    precision = tp_count / (tp_count + fp_count) if (tp_count + fp_count) > 0 else 0.0
    recall = tp_count / (tp_count + fn_count) if (tp_count + fn_count) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    return EvalMetrics(
        true_positive_count=tp_count,
        false_negative_count=fn_count,
        false_positive_count=fp_count,
        total_expected=len(expected),
        total_confirmed=len(confirmed),
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1=round(f1, 4),
        match_detail=MatchResult(
            true_positives=tp_pairs,
            false_negatives=fn,
            false_positives=fp,
        ),
    )
