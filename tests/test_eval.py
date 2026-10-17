"""Tests for the eval harness — fixtures, metrics, baseline."""
import pytest

from agent.eval.fixtures import (
    ExpectedFinding, TargetFixture, get_fixture, ALL_FIXTURES, ALTORO_MUTUAL,
)
from agent.eval.metrics import compute_metrics, _normalize_class, _matches
from agent.eval.baseline import save_baseline, load_baseline, compare


# ── Fixtures ────────────────────────────────────────────────

def test_altoro_fixture_exists():
    f = get_fixture("altoro")
    assert f.name == "Altoro Mutual (demo.testfire.net)"
    assert len(f.expected) >= 5


def test_get_fixture_unknown_raises():
    with pytest.raises(KeyError, match="Unknown fixture"):
        get_fixture("nonexistent")


def test_expected_finding_fields():
    ef = ExpectedFinding(vuln_class="sqli", endpoint="/login")
    assert ef.method == "GET"
    assert ef.param == ""


# ── Metrics ─────────────────────────────────────────────────

def test_normalize_class():
    assert _normalize_class("SQL_Injection") == "sql-injection"
    assert _normalize_class("  XSS ") == "xss"
    assert _normalize_class("broken access") == "broken-access"


def test_perfect_match():
    expected = [
        ExpectedFinding(vuln_class="sqli", endpoint="/login", method="POST"),
        ExpectedFinding(vuln_class="xss", endpoint="/search"),
    ]
    confirmed = [
        {"recipe_id": "sqli-login", "scanner": "SqliScanner", "endpoint": "/login",
         "method": "POST", "evidence": {}, "request_data": {}},
        {"recipe_id": "xss-reflected", "scanner": "XssScanner", "endpoint": "/search",
         "method": "GET", "evidence": {}, "request_data": {}},
    ]
    m = compute_metrics(expected, confirmed)
    assert m.precision == 1.0
    assert m.recall == 1.0
    assert m.f1 == 1.0
    assert m.true_positive_count == 2
    assert m.false_positive_count == 0
    assert m.false_negative_count == 0


def test_all_missed():
    expected = [
        ExpectedFinding(vuln_class="sqli", endpoint="/login"),
    ]
    m = compute_metrics(expected, [])
    assert m.recall == 0.0
    assert m.false_negative_count == 1


def test_all_false_positives():
    confirmed = [
        {"recipe_id": "xss-thing", "scanner": "XssScanner", "endpoint": "/foo",
         "evidence": {}, "request_data": {}},
    ]
    m = compute_metrics([], confirmed)
    assert m.precision == 0.0
    assert m.false_positive_count == 1
    assert m.true_positive_count == 0


def test_partial_match():
    expected = [
        ExpectedFinding(vuln_class="sqli", endpoint="/login"),
        ExpectedFinding(vuln_class="xss", endpoint="/search"),
        ExpectedFinding(vuln_class="idor", endpoint="/account"),
    ]
    confirmed = [
        {"recipe_id": "sqli-login", "scanner": "SqliScanner", "endpoint": "/login",
         "evidence": {}, "request_data": {}},
        {"recipe_id": "csrf-form", "scanner": "CsrfScanner", "endpoint": "/form",
         "evidence": {}, "request_data": {}},
    ]
    m = compute_metrics(expected, confirmed)
    assert m.true_positive_count == 1
    assert m.false_negative_count == 2
    assert m.false_positive_count == 1
    assert 0 < m.precision < 1
    assert 0 < m.recall < 1


def test_param_matching():
    expected = [
        ExpectedFinding(vuln_class="sqli", endpoint="/login", param="uid"),
    ]
    no_param = [
        {"recipe_id": "sqli-login", "scanner": "SqliScanner", "endpoint": "/login",
         "evidence": {}, "request_data": {"body": "password=x"}},
    ]
    m = compute_metrics(expected, no_param)
    assert m.true_positive_count == 0

    with_param = [
        {"recipe_id": "sqli-login", "scanner": "SqliScanner", "endpoint": "/login",
         "evidence": {"param": "uid"}, "request_data": {}},
    ]
    m2 = compute_metrics(expected, with_param)
    assert m2.true_positive_count == 1


def test_matches_function():
    exp = ExpectedFinding(vuln_class="sqli", endpoint="/doLogin", method="POST")
    finding = {
        "recipe_id": "sqli-auth-bypass",
        "scanner": "SqliScanner",
        "endpoint": "http://demo.testfire.net/doLogin",
        "evidence": {},
        "request_data": {},
    }
    assert _matches(exp, finding) is True


def test_matches_wrong_class():
    exp = ExpectedFinding(vuln_class="xss", endpoint="/login")
    finding = {"recipe_id": "sqli-login", "scanner": "SqliScanner",
               "endpoint": "/login", "evidence": {}, "request_data": {}}
    assert _matches(exp, finding) is False


# ── Baseline ────────────────────────────────────────────────

def test_save_and_load_baseline(tmp_path):
    metrics = {"precision": 0.8, "recall": 0.6, "f1": 0.6857, "false_positives": 2}
    p = save_baseline("test", metrics, path=tmp_path / "bl.json")
    loaded = load_baseline("test", path=p)
    assert loaded == metrics


def test_load_missing_baseline(tmp_path):
    assert load_baseline("nope", path=tmp_path / "nope.json") is None


def test_compare_no_regression():
    bl = {"precision": 0.8, "recall": 0.6, "f1": 0.68, "false_positives": 2}
    cur = {"precision": 0.85, "recall": 0.65, "f1": 0.74, "false_positives": 1}
    comp = compare(bl, cur)
    assert not comp.any_regression


def test_compare_recall_regression():
    bl = {"precision": 0.8, "recall": 0.6, "f1": 0.68, "false_positives": 2}
    cur = {"precision": 0.9, "recall": 0.4, "f1": 0.55, "false_positives": 1}
    comp = compare(bl, cur)
    assert comp.recall_regression
    assert comp.f1_regression
    assert comp.any_regression


def test_compare_fp_increase():
    bl = {"precision": 0.8, "recall": 0.6, "f1": 0.68, "false_positives": 2}
    cur = {"precision": 0.7, "recall": 0.6, "f1": 0.64, "false_positives": 5}
    comp = compare(bl, cur)
    assert comp.fp_increase
    assert comp.any_regression


def test_compare_summary_format():
    bl = {"precision": 0.8, "recall": 0.6, "f1": 0.68, "false_positives": 2}
    cur = {"precision": 0.85, "recall": 0.65, "f1": 0.74, "false_positives": 1}
    comp = compare(bl, cur)
    s = comp.summary()
    assert "VERDICT: OK" in s
    assert "F1:" in s
