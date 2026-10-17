"""Tests for bug bounty dedupe and platform export."""
import json
import pytest

from agent.report.dedupe import (
    finding_key,
    DedupeStore,
    _normalize_vuln_class,
    _normalize_endpoint,
)
from agent.report.export import (
    export_finding,
    to_markdown,
    to_hackerone,
    to_bugcrowd,
    export_batch,
)


# --- Dedupe ---

class TestNormalization:
    def test_vuln_class_strips_variant(self):
        assert _normalize_vuln_class("sqli-error") == "sqli"
        assert _normalize_vuln_class("sqli-blind") == "sqli"

    def test_vuln_class_strips_auto_prefix(self):
        assert _normalize_vuln_class("auto:auth-bypass") == "auth"

    def test_endpoint_normalization(self):
        assert _normalize_endpoint("https://Example.com/API/users?id=1") == "https://example.com/api/users"
        assert _normalize_endpoint("https://example.com/path/") == "https://example.com/path"


class TestFindingKey:
    def test_same_finding_same_key(self):
        f1 = {"recipe_id": "sqli-error", "endpoint": "https://example.com/login", "request_data": {"param": "uid"}}
        f2 = {"recipe_id": "sqli-blind", "endpoint": "https://example.com/login?foo=bar", "request_data": {"param": "uid"}}
        assert finding_key(f1) == finding_key(f2)

    def test_different_endpoint_different_key(self):
        f1 = {"recipe_id": "sqli", "endpoint": "https://example.com/login"}
        f2 = {"recipe_id": "sqli", "endpoint": "https://example.com/search"}
        assert finding_key(f1) != finding_key(f2)

    def test_different_vuln_different_key(self):
        f1 = {"recipe_id": "sqli", "endpoint": "https://example.com/login"}
        f2 = {"recipe_id": "xss", "endpoint": "https://example.com/login"}
        assert finding_key(f1) != finding_key(f2)


class TestDedupeStore:
    def test_no_false_duplicates(self):
        store = DedupeStore()
        f = {"recipe_id": "sqli", "endpoint": "https://example.com/login"}
        assert not store.is_duplicate(f)

    def test_mark_and_detect(self):
        store = DedupeStore()
        f = {"recipe_id": "sqli", "endpoint": "https://example.com/login"}
        store.mark_reported(f, platform_id="H1-12345")
        assert store.is_duplicate(f)
        assert store.reported_count == 1

    def test_dedupe_filters(self):
        store = DedupeStore()
        f1 = {"recipe_id": "sqli", "endpoint": "https://example.com/a"}
        f2 = {"recipe_id": "xss", "endpoint": "https://example.com/b"}
        store.mark_reported(f1)
        result = store.dedupe([f1, f2])
        assert len(result) == 1
        assert result[0]["recipe_id"] == "xss"

    def test_save_load(self, tmp_path):
        path = tmp_path / "dedupe.json"
        store = DedupeStore(_path=path)
        f = {"recipe_id": "sqli", "endpoint": "https://example.com/login"}
        store.mark_reported(f, "H1-999")
        store.save()

        loaded = DedupeStore.load(path)
        assert loaded.is_duplicate(f)
        assert loaded.reported_count == 1

    def test_load_nonexistent(self, tmp_path):
        store = DedupeStore.load(tmp_path / "missing.json")
        assert store.reported_count == 0


# --- Export ---

class TestExport:
    SAMPLE = {
        "recipe_id": "sqli-error",
        "endpoint": "https://example.com/login",
        "method": "POST",
        "reason": "Error-based SQL injection confirmed",
        "scanner": "SqliScanner",
        "evidence": {"technique": "error-based"},
        "request_data": {"url": "https://example.com/login", "method": "POST",
                         "param": "uid", "payload": "' OR 1=1--"},
        "response_data": {"status": 500, "body_snippet": "SQL syntax error"},
    }

    def test_export_finding(self):
        f = export_finding(self.SAMPLE)
        assert "Sqli Error" in f.title
        assert f.severity == "critical"
        assert f.cvss_score == 9.8
        assert f.cwe == "CWE-89"

    def test_markdown_format(self):
        f = export_finding(self.SAMPLE)
        md = to_markdown(f)
        assert "## " in md
        assert "CRITICAL" in md
        assert "CWE-89" in md
        assert "Steps to Reproduce" in md

    def test_hackerone_format(self):
        f = export_finding(self.SAMPLE)
        h1 = to_hackerone(f)
        assert h1["data"]["type"] == "report"
        assert h1["data"]["attributes"]["severity_rating"] == "critical"

    def test_bugcrowd_format(self):
        f = export_finding(self.SAMPLE)
        bc = to_bugcrowd(f)
        assert bc["severity"] == "critical"
        assert "CVSS" in bc["extra_info"]

    def test_export_batch_markdown(self):
        results = export_batch([self.SAMPLE], format="markdown")
        assert len(results) == 1
        assert isinstance(results[0], str)

    def test_export_batch_hackerone(self):
        results = export_batch([self.SAMPLE], format="hackerone")
        assert len(results) == 1
        assert isinstance(results[0], dict)

    def test_steps_with_full_request(self):
        finding = dict(self.SAMPLE)
        finding["request_data"]["full_request"] = "POST /login HTTP/1.1\nHost: example.com"
        f = export_finding(finding)
        assert "POST /login" in f.steps_to_reproduce
