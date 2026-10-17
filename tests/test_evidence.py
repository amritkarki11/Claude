"""Tests for evidence chain-of-custody collector."""
import json
import pytest

from agent.evidence.collector import (
    EvidenceItem,
    EvidenceChain,
    EvidenceCollector,
)


class TestEvidenceItem:
    def test_hash_computed_on_init(self):
        item = EvidenceItem(
            evidence_id="f1-000",
            finding_id="f1",
            timestamp="2024-01-01T00:00:00Z",
            category="request",
            content={"method": "GET", "url": "https://example.com"},
            prev_hash="0" * 64,
        )
        assert len(item.sha256) == 64
        assert item.verify()

    def test_tampered_content_fails_verify(self):
        item = EvidenceItem(
            evidence_id="f1-000",
            finding_id="f1",
            timestamp="2024-01-01T00:00:00Z",
            category="request",
            content={"method": "GET", "url": "https://example.com"},
            prev_hash="0" * 64,
        )
        original_hash = item.sha256
        item.content["url"] = "https://evil.com"
        assert not item.verify()

    def test_deterministic_hash(self):
        kwargs = dict(
            evidence_id="f1-000",
            finding_id="f1",
            timestamp="2024-01-01T00:00:00Z",
            category="request",
            content={"method": "GET", "url": "https://example.com"},
            prev_hash="0" * 64,
        )
        a = EvidenceItem(**kwargs)
        b = EvidenceItem(**kwargs)
        assert a.sha256 == b.sha256


class TestEvidenceChain:
    def test_chain_links(self):
        chain = EvidenceChain(finding_id="f1")
        item1 = chain.add("request", {"url": "https://example.com"})
        item2 = chain.add("response", {"status": 200})
        assert item1.prev_hash == "0" * 64
        assert item2.prev_hash == item1.sha256

    def test_chain_verify_valid(self):
        chain = EvidenceChain(finding_id="f1")
        chain.add("request", {"url": "https://example.com"})
        chain.add("response", {"status": 200})
        chain.add("note", {"text": "Confirmed SQL injection"})
        valid, errors = chain.verify_chain()
        assert valid
        assert errors == []

    def test_chain_verify_tampered(self):
        chain = EvidenceChain(finding_id="f1")
        chain.add("request", {"url": "https://example.com"})
        chain.add("response", {"status": 200})
        # Tamper
        chain.items[0].content["url"] = "https://evil.com"
        valid, errors = chain.verify_chain()
        assert not valid
        assert len(errors) >= 1

    def test_broken_chain_link(self):
        chain = EvidenceChain(finding_id="f1")
        chain.add("request", {"url": "https://example.com"})
        chain.add("response", {"status": 200})
        # Break the chain link
        chain.items[1].prev_hash = "bad" * 21 + "ba"
        valid, errors = chain.verify_chain()
        assert not valid


class TestEvidenceCollector:
    def test_capture_request_response(self, tmp_path):
        collector = EvidenceCollector(tmp_path)
        req = collector.capture_request("f1", "POST", "https://example.com/login",
                                         headers={"Content-Type": "application/json"},
                                         body='{"user":"admin"}')
        resp = collector.capture_response("f1", 200, body='{"token":"abc"}', elapsed_ms=42.5)
        assert req.category == "request"
        assert resp.category == "response"
        assert resp.prev_hash == req.sha256

    def test_capture_note(self, tmp_path):
        collector = EvidenceCollector(tmp_path)
        note = collector.capture_note("f1", "Manual verification confirmed")
        assert note.category == "note"

    def test_log_file_written(self, tmp_path):
        collector = EvidenceCollector(tmp_path)
        collector.capture_request("f1", "GET", "https://example.com")
        collector.capture_response("f1", 200)
        log = tmp_path / "evidence.jsonl"
        assert log.exists()
        lines = log.read_text().strip().split("\n")
        assert len(lines) == 2
        entry = json.loads(lines[0])
        assert "sha256" in entry
        assert len(entry["sha256"]) == 64

    def test_verify_all(self, tmp_path):
        collector = EvidenceCollector(tmp_path)
        collector.capture_request("f1", "GET", "https://example.com")
        collector.capture_response("f1", 200)
        collector.capture_request("f2", "POST", "https://example.com/api")
        results = collector.verify_all()
        assert results["f1"][0] is True
        assert results["f2"][0] is True

    def test_export(self, tmp_path):
        collector = EvidenceCollector(tmp_path)
        collector.capture_request("f1", "GET", "https://example.com")
        collector.capture_response("f1", 200)
        path = collector.export()
        assert path.exists()
        data = json.loads(path.read_text())
        assert "chains" in data
        assert data["chains"]["f1"]["integrity_valid"] is True

    def test_get_chain(self, tmp_path):
        collector = EvidenceCollector(tmp_path)
        assert collector.get_chain("nonexistent") is None
        collector.capture_request("f1", "GET", "https://example.com")
        chain = collector.get_chain("f1")
        assert chain is not None
        assert len(chain.items) == 1

    def test_body_capped(self, tmp_path):
        collector = EvidenceCollector(tmp_path)
        big_body = "x" * 20000
        collector.capture_response("f1", 200, body=big_body)
        chain = collector.get_chain("f1")
        assert len(chain.items[0].content["body"]) == 10000
