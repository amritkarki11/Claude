"""Tests for auton/router/parser.py — modular command parser."""
import pytest
from auton.router.parser import parse, _SCANNER_MAP


class TestParse:
    def test_exit(self):
        cmd = parse("/exit")
        assert cmd.action == "exit"

    def test_commands(self):
        cmd = parse("/commands")
        assert cmd.action == "commands"

    def test_empty(self):
        cmd = parse("")
        assert cmd.error

    def test_unknown(self):
        cmd = parse("/bogus")
        assert cmd.action == "unknown"
        assert "Unknown command" in cmd.error

    def test_recon_basic(self):
        cmd = parse("/recon example.com")
        assert cmd.action == "recon"
        assert cmd.target == "example.com"
        assert cmd.nmap is False
        assert cmd.allports is False

    def test_recon_with_nmap(self):
        cmd = parse("/recon example.com /nmap")
        assert cmd.action == "recon"
        assert cmd.target == "example.com"
        assert cmd.nmap is True

    def test_recon_nmap_allports(self):
        cmd = parse("/recon example.com /nmap /allports")
        assert cmd.action == "recon"
        assert cmd.nmap is True
        assert cmd.allports is True

    def test_fullscan_basic(self):
        cmd = parse("/fullscan example.com")
        assert cmd.action == "fullscan"
        assert cmd.target == "example.com"
        assert cmd.nmap is False

    def test_fullscan_with_nmap(self):
        cmd = parse("/fullscan example.com /nmap")
        assert cmd.nmap is True

    def test_nmap_standalone(self):
        cmd = parse("/nmap example.com")
        assert cmd.action == "nmap"
        assert cmd.target == "example.com"
        assert cmd.nmap is True

    def test_nmap_allports(self):
        cmd = parse("/nmap example.com /allports")
        assert cmd.action == "nmap"
        assert cmd.allports is True

    def test_wildcard(self):
        cmd = parse("/recon *.example.com")
        assert cmd.is_wildcard is True
        assert cmd.target == "*.example.com"

    def test_missing_target(self):
        cmd = parse("/recon")
        assert "Missing target" in cmd.error

    def test_nmap_missing_target(self):
        cmd = parse("/nmap")
        assert "Missing target" in cmd.error

    def test_url_normalized(self):
        cmd = parse("/recon https://example.com/path")
        assert cmd.target == "example.com"


class TestSingleScanners:
    @pytest.mark.parametrize("key", list(_SCANNER_MAP.keys()))
    def test_scanner_parses(self, key):
        cmd = parse(f"/{key} example.com")
        assert cmd.action == "scan_single"
        assert cmd.scanner == key
        assert cmd.target == "example.com"

    @pytest.mark.parametrize("key", list(_SCANNER_MAP.keys()))
    def test_scanner_missing_target(self, key):
        cmd = parse(f"/{key}")
        assert "Missing target" in cmd.error

    def test_sqli(self):
        cmd = parse("/sqli demo.testfire.net")
        assert cmd.scanner == "sqli"

    def test_xss(self):
        cmd = parse("/xss demo.testfire.net")
        assert cmd.scanner == "xss"

    def test_idor(self):
        cmd = parse("/idor demo.testfire.net")
        assert cmd.scanner == "idor"
