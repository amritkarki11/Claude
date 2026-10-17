"""Tests for auton/router/parser.py — slash-command parser."""
import pytest
from auton.router.parser import parse, build_nmap_cmd, ParsedCommand, _normalize_target


class TestParse:
    def test_empty_input(self):
        cmd = parse("")
        assert cmd.action == "unknown"
        assert cmd.error

    def test_exit(self):
        cmd = parse("/exit")
        assert cmd.action == "exit"
        assert not cmd.error

    def test_commands(self):
        cmd = parse("/commands")
        assert cmd.action == "commands"
        assert not cmd.error

    def test_recon_basic(self):
        cmd = parse("/recon example.com")
        assert cmd.action == "recon"
        assert cmd.target == "example.com"
        assert not cmd.is_wildcard
        assert not cmd.allports
        assert not cmd.error

    def test_recon_allports(self):
        cmd = parse("/recon /allports example.com")
        assert cmd.action == "recon"
        assert cmd.target == "example.com"
        assert cmd.allports is True

    def test_recon_missing_target(self):
        cmd = parse("/recon")
        assert cmd.action == "recon"
        assert cmd.error
        assert "Missing target" in cmd.error

    def test_fullscan_basic(self):
        cmd = parse("/fullscan target.io")
        assert cmd.action == "fullscan"
        assert cmd.target == "target.io"

    def test_fullscan_allports(self):
        cmd = parse("/fullscan /allports target.io")
        assert cmd.action == "fullscan"
        assert cmd.allports is True
        assert cmd.target == "target.io"

    def test_wildcard_target(self):
        cmd = parse("/recon *.example.com")
        assert cmd.is_wildcard is True
        assert cmd.target == "*.example.com"

    def test_unknown_command(self):
        cmd = parse("/bogus")
        assert cmd.action == "unknown"
        assert "Unknown command" in cmd.error

    def test_case_insensitive_command(self):
        cmd = parse("/RECON example.com")
        assert cmd.action == "recon"
        assert cmd.target == "example.com"

    def test_case_insensitive_allports(self):
        cmd = parse("/recon /ALLPORTS example.com")
        assert cmd.allports is True

    def test_raw_input_preserved(self):
        raw = "/recon /allports example.com"
        cmd = parse(raw)
        assert cmd.raw_input == raw

    def test_whitespace_stripped(self):
        cmd = parse("  /exit  ")
        assert cmd.action == "exit"

    def test_url_target_stripped_to_hostname(self):
        cmd = parse("/recon https://demo.testfire.net/")
        assert cmd.target == "demo.testfire.net"

    def test_url_with_port_stripped(self):
        cmd = parse("/recon https://example.com:8443/path")
        assert cmd.target == "example.com"

    def test_bare_domain_unchanged(self):
        cmd = parse("/recon example.com")
        assert cmd.target == "example.com"

    def test_ip_unchanged(self):
        cmd = parse("/recon 10.0.0.1")
        assert cmd.target == "10.0.0.1"

    def test_wildcard_preserved(self):
        cmd = parse("/recon *.example.com")
        assert cmd.target == "*.example.com"
        assert cmd.is_wildcard


class TestNormalizeTarget:
    def test_https_url(self):
        assert _normalize_target("https://example.com/path") == "example.com"

    def test_http_url(self):
        assert _normalize_target("http://example.com:8080/") == "example.com"

    def test_bare_domain(self):
        assert _normalize_target("example.com") == "example.com"

    def test_domain_with_path(self):
        assert _normalize_target("example.com/api/v1") == "example.com"

    def test_wildcard_passthrough(self):
        assert _normalize_target("*.example.com") == "*.example.com"

    def test_ip_address(self):
        assert _normalize_target("192.168.1.1") == "192.168.1.1"


class TestBuildNmapCmd:
    def test_default(self):
        cmd = build_nmap_cmd("example.com")
        assert cmd == ["nmap", "-Pn", "--top-ports", "1000", "example.com"]

    def test_allports(self):
        cmd = build_nmap_cmd("example.com", allports=True)
        assert cmd == ["nmap", "-Pn", "-p-", "example.com"]

    def test_always_has_pn(self):
        cmd = build_nmap_cmd("10.0.0.1")
        assert "-Pn" in cmd
