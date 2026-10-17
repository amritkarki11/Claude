"""Nmap port scanning and service detection for the recon pipeline.

Runs nmap against the target, parses results into structured data,
and checks for outdated service versions with known public exploits.

Requires: nmap installed on the system (apt install nmap).
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import shutil
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ServiceInfo:
    """A single service discovered on a port."""
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    version: str = ""
    product: str = ""
    extra_info: str = ""
    cpe: str = ""
    is_outdated: bool = False
    known_exploits: list[dict] = field(default_factory=list)

    @property
    def display_version(self) -> str:
        parts = [self.product, self.version]
        return " ".join(p for p in parts if p) or self.service


@dataclass
class NmapResult:
    """Complete nmap scan result."""
    target: str
    host_status: str = "unknown"
    services: list[ServiceInfo] = field(default_factory=list)
    os_guess: str = ""
    scan_time: float = 0.0
    raw_output: str = ""
    errors: list[str] = field(default_factory=list)

    @property
    def open_ports(self) -> list[ServiceInfo]:
        return [s for s in self.services if s.state == "open"]

    @property
    def outdated_services(self) -> list[ServiceInfo]:
        return [s for s in self.services if s.is_outdated]


class NmapScanner:
    """Run nmap scans and parse results."""

    def __init__(self, target: str, *, ports: str = "1-10000",
                 scan_type: str = "-sV -sC", timeout: int = 300):
        self.target = target
        self.ports = ports
        self.scan_type = scan_type
        self.timeout = timeout

    async def scan(self) -> NmapResult:
        """Run nmap and return parsed results."""
        result = NmapResult(target=self.target)

        if not shutil.which("nmap"):
            result.errors.append("nmap not installed — run: apt install nmap")
            return result

        # Build command with XML output for parsing
        # --host-timeout keeps nmap itself from hanging on slow hosts
        host_timeout = max(self.timeout - 30, 60)
        cmd = f"nmap {self.scan_type} -p {self.ports} --host-timeout {host_timeout}s -oX - --open {self.target}"

        try:
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=self.timeout
            )

            xml_output = stdout.decode("utf-8", errors="replace")
            result.raw_output = xml_output

            if stderr:
                err_text = stderr.decode("utf-8", errors="replace").strip()
                if err_text and "WARNING" not in err_text:
                    result.errors.append(err_text)

            # Parse XML
            self._parse_xml(xml_output, result)

        except asyncio.TimeoutError:
            result.errors.append(f"nmap scan timed out after {self.timeout}s")
        except Exception as e:
            result.errors.append(f"nmap error: {e}")

        return result

    def _parse_xml(self, xml_str: str, result: NmapResult) -> None:
        """Parse nmap XML output into NmapResult."""
        try:
            root = ET.fromstring(xml_str)
        except ET.ParseError as e:
            result.errors.append(f"Failed to parse nmap XML: {e}")
            return

        # Host status
        host = root.find(".//host")
        if host is None:
            result.host_status = "down"
            return

        status = host.find("status")
        if status is not None:
            result.host_status = status.get("state", "unknown")

        # OS detection
        osmatch = host.find(".//osmatch")
        if osmatch is not None:
            result.os_guess = osmatch.get("name", "")

        # Ports/services
        for port_el in host.findall(".//port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            service_el = port_el.find("service")
            svc = ServiceInfo(
                port=int(port_el.get("portid", 0)),
                protocol=port_el.get("protocol", "tcp"),
                state="open",
            )

            if service_el is not None:
                svc.service = service_el.get("name", "")
                svc.product = service_el.get("product", "")
                svc.version = service_el.get("version", "")
                svc.extra_info = service_el.get("extrainfo", "")

                # CPE
                cpe_el = service_el.find("cpe")
                if cpe_el is not None and cpe_el.text:
                    svc.cpe = cpe_el.text

            result.services.append(svc)

        # Scan timing
        runstats = root.find(".//runstats/finished")
        if runstats is not None:
            result.scan_time = float(runstats.get("elapsed", 0))


class ExploitLookup:
    """Check services for known public exploits via searchsploit / CVE databases."""

    # Known outdated/vulnerable version patterns
    _OUTDATED_PATTERNS: list[tuple[str, str, str]] = [
        # (product_regex, version_regex, note)
        (r"Apache", r"2\.[0-3]\.", "Apache < 2.4 — EOL"),
        (r"Apache", r"2\.4\.[0-3][0-9]$", "Apache 2.4.x < 2.4.50 — check CVEs"),
        (r"nginx", r"1\.(0|1|2|3|4|5|6|7|8|9|1[0-9])\.", "nginx < 1.20 — check CVEs"),
        (r"OpenSSH", r"[1-7]\.", "OpenSSH < 8.0 — multiple CVEs"),
        (r"OpenSSH", r"8\.[0-8]", "OpenSSH < 8.9 — check CVE-2023-38408"),
        (r"vsftpd", r"[12]\.", "vsftpd < 3.0 — known backdoor in 2.3.4"),
        (r"ProFTPD", r"1\.[23]\.", "ProFTPD < 1.3.6 — multiple RCE"),
        (r"MySQL", r"5\.[0-6]\.", "MySQL < 5.7 — EOL"),
        (r"PHP", r"[5-7]\.", "PHP < 8.0 — EOL/vulnerable"),
        (r"Microsoft IIS", r"[5-7]\.", "IIS < 8.0 — outdated"),
        (r"Tomcat", r"[5-8]\.", "Tomcat < 9.0 — check CVEs"),
        (r"Exim", r"4\.(8[0-9]|9[0-4])", "Exim < 4.95 — CVE-2021-27216"),
        (r"Postfix", r"2\.", "Postfix < 3.0 — EOL"),
        (r"Dovecot", r"2\.[0-2]\.", "Dovecot < 2.3 — check CVEs"),
    ]

    @classmethod
    def check_outdated(cls, services: list[ServiceInfo]) -> list[ServiceInfo]:
        """Mark services as outdated if they match known vulnerable patterns."""
        for svc in services:
            version_str = f"{svc.product} {svc.version}"
            for prod_re, ver_re, note in cls._OUTDATED_PATTERNS:
                if (re.search(prod_re, version_str, re.I) and
                        re.search(ver_re, svc.version)):
                    svc.is_outdated = True
                    svc.known_exploits.append({"source": "version-check", "note": note})
                    break
        return services

    @classmethod
    async def searchsploit(cls, services: list[ServiceInfo]) -> list[ServiceInfo]:
        """Run searchsploit for each service to find public exploits."""
        if not shutil.which("searchsploit"):
            logger.debug("searchsploit not installed — skipping exploit lookup")
            return services

        for svc in services:
            if not svc.product:
                continue
            query = f"{svc.product} {svc.version}".strip()
            if not query:
                continue

            try:
                proc = await asyncio.create_subprocess_exec(
                    "searchsploit", "--json", query,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
                data = json.loads(stdout.decode("utf-8", errors="replace"))

                exploits = data.get("RESULTS_EXPLOIT", [])
                for exp in exploits[:5]:  # limit to top 5
                    svc.known_exploits.append({
                        "source": "exploitdb",
                        "title": exp.get("Title", ""),
                        "edb_id": exp.get("EDB-ID", ""),
                        "path": exp.get("Path", ""),
                    })
                if exploits:
                    svc.is_outdated = True

            except (asyncio.TimeoutError, json.JSONDecodeError, Exception) as e:
                logger.debug("searchsploit error for %s: %s", query, e)

        return services
