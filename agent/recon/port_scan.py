"""Port scan via nmap running inside Kali WSL (`wsl -d kali-linux -u root -- nmap ...`).

Non-aggressive by design: timing is capped at -T3 and out-of-range values
are rejected (never clamped silently). The host must pass scope.check()
before anything is executed. Failures (no WSL, no nmap, timeout) come back
as an error result with a hint rather than an exception.
"""
from __future__ import annotations

import asyncio
import re
import subprocess
import xml.etree.ElementTree as ET

from ..scope import check as scope_check

MAX_TIMING = 3
DEFAULT_TIMING = 3
WSL_DISTRO = "kali-linux"
SCAN_TIMEOUT = 900  # seconds
_PORTS_RE = re.compile(r"^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$")
_HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.\-]*[A-Za-z0-9])?$")


def validate_timing(timing) -> int:
    if isinstance(timing, bool) or not isinstance(timing, int) or not 0 <= timing <= MAX_TIMING:
        raise ValueError(f"timing must be an integer 0-{MAX_TIMING} (T4/T5 are not allowed), got {timing!r}")
    return timing


def validate_ports(ports: str | None) -> str | None:
    if ports is None:
        return None
    ports = ports.strip()
    if not _PORTS_RE.match(ports):
        raise ValueError(f"invalid port spec {ports!r}; use e.g. '80,443,8080' or '1-1000'")
    for part in re.split(r"[,-]", ports):
        if not 0 < int(part) <= 65535:
            raise ValueError(f"port out of range in {ports!r}")
    return ports


def build_command(host: str, ports: str | None, timing: int) -> list[str]:
    cmd = ["wsl", "-d", WSL_DISTRO, "-u", "root", "--", "nmap", "-sV", f"-T{timing}", "-oX", "-"]
    if ports:
        cmd += ["-p", ports]
    else:
        cmd += ["--top-ports", "1000"]
    return cmd + ["--", host]


def parse_nmap_xml(xml_text: str) -> list[dict]:
    """nmap XML -> [{port, protocol, state, service, version}] for every port listed."""
    root = ET.fromstring(xml_text)
    out: list[dict] = []
    for p in root.iterfind(".//host/ports/port"):
        state = p.find("state")
        svc = p.find("service")
        version = ""
        if svc is not None:
            version = " ".join(
                x for x in (svc.get("product"), svc.get("version"), svc.get("extrainfo")) if x
            )
        out.append({
            "port": int(p.get("portid")),
            "protocol": p.get("protocol"),
            "state": state.get("state") if state is not None else "unknown",
            "service": svc.get("name") if svc is not None else "",
            "version": version,
        })
    return sorted(out, key=lambda r: (r["protocol"], r["port"]))


def _decode(b: bytes | str | None) -> str:
    if isinstance(b, str):
        return b
    b = b or b""
    # wsl.exe's own error messages are UTF-16LE; nmap's are UTF-8.
    if b"\x00" in b[:8]:
        return b.decode("utf-16-le", "replace").replace("\x00", "")
    return b.decode("utf-8", "replace")


def _error(host: str, error: str, hint: str) -> dict:
    return {"host": host, "ok": False, "error": error, "hint": hint, "ports": []}


def _run(cmd: list[str]):
    return subprocess.run(cmd, capture_output=True, timeout=SCAN_TIMEOUT)


async def scan_ports(host: str, ports: str | None = None, timing: int = DEFAULT_TIMING, runner=None) -> dict:
    """Scan `host` (must be in scope). Raises ScopeError / ValueError for bad
    input; environment failures are returned as {"ok": False, "error", "hint"}."""
    timing = validate_timing(timing)
    ports = validate_ports(ports)
    scope_check(host)
    if not _HOST_RE.match(host):
        raise ValueError(f"invalid host {host!r}")
    host = host.lower()

    cmd = build_command(host, ports, timing)
    try:
        proc = await asyncio.to_thread(runner or _run, cmd)
    except FileNotFoundError:
        return _error(host, "WSL not available", "wsl.exe was not found; install/enable WSL (wsl --install).")
    except subprocess.TimeoutExpired:
        return _error(host, f"nmap timed out after {SCAN_TIMEOUT}s", "Narrow the scan with --ports.")
    except OSError as e:
        return _error(host, f"WSL could not be started: {e}", "Check that WSL is installed and enabled.")

    stdout, stderr = _decode(proc.stdout), _decode(proc.stderr)
    low = (stderr + stdout[:200]).lower()
    if proc.returncode != 0 or "<nmaprun" not in stdout:
        if "nmap" in low and ("not found" in low or "no such file" in low):
            return _error(host, "nmap not found in WSL", f"In Kali run: apt install nmap ({WSL_DISTRO}).")
        if "there is no distribution" in low or "distribution" in low and "not" in low:
            return _error(host, "WSL distro not available", f"Install it: wsl --install -d {WSL_DISTRO}")
        return _error(host, f"nmap failed (exit {proc.returncode}): {stderr.strip()[:300]}",
                      "Check WSL/nmap manually: wsl -d kali-linux -u root -- nmap --version")
    try:
        found = parse_nmap_xml(stdout)
    except ET.ParseError as e:
        return _error(host, f"could not parse nmap XML: {e}", "Re-run the scan; check nmap version.")
    return {"host": host, "ok": True, "timing": timing, "ports_spec": ports or "top-1000", "ports": found}
