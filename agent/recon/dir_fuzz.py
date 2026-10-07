"""Directory/content discovery via ffuf running inside Kali WSL
(`wsl -d kali-linux -u root -- ffuf ...`), same shelling pattern as
port_scan.py's nmap integration.

Non-aggressive by design: -rate and -t (threads) have sane, capped
defaults and reject (never silently clamp) anything above the cap. The
target's host must pass scope.check() before anything is executed.
Failures (no WSL, no ffuf, bad wordlist, timeout) come back as an error
result with a hint rather than an exception.

Noise control: ffuf itself is told to only match the allow-listed status
codes (-mc), and the parsed results are filtered again client-side as a
second line of defense -- 404s never make it into the report either way.
"""
from __future__ import annotations

import asyncio
import json
import re
import subprocess

from ..scope import check as scope_check
from ..scope import host_of

WSL_DISTRO = "kali-linux"
FUZZ_TIMEOUT = 600  # seconds

DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"
DEFAULT_STATUS_CODES = "200,204,301,302,307,401,403"  # 404 (and anything else) stays hidden

DEFAULT_RATE = 40
MAX_RATE = 200
DEFAULT_THREADS = 10
MAX_THREADS = 40

_STATUS_RE = re.compile(r"^\d{3}(,\d{3})*$")


def validate_rate(rate) -> int:
    if isinstance(rate, bool) or not isinstance(rate, int) or not 0 < rate <= MAX_RATE:
        raise ValueError(f"rate must be an integer 1-{MAX_RATE} req/s, got {rate!r}")
    return rate


def validate_threads(threads) -> int:
    if isinstance(threads, bool) or not isinstance(threads, int) or not 0 < threads <= MAX_THREADS:
        raise ValueError(f"threads must be an integer 1-{MAX_THREADS}, got {threads!r}")
    return threads


def validate_status_codes(codes: str) -> str:
    codes = (codes or "").strip()
    if not _STATUS_RE.match(codes):
        raise ValueError(f"invalid status-code list {codes!r}; use e.g. '200,204,301'")
    return codes


def build_command(target: str, wordlist: str, rate: int, threads: int, status_codes: str) -> list[str]:
    url = f"{target.rstrip('/')}/FUZZ"
    return [
        "wsl", "-d", WSL_DISTRO, "-u", "root", "--",
        "ffuf", "-u", url, "-w", wordlist,
        "-of", "json", "-o", "-",
        "-rate", str(rate), "-t", str(threads),
        "-mc", status_codes,
        "-s",  # silent: no banner/progress mixed into the JSON on stdout
    ]


def parse_ffuf_json(json_text: str) -> list[dict]:
    """ffuf's `-of json` output -> [{path, status, length, words}, ...]."""
    data = json.loads(json_text)
    out: list[dict] = []
    for r in data.get("results", []):
        path = (r.get("input") or {}).get("FUZZ") or ""
        if not path.startswith("/"):
            path = "/" + path
        out.append({
            "path": path,
            "status": r.get("status"),
            "length": r.get("length"),
            "words": r.get("words"),
        })
    return sorted(out, key=lambda e: e["path"])


def filter_by_status(results: list[dict], status_codes: str = DEFAULT_STATUS_CODES) -> list[dict]:
    """Keep only results whose status is in the allow-list (hides 404s and
    anything else not explicitly allowed)."""
    allowed = {int(c) for c in status_codes.split(",") if c}
    return [r for r in results if r["status"] in allowed]


def _decode(b: bytes | str | None) -> str:
    if isinstance(b, str):
        return b
    b = b or b""
    # wsl.exe's own error messages are UTF-16LE; ffuf's are UTF-8.
    if b"\x00" in b[:8]:
        return b.decode("utf-16-le", "replace").replace("\x00", "")
    return b.decode("utf-8", "replace")


def _error(target: str, error: str, hint: str) -> dict:
    return {"target": target, "ok": False, "error": error, "hint": hint, "paths": []}


def _run(cmd: list[str]):
    return subprocess.run(cmd, capture_output=True, timeout=FUZZ_TIMEOUT)


async def fuzz_directories(
    target: str,
    *,
    wordlist: str | None = None,
    rate: int = DEFAULT_RATE,
    threads: int = DEFAULT_THREADS,
    status_codes: str = DEFAULT_STATUS_CODES,
    runner=None,
) -> dict:
    """Fuzz `target` (a URL; its host must be in scope). Raises ScopeError /
    ValueError for bad input; environment failures are returned as
    {"ok": False, "error", "hint"} rather than raised."""
    rate = validate_rate(rate)
    threads = validate_threads(threads)
    status_codes = validate_status_codes(status_codes)
    wordlist = wordlist or DEFAULT_WORDLIST

    host = host_of(target)
    scope_check(host)  # fail closed before anything touches the network

    cmd = build_command(target, wordlist, rate, threads, status_codes)
    try:
        proc = await asyncio.to_thread(runner or _run, cmd)
    except FileNotFoundError:
        return _error(target, "WSL not available", "wsl.exe was not found; install/enable WSL (wsl --install).")
    except subprocess.TimeoutExpired:
        return _error(target, f"ffuf timed out after {FUZZ_TIMEOUT}s", "Narrow the wordlist or lower -rate/-t.")
    except OSError as e:
        return _error(target, f"WSL could not be started: {e}", "Check that WSL is installed and enabled.")

    stdout, stderr = _decode(proc.stdout), _decode(proc.stderr)
    low = (stderr + stdout[:200]).lower()
    if proc.returncode != 0 or not stdout.strip().startswith("{"):
        if "ffuf" in low and ("not found" in low or "no such file" in low):
            return _error(target, "ffuf not found in WSL", f"In Kali run: apt install ffuf ({WSL_DISTRO}).")
        if "there is no distribution" in low or ("distribution" in low and "not" in low):
            return _error(target, "WSL distro not available", f"Install it: wsl --install -d {WSL_DISTRO}")
        return _error(target, f"ffuf failed (exit {proc.returncode}): {stderr.strip()[:300]}",
                      "Check WSL/ffuf manually: wsl -d kali-linux -u root -- ffuf -V")

    try:
        parsed = parse_ffuf_json(stdout)
    except (json.JSONDecodeError, ValueError) as e:
        return _error(target, f"could not parse ffuf JSON: {e}", "Re-run the fuzz; check the ffuf version.")

    found = filter_by_status(parsed, status_codes)
    return {
        "target": target,
        "ok": True,
        "wordlist": wordlist,
        "rate": rate,
        "threads": threads,
        "status_codes": status_codes,
        "paths": found,
    }
