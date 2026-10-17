"""Terminal display — clean, structured output for recon and scan results.

Renders per-tool recon tables (nmap, fingerprint, crawl, JS extract, params)
and confirmed-only vulnerability findings with exact request/response.

All output uses ANSI color codes for terminal rendering.
"""
from __future__ import annotations

import re
import shutil
import sys
import threading
import time
from typing import Any
from urllib.parse import urlparse

# ── ANSI codes ──────────────────────────────────────────────

_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_UNDERLINE = "\033[4m"
_RED = "\033[31m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_BLUE = "\033[34m"
_MAGENTA = "\033[35m"
_CYAN = "\033[36m"
_WHITE = "\033[37m"
_BRIGHT_RED = "\033[91m"
_BRIGHT_GREEN = "\033[92m"
_BRIGHT_YELLOW = "\033[93m"
_BRIGHT_CYAN = "\033[96m"
_ORANGE = "\033[38;5;208m"
_BRIGHT_ORANGE = "\033[38;5;214m"
_BG_RED = "\033[41m"
_BG_GREEN = "\033[42m"
_BG_YELLOW = "\033[43m"

_SEVERITY_COLORS = {
    "critical": _BRIGHT_RED,
    "high": _RED,
    "medium": _YELLOW,
    "low": _CYAN,
    "info": _WHITE,
}

# ── ANSI-aware text helpers ─────────────────────────────────

_ANSI_RE = re.compile(r'\033\[[0-9;]*m')


def _vis_len(text: str) -> int:
    """Visible length of text (excluding ANSI escape codes)."""
    return len(_ANSI_RE.sub('', str(text)))


def _vis_ljust(text: str, width: int) -> str:
    """Left-justify text to width, accounting for invisible ANSI chars."""
    extra = len(str(text)) - _vis_len(text)
    return str(text).ljust(width + extra)


def _vis_truncate(text: str, width: int) -> str:
    """Truncate to visible width, preserving ANSI codes."""
    result = []
    count = 0
    i = 0
    s = str(text)
    while i < len(s):
        if s[i] == '\033' and i + 1 < len(s) and s[i + 1] == '[':
            j = i + 2
            while j < len(s) and s[j] != 'm':
                j += 1
            result.append(s[i:j + 1])
            i = j + 1
        else:
            if count >= width:
                break
            result.append(s[i])
            count += 1
            i += 1
    result.append(_RESET)
    return ''.join(result)


def _term_width() -> int:
    return min(shutil.get_terminal_size((100, 25)).columns, 120)


def _box_line(char: str = "─") -> str:
    return char * _term_width()


def _header(text: str, icon: str = "◆") -> str:
    w = _term_width()
    line = "─" * w
    return (
        f"\n{_BOLD}{_ORANGE}{line}{_RESET}\n"
        f"  {_BOLD}{_ORANGE}{icon} {text}{_RESET}\n"
        f"{_BOLD}{_ORANGE}{line}{_RESET}"
    )


def _sub_header(text: str) -> str:
    return f"\n  {_BOLD}{_WHITE}{text}{_RESET}"


def _table(headers: list[str], rows: list[list[str]], *,
           col_widths: list[int] | None = None) -> str:
    """Render a simple ASCII table with ANSI-aware column alignment."""
    if not rows:
        return f"  {_DIM}(no data){_RESET}"

    # Auto-calculate widths using visible length
    if col_widths is None:
        col_widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                if i < len(col_widths):
                    col_widths[i] = max(col_widths[i], _vis_len(str(cell)))

    # Cap widths to terminal
    max_w = _term_width() - 4 - (len(headers) - 1) * 3
    total = sum(col_widths)
    if total > max_w:
        ratio = max_w / total
        col_widths = [max(4, int(w * ratio)) for w in col_widths]

    def _fmt_row(cells: list[str], is_header: bool = False) -> str:
        parts = []
        for i, cell in enumerate(cells):
            w = col_widths[i] if i < len(col_widths) else 10
            text = str(cell)
            vis = _vis_len(text)
            if vis > w:
                text = _vis_truncate(text, w)
            parts.append(_vis_ljust(text, w))
        return "  " + " │ ".join(parts)

    # Header row with bold formatting
    header_cells = [f"{_BOLD}{h}{_RESET}" for h in headers]
    lines = [
        _fmt_row(header_cells, is_header=True),
        "  " + "─┼─".join("─" * w for w in col_widths),
    ]
    for row in rows:
        lines.append(_fmt_row(row))

    return "\n".join(lines)


# ── Recon display functions ──────────────────────────────────


def display_nmap(nmap_result) -> None:
    """Print nmap scan results as a clean table."""
    print(_header("NMAP PORT SCAN", "🔍"))

    if nmap_result.errors:
        for err in nmap_result.errors:
            print(f"  {_RED}⚠ {err}{_RESET}")
        return

    if not nmap_result.services:
        print(f"  {_DIM}No open ports found{_RESET}")
        return

    # Host status
    status_color = _GREEN if nmap_result.host_status == "up" else _RED
    print(f"  {_BOLD}Host:{_RESET} {nmap_result.target}  "
          f"{status_color}{_BOLD}{nmap_result.host_status.upper()}{_RESET}")
    if nmap_result.os_guess:
        print(f"  {_BOLD}OS:{_RESET}   {nmap_result.os_guess}")
    print(f"  {_BOLD}Scan:{_RESET} {nmap_result.scan_time:.1f}s\n")

    # Port table
    headers = ["PORT", "STATE", "SERVICE", "VERSION", "STATUS"]
    rows = []
    for svc in nmap_result.services:
        status = ""
        if svc.is_outdated:
            status = f"{_RED}OUTDATED{_RESET}"
        elif svc.version:
            status = f"{_GREEN}OK{_RESET}"

        rows.append([
            f"{svc.port}/{svc.protocol}",
            f"{_GREEN}{svc.state}{_RESET}",
            svc.service,
            svc.display_version or _DIM + "unknown" + _RESET,
            status,
        ])

    print(_table(headers, rows, col_widths=[12, 8, 15, 35, 12]))

    # Outdated services detail
    outdated = nmap_result.outdated_services
    if outdated:
        print(_sub_header(f"⚠  OUTDATED / VULNERABLE SERVICES ({len(outdated)})"))
        for svc in outdated:
            print(f"  {_RED}●{_RESET} {_BOLD}{svc.port}/{svc.protocol}{_RESET} "
                  f"— {svc.display_version}")
            for exp in svc.known_exploits:
                if exp.get("source") == "version-check":
                    print(f"    {_YELLOW}⮑ {exp['note']}{_RESET}")
                elif exp.get("source") == "exploitdb":
                    print(f"    {_RED}⮑ EDB-{exp.get('edb_id', '?')}: "
                          f"{exp.get('title', 'N/A')}{_RESET}")
    print()


def display_fingerprint(fp_result) -> None:
    """Print fingerprint/tech detection results."""
    print(_header("TECHNOLOGY FINGERPRINT", "🔎"))

    if not fp_result.signal_list:
        print(f"  {_DIM}No tech signals detected{_RESET}\n")
        return

    # Tech signals table
    headers = ["SIGNAL", "SOURCE"]
    rows = []
    for sig in fp_result.signals:
        # sig is a TechSignal dataclass with .signal and .source attrs
        source = getattr(sig, "source", "detection")
        rows.append([sig.signal, source])

    print(_table(headers, rows, col_widths=[30, 25]))

    # Security headers
    if fp_result.security_headers:
        print(_sub_header("Security Headers"))
        for hdr in fp_result.security_headers:
            print(f"  {_GREEN}✓{_RESET} {hdr}")

    # WAF detection
    if fp_result.waf_detected:
        print(_sub_header("WAF Detected"))
        for waf in fp_result.waf_detected:
            print(f"  {_YELLOW}🛡 {waf}{_RESET}")
    print()


def display_crawl(crawl_result) -> None:
    """Print crawler results summary."""
    print(_header("CRAWLER RESULTS", "🕷"))

    print(f"  {_BOLD}Pages crawled:{_RESET}  {crawl_result.urls_visited}")
    print(f"  {_BOLD}Forms found:{_RESET}    {crawl_result.forms_found}")
    soft_404 = getattr(crawl_result, "soft_404_count", 0)
    if soft_404:
        print(f"  {_BOLD}Soft-404s:{_RESET}      {_DIM}{soft_404} (filtered){_RESET}")
    print()

    # Forms table
    if crawl_result.all_forms:
        headers = ["ACTION", "METHOD", "FIELDS", "SOURCE"]
        rows = []
        for form in crawl_result.all_forms[:20]:  # limit display
            action_path = urlparse(form.action).path or form.action
            field_names = ", ".join(
                (f.name if hasattr(f, "name") else str(f))
                for f in form.fields[:5]
            ) if hasattr(form, "fields") else ""
            if not field_names:
                field_names = str(len(getattr(form, "fields", []))) + " fields"
            source_path = urlparse(form.source_page).path if form.source_page else "?"
            rows.append([
                action_path[:35],
                form.method,
                field_names[:30],
                source_path[:25],
            ])

        print(_sub_header("Discovered Forms"))
        print(_table(headers, rows, col_widths=[35, 8, 30, 25]))

        remaining = len(crawl_result.all_forms) - 20
        if remaining > 0:
            print(f"  {_DIM}... and {remaining} more forms{_RESET}")
    print()


def display_js_extraction(js_result) -> None:
    """Print JS endpoint extraction results."""
    print(_header("JS ENDPOINT EXTRACTION", "📜"))

    print(f"  {_BOLD}JS files analyzed:{_RESET} {js_result.js_files_fetched}")
    print(f"  {_BOLD}Endpoints found:{_RESET}  {len(js_result.endpoints)}")
    print()

    if js_result.endpoints:
        headers = ["ENDPOINT", "METHOD", "SOURCE"]
        rows = []
        for ep in js_result.endpoints[:20]:
            rows.append([
                ep.path[:45],
                ep.method,
                (ep.source_file or "?")[-30:],
            ])

        print(_table(headers, rows, col_widths=[45, 8, 30]))

        remaining = len(js_result.endpoints) - 20
        if remaining > 0:
            print(f"  {_DIM}... and {remaining} more endpoints{_RESET}")
    print()


def display_params(param_inventory) -> None:
    """Print parameter discovery results."""
    print(_header("PARAMETER DISCOVERY", "🔑"))

    high_value = param_inventory.high_value_params
    print(f"  {_BOLD}Total endpoints:{_RESET}    {len(param_inventory.endpoints)}")
    print(f"  {_BOLD}High-value params:{_RESET}  {len(high_value)}")
    print()

    if high_value:
        headers = ["PARAMETER", "TYPE", "SCORE", "SOURCES"]
        rows = []
        for p in high_value[:15]:
            score_color = _RED if p.security_score >= 0.7 else (
                _YELLOW if p.security_score >= 0.4 else _GREEN)
            rows.append([
                p.name,
                p.param_type,
                f"{score_color}{p.security_score:.1f}{_RESET}",
                ", ".join(p.sources[:3]),
            ])

        print(_sub_header("High-Value Parameters"))
        print(_table(headers, rows, col_widths=[25, 12, 8, 30]))
    print()


def display_classification(endpoints: list) -> None:
    """Print endpoint classification summary."""
    print(_header("ENDPOINT CLASSIFICATION", "🏷"))

    # Group by function
    func_groups: dict[str, list] = {}
    for ep in endpoints:
        func = getattr(ep, "function", "unknown")
        func_groups.setdefault(func, []).append(ep)

    headers = ["FUNCTION", "COUNT", "VULNS"]
    rows = []
    for func, eps in sorted(func_groups.items(), key=lambda x: -len(x[1])):
        # Collect unique relevant vulns
        vulns = set()
        for ep in eps:
            rv = getattr(ep, "relevant_vulns", [])
            vulns.update(rv)
        rows.append([
            func,
            str(len(eps)),
            ", ".join(sorted(vulns)[:5]) or "—",
        ])

    print(_table(headers, rows, col_widths=[20, 8, 50]))
    print(f"\n  {_BOLD}Total endpoints:{_RESET} {len(endpoints)}\n")


# ── Recon summary (all tools combined) ──────────────────────


def display_recon_summary(inventory) -> None:
    """Print the complete recon summary after all tools finish."""
    print(_header("RECON COMPLETE", "✅"))

    summary = inventory.summary()
    print(f"  {_BOLD}Target:{_RESET}           {summary['target']}")
    print(f"  {_BOLD}Endpoints:{_RESET}        {summary['endpoints']}")
    print(f"  {_BOLD}Tech signals:{_RESET}     {', '.join(summary['tech_signals'][:8]) or '—'}")
    print(f"  {_BOLD}Security hdrs:{_RESET}    {len(summary['security_headers'])}")
    print(f"  {_BOLD}WAF:{_RESET}              {', '.join(summary['waf']) or 'None detected'}")
    print(f"  {_BOLD}Pages crawled:{_RESET}    {summary['pages_crawled']}")
    if summary.get('soft_404s_filtered'):
        print(f"  {_BOLD}Soft-404s:{_RESET}        {summary['soft_404s_filtered']} (filtered)")
    print(f"  {_BOLD}Forms found:{_RESET}      {summary['forms_found']}")
    print(f"  {_BOLD}JS analyzed:{_RESET}      {summary['js_files_analyzed']}")
    print(f"  {_BOLD}HV params:{_RESET}        {summary['high_value_params']}")
    print()


# ── Confirmed finding display ────────────────────────────────

_finding_counter = 0


def display_confirmed_finding(result) -> None:
    """Display a confirmed vulnerability with exact request/response and curl command.

    ONLY shows CONFIRMED findings, not every HTTP call the backend makes.
    """
    global _finding_counter
    _finding_counter += 1
    count = _finding_counter

    candidate = result.candidate
    vuln_class = candidate.scanner.replace("Scanner", "").replace("Discovery", "")
    verdict_str = result.verdict.name

    # Determine severity
    severity = "medium"
    if candidate.confidence == "high":
        severity = "high"
    if vuln_class.lower() in ("authbypass", "sqli", "cmdi", "ssti", "lfi"):
        severity = "high" if candidate.confidence == "high" else "medium"

    color = _SEVERITY_COLORS.get(severity, "")
    verdict_color = _GREEN if verdict_str == "CONFIRMED" else _YELLOW

    # Extract key info
    param = candidate.request_data.get("param", candidate.request_data.get("id_param", ""))
    payload = candidate.request_data.get("payload", candidate.request_data.get("id_value", ""))
    endpoint = candidate.endpoint
    method = candidate.method

    # Truncate payload for header display
    short_payload = payload
    if len(str(payload)) > 60:
        short_payload = str(payload)[:57] + "..."

    # Finding header
    w = _term_width()
    print(f"\n{_BOLD}{'═' * w}{_RESET}")
    print(f"  {color}{_BOLD}[FINDING #{count:03d}]{_RESET}  "
          f"{verdict_color}{_BOLD}{verdict_str}{_RESET}  "
          f"{color}{_BOLD}{severity.upper()}{_RESET}")
    print(f"  {_BOLD}Type:{_RESET}      {vuln_class}")
    print(f"  {_BOLD}Endpoint:{_RESET}  {method} {endpoint}")
    if param:
        print(f"  {_BOLD}Parameter:{_RESET} {param}")
    if short_payload:
        print(f"  {_BOLD}Payload:{_RESET}   {_DIM}{short_payload}{_RESET}")
    # Show the best detail: evidence.detail > result.reason
    evidence = getattr(result, "evidence", {}) or {}
    detail_text = evidence.get("detail", "") or result.reason or ""
    if detail_text:
        print(f"  {_BOLD}Detail:{_RESET}    {detail_text[:120]}")

    # Curl command — most important for reproduction, show prominently
    curl_cmd = build_curl_command(candidate)
    if curl_cmd:
        print(f"\n  {_BOLD}{_ORANGE}┌─ REPRODUCE ─────────────────────────────────────────────{_RESET}")
        print(f"  {_BOLD}{_ORANGE}│{_RESET} {_BOLD}{curl_cmd}{_RESET}")
        print(f"  {_BOLD}{_ORANGE}└─────────────────────────────────────────────────────────{_RESET}")

    # ── Request display ──
    full_request = candidate.request_data.get("full_request", "")
    form_data = candidate.request_data.get("form_data", {})
    siblings = candidate.request_data.get("sibling_fields", {})

    print(f"\n  {_BOLD}┌─ REQUEST ──────────────────────────────────────────────{_RESET}")
    if full_request:
        req_lines = [l for l in full_request.split("\n") if l.strip()]
        for line in req_lines[:12]:
            trunc = line.strip()[:120]
            print(f"  {_DIM}│ {trunc}{_RESET}")
    elif form_data or param:
        # Reconstruct request from available data
        id_loc = candidate.request_data.get("id_location", "body")
        print(f"  {_DIM}│ {method} {endpoint} HTTP/1.1{_RESET}")
        if id_loc == "body":
            print(f"  {_DIM}│ Content-Type: application/x-www-form-urlencoded{_RESET}")
            body = dict(form_data) if form_data else dict(siblings)
            if param and payload:
                body[param] = payload
            body_str = "&".join(f"{k}={v}" for k, v in body.items())
            print(f"  {_DIM}│{_RESET}")
            print(f"  {_DIM}│ {body_str[:200]}{_RESET}")
        elif id_loc == "query":
            qp = dict(siblings)
            if param and payload:
                qp[param] = payload
            qs = "&".join(f"{k}={v}" for k, v in qp.items())
            print(f"  {_DIM}│ Query: {qs[:200]}{_RESET}")
        else:
            print(f"  {_DIM}│ {method} {endpoint}/{payload} HTTP/1.1{_RESET}")
    else:
        print(f"  {_DIM}│ {method} {endpoint} HTTP/1.1{_RESET}")
    print(f"  {_BOLD}└───────────────────────────────────────────────────────{_RESET}")

    # ── Response display ──
    resp_data = getattr(candidate, "response_data", {}) or {}
    full_response = resp_data.get("full_response", "")

    print(f"  {_BOLD}┌─ RESPONSE ─────────────────────────────────────────────{_RESET}")
    if full_response:
        resp_lines = [l for l in full_response.split("\n") if l.strip()]
        for line in resp_lines[:10]:
            trunc = line.strip()[:120]
            print(f"  {_DIM}│ {trunc}{_RESET}")
        if len(resp_lines) > 10:
            # Save full response to file so user can view it
            import pathlib
            resp_dir = pathlib.Path("output") / "responses"
            resp_dir.mkdir(parents=True, exist_ok=True)
            resp_file = resp_dir / f"finding-{count:03d}-response.txt"
            resp_file.write_text(full_response, encoding="utf-8")
            print(f"  {_DIM}│ ... ({len(resp_lines) - 10} more lines){_RESET}")
            print(f"  {_ORANGE}│ See full: cat {resp_file}{_RESET}")
    else:
        status = resp_data.get("status", "?")
        print(f"  {_DIM}│ HTTP {status}{_RESET}")
        snippet = resp_data.get("body_snippet", "")
        if snippet:
            for line in snippet.split("\n")[:5]:
                trunc = line.strip()[:120]
                if trunc:
                    print(f"  {_DIM}│ {trunc}{_RESET}")
        ev_detail = evidence.get("detail", "")
        if ev_detail and not snippet:
            print(f"  {_DIM}│ {ev_detail[:200]}{_RESET}")
    print(f"  {_BOLD}└───────────────────────────────────────────────────────{_RESET}")

    print(f"{_BOLD}{'═' * w}{_RESET}")


# ── Curl command builder ────────────────────────────────────


def build_curl_command(candidate) -> str:
    """Build a curl command to reproduce the finding (single line)."""
    req = candidate.request_data
    method = candidate.method
    endpoint = candidate.endpoint
    param = req.get("param", req.get("id_param", ""))
    payload = req.get("payload", req.get("id_value", ""))
    id_location = req.get("id_location", req.get("location", "body"))
    siblings = req.get("sibling_fields", {})

    parts = ["curl -k -v"]

    # Method
    if method != "GET":
        parts.append(f"-X {method}")

    # URL
    if id_location == "query" and param:
        query_parts = [f"{param}={payload}"]
        for k, v in siblings.items():
            query_parts.append(f"{k}={v}")
        sep = "&" if "?" in endpoint else "?"
        url = f"{endpoint}{sep}{'&'.join(query_parts)}"
        parts.append(f"'{url}'")
    else:
        parts.append(f"'{endpoint}'")

    # Body — from param/payload or from form_data (CSRF findings)
    form_data = req.get("form_data", {})
    if id_location == "body" and param:
        body_parts = dict(siblings)
        body_parts[param] = payload
        body_str = "&".join(f"{k}={v}" for k, v in body_parts.items())
        parts.append(f"-d '{body_str}'")
        parts.append("-H 'Content-Type: application/x-www-form-urlencoded'")
    elif form_data and not param:
        body_str = "&".join(f"{k}={v}" for k, v in form_data.items())
        parts.append(f"-d '{body_str}'")
        parts.append("-H 'Content-Type: application/x-www-form-urlencoded'")

    # JSON body
    if id_location == "json" and param:
        import json
        body = dict(siblings)
        body[param] = payload
        parts.append(f"-d '{json.dumps(body)}'")
        parts.append("-H 'Content-Type: application/json'")

    # Cookie placeholder — skip for unauthenticated endpoints (login, auth bypass)
    technique = req.get("technique", "")
    is_login_sqli = technique in ("auth-bypass", "redirect-based")
    vuln_type = candidate.scanner.lower() if hasattr(candidate, "scanner") else ""
    is_csrf_login = "csrf" in vuln_type and "login" in endpoint.lower()
    if not is_login_sqli and not is_csrf_login:
        parts.append("-b 'SESSION_COOKIE=YOUR_SESSION'")

    return " ".join(parts)


# ── Scan phase display ───────────────────────────────────────


def display_scan_start(target: str = "", endpoint_count: int = 0,
                       recipe_count: int = 0) -> None:
    """Print scan phase start banner."""
    print(_header("SCANNING", "⚡"))
    if target:
        print(f"  {_BOLD}Target:{_RESET}     {target}")
    if endpoint_count:
        print(f"  {_BOLD}Endpoints:{_RESET}  {endpoint_count}")
    if recipe_count:
        print(f"  {_BOLD}Recipes:{_RESET}    {recipe_count}")
    print(f"  {_DIM}Only confirmed findings will be shown below{_RESET}\n")


# ── AUTON status bar ────────────────────────────────────────


class Auton:
    """AUTON status bar — shows current phase and progress."""

    _FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    _frame_idx = 0

    @classmethod
    def status(cls, phase: str, detail: str = "", progress: str = "") -> None:
        """Print an AUTON status line (overwrites previous)."""
        cls._frame_idx = (cls._frame_idx + 1) % len(cls._FRAMES)
        spinner = cls._FRAMES[cls._frame_idx]
        w = _term_width()

        left = f"  {_BOLD}{_ORANGE}{spinner} AUTON{_RESET} │ {phase}"
        if detail:
            left += f" {_DIM}— {detail}{_RESET}"
        if progress:
            right = f"{_DIM}{progress}{_RESET}  "
        else:
            right = ""

        pad = max(0, w - _vis_len(left) - _vis_len(right))
        line = f"{left}{' ' * pad}{right}"
        print(f"\r{line}", end="", flush=True)

    @classmethod
    def update(cls, phase: str, detail: str = "") -> None:
        """Print a persistent AUTON log line (does NOT overwrite)."""
        cls._frame_idx = (cls._frame_idx + 1) % len(cls._FRAMES)
        spinner = cls._FRAMES[cls._frame_idx]
        print(f"  {_BOLD}{_ORANGE}{spinner} AUTON{_RESET} │ {phase}"
              + (f" {_DIM}— {detail}{_RESET}" if detail else ""))

    @classmethod
    def phase_start(cls, phase: str) -> None:
        """Announce the start of a major phase."""
        print(f"\n  {_BOLD}{_ORANGE}▶ AUTON{_RESET} │ {_BOLD}{phase}{_RESET}")

    @classmethod
    def phase_done(cls, phase: str, summary: str = "") -> None:
        """Announce completion of a phase."""
        msg = f"  {_BOLD}{_GREEN}✓ AUTON{_RESET} │ {phase}"
        if summary:
            msg += f" {_DIM}— {summary}{_RESET}"
        print(msg)

    @classmethod
    def warn(cls, message: str) -> None:
        """Print a warning."""
        print(f"  {_BOLD}{_YELLOW}⚠ AUTON{_RESET} │ {message}")

    @classmethod
    def error(cls, message: str) -> None:
        """Print an error."""
        print(f"  {_BOLD}{_RED}✗ AUTON{_RESET} │ {message}")

    @classmethod
    def banner(cls) -> None:
        """Print the AUTON startup banner."""
        w = _term_width()
        print(f"\n{_BOLD}{_ORANGE}{'═' * w}{_RESET}")
        print(f"  {_BOLD}{_ORANGE}  █████╗ ██╗   ██╗████████╗ ██████╗ ███╗   ██╗{_RESET}")
        print(f"  {_BOLD}{_ORANGE} ██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗████╗  ██║{_RESET}")
        print(f"  {_BOLD}{_ORANGE} ███████║██║   ██║   ██║   ██║   ██║██╔██╗ ██║{_RESET}")
        print(f"  {_BOLD}{_ORANGE} ██╔══██║██║   ██║   ██║   ██║   ██║██║╚██╗██║{_RESET}")
        print(f"  {_BOLD}{_ORANGE} ██║  ██║╚██████╔╝   ██║   ╚██████╔╝██║ ╚████║{_RESET}")
        print(f"  {_BOLD}{_ORANGE} ╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝ ╚═╝  ╚═══╝{_RESET}")
        print(f"  {_DIM}Autonomous Penetration Testing Agent{_RESET}")
        print(f"{_BOLD}{_ORANGE}{'═' * w}{_RESET}\n")


# ── AUTON Pet — cute running dog at terminal bottom ─────────


class AutonPet:
    """A cute ASCII dog that runs back and forth at the bottom of the
    terminal while scanning is in progress, showing the agent is alive.

    Just the dog — no status text alongside it.
    Runs in a daemon thread so it doesn't block the main scan loop.
    """

    # Right-facing four-legged dog frames (legs animate running)
    _RIGHT = [
        f"{_ORANGE}ᐢ·ᴥ·ᐢ{_RESET}{_ORANGE} /\\/\\{_RESET} {_BRIGHT_ORANGE}~{_RESET}",
        f"{_ORANGE}ᐢ·ᴥ·ᐢ{_RESET}{_ORANGE}  ||||{_RESET}  {_BRIGHT_ORANGE}~{_RESET}",
        f"{_ORANGE}ᐢ·ᴥ·ᐢ{_RESET}{_ORANGE} \\//\\{_RESET}{_BRIGHT_ORANGE}~{_RESET}",
    ]
    # Left-facing four-legged dog frames
    _LEFT = [
        f"{_BRIGHT_ORANGE}~{_RESET} {_ORANGE}/\\/{_RESET}{_ORANGE} ᐢ·ᴥ·ᐢ{_RESET}",
        f"  {_BRIGHT_ORANGE}~{_RESET} {_ORANGE}||||{_RESET}{_ORANGE}  ᐢ·ᴥ·ᐢ{_RESET}",
        f"{_BRIGHT_ORANGE}~{_RESET}{_ORANGE}\\//{_RESET}{_ORANGE} ᐢ·ᴥ·ᐢ{_RESET}",
    ]

    _PET_WIDTH = 16  # visible char width of the creature

    def __init__(self) -> None:
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    def start(self, msg: str = "") -> None:
        """Start the dog animation in a background thread."""
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def update_msg(self, msg: str) -> None:
        """No-op — dog just runs, no status text."""
        pass

    def stop(self) -> None:
        """Stop the dog and clear the line."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=2)
            self._thread = None
        w = _term_width()
        sys.stdout.write(f"\r{' ' * w}\r")
        sys.stdout.flush()

    def _run(self) -> None:
        """Animation loop — bounces the dog across the terminal."""
        w = _term_width()
        usable = max(w - self._PET_WIDTH - 4, 10)
        pos = 0
        direction = 1  # 1 = right, -1 = left
        frame_idx = 0
        speed = 0.15

        while not self._stop_event.is_set():
            w = _term_width()
            usable = max(w - self._PET_WIDTH - 4, 10)

            # Pick frame based on direction
            frames = self._RIGHT if direction == 1 else self._LEFT
            creature = frames[frame_idx % len(frames)]
            frame_idx += 1

            pad = " " * pos
            line = f"{pad}{creature}"

            # Write to terminal (overwrite same line)
            sys.stdout.write(f"\r{' ' * w}\r{line}")
            sys.stdout.flush()

            # Move position
            pos += direction * 2
            if pos >= usable:
                direction = -1
                pos = usable
            elif pos <= 0:
                direction = 1
                pos = 0

            self._stop_event.wait(speed)

        # Final clear
        sys.stdout.write(f"\r{' ' * _term_width()}\r")
        sys.stdout.flush()


# Singleton pet instance
auton_pet = AutonPet()


def display_scan_complete(state) -> None:
    """Print final scan summary with diagnostics."""
    s = state.summary()
    w = _term_width()
    print(f"\n{_BOLD}{'═' * w}{_RESET}")
    print(f"  {_BOLD}{_ORANGE}SCAN COMPLETE{_RESET}")
    print(f"{_BOLD}{'═' * w}{_RESET}")
    print(f"  {_BOLD}Endpoints scanned:{_RESET}   {s['endpoints_discovered']}")
    print(f"  {_BOLD}Scans run:{_RESET}           {s['scans_run']}")
    print(f"  {_BOLD}Candidates found:{_RESET}    {s['candidates_found']}")
    print()

    confirmed = s['confirmed']
    needs_human = s['needs_human']
    false_pos = s['false_positives']

    c_color = _GREEN if confirmed > 0 else _DIM
    h_color = _YELLOW if needs_human > 0 else _DIM
    f_color = _DIM

    print(f"  {c_color}{_BOLD}✓ CONFIRMED:{_RESET}        {confirmed}")
    print(f"  {h_color}{_BOLD}? NEEDS REVIEW:{_RESET}     {needs_human}")
    print(f"  {f_color}✗ FALSE POSITIVE:   {false_pos}{_RESET}")

    # Diagnostics when no results found
    if confirmed == 0 and needs_human == 0 and s['candidates_found'] == 0:
        print(f"\n  {_YELLOW}{_BOLD}─── DIAGNOSTICS ───{_RESET}")
        if s['endpoints_discovered'] == 0:
            print(f"  {_YELLOW}⚠ No endpoints discovered — check crawl/recon output{_RESET}")
            print(f"    {_DIM}Ensure --recon flag is set and target is reachable{_RESET}")
        elif s['scans_run'] == 0:
            print(f"  {_YELLOW}⚠ No scans executed — endpoints found but no recipes matched{_RESET}")
            print(f"    {_DIM}Check that recipes/ directory contains YAML files{_RESET}")
        else:
            print(f"  {_DIM}Ran {s['scans_run']} scans on {s['endpoints_discovered']} "
                  f"endpoints — no injectable parameters found{_RESET}")
            print(f"    {_DIM}Check outputs/agent.log (log terminal) for details{_RESET}")

    print(f"{_BOLD}{'═' * w}{_RESET}\n")
