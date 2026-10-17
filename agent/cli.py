"""CLI entry point — run the pentest agent from the command line.

Usage:
    python -m agent.cli --target https://target.example.com \\
        --scope target.example.com \\
        --attacker-cookie sid=attacker123 \\
        --victim-cookie sid=victim456 \\
        --victim-id 42 \\
        --param user_id \\
        --endpoint /api/users \\
        --method POST

Minimal:
    python -m agent.cli --target https://target.example.com \\
        --scope target.example.com \\
        --attacker-cookie sid=abc

The CLI validates inputs, wires up the orchestrator, runs the full
scan → verify → report pipeline, and writes outputs to --output-dir.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import pathlib
import sys
import time
from typing import Any

from .http import HttpClient, Session
from .scope import set_scope, add_to_scope, ALLOWED
from .orchestrator import (
    Orchestrator, OrchestratorConfig, EndpointInfo, TargetState,
)
from .reporter import Reporter
from .benchmark import BenchmarkRunner
from .display import (
    Auton,
    AutonPet,
    auton_pet,
    display_nmap,
    display_fingerprint,
    display_crawl,
    display_js_extraction,
    display_params,
    display_classification,
    display_recon_summary,
    display_confirmed_finding,
    display_scan_start,
    display_scan_complete,
)


logger = logging.getLogger("agent")

DEFAULT_OUTPUT = pathlib.Path("outputs")
DEFAULT_RECIPES = pathlib.Path(__file__).parent / "recipes"


# ── Argument parsing ───────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pentest-agent",
        description="Hybrid AI pentest agent — automated VAPT scanner",
    )

    # Target
    p.add_argument(
        "--target", required=True,
        help="Base URL of the target (e.g. https://app.example.com)",
    )

    # Scope
    p.add_argument(
        "--scope", nargs="+", required=True,
        help="Allowed hostnames (space-separated). Only these will be probed.",
    )

    # Sessions — attacker (required)
    att = p.add_argument_group("Attacker session")
    att.add_argument("--attacker-cookie", action="append", default=[],
                     help="Cookie as name=value (repeatable)")
    att.add_argument("--attacker-header", action="append", default=[],
                     help="Header as Name: value (repeatable)")
    att.add_argument("--attacker-bearer", help="Bearer token")
    att.add_argument("--attacker-jwt", help="JWT token")

    # Sessions — victim (optional, needed for IDOR)
    vic = p.add_argument_group("Victim session (for IDOR scanning)")
    vic.add_argument("--victim-cookie", action="append", default=[],
                     help="Victim cookie as name=value (repeatable)")
    vic.add_argument("--victim-header", action="append", default=[],
                     help="Victim header as Name: value (repeatable)")
    vic.add_argument("--victim-bearer", help="Victim bearer token")
    vic.add_argument("--victim-jwt", help="Victim JWT token")

    # IDOR context
    idor = p.add_argument_group("IDOR parameters")
    idor.add_argument("--victim-id", action="append", default=[],
                      help="Victim identifier (repeatable)")
    idor.add_argument("--id-param", default="id",
                      help="Parameter name carrying the identifier (default: id)")
    idor.add_argument("--id-location", default="body",
                      choices=["body", "query", "path"],
                      help="Where the id param lives (default: body)")

    # Endpoints
    ep = p.add_argument_group("Endpoints to scan")
    ep.add_argument("--endpoint", action="append", default=[],
                    help="Endpoint path (repeatable, appended to --target)")
    ep.add_argument("--method", default="GET",
                    help="HTTP method for endpoints (default: GET)")
    ep.add_argument("--param", action="append", default=[],
                    help="Parameter to test (repeatable)")

    # Recipes
    p.add_argument("--recipes-dir", type=pathlib.Path, default=DEFAULT_RECIPES,
                   help=f"Directory containing recipe YAML files (default: {DEFAULT_RECIPES})")

    # Output
    p.add_argument("--output-dir", type=pathlib.Path, default=DEFAULT_OUTPUT,
                   help=f"Output directory (default: {DEFAULT_OUTPUT})")

    # Tuning
    p.add_argument("--replays", type=int, default=3,
                   help="Number of verification replays (default: 3)")
    p.add_argument("--timeout", type=float, default=15.0,
                   help="HTTP timeout in seconds (default: 15)")
    p.add_argument("--proxy", action="store_true",
                   help="Route traffic through Burp proxy (127.0.0.1:8080)")
    p.add_argument("--rate-limit", type=float, default=0.0,
                   help="Minimum seconds between requests (default: 0 = no limit)")
    p.add_argument("--stealth", action="store_true",
                   help="Low-noise mode: randomize User-Agent, add request jitter")
    p.add_argument("--tech-signal", action="append", default=[],
                   help="Tech signal for recipe matching (repeatable)")

    # Recon
    recon = p.add_argument_group("Automated recon")
    recon.add_argument("--recon", action="store_true",
                       help="Enable automated recon (crawl + JS extract + fingerprint + param discovery)")
    recon.add_argument("--crawl-depth", type=int, default=3,
                       help="Max crawl depth (default: 3)")
    recon.add_argument("--crawl-max-pages", type=int, default=100,
                       help="Max pages to crawl (default: 100)")
    recon.add_argument("--max-js-files", type=int, default=50,
                       help="Max JS files to analyze (default: 50)")

    # Nmap
    nmap_grp = p.add_argument_group("Nmap port scanning")
    nmap_grp.add_argument("--nmap-ports", type=str, default="1-10000",
                          help="Port range for nmap (default: 1-10000)")
    nmap_grp.add_argument("--nmap-scan-type", type=str, default="-sV -sC",
                          help="Nmap scan flags (default: '-sV -sC')")
    nmap_grp.add_argument("--nmap-timeout", type=int, default=300,
                          help="Nmap timeout in seconds (default: 300)")
    nmap_grp.add_argument("--no-nmap", action="store_true",
                          help="Disable nmap scanning even when --recon is on")

    # Modes
    p.add_argument("--benchmark", action="store_true",
                   help="Run benchmark scorecard instead of a live scan")
    p.add_argument("--report-only", type=pathlib.Path, default=None,
                   help="Skip scanning; generate report from existing human_queue.jsonl")

    # Headless / CI mode
    headless = p.add_argument_group("Headless / CI mode")
    headless.add_argument("--headless", action="store_true",
                          help="CI-friendly mode: JSON to stdout, no human-formatted output")
    headless.add_argument("--min-precision", type=float, default=None,
                          help="Benchmark gate: exit non-zero if precision < threshold (0.0-1.0)")
    headless.add_argument("--min-recall", type=float, default=None,
                          help="Benchmark gate: exit non-zero if recall < threshold (0.0-1.0)")

    # BurpSuite integration
    burp = p.add_argument_group("BurpSuite integration")
    burp.add_argument("--burp", action="store_true",
                      help="Launch BurpSuite and proxy traffic through it")
    burp.add_argument("--burp-dir", type=str, default=None,
                      help="BurpSuite directory (auto-detected on WSL if omitted)")
    burp.add_argument("--burp-project-dir", type=str, default=None,
                      help="Directory for Burp project files (default: <burp-dir>/projects)")

    # Verbosity
    p.add_argument("-v", "--verbose", action="count", default=0,
                   help="Increase verbosity (-v info, -vv debug)")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="Suppress all output except errors")

    return p


# ── Input helpers ──────────────────────────────────────────────


def _parse_cookies(raw: list[str]) -> dict[str, str]:
    """Parse ['name=value', ...] into a dict."""
    cookies = {}
    for item in raw:
        if "=" not in item:
            raise ValueError(f"Invalid cookie format (expected name=value): {item!r}")
        name, _, value = item.partition("=")
        cookies[name.strip()] = value.strip()
    return cookies


def _parse_headers(raw: list[str]) -> dict[str, str]:
    """Parse ['Name: value', ...] into a dict."""
    headers = {}
    for item in raw:
        if ": " not in item:
            raise ValueError(f"Invalid header format (expected 'Name: value'): {item!r}")
        name, _, value = item.partition(": ")
        headers[name.strip()] = value.strip()
    return headers


def _build_session(cookies_raw: list[str], headers_raw: list[str],
                   bearer: str | None, jwt: str | None) -> Session:
    return Session(
        cookies=_parse_cookies(cookies_raw),
        headers=_parse_headers(headers_raw),
        bearer=bearer,
        jwt=jwt,
    )


def _build_endpoints(target: str, endpoint_paths: list[str],
                     method: str, params: list[str]) -> list[EndpointInfo]:
    if not endpoint_paths:
        return []
    endpoints = []
    for ep_path in endpoint_paths:
        url = target.rstrip("/") + "/" + ep_path.lstrip("/")
        endpoints.append(EndpointInfo(
            url=url,
            method=method,
            params=params,
        ))
    return endpoints


# ── Validation ─────────────────────────────────────────────────


class ConfigError(ValueError):
    """Raised when CLI arguments are invalid."""


def validate_args(args: argparse.Namespace) -> None:
    """Validate parsed arguments. Raises ConfigError on problems."""
    # Target must be a URL
    if not args.target.startswith(("http://", "https://")):
        raise ConfigError(
            f"--target must be a URL starting with http:// or https://, got: {args.target!r}"
        )

    # Scope must not be empty
    if not args.scope:
        raise ConfigError("--scope requires at least one hostname")

    # Attacker session auth is optional — unauthenticated scans are valid.
    # When --recon is enabled the agent will attempt login-bypass discovery
    # automatically and upgrade to an authenticated session if successful.

    # Victim IDs require victim session
    if args.victim_id and not (args.victim_cookie or args.victim_header
                               or args.victim_bearer or args.victim_jwt):
        raise ConfigError(
            "--victim-id requires a victim session "
            "(--victim-cookie, --victim-header, --victim-bearer, or --victim-jwt)"
        )

    # Recipes dir must exist
    if not args.recipes_dir.is_dir():
        raise ConfigError(f"--recipes-dir does not exist: {args.recipes_dir}")

    # Replays must be >= 2
    if args.replays < 2:
        raise ConfigError("--replays must be at least 2")

    # Threshold gates require --benchmark
    min_p = getattr(args, "min_precision", None)
    min_r = getattr(args, "min_recall", None)
    if (min_p is not None or min_r is not None) and not getattr(args, "benchmark", False):
        raise ConfigError("--min-precision / --min-recall require --benchmark")
    if min_p is not None and not (0.0 <= min_p <= 1.0):
        raise ConfigError("--min-precision must be between 0.0 and 1.0")
    if min_r is not None and not (0.0 <= min_r <= 1.0):
        raise ConfigError("--min-recall must be between 0.0 and 1.0")


# ── Logging setup ──────────────────────────────────────────────


def setup_logging(verbose: int, quiet: bool,
                  log_file: pathlib.Path | None = None) -> None:
    """Configure logging — file gets DEBUG, console gets ERROR only.

    All detailed logs go to the log file (visible in the second terminal
    via ``tail -f``).  The main terminal stays clean — only results and
    display module output appear there.
    """
    fmt = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"
    datefmt = "%H:%M:%S"

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    # Remove any pre-existing handlers
    root.handlers.clear()

    # Console handler — ERROR only (main terminal stays clean)
    console = logging.StreamHandler(sys.stderr)
    console.setLevel(logging.ERROR)
    console.setFormatter(logging.Formatter(fmt, datefmt=datefmt))
    root.addHandler(console)

    # File handler — DEBUG level (everything goes to log file)
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(fmt, datefmt=datefmt))
        root.addHandler(fh)


def _open_log_terminal(log_file: pathlib.Path) -> None:
    """Open a second WSL terminal that tails the log file.

    Tries Windows Terminal (wt.exe) first, falls back to cmd.exe /c start.
    If not WSL, tries tmux. Prints a message on failure so user knows why.
    """
    import subprocess
    import os
    import shutil

    log_path = str(log_file.resolve())

    # Ensure log file exists so tail -f doesn't error
    log_file.parent.mkdir(parents=True, exist_ok=True)
    log_file.touch(exist_ok=True)

    # Build the tail command
    tail_cmd = f"echo '\\033[38;5;208m── AUTON Live Logs ──\\033[0m'; tail -F {log_path}"

    # Check if running under WSL
    is_wsl = False
    if os.path.exists("/proc/version"):
        try:
            with open("/proc/version") as f:
                if "microsoft" in f.read().lower():
                    is_wsl = True
        except Exception:
            pass

    if is_wsl:
        # Try Windows Terminal first (wt.exe) — check common paths too
        wt = shutil.which("wt.exe")
        if not wt:
            # Sometimes wt.exe is not in PATH inside WSL, check common locations
            for wt_path in [
                "/mnt/c/Users/amrit.karki_kratikal/AppData/Local/Microsoft/WindowsApps/wt.exe",
                "/mnt/c/Program Files/WindowsApps/wt.exe",
            ]:
                if os.path.isfile(wt_path):
                    wt = wt_path
                    break
        if wt:
            try:
                subprocess.Popen(
                    [wt, "new-tab", "--title", "AUTON Logs", "--",
                     "wsl.exe", "-e", "bash", "-c", tail_cmd],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
                return
            except Exception as e:
                print(f"  \033[38;5;208m[!]\033[0m Could not open Windows Terminal: {e}")

        # Fallback: cmd.exe /c start
        cmd = shutil.which("cmd.exe")
        if not cmd:
            cmd = "/mnt/c/Windows/System32/cmd.exe"
        if os.path.isfile(cmd) if cmd.startswith("/") else shutil.which(cmd):
            try:
                subprocess.Popen(
                    [cmd, "/c", "start", "AUTON Logs",
                     "wsl.exe", "-e", "bash", "-c", tail_cmd],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
                return
            except Exception as e:
                print(f"  \033[38;5;208m[!]\033[0m Could not open cmd.exe terminal: {e}")

        # WSL but neither wt.exe nor cmd.exe found
        print(f"  \033[38;5;208m[!]\033[0m WSL detected but cannot open log terminal.")
        print(f"      Open a second terminal and run: tail -F {log_path}")
        return

    # Non-WSL: try tmux
    if shutil.which("tmux"):
        try:
            # Check if tmux session exists
            check = subprocess.run(
                ["tmux", "has-session", "-t", "auton-logs"],
                capture_output=True,
            )
            if check.returncode != 0:
                subprocess.Popen(
                    ["tmux", "new-session", "-d", "-s", "auton-logs",
                     "-n", "logs", "bash", "-c", tail_cmd],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
            else:
                subprocess.Popen(
                    ["tmux", "new-window", "-t", "auton-logs",
                     "-n", "logs", "bash", "-c", tail_cmd],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
            print(f"  \033[38;5;208m[*]\033[0m Logs: tmux attach -t auton-logs")
            return
        except Exception:
            pass

    # Final fallback message
    print(f"  \033[38;5;208m[*]\033[0m Live logs: tail -F {log_path}")


# ── Summary printer ───────────────────────────────────────────


# ── Severity colors for terminal ─────────────────────────────

_SEVERITY_COLORS = {
    "critical": "\033[91m",   # bright red
    "high":     "\033[31m",   # red
    "medium":   "\033[33m",   # yellow
    "low":      "\033[36m",   # cyan
    "info":     "\033[37m",   # white
}
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_GREEN = "\033[32m"
_ORANGE = "\033[38;5;208m"


def _make_finding_callback():
    """Create a finding callback that uses the display module."""
    def callback(result) -> None:
        auton_pet.stop()
        display_confirmed_finding(result)
        Auton.phase_done("Finding confirmed",
                         f"{result.candidate.scanner} on {result.candidate.endpoint}")
        auton_pet.start()
    return callback


def print_summary(state: TargetState, elapsed: float,
                  report_path: pathlib.Path | None = None) -> None:
    """Print a human-readable summary to stdout."""
    s = state.summary()
    print(f"\n{_BOLD}{'═' * 70}{_RESET}")
    print(f"  {_BOLD}{_ORANGE}PENTEST AGENT — RUN SUMMARY{_RESET}")
    print(f"{_BOLD}{'═' * 70}{_RESET}")
    print(f"  {_BOLD}Target:{_RESET}          {s['target']}")
    print(f"  {_BOLD}Endpoints:{_RESET}       {s['endpoints_discovered']}")
    print(f"  {_BOLD}Recipes matched:{_RESET} {s['recipes_matched']}")
    print(f"  {_BOLD}Scans run:{_RESET}       {s['scans_run']}")
    print(f"  {_BOLD}Candidates:{_RESET}      {s['candidates_found']}")
    print(f"  {_BOLD}Verified:{_RESET}        {s['verifications_run']}")
    print()

    confirmed = s['confirmed']
    needs_human = s['needs_human']
    false_pos = s['false_positives']

    confirmed_color = "\033[32m" if confirmed > 0 else ""
    human_color = "\033[33m" if needs_human > 0 else ""
    fp_color = _DIM

    print(f"  {confirmed_color}{_BOLD}✓ CONFIRMED:{_RESET}     {confirmed}")
    print(f"  {human_color}{_BOLD}? NEEDS_HUMAN:{_RESET}   {needs_human}")
    print(f"  {fp_color}✗ FALSE_POSITIVE: {false_pos}{_RESET}")
    print(f"  {_BOLD}Elapsed:{_RESET}         {elapsed:.1f}s")
    if report_path:
        print(f"\n  {_BOLD}📄 Report:{_RESET} {report_path}")
    print(f"{_BOLD}{'═' * 70}{_RESET}\n")


# ── Main ───────────────────────────────────────────────────────


async def async_main(args: argparse.Namespace) -> int:
    """Async entry point — returns exit code."""
    output_dir = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    log_file = output_dir / "agent.log"
    setup_logging(args.verbose, args.quiet, log_file)

    # ── Benchmark mode ──
    if args.benchmark:
        logger.info("Running benchmark harness")
        runner = BenchmarkRunner()
        card = await runner.run()
        md_path = runner.write_report(card, output_dir=output_dir)

        if getattr(args, "headless", False):
            # CI mode: JSON to stdout, no human formatting
            print(json.dumps(card.to_dict(), indent=2))
        elif not args.quiet:
            print(card.to_markdown())
            print(f"\nScorecard written to: {md_path}")

        # Threshold gates (work in both headless and normal mode)
        min_p = getattr(args, "min_precision", None)
        min_r = getattr(args, "min_recall", None)
        if min_p is not None and card.precision < min_p:
            msg = (f"GATE FAIL: precision {card.precision:.4f} "
                   f"< threshold {min_p:.4f}")
            if getattr(args, "headless", False):
                print(json.dumps({"gate": "precision", "actual": card.precision,
                                  "threshold": min_p, "pass": False}),
                      file=sys.stderr)
            else:
                print(msg, file=sys.stderr)
            return 3
        if min_r is not None and card.recall < min_r:
            msg = (f"GATE FAIL: recall {card.recall:.4f} "
                   f"< threshold {min_r:.4f}")
            if getattr(args, "headless", False):
                print(json.dumps({"gate": "recall", "actual": card.recall,
                                  "threshold": min_r, "pass": False}),
                      file=sys.stderr)
            else:
                print(msg, file=sys.stderr)
            return 3
        return 0

    # ── Report-only mode ──
    if args.report_only:
        queue_path = args.report_only
        if not queue_path.exists():
            print(f"Error: queue file not found: {queue_path}", file=sys.stderr)
            return 1
        entries = []
        with queue_path.open("r") as f:
            for line in f:
                line = line.strip()
                if line:
                    entries.append(json.loads(line))
        reporter = Reporter(output_dir=output_dir)
        report = reporter.build_report(args.target, queue_entries=entries)
        report.set_summary(confirmed=len(entries))
        md_path = reporter.export_markdown(report)
        reporter.export_json(report)
        print(f"Report generated from {len(entries)} queue entries: {md_path}")
        return 0

    # ── Live scan ──
    # Build sessions
    attacker = _build_session(
        args.attacker_cookie, args.attacker_header,
        args.attacker_bearer, args.attacker_jwt,
    )

    victim = None
    if args.victim_cookie or args.victim_header or args.victim_bearer or args.victim_jwt:
        victim = _build_session(
            args.victim_cookie, args.victim_header,
            args.victim_bearer, args.victim_jwt,
        )

    # Build endpoints
    endpoints = _build_endpoints(
        args.target, args.endpoint, args.method, args.param,
    )

    # Set scope
    set_scope(args.scope)

    # Build config
    config = OrchestratorConfig(
        attacker_session=attacker,
        victim_session=victim,
        victim_ids=args.victim_id,
        id_param=args.id_param,
        id_location=args.id_location,
        recipes_dir=args.recipes_dir,
        endpoints=endpoints or None,
        tech_signals=args.tech_signal,
        verify_replays=args.replays,
        output_dir=output_dir,
        timeout=args.timeout,
        use_proxy=args.proxy,
        log_path=output_dir / "http_log.jsonl",
        rate_limit=args.rate_limit,
        stealth=args.stealth,
        recon=args.recon,
        crawl_depth=args.crawl_depth,
        crawl_max_pages=args.crawl_max_pages,
        max_js_files=args.max_js_files,
    )

    # ── AUTON banner ──
    show_ui = not args.quiet and not getattr(args, "headless", False)
    if show_ui:
        Auton.banner()
        Auton.phase_start(f"Target acquired: {args.target}")
        # Open second terminal for live logs
        _open_log_terminal(log_file)

    # ── BurpSuite integration ──
    burp_integration = None
    if getattr(args, "burp", False):
        from .integrations.burpsuite import BurpSuiteIntegration
        burp_integration = BurpSuiteIntegration(
            burp_dir=getattr(args, "burp_dir", None),
            projects_dir=getattr(args, "burp_project_dir", None),
        )
        if show_ui:
            Auton.update("Launching BurpSuite")
        burp_result = await burp_integration.setup(target=args.target)
        if burp_result["errors"]:
            for err in burp_result["errors"]:
                if show_ui:
                    Auton.error(err)
        else:
            if show_ui:
                Auton.phase_done("BurpSuite launched",
                                 f"Proxy: {burp_result['proxy']}")
            proxy_ready = await burp_integration.wait_for_proxy(timeout=30)
            if proxy_ready:
                config.use_proxy = True
                if show_ui:
                    Auton.phase_done("Proxy ready")
            else:
                if show_ui:
                    Auton.warn("Proxy not responding — scanning without proxy")

    # ── Pass nmap config into orchestrator config ──
    config.nmap_ports = getattr(args, "nmap_ports", "1-10000")
    config.nmap_scan_type = getattr(args, "nmap_scan_type", "-sV -sC")
    config.nmap_timeout = getattr(args, "nmap_timeout", 300)
    config.no_nmap = getattr(args, "no_nmap", False)

    # Run orchestrator with real-time finding output
    finding_callback = _make_finding_callback() if show_ui else None
    orch = Orchestrator(config, on_finding=finding_callback)
    start = time.monotonic()

    # ── AUTON recon display callback ──
    def on_recon_phase(phase: str, data: Any = None) -> None:
        """Called by orchestrator after each recon sub-step to display results."""
        if not show_ui:
            return
        if phase == "phase_start":
            auton_pet.start()
        if phase == "nmap" and data is not None:
            auton_pet.stop()
            Auton.phase_done("Nmap scan complete",
                             f"{len(data.open_ports)} open ports")
            display_nmap(data)
            auton_pet.start()
        elif phase == "fingerprint" and data is not None:
            auton_pet.stop()
            Auton.phase_done("Fingerprinting complete",
                             f"{len(data.signal_list)} signals")
            display_fingerprint(data)
            auton_pet.start()
        elif phase == "crawl" and data is not None:
            auton_pet.stop()
            Auton.phase_done("Crawl complete",
                             f"{data.urls_visited} pages, {data.forms_found} forms")
            display_crawl(data)
            auton_pet.start()
        elif phase == "js_extract" and data is not None:
            auton_pet.stop()
            Auton.phase_done("JS extraction complete",
                             f"{data.js_files_fetched} files")
            display_js_extraction(data)
            auton_pet.start()
        elif phase == "params" and data is not None:
            auton_pet.stop()
            Auton.phase_done("Param discovery complete",
                             f"{len(data.high_value_params)} high-value params")
            display_params(data)
            auton_pet.start()
        elif phase == "classify":
            auton_pet.stop()
            Auton.phase_done("Classification complete")
            if data:
                display_classification(data)
            auton_pet.start()
        elif phase == "recon_summary" and data is not None:
            auton_pet.stop()
            display_recon_summary(data)
            auton_pet.start()
        elif phase == "auth_bypass_start":
            Auton.phase_start("Attempting auth bypass discovery")
        elif phase == "auth_bypass_success":
            Auton.phase_done("Auth bypass successful", str(data))
        elif phase == "auth_bypass_fail":
            Auton.update("No exploitable login found")
        elif phase == "auth_recrawl":
            Auton.phase_start("Re-crawling with authenticated session")
        elif phase == "privesc_check":
            Auton.phase_start("Checking for privilege escalation")
        elif phase == "privesc_found":
            Auton.phase_done("Privilege escalation detected", str(data))
        elif phase == "scan_start":
            if show_ui:
                auton_pet.stop()
                display_scan_start()
                Auton.phase_start("Scanning endpoints for vulnerabilities")
                auton_pet.start()
        elif phase == "scan_progress":
            if data:
                Auton.update("Scanning", data)
        elif phase == "verify_start":
            Auton.phase_start(f"Verifying {data} candidates")

    orch.on_recon_phase = on_recon_phase

    try:
        state = await orch.run(args.target)
    except Exception as e:
        auton_pet.stop()
        logger.error("Orchestrator failed: %s", e)
        if show_ui:
            Auton.error(f"Scan failed: {e}")
        print(f"Error: {e}", file=sys.stderr)
        return 1

    elapsed = time.monotonic() - start

    # Generate report
    report_path = None
    if state.confirmed or state.needs_human:
        if show_ui:
            Auton.phase_start("Generating report")
        reporter = Reporter(output_dir=output_dir)
        results = state.confirmed + state.needs_human
        report = reporter.build_report(args.target, results=results)
        report.set_summary(
            total_endpoints=len(state.endpoints),
            scans_run=state.scans_run,
            confirmed=len(state.confirmed),
            needs_human=len(state.needs_human),
            false_positives=len(state.false_positives),
        )
        report_path = reporter.export_markdown(report)
        reporter.export_json(report)
        if show_ui:
            Auton.phase_done("Report generated", str(report_path))

    auton_pet.stop()

    if getattr(args, "headless", False):
        # CI mode: JSON summary to stdout
        summary = state.summary()
        summary["elapsed_seconds"] = round(elapsed, 2)
        if report_path:
            summary["report_path"] = str(report_path)
        print(json.dumps(summary, indent=2))
    elif not args.quiet:
        if show_ui:
            display_scan_complete(state)
        print_summary(state, elapsed, report_path)

    # Clean up BurpSuite
    if burp_integration and burp_integration.is_running():
        if not args.quiet:
            print(f"\n{_DIM}BurpSuite still running (PID). "
                  f"Project file: {burp_integration.project_file}{_RESET}")

    # Exit code: 0 if no confirmed findings, 1 if findings exist
    return 1 if state.confirmed else 0


def main(argv: list[str] | None = None) -> int:
    """Synchronous entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        validate_args(args)
    except ConfigError as e:
        print(f"Config error: {e}", file=sys.stderr)
        return 2

    return asyncio.run(async_main(args))


if __name__ == "__main__":
    sys.exit(main())
