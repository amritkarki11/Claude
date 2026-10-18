"""Slash-command parser — deterministic routing for the interactive shell.

100% deterministic Python. No LLMs. No APIs.
"""
from __future__ import annotations

import shlex
import subprocess
import logging
from dataclasses import dataclass, field
from typing import Any

from rich.console import Console
from rich.table import Table
from rich.text import Text

from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def _normalize_target(raw_target: str) -> str:
    """Strip scheme, port, and path so nmap gets a bare hostname/IP."""
    if raw_target.startswith("*."):
        return raw_target
    if "://" in raw_target:
        parsed = urlparse(raw_target)
        return parsed.hostname or raw_target
    if "/" in raw_target:
        return raw_target.split("/")[0]
    return raw_target


_SCANNER_MAP = {
    "sqli": "SqliScanner",
    "xss": "XssScanner",
    "ssrf": "SsrfScanner",
    "idor": "IdorScanner",
    "nosqli": "NosqliScanner",
    "ssti": "SstiScanner",
    "cmdi": "CmdiScanner",
    "lfi": "LfiScanner",
    "csrf": "CsrfScanner",
    "storedxss": "StoredXssScanner",
    "redirect": "OpenRedirectScanner",
}

_SCANNER_NAMES = [
    "SQLi", "XSS", "SSRF", "IDOR/BOLA", "NoSQLi", "SSTI",
    "CMDi", "LFI", "CSRF", "Stored XSS", "Open Redirect",
    "OAuth/JWT", "Race Condition", "Privesc",
]


@dataclass
class ParsedCommand:
    """Result of parsing a slash command."""
    action: str  # commands, recon, fullscan, nmap, scan_single, exit, unknown
    target: str = ""
    is_wildcard: bool = False
    allports: bool = False
    nmap: bool = False
    scanner: str = ""
    username: str = ""
    password: str = ""
    raw_input: str = ""
    error: str = ""


def parse(raw: str) -> ParsedCommand:
    """Parse a raw input line into a structured command."""
    raw = raw.strip()
    if not raw:
        return ParsedCommand(action="unknown", raw_input=raw, error="Empty input.")

    try:
        tokens = shlex.split(raw)
    except ValueError as exc:
        return ParsedCommand(action="unknown", raw_input=raw, error=f"Parse error: {exc}")

    if not tokens:
        return ParsedCommand(action="unknown", raw_input=raw, error="Empty input.")

    cmd = tokens[0].lower().lstrip("/")

    if cmd == "exit":
        return ParsedCommand(action="exit", raw_input=raw)

    if cmd == "commands":
        return ParsedCommand(action="commands", raw_input=raw)

    if cmd == "nmap":
        return _parse_target_cmd("nmap", tokens[1:], raw)

    if cmd in ("recon", "fullscan"):
        return _parse_target_cmd(cmd, tokens[1:], raw)

    if cmd in _SCANNER_MAP:
        return _parse_target_cmd("scan_single", tokens[1:], raw, scanner=cmd)

    return ParsedCommand(
        action="unknown", raw_input=raw,
        error=f"Unknown command: /{cmd}. Type /commands for help.",
    )


def _parse_target_cmd(action: str, remaining: list[str], raw: str,
                      scanner: str = "") -> ParsedCommand:
    """Parse target + flags for recon/fullscan/nmap/scanner commands."""
    allports = False
    nmap = False
    target = ""
    username = ""
    password = ""

    i = 0
    while i < len(remaining):
        tok = remaining[i]
        low = tok.lower().lstrip("/")
        if low == "allports":
            allports = True
        elif low == "nmap":
            nmap = True
        elif low in ("-u", "--username"):
            if i + 1 < len(remaining):
                i += 1
                username = remaining[i]
            else:
                return ParsedCommand(
                    action=action, raw_input=raw,
                    error=f"{tok} requires a value.",
                )
        elif low in ("-p", "--password"):
            if i + 1 < len(remaining):
                i += 1
                password = remaining[i]
            else:
                return ParsedCommand(
                    action=action, raw_input=raw,
                    error=f"{tok} requires a value.",
                )
        elif not tok.startswith("/") and not tok.startswith("-"):
            target = tok
        i += 1

    if not target:
        label = f"/{scanner}" if scanner else f"/{action}"
        return ParsedCommand(
            action=action, raw_input=raw,
            error=f"Missing target. Usage: {label} <target>",
        )

    target = _normalize_target(target)
    is_wildcard = target.startswith("*.")

    if action == "nmap":
        nmap = True

    return ParsedCommand(
        action=action, target=target, is_wildcard=is_wildcard,
        allports=allports, nmap=nmap, scanner=scanner,
        username=username, password=password, raw_input=raw,
    )


def print_commands_table(console: Console | None = None) -> None:
    """Print the rich table of all available commands."""
    con = console or Console()

    # Main commands
    tbl = Table(
        title="[bold red]AUTON Commands[/bold red]",
        title_style="bold",
        border_style="grey50",
        header_style="bold white",
        show_lines=True,
        expand=False,
    )
    tbl.add_column("Command", style="bold green", min_width=34)
    tbl.add_column("Description", style="white")

    tbl.add_row("/recon <target>", "Crawl + JS analysis + secrets (no nmap)")
    tbl.add_row("/recon <target> /nmap", "Recon with nmap port scan")
    tbl.add_row("/recon <target> /nmap /allports", "Recon with nmap all 65535 ports")
    tbl.add_row("/fullscan <target>", "Recon + all vulnerability scanners")
    tbl.add_row("/fullscan <target> /nmap", "Full scan with nmap")
    tbl.add_row("/nmap <target>", "Standalone nmap scan (top 1000 ports)")
    tbl.add_row("/nmap <target> /allports", "Nmap all 65535 ports")
    tbl.add_row("/commands", "Show this help table")
    tbl.add_row("/exit", "Exit the AUTON shell")

    con.print()
    con.print(tbl)

    # Individual scanners
    scan_tbl = Table(
        title="[bold red]Individual Scanners[/bold red]",
        border_style="grey50",
        header_style="bold white",
        show_lines=True,
        expand=False,
    )
    scan_tbl.add_column("Command", style="bold green", min_width=28)
    scan_tbl.add_column("Vulnerability", style="white")

    scan_tbl.add_row("/sqli <target>", "SQL Injection")
    scan_tbl.add_row("/xss <target>", "Reflected XSS")
    scan_tbl.add_row("/storedxss <target>", "Stored XSS")
    scan_tbl.add_row("/ssrf <target>", "Server-Side Request Forgery")
    scan_tbl.add_row("/idor <target>", "IDOR / Broken Object-Level Auth")
    scan_tbl.add_row("/nosqli <target>", "NoSQL Injection")
    scan_tbl.add_row("/ssti <target>", "Server-Side Template Injection")
    scan_tbl.add_row("/cmdi <target>", "OS Command Injection")
    scan_tbl.add_row("/lfi <target>", "Local File Inclusion")
    scan_tbl.add_row("/csrf <target>", "Cross-Site Request Forgery")
    scan_tbl.add_row("/redirect <target>", "Open Redirect")

    con.print()
    con.print(scan_tbl)

    # Flags
    flags_tbl = Table(
        title="[bold red]Flags[/bold red]",
        border_style="grey50",
        header_style="bold white",
        show_lines=True,
        expand=False,
    )
    flags_tbl.add_column("Flag", style="bold green", min_width=16)
    flags_tbl.add_column("Effect", style="white")

    flags_tbl.add_row("/nmap", "Add nmap port scan to recon/fullscan")
    flags_tbl.add_row("/allports", "Nmap scans all 65535 ports instead of top 1000")
    flags_tbl.add_row("*.domain", "Wildcard — enumerate subdomains first")
    flags_tbl.add_row("-u <username>", "Login with username (auto-detects login form)")
    flags_tbl.add_row("-p <password>", "Login with password (use with -u)")

    con.print()
    con.print(flags_tbl)
    con.print()


def build_nmap_cmd(target: str, allports: bool = False) -> list[str]:
    """Build the nmap command list. Always includes -Pn."""
    cmd = ["nmap", "-Pn"]
    if allports:
        cmd.append("-p-")
    else:
        cmd.extend(["--top-ports", "1000"])
    cmd.append(target)
    return cmd


def enumerate_subdomains(wildcard_target: str, console: Console | None = None) -> list[str]:
    """Enumerate subdomains for a wildcard target like *.example.com."""
    con = console or Console()
    base_domain = wildcard_target.lstrip("*.")

    con.print(f"[bright_cyan]Enumerating subdomains for[/bright_cyan] [bold]{base_domain}[/bold]")

    _COMMON_SUBS = [
        "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
        "blog", "shop", "app", "portal", "secure", "vpn", "cdn", "docs",
        "support", "status", "git", "ci", "beta", "demo", "internal",
        "dashboard", "auth", "sso", "login", "m", "mobile", "ws",
    ]

    live_hosts: list[str] = []
    import socket

    for sub in _COMMON_SUBS:
        fqdn = f"{sub}.{base_domain}"
        try:
            socket.getaddrinfo(fqdn, None, socket.AF_INET)
            live_hosts.append(fqdn)
            con.print(f"  [green]+[/green] {fqdn}")
        except socket.gaierror:
            pass

    if not live_hosts:
        con.print(f"  [yellow]No live subdomains found for {base_domain}[/yellow]")
    else:
        con.print(
            f"  [bold bright_magenta]Found {len(live_hosts)} live subdomains[/bold bright_magenta]"
        )
    return live_hosts


def run_nmap(target: str, allports: bool = False, console: Console | None = None) -> str | None:
    """Execute nmap against a target. Returns stdout or None on error."""
    con = console or Console()
    cmd = build_nmap_cmd(target, allports)
    cmd_str = " ".join(cmd)
    con.print(f"  [dim bright_blue]$ {cmd_str}[/dim bright_blue]")

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=600,
        )
        if result.returncode == 0:
            return result.stdout
        else:
            con.print(f"  [red]nmap error:[/red] {result.stderr[:300]}")
            return None
    except FileNotFoundError:
        con.print("  [red]nmap not found — install it or add to PATH[/red]")
        return None
    except subprocess.TimeoutExpired:
        con.print("  [red]nmap timed out after 600s[/red]")
        return None
