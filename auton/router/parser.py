"""Slash-command parser — deterministic routing for the interactive shell.

Accepts: /commands, /recon, /fullscan, /exit
Flags:   /allports, --no-dog
Target:  single domain or *.domain for wildcard subdomain enumeration.

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

logger = logging.getLogger(__name__)

# The 14 scanner names from agent/scanners/
_SCANNER_NAMES = [
    "SQLi", "XSS", "SSRF", "IDOR/BOLA", "NoSQLi", "SSTI",
    "CMDi", "LFI", "CSRF", "Stored XSS", "Open Redirect",
    "OAuth/JWT", "Race Condition", "Privesc",
]


@dataclass
class ParsedCommand:
    """Result of parsing a slash command."""
    action: str  # "commands", "recon", "fullscan", "exit", "unknown"
    target: str = ""
    is_wildcard: bool = False
    allports: bool = False
    raw_input: str = ""
    error: str = ""


def parse(raw: str) -> ParsedCommand:
    """Parse a raw input line into a structured command.

    Grammar:
        /commands
        /recon  [/allports] <target>
        /fullscan [/allports] <target>
        /exit
    """
    raw = raw.strip()
    if not raw:
        return ParsedCommand(action="unknown", raw_input=raw, error="Empty input.")

    try:
        tokens = shlex.split(raw)
    except ValueError as exc:
        return ParsedCommand(action="unknown", raw_input=raw, error=f"Parse error: {exc}")

    if not tokens:
        return ParsedCommand(action="unknown", raw_input=raw, error="Empty input.")

    cmd = tokens[0].lower()

    if cmd == "/exit":
        return ParsedCommand(action="exit", raw_input=raw)

    if cmd == "/commands":
        return ParsedCommand(action="commands", raw_input=raw)

    if cmd in ("/recon", "/fullscan"):
        action = cmd.lstrip("/")
        allports = False
        target = ""

        remaining = tokens[1:]
        for tok in remaining:
            if tok.lower() == "/allports":
                allports = True
            elif not tok.startswith("/") and not tok.startswith("--"):
                target = tok

        if not target:
            return ParsedCommand(
                action=action, raw_input=raw,
                error=f"Missing target. Usage: {cmd} [/allports] <target>",
            )

        is_wildcard = target.startswith("*.")

        return ParsedCommand(
            action=action,
            target=target,
            is_wildcard=is_wildcard,
            allports=allports,
            raw_input=raw,
        )

    return ParsedCommand(
        action="unknown", raw_input=raw,
        error=f"Unknown command: {cmd!r}. Type /commands for help.",
    )


def print_commands_table(console: Console | None = None) -> None:
    """Print the rich table of all available commands and flags."""
    con = console or Console()

    tbl = Table(
        title="[bold bright_cyan]AUTON Commands[/bold bright_cyan]",
        title_style="bold",
        border_style="bright_blue",
        header_style="bold bright_magenta",
        show_lines=True,
        expand=False,
    )
    tbl.add_column("Command", style="bold bright_cyan", min_width=28)
    tbl.add_column("Description", style="white")

    tbl.add_row(
        "/commands",
        "Show this help table",
    )
    tbl.add_row(
        "/recon <target>",
        "Recon only: Nmap + directory fuzzing + JS extraction",
    )
    tbl.add_row(
        "/recon /allports <target>",
        "Recon with full 65535-port Nmap scan",
    )
    tbl.add_row(
        "/fullscan <target>",
        "Full scan: recon + all 14 vulnerability scanners",
    )
    tbl.add_row(
        "/fullscan /allports <target>",
        "Full scan with all-ports Nmap",
    )
    tbl.add_row(
        "/exit",
        "Exit the AUTON shell",
    )

    con.print()
    con.print(tbl)

    # Flags sub-table
    flags_tbl = Table(
        title="[bold bright_cyan]Flags[/bold bright_cyan]",
        border_style="bright_blue",
        header_style="bold bright_magenta",
        show_lines=True,
        expand=False,
    )
    flags_tbl.add_column("Flag", style="bold green", min_width=16)
    flags_tbl.add_column("Effect", style="white")

    flags_tbl.add_row("/allports", "Nmap scans all 65535 ports (-p-) instead of top 1000")
    flags_tbl.add_row("*.domain", "Wildcard target — enumerate subdomains first, then scan each live host")
    flags_tbl.add_row("--no-dog", "Disable the running-dog animation (CLI flag)")

    con.print()
    con.print(flags_tbl)

    # Scanners
    con.print()
    con.print("[bold bright_cyan]Scanners (14):[/bold bright_cyan]")
    scanners_text = "  " + "  |  ".join(
        f"[bright_magenta]{s}[/bright_magenta]" for s in _SCANNER_NAMES
    )
    con.print(scanners_text)
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
    """Enumerate subdomains for a wildcard target like *.example.com.

    Uses DNS brute-force with a small built-in wordlist. Returns live hosts.
    """
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
