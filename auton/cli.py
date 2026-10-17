"""AUTON interactive REPL — the main entry point.

Launch with: auton
Inside the shell: /commands, /recon, /fullscan, /exit

Wires the deterministic slash-command parser to the real agent/ recon pipeline
and vulnerability scanners. No LLMs, no API keys — routing is 100% deterministic.
"""
from __future__ import annotations

import argparse
import asyncio
import sys

from rich.console import Console
from rich.prompt import Prompt

from auton.ui.banner import print_banner
from auton.ui.results import (
    print_recon_summary,
    print_endpoint_classification,
    print_finding,
    print_scan_summary,
)
from auton.router.parser import (
    parse,
    route_input,
    print_commands_table,
    enumerate_subdomains,
    run_nmap,
)


def _status(console: Console, text: str) -> None:
    """Print a bold blue status line."""
    console.print(f"  [bold blue]* {text}[/bold blue]")


def _add_target_to_scope(target: str, console: Console) -> None:
    """Add the target host (and subdomains if wildcard) to the scope allowlist."""
    from agent.scope import add_to_scope, host_of
    if target.startswith("*."):
        base = target.lstrip("*.")
        add_to_scope(base)
        add_to_scope(f"*.{base}")
        console.print(f"  [dim]Scope: *.{base}[/dim]")
    else:
        h = host_of(target) or target
        add_to_scope(h)
        console.print(f"  [dim]Scope: {h}[/dim]")


async def _async_recon(target: str, is_wildcard: bool, allports: bool,
                       console: Console) -> dict | None:
    """Run the full recon pipeline from agent/recon/pipeline.py."""
    _add_target_to_scope(target, console)

    # Subdomain enumeration for wildcard targets
    targets: list[str] = []
    if is_wildcard:
        _status(console, f"Enumerating subdomains for {target}")
        targets = enumerate_subdomains(target, console=console)
        if not targets:
            console.print("[yellow]No live subdomains found.[/yellow]")
            return None
    else:
        from agent.scope import host_of as _host_of
        targets = [_host_of(target) or target]

    # Nmap scan
    for t in targets:
        from agent.scope import add_to_scope
        add_to_scope(t)
        _status(console, f"Port scanning {t}")
        nmap_out = run_nmap(t, allports=allports, console=console)
        if nmap_out:
            console.print(f"\n[bold bright_cyan]— Nmap results for {t} —[/bold bright_cyan]")
            console.print(nmap_out)

    # Full recon pipeline: crawl + JS extraction + secret scan + sourcemaps
    seed_url = targets[0] if targets else target
    if not seed_url.startswith("http"):
        seed_url = f"https://{seed_url}"

    _status(console, f"Crawling & analyzing {seed_url}")
    report = None
    try:
        from agent.http import HttpClient
        from agent.recon.pipeline import run_recon, write_report, format_summary
        async with HttpClient(verify_ssl=False, stealth=True) as client:
            report = await run_recon(client, seed_url)
        if report:
            path = write_report(report)
            print_recon_summary(report, str(path), console)
    except ImportError as exc:
        console.print(f"  [yellow]Recon pipeline not available: {exc}[/yellow]")
        console.print("  [dim]Nmap scan completed above.[/dim]\n")
    except Exception as exc:
        console.print(f"  [red]Recon pipeline error: {exc}[/red]")

    return report


def _run_recon(target: str, is_wildcard: bool, allports: bool,
               console: Console) -> dict | None:
    """Execute the full recon pipeline (sync wrapper)."""
    return asyncio.run(
        _async_recon(target, is_wildcard, allports, console)
    )


def _build_scan_targets(report: dict) -> list[dict]:
    """Extract scannable targets from the recon report.

    Each target is a dict with: url, params, method, id_location, siblings.
    Built from forms (primary) and parameterized endpoints (secondary).
    """
    from urllib.parse import urljoin

    targets: list[dict] = []
    seed_url = report["seed"]
    seen: set[str] = set()

    # Forms — the richest source of injection points
    for form in report.get("forms", []):
        fields = form.get("fields", [])
        param_names = [f["name"] for f in fields if f.get("name")]
        if not param_names:
            continue

        action = form.get("action", "")
        if not action:
            continue
        if not action.startswith("http"):
            action = urljoin(seed_url, action)

        method = (form.get("method") or "GET").upper()
        id_location = "body" if method == "POST" else "query"

        # Default values for sibling fields so multi-field forms work
        siblings = {}
        for f in fields:
            name = f.get("name", "")
            if not name:
                continue
            ftype = f.get("type", "text").lower()
            if ftype == "password":
                siblings[name] = "Test1234!"
            elif ftype == "email":
                siblings[name] = "test@example.com"
            elif ftype == "number":
                siblings[name] = "1"
            else:
                siblings[name] = "test123"

        key = f"{method}:{action}:{','.join(sorted(param_names))}"
        if key in seen:
            continue
        seen.add(key)

        targets.append({
            "url": action,
            "params": param_names,
            "method": method,
            "id_location": id_location,
            "siblings": siblings,
        })

    # JS-extracted endpoints that have params
    for ep in report.get("endpoints", []):
        params = ep.get("params", [])
        if not params:
            continue
        path = ep.get("path", "")
        if not path:
            continue
        url = urljoin(seed_url, path)
        method = (ep.get("method") or "GET").upper()

        key = f"{method}:{url}:{','.join(sorted(params))}"
        if key in seen:
            continue
        seen.add(key)

        targets.append({
            "url": url,
            "params": params,
            "method": method,
            "id_location": "query",
            "siblings": {},
        })

    return targets


async def _async_fullscan(target: str, is_wildcard: bool, allports: bool,
                          console: Console) -> None:
    """Run recon + all vulnerability scanners."""
    report = await _async_recon(target, is_wildcard, allports, console)

    if not report:
        console.print(
            "[yellow]No recon data — skipping vulnerability scanners.[/yellow]\n"
        )
        return

    scan_targets = _build_scan_targets(report)
    if not scan_targets:
        console.print(
            "[yellow]No injectable endpoints found (0 forms, 0 parameterized paths) "
            "— skipping vulnerability scanners.[/yellow]\n"
        )
        return

    try:
        from agent.scanners import (
            SqliScanner, XssScanner, SsrfScanner, IdorScanner,
            NosqliScanner, SstiScanner, CmdiScanner, LfiScanner,
            CsrfScanner, StoredXssScanner, OpenRedirectScanner,
        )
        from agent.recipes.loader import load_recipes
        from agent.http import HttpClient, Session
    except ImportError as exc:
        console.print(f"  [yellow]Scanners not available: {exc}[/yellow]\n")
        return

    seed_url = report["seed"]

    # Show endpoint classification table
    print_endpoint_classification(scan_targets, console)

    console.print(
        f"[bold orange1]  VULNERABILITY SCAN: {report['host']}[/bold orange1]"
    )

    scanner_classes = [
        SqliScanner, XssScanner, SsrfScanner,
        NosqliScanner, SstiScanner, CmdiScanner, LfiScanner,
        CsrfScanner, StoredXssScanner, OpenRedirectScanner,
    ]

    load_result = load_recipes()
    recipes = load_result.recipes
    all_candidates = []
    finding_num = 0

    session = Session()

    async with HttpClient(verify_ssl=False, stealth=True) as client:
        for scanner_cls in scanner_classes:
            name = scanner_cls.__name__.replace("Scanner", "")
            _status(console, f"Scanning for {name}")
            try:
                scanner = scanner_cls(client, session)
                matching_recipes = [
                    r for r in recipes
                    if any(vc in scanner.vuln_classes for vc in r.applies_to)
                ]
                if not matching_recipes:
                    matching_recipes = recipes[:1] if recipes else []

                for st in scan_targets:
                    for recipe in matching_recipes:
                        candidates = await scanner.detect(
                            st["url"], recipe,
                            params=st["params"],
                            method=st["method"],
                            id_location=st["id_location"],
                            siblings=st["siblings"],
                        )
                        if candidates:
                            all_candidates.extend(candidates)
                            for c in candidates:
                                finding_num += 1
                                console.print(
                                    f"  [green]/ AUTON[/green] | "
                                    f"[white]Finding confirmed — {name} on {c.endpoint}[/white]"
                                )
                                print_finding(finding_num, c, console)
            except Exception as exc:
                console.print(f"  [red]{name} error: {exc}[/red]")

        # IDOR scanner needs two sessions (attacker + victim)
        _status(console, "Scanning for IDOR/BOLA")
        try:
            attacker = Session()
            victim = Session()
            idor = IdorScanner(client, attacker, victim)
            matching_recipes = [
                r for r in recipes
                if any(vc in idor.vuln_classes for vc in r.applies_to)
            ]
            if not matching_recipes:
                matching_recipes = recipes[:1] if recipes else []
            for st in scan_targets:
                for recipe in matching_recipes:
                    candidates = await idor.detect(
                        st["url"], recipe,
                        params=st["params"],
                        method=st["method"],
                        id_location=st["id_location"],
                        siblings=st["siblings"],
                    )
                    if candidates:
                        all_candidates.extend(candidates)
                        for c in candidates:
                            finding_num += 1
                            console.print(
                                f"  [green]/ AUTON[/green] | "
                                f"[white]Finding confirmed — IDOR on {c.endpoint}[/white]"
                            )
                            print_finding(finding_num, c, console)
        except Exception as exc:
            console.print(f"  [red]IDOR error: {exc}[/red]")

    print_scan_summary(all_candidates, console)


def _run_fullscan(target: str, is_wildcard: bool, allports: bool,
                  console: Console) -> None:
    """Execute full scan: recon + all vulnerability scanners (sync wrapper)."""
    asyncio.run(
        _async_fullscan(target, is_wildcard, allports, console)
    )


def repl() -> None:
    """Run the interactive REPL loop."""
    console = Console()

    print_banner(console=console)
    console.print(
        "[dim]Type [bold]/commands[/bold] for help or "
        "[bold]/exit[/bold] to quit.[/dim]\n"
    )

    while True:
        try:
            raw = Prompt.ask("[bold green]Auton >[/bold green] ")
        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]Exiting.[/dim]")
            break

        stripped = raw.strip()
        if not stripped:
            continue

        if not stripped.startswith("/"):
            console.print("[bold blue]  * Thinking...[/bold blue]")
            translated = route_input(stripped)
            if not translated:
                console.print(
                    "[red][!] LLM could not understand the request. "
                    "Please use /commands.[/red]"
                )
                continue
            console.print(f"[dim]  → {translated}[/dim]")
            raw = translated

        cmd = parse(raw)

        if cmd.error:
            console.print(f"[red]{cmd.error}[/red]")
            continue

        if cmd.action == "exit":
            console.print("[dim]Goodbye.[/dim]")
            break

        if cmd.action == "commands":
            print_commands_table(console=console)
            continue

        if cmd.action == "recon":
            _run_recon(cmd.target, cmd.is_wildcard, cmd.allports, console)
            continue

        if cmd.action == "fullscan":
            _run_fullscan(cmd.target, cmd.is_wildcard, cmd.allports, console)
            continue


def main() -> None:
    """CLI entry point."""
    ap = argparse.ArgumentParser(
        prog="auton",
        description="AUTON — Autonomous Pentesting Agent",
    )
    args = ap.parse_args()
    repl()


if __name__ == "__main__":
    main()
