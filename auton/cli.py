"""AUTON interactive REPL — the main entry point.

Launch with: auton
Inside the shell: /commands, /recon, /fullscan, /nmap, /sqli, /xss, etc.

100% deterministic slash-command routing. No LLMs, no API keys.
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
    print_commands_table,
    enumerate_subdomains,
    run_nmap,
    _SCANNER_MAP,
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


def _resolve_targets(target: str, is_wildcard: bool, console: Console) -> list[str]:
    """Resolve target into a list of hosts (with subdomain enum for wildcards)."""
    if is_wildcard:
        _status(console, f"Enumerating subdomains for {target}")
        targets = enumerate_subdomains(target, console=console)
        if not targets:
            console.print("[yellow]No live subdomains found.[/yellow]")
        return targets

    from agent.scope import host_of as _host_of
    return [_host_of(target) or target]


def _run_nmap_on_targets(targets: list[str], allports: bool, console: Console) -> None:
    """Run nmap on each target in the list."""
    from agent.scope import add_to_scope
    for t in targets:
        add_to_scope(t)
        _status(console, f"Port scanning {t}")
        nmap_out = run_nmap(t, allports=allports, console=console)
        if nmap_out:
            console.print(f"\n[bold bright_cyan]— Nmap results for {t} —[/bold bright_cyan]")
            console.print(nmap_out)


async def _async_recon(target: str, is_wildcard: bool, allports: bool,
                       use_nmap: bool, console: Console) -> dict | None:
    """Run the recon pipeline. Nmap only if use_nmap=True."""
    _add_target_to_scope(target, console)

    targets = _resolve_targets(target, is_wildcard, console)
    if not targets:
        return None

    if use_nmap:
        _run_nmap_on_targets(targets, allports, console)

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
        if use_nmap:
            console.print("  [dim]Nmap scan completed above.[/dim]\n")
    except Exception as exc:
        console.print(f"  [red]Recon pipeline error: {exc}[/red]")

    return report


def _run_recon(target: str, is_wildcard: bool, allports: bool,
               use_nmap: bool, console: Console) -> dict | None:
    """Execute the full recon pipeline (sync wrapper)."""
    return asyncio.run(
        _async_recon(target, is_wildcard, allports, use_nmap, console)
    )


def _build_scan_targets(report: dict) -> list[dict]:
    """Extract scannable targets from the recon report."""
    from urllib.parse import urljoin

    targets: list[dict] = []
    seed_url = report["seed"]
    seen: set[str] = set()

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
            "url": action, "params": param_names, "method": method,
            "id_location": id_location, "siblings": siblings,
        })

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
            "url": url, "params": params, "method": method,
            "id_location": "query", "siblings": {},
        })

    return targets


def _get_scanner_class(scanner_key: str):
    """Import and return a single scanner class by key."""
    from agent.scanners import (
        SqliScanner, XssScanner, SsrfScanner, IdorScanner,
        NosqliScanner, SstiScanner, CmdiScanner, LfiScanner,
        CsrfScanner, StoredXssScanner, OpenRedirectScanner,
    )
    cls_map = {
        "sqli": SqliScanner, "xss": XssScanner, "ssrf": SsrfScanner,
        "idor": IdorScanner, "nosqli": NosqliScanner, "ssti": SstiScanner,
        "cmdi": CmdiScanner, "lfi": LfiScanner, "csrf": CsrfScanner,
        "storedxss": StoredXssScanner, "redirect": OpenRedirectScanner,
    }
    return cls_map[scanner_key]


async def _async_run_scanners(report: dict, scanner_keys: list[str],
                              console: Console) -> None:
    """Run specified scanners against recon report targets."""
    scan_targets = _build_scan_targets(report)
    if not scan_targets:
        console.print(
            "[yellow]No injectable endpoints found (0 forms, 0 parameterized paths) "
            "— skipping vulnerability scanners.[/yellow]\n"
        )
        return

    try:
        from agent.recipes.loader import load_recipes
        from agent.http import HttpClient, Session
    except ImportError as exc:
        console.print(f"  [yellow]Scanners not available: {exc}[/yellow]\n")
        return

    print_endpoint_classification(scan_targets, console)
    console.print(
        f"[bold orange1]  VULNERABILITY SCAN: {report['host']}[/bold orange1]"
    )

    load_result = load_recipes()
    recipes = load_result.recipes
    all_candidates = []
    finding_num = 0

    async with HttpClient(verify_ssl=False, stealth=True) as client:
        for key in scanner_keys:
            try:
                scanner_cls = _get_scanner_class(key)
            except (ImportError, KeyError) as exc:
                console.print(f"  [red]Scanner {key} not available: {exc}[/red]")
                continue

            name = scanner_cls.__name__.replace("Scanner", "")
            _status(console, f"Scanning for {name}")

            try:
                if key == "idor":
                    attacker = Session()
                    victim = Session()
                    scanner = scanner_cls(client, attacker, victim)
                else:
                    session = Session()
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

    print_scan_summary(all_candidates, console)


_ALL_SCANNER_KEYS = [
    "sqli", "xss", "ssrf", "nosqli", "ssti", "cmdi",
    "lfi", "csrf", "storedxss", "redirect", "idor",
]


async def _async_fullscan(target: str, is_wildcard: bool, allports: bool,
                          use_nmap: bool, console: Console) -> None:
    """Run recon + all vulnerability scanners."""
    report = await _async_recon(target, is_wildcard, allports, use_nmap, console)
    if not report:
        console.print(
            "[yellow]No recon data — skipping vulnerability scanners.[/yellow]\n"
        )
        return
    await _async_run_scanners(report, _ALL_SCANNER_KEYS, console)


async def _async_single_scan(target: str, is_wildcard: bool, scanner_key: str,
                             console: Console) -> None:
    """Run recon + a single scanner."""
    report = await _async_recon(target, is_wildcard, False, False, console)
    if not report:
        console.print(
            "[yellow]No recon data — cannot run scanner.[/yellow]\n"
        )
        return
    await _async_run_scanners(report, [scanner_key], console)


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
            console.print(
                "[red]Unknown input. Commands start with /. "
                "Type /commands for help.[/red]"
            )
            continue

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

        if cmd.action == "nmap":
            _add_target_to_scope(cmd.target, console)
            targets = _resolve_targets(cmd.target, cmd.is_wildcard, console)
            if targets:
                _run_nmap_on_targets(targets, cmd.allports, console)
            continue

        if cmd.action == "recon":
            _run_recon(cmd.target, cmd.is_wildcard, cmd.allports, cmd.nmap, console)
            continue

        if cmd.action == "fullscan":
            asyncio.run(
                _async_fullscan(cmd.target, cmd.is_wildcard, cmd.allports,
                                cmd.nmap, console)
            )
            continue

        if cmd.action == "scan_single":
            asyncio.run(
                _async_single_scan(cmd.target, cmd.is_wildcard, cmd.scanner,
                                   console)
            )
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
