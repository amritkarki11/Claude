"""AUTON interactive REPL — the main entry point.

Launch with: auton [--no-dog]
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
from auton.ui.terminal import RunningDog
from auton.router.parser import (
    parse,
    print_commands_table,
    enumerate_subdomains,
    run_nmap,
)

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
                       dog: RunningDog, console: Console) -> dict | None:
    """Run the full recon pipeline from agent/recon/pipeline.py."""
    _add_target_to_scope(target, console)

    # Subdomain enumeration for wildcard targets
    targets: list[str] = []
    if is_wildcard:
        dog.start("Enumerating subdomains")
        dog.update_status(f"DNS brute-force on {target}")
        targets = enumerate_subdomains(target, console=console)
        dog.stop()
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
        dog.start(f"Port scanning {t}")
        dog.update_status(f"Nmap scanning {t}")
        nmap_out = run_nmap(t, allports=allports, console=console)
        dog.stop()
        if nmap_out:
            console.print(f"\n[bold bright_cyan]— Nmap results for {t} —[/bold bright_cyan]")
            console.print(nmap_out)

    # Full recon pipeline: crawl + JS extraction + secret scan + sourcemaps
    seed_url = targets[0] if targets else target
    if not seed_url.startswith("http"):
        seed_url = f"https://{seed_url}"

    dog.start(f"Crawling & analyzing {seed_url}")
    dog.update_status(f"Crawling {seed_url}")
    report = None
    try:
        from agent.http import HttpClient
        from agent.recon.pipeline import run_recon, write_report, format_summary
        async with HttpClient(verify_ssl=False, stealth=True) as client:
            report = await run_recon(client, seed_url)
        dog.stop()
        if report:
            path = write_report(report)
            console.print(f"\n{format_summary(report, path)}")
            console.print()
    except ImportError as exc:
        dog.stop()
        console.print(f"  [yellow]Recon pipeline not available: {exc}[/yellow]")
        console.print("  [dim]Nmap scan completed above.[/dim]\n")
    except Exception as exc:
        dog.stop()
        console.print(f"  [red]Recon pipeline error: {exc}[/red]")

    return report


def _run_recon(target: str, is_wildcard: bool, allports: bool,
               dog: RunningDog, console: Console) -> dict | None:
    """Execute the full recon pipeline (sync wrapper)."""
    return asyncio.run(
        _async_recon(target, is_wildcard, allports, dog, console)
    )


async def _async_fullscan(target: str, is_wildcard: bool, allports: bool,
                          dog: RunningDog, console: Console) -> None:
    """Run recon + all vulnerability scanners."""
    report = await _async_recon(target, is_wildcard, allports, dog, console)

    if not report or not report.get("endpoints"):
        console.print(
            "[yellow]No endpoints discovered — skipping vulnerability scanners.[/yellow]\n"
        )
        return

    try:
        from agent.scanners import (
            SqliScanner, XssScanner, SsrfScanner, IdorScanner,
            NosqliScanner, SstiScanner, CmdiScanner, LfiScanner,
            CsrfScanner, StoredXssScanner, OpenRedirectScanner,
        )
        from agent.recipes.loader import load_recipes
        from agent.http import HttpClient
    except ImportError as exc:
        console.print(f"  [yellow]Scanners not available: {exc}[/yellow]\n")
        return

    seed_url = report["seed"]
    console.print(
        f"\n[bold bright_magenta]— Vulnerability Scan: {report['host']} —[/bold bright_magenta]"
    )

    scanner_classes = [
        SqliScanner, XssScanner, SsrfScanner, IdorScanner,
        NosqliScanner, SstiScanner, CmdiScanner, LfiScanner,
        CsrfScanner, StoredXssScanner, OpenRedirectScanner,
    ]

    load_result = load_recipes()
    recipes = load_result.recipes
    all_candidates = []

    async with HttpClient(verify_ssl=False, stealth=True) as client:
        for scanner_cls in scanner_classes:
            name = scanner_cls.__name__.replace("Scanner", "")
            dog.start(f"Scanning for {name}")
            try:
                scanner = scanner_cls(client)
                matching_recipes = [
                    r for r in recipes
                    if any(vc in scanner.vuln_classes for vc in r.applies_to)
                ]
                if not matching_recipes:
                    matching_recipes = recipes[:1] if recipes else []
                for recipe in matching_recipes:
                    candidates = await scanner.detect(seed_url, recipe)
                    if candidates:
                        all_candidates.extend(candidates)
                        for c in candidates:
                            console.print(
                                f"  [bright_magenta][{name}][/bright_magenta] "
                                f"[yellow]{c.confidence}[/yellow] — {c.endpoint}"
                            )
            except Exception as exc:
                console.print(f"  [red]{name} error: {exc}[/red]")
            finally:
                dog.stop()

    if all_candidates:
        console.print(
            f"\n[bold green]{len(all_candidates)} candidate findings "
            f"(unverified) — run verifiers next.[/bold green]\n"
        )
    else:
        console.print(
            "\n[bold bright_cyan]No candidate findings from scanners.[/bold bright_cyan]\n"
        )


def _run_fullscan(target: str, is_wildcard: bool, allports: bool,
                  dog: RunningDog, console: Console) -> None:
    """Execute full scan: recon + all vulnerability scanners (sync wrapper)."""
    asyncio.run(
        _async_fullscan(target, is_wildcard, allports, dog, console)
    )


def repl(no_dog: bool = False) -> None:
    """Run the interactive REPL loop."""
    console = Console()
    dog = RunningDog(console=console, disabled=no_dog)

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
            _run_recon(cmd.target, cmd.is_wildcard, cmd.allports, dog, console)
            continue

        if cmd.action == "fullscan":
            _run_fullscan(cmd.target, cmd.is_wildcard, cmd.allports, dog, console)
            continue


def main() -> None:
    """CLI entry point — parse --no-dog then launch the REPL."""
    ap = argparse.ArgumentParser(
        prog="auton",
        description="AUTON — Autonomous Pentesting Agent",
    )
    ap.add_argument(
        "--no-dog", action="store_true",
        help="Disable the running-dog animation",
    )
    args = ap.parse_args()
    repl(no_dog=args.no_dog)


if __name__ == "__main__":
    main()
