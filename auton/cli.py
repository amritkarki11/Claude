"""AUTON interactive REPL — the main entry point.

Launch with: auton [--no-dog]
Inside the shell: /commands, /recon, /fullscan, /exit

100% deterministic Python. No LLMs. No APIs.
"""
from __future__ import annotations

import argparse
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


def _run_recon(target: str, is_wildcard: bool, allports: bool,
               dog: RunningDog, console: Console) -> None:
    """Execute the recon pipeline: subdomain enum (if wildcard) + nmap."""
    targets: list[str] = []

    if is_wildcard:
        dog.start("Enumerating subdomains")
        targets = enumerate_subdomains(target, console=console)
        dog.stop()
        if not targets:
            console.print("[yellow]No live hosts found — skipping nmap.[/yellow]")
            return
    else:
        targets = [target]

    for t in targets:
        dog.start(f"Scanning {t}")
        result = run_nmap(t, allports=allports, console=console)
        dog.stop()
        if result:
            console.print(f"\n[bold bright_cyan]— Nmap results for {t} —[/bold bright_cyan]")
            console.print(result)


def _run_fullscan(target: str, is_wildcard: bool, allports: bool,
                  dog: RunningDog, console: Console) -> None:
    """Execute full scan: recon + all 14 vulnerability scanners.

    Currently runs recon; scanner integration is Phase 2.
    """
    _run_recon(target, is_wildcard, allports, dog, console)
    console.print(
        "\n[bold bright_magenta]Vulnerability scanners not yet wired — "
        "recon complete.[/bold bright_magenta]\n"
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
            raw = Prompt.ask("[bold cyan]Auton >[/bold cyan] ")
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
