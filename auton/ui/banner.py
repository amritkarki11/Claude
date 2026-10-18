"""Startup banner — minimal one-liner."""
from __future__ import annotations

from rich.console import Console


def print_banner(console: Console | None = None) -> None:
    """Print a compact startup line."""
    con = console or Console()
    con.print(
        "\n[bold red]AUTON[/bold red] [white]v0.1.0[/white] "
        "[dim]|[/dim] [white]14 scanners[/white] "
        "[dim]|[/dim] [white]deterministic verification[/white] "
        "[dim]|[/dim] [italic grey70]by Amrit Karki[/italic grey70]\n"
    )
