"""Startup banner — colorful ASCII art with attribution."""
from __future__ import annotations

from rich.console import Console
from rich.table import Table
from rich.text import Text

_ASCII_ART = r"""
   ▄████████ ███    █▄      ███      ▄██████▄  ███▄▄▄▄
  ███    ███ ███    ███ ▀█████████▄ ███    ███ ███▀▀▀██▄
  ███    ███ ███    ███    ▀███▀▀██ ███    ███ ███   ███
  ███    ███ ███    ███     ███   ▀ ███    ███ ███   ███
▀███████████ ███    ███     ███     ███    ███ ███   ███
  ███    ███ ███    ███     ███     ███    ███ ███   ███
  ███    ███ ███    ███     ███     ███    ███ ███   ███
  ███    █▀  ████████▀     ▄████▀   ▀██████▀   ▀█   █▀
"""

_TAGLINE = "Autonomous Pentesting Agent"
_CREDIT = "Created by Amrit Karki"
_VERSION_LINE = "v0.1.0  |  14 scanners  |  deterministic verification"


def print_banner(console: Console | None = None) -> None:
    """Print the startup banner with attribution."""
    con = console or Console()

    # Build a two-column layout: logo left, credit right
    tbl = Table(
        show_header=False,
        show_edge=False,
        show_lines=False,
        padding=(0, 0),
        expand=True,
        box=None,
    )
    tbl.add_column("art", ratio=3, no_wrap=True)
    tbl.add_column("credit", ratio=1, justify="right", vertical="bottom")

    art_text = Text(_ASCII_ART, style="bold bright_cyan")
    credit_text = Text(f"\n\n\n\n{_CREDIT}\n", style="italic dim magenta")

    tbl.add_row(art_text, credit_text)
    con.print(tbl)

    # Tagline centered
    con.print(
        f"  [bold bright_magenta]{_TAGLINE}[/bold bright_magenta]",
        justify="center",
    )
    con.print(
        f"  [dim bright_blue]{_VERSION_LINE}[/dim bright_blue]",
        justify="center",
    )
    con.print()
