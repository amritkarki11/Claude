"""Startup banner — multi-color ASCII art with attribution."""
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

_ROW_COLORS = ["green", "blue", "dark_orange", "red", "yellow"]


def print_banner(console: Console | None = None) -> None:
    """Print the startup banner with multi-color gradient."""
    con = console or Console()

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

    art_text = Text()
    lines = _ASCII_ART.strip("\n").split("\n")
    for i, line in enumerate(lines):
        color = _ROW_COLORS[i % len(_ROW_COLORS)]
        art_text.append(line, style=f"bold {color}")
        if i < len(lines) - 1:
            art_text.append("\n")

    credit_text = Text(f"\n\n\n\n{_CREDIT}\n", style="italic yellow")

    tbl.add_row(art_text, credit_text)
    con.print(tbl)

    con.print(
        f"  [bold green]{_TAGLINE}[/bold green]",
        justify="center",
    )
    con.print(
        f"  [dim bright_blue]{_VERSION_LINE}[/dim bright_blue]",
        justify="center",
    )
    con.print()
