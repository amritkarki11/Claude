"""Startup banner — grey AUTON logo with attribution."""
from __future__ import annotations

from rich.console import Console
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

_ROW_COLORS = ["grey70"]


def print_banner(console: Console | None = None) -> None:
    """Print the startup banner with grey logo and attribution."""
    con = console or Console()
    width = con.width or 80

    lines = _ASCII_ART.strip("\n").split("\n")

    art_text = Text()
    for i, line in enumerate(lines):
        art_text.append(line, style="bold grey70")
        if i < len(lines) - 1:
            art_text.append("\n")

    con.print(art_text)

    credit_line = Text()
    padding = max(width - len(_CREDIT) - 2, 0)
    credit_line.append(" " * padding)
    credit_line.append(_CREDIT, style="italic yellow")
    con.print(credit_line)

    con.print(
        f"  [bold green]{_TAGLINE}[/bold green]",
        justify="center",
    )
    con.print(
        f"  [dim bright_blue]{_VERSION_LINE}[/dim bright_blue]",
        justify="center",
    )
    con.print()
