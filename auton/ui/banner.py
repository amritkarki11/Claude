"""Startup banner — AUTON logo with detailed robot and attribution."""
from __future__ import annotations

from rich.console import Console
from rich.text import Text

_ROBOT_LINES = [
    r"        ___________        ",
    r"       |    ___    |       ",
    r"       |   |   |   |      ",
    r"       |   |___|   |      ",
    r"    ___|___________|___    ",
    r"   |  ___|_________|___   ",
    r"   | |  ___     ___  | |  ",
    r"   | | |0  |   |  0| | |  ",
    r"   | | |___|   |___| | |  ",
    r"   | |   _________   | |  ",
    r"   | |  |  =====  |  | |  ",
    r"   | |  |_________|  | |  ",
    r"   |_|_______________|_|  ",
    r"     |  |||     |||  |    ",
    r"     |  |||     |||  |    ",
    r"     |__|_|     |_|__|    ",
]

_AUTON_TEXT = [
    r"    _   _   _ _____ ___  _  _  ",
    r"   / \ | | | |_   _/ _ \| \| | ",
    r"  / _ \| | | | | || | | |  ` | ",
    r" / ___ | |_| | | || |_| | |\ | ",
    r"/_/   \_\___/  |_| \___/|_| \_|",
]

_TAGLINE = "Autonomous Pentesting Agent"
_CREDIT = "Created by Amrit Karki"
_VERSION_LINE = "v0.1.0  |  14 scanners  |  deterministic verification"

_ROW_COLORS = ["grey70"]


def print_banner(console: Console | None = None) -> None:
    """Print the startup banner with detailed robot + AUTON text."""
    con = console or Console()
    width = con.width or 80

    con.print()

    # Print robot
    for line in _ROBOT_LINES:
        txt = Text()
        txt.append(line, style="bold green")
        con.print(txt)

    con.print()

    # Print AUTON figlet text
    for line in _AUTON_TEXT:
        txt = Text()
        pad = max((width - len(line)) // 2, 0)
        txt.append(" " * pad)
        txt.append(line, style="bold bright_cyan")
        con.print(txt)

    con.print()

    # Credit right-aligned
    credit_line = Text()
    padding = max(width - len(_CREDIT) - 2, 0)
    credit_line.append(" " * padding)
    credit_line.append(_CREDIT, style="italic yellow")
    con.print(credit_line)

    # Tagline centered
    tagline_line = Text()
    tag_pad = max((width - len(_TAGLINE)) // 2, 0)
    tagline_line.append(" " * tag_pad)
    tagline_line.append(_TAGLINE, style="bold green")
    con.print(tagline_line)

    # Version centered
    ver_line = Text()
    ver_pad = max((width - len(_VERSION_LINE)) // 2, 0)
    ver_line.append(" " * ver_pad)
    ver_line.append(_VERSION_LINE, style="blue")
    con.print(ver_line)

    con.print()
