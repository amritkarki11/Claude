"""Startup banner — heavy block AUTON logo with robot and attribution."""
from __future__ import annotations

from rich.console import Console
from rich.text import Text

# Large heavy block letters + robot on the right
# Each line: (AUTON text, robot part)
_BANNER_LINES = [
    ("    ████      ██    ██   ████████    ██████     ██    ██ ", "    ▄█████▄    "),
    ("   ██  ██     ██    ██      ██      ██    ██    ███   ██ ", "   ██ ▄▄▄ ██   "),
    ("  ██    ██    ██    ██      ██      ██    ██    ████  ██ ", "   ██ ▀█▀ ██   "),
    ("  ████████    ██    ██      ██      ██    ██    ██ ██ ██ ", "  ████████████  "),
    ("  ██    ██    ██    ██      ██      ██    ██    ██  ████ ", "  ██ ██ ██ ██  "),
    ("  ██    ██    ██    ██      ██      ██    ██    ██   ███ ", "  ██ █████ ██  "),
    ("  ██    ██     ██████       ██       ██████     ██    ██ ", "  ▀██████████▀  "),
    ("                                                        ", "    ██▀ ▀██     "),
]

_TAGLINE = "[ Autonomous Pentesting Agent ]"
_CREDIT = "Created by Amrit Karki"
_VERSION_LINE = "v0.1.0  |  14 scanners  |  deterministic verification"

_ROW_COLORS = ["grey70"]


def print_banner(console: Console | None = None) -> None:
    """Print the startup banner with heavy AUTON text + robot."""
    con = console or Console()
    width = con.width or 80

    con.print()

    for text_part, robot_part in _BANNER_LINES:
        line = Text()
        line.append(text_part, style="bold white")
        line.append(robot_part, style="bold green")
        con.print(line)

    con.print()

    # Tagline centered
    tagline_line = Text()
    tag_pad = max((width - len(_TAGLINE)) // 2, 0)
    tagline_line.append(" " * tag_pad)
    tagline_line.append(_TAGLINE, style="bold red")
    con.print(tagline_line)

    # Credit right-aligned
    credit_line = Text()
    padding = max(width - len(_CREDIT) - 2, 0)
    credit_line.append(" " * padding)
    credit_line.append(_CREDIT, style="italic grey70")
    con.print(credit_line)

    # Version centered
    ver_line = Text()
    ver_pad = max((width - len(_VERSION_LINE)) // 2, 0)
    ver_line.append(" " * ver_pad)
    ver_line.append(_VERSION_LINE, style="grey50")
    con.print(ver_line)

    con.print()
