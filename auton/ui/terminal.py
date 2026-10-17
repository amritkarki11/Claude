"""Minimalist terminal bot animation with rich.live.Live in a background thread."""
from __future__ import annotations

import shutil
import threading
import time

from rich.console import Console
from rich.live import Live
from rich.text import Text


_BOT_HEAD = r"  [ o_o ]"
_BOT_BODY = r"  [ ### ]"

_BOT_BASE = [
    r"    ___",
    _BOT_HEAD,
    _BOT_BODY,
]

_LEGS_SPREAD = r"   /   \\"
_LEGS_TOGETHER = r"    | |"

_FRAME_A = _BOT_BASE + [_LEGS_SPREAD]
_FRAME_B = _BOT_BASE + [_LEGS_TOGETHER]

_FRAMES = [_FRAME_A, _FRAME_B]


class TerminalBot:
    """Minimalist ASCII robot that walks back and forth across the terminal.

    Usage:
        bot = TerminalBot()
        bot.start("Scanning targets")
        bot.update_status("Found 3 hosts")
        bot.stop()
    """

    def __init__(self, console: Console | None = None, disabled: bool = False):
        self._console = console or Console()
        self._disabled = disabled
        self._running = False
        self._thread: threading.Thread | None = None
        self._status = ""
        self._pos = 0
        self._direction = 1
        self._live: Live | None = None
        self._lock = threading.Lock()

    def start(self, message: str = "Working") -> None:
        if self._disabled or self._running:
            return
        self._status = message
        self._running = True
        self._pos = 0
        self._direction = 1
        self._thread = threading.Thread(target=self._animate, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None

    def update_status(self, text: str) -> None:
        with self._lock:
            self._status = text

    def _build_frame(self, frame_idx: int) -> Text:
        frame = _FRAMES[frame_idx % 2]
        bot_width = max(len(line) for line in frame)

        cols = shutil.get_terminal_size((80, 24)).columns
        max_pos = max(cols - bot_width - 2, 1)
        pos = min(self._pos, max_pos)

        line_styles = ["bold cyan", "bold cyan", "bold yellow", "bold green"]

        result = Text()
        for i, line in enumerate(frame):
            padded = " " * pos + line
            style = line_styles[i] if i < len(line_styles) else "white"
            result.append(padded, style=style)
            result.append("\n")

        with self._lock:
            status_text = self._status
        result.append(f"  * {status_text}", style="bold blue")
        result.append("\n")

        return result

    def _animate(self) -> None:
        frame_idx = 0
        try:
            self._live = Live(
                console=self._console,
                transient=True,
                refresh_per_second=8,
            )
            with self._live:
                while self._running:
                    display = self._build_frame(frame_idx)
                    self._live.update(display)

                    cols = shutil.get_terminal_size((80, 24)).columns
                    bot_width = max(len(line) for line in _FRAME_A)
                    max_pos = max(cols - bot_width - 2, 1)

                    self._pos += self._direction * 2
                    if self._pos >= max_pos:
                        self._pos = max_pos
                        self._direction = -1
                    elif self._pos <= 0:
                        self._pos = 0
                        self._direction = 1

                    frame_idx += 1
                    time.sleep(0.2)
        finally:
            self._live = None


RunningDog = TerminalBot
DogSpinner = TerminalBot
