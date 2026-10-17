"""Running-dog terminal animation using rich, in a background thread."""
from __future__ import annotations

import sys
import threading
import time

from rich.console import Console

_DOG_FRAME_A = [
    r"   __      / )",
    r"  /  \    / / ",
    r" / /\ \--/ /  ",
    r"/_/  \_____/   ",
    r"       ||  ||  ",
    r"      _||_ ||_ ",
]

_DOG_FRAME_B = [
    r"   __      / )",
    r"  /  \    / / ",
    r" / /\ \--/ /  ",
    r"/_/  \_____/   ",
    r"      _/  \_   ",
    r"     (__)(__)   ",
]

_DOG_FRAMES = [_DOG_FRAME_A, _DOG_FRAME_B]

_CLEAR_LINE = "\033[2K"
_CURSOR_UP = "\033[A"


class RunningDog:
    """A 2-frame ASCII running-dog spinner that runs in a background thread.

    Usage:
        dog = RunningDog()
        dog.start("Scanning targets")
        # ... do work ...
        dog.stop()
    """

    def __init__(self, console: Console | None = None, disabled: bool = False):
        self._console = console or Console()
        self._disabled = disabled
        self._running = False
        self._thread: threading.Thread | None = None
        self._message = ""
        self._frame_lines = 0

    def start(self, message: str = "Working") -> None:
        if self._disabled or self._running:
            return
        self._message = message
        self._running = True
        self._frame_lines = 0
        self._thread = threading.Thread(target=self._animate, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
        self._erase_frame()

    def _erase_frame(self) -> None:
        out = self._console.file
        for _ in range(self._frame_lines):
            out.write(f"{_CURSOR_UP}{_CLEAR_LINE}\r")
        out.flush()
        self._frame_lines = 0

    def _animate(self) -> None:
        idx = 0
        out = self._console.file
        while self._running:
            self._erase_frame()
            frame = _DOG_FRAMES[idx % 2]
            lines_written = 0
            for line in frame:
                out.write(f"  \033[96m{line}\033[0m\n")
                lines_written += 1
            out.write(f"  \033[2;94m{self._message}...\033[0m\n")
            lines_written += 1
            out.flush()
            self._frame_lines = lines_written
            idx += 1
            time.sleep(0.4)
