"""Running-dog terminal animation using rich, in a background thread."""
from __future__ import annotations

import threading
import time

from rich.console import Console
from rich.text import Text

# Two-frame ASCII running dog
_DOG_FRAMES = [
    r"   __      / )",
    r"  /  \    / / ",
    r" / /\ \--/ /  ",
    r"/_/  \_____/   ",
    r"       ||  ||  ",
    r"      _||_ ||_ ",
], [
    r"   __      / )",
    r"  /  \    / / ",
    r" / /\ \--/ /  ",
    r"/_/  \_____/   ",
    r"      _/  \_   ",
    r"     (__)(__)   ",
]


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

    def start(self, message: str = "Working") -> None:
        if self._disabled or self._running:
            return
        self._message = message
        self._running = True
        self._thread = threading.Thread(target=self._animate, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
        # Clear the dog frames from terminal
        frame_height = len(_DOG_FRAMES[0]) + 1  # frames + message line
        for _ in range(frame_height):
            self._console.print(" " * 60)
        # Move cursor back up and overwrite
        self._console.file.write(f"\033[{frame_height}A")
        self._console.file.flush()

    def _animate(self) -> None:
        frame_idx = 0
        frame_height = len(_DOG_FRAMES[0]) + 1
        while self._running:
            frame = _DOG_FRAMES[frame_idx % 2]
            lines = []
            for line in frame:
                lines.append(f"  [bright_cyan]{line}[/bright_cyan]")
            lines.append(f"  [dim bright_blue]{self._message}...[/dim bright_blue]")
            output = "\n".join(lines)
            self._console.print(output, highlight=False)
            time.sleep(0.4)
            if self._running:
                # Move cursor up to overwrite
                self._console.file.write(f"\033[{frame_height}A")
                self._console.file.flush()
            frame_idx += 1
