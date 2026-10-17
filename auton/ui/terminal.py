"""4-legged bouncing dog animation with rich.live.Live in a background thread."""
from __future__ import annotations

import shutil
import threading
import time

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.text import Text

# Right-facing frames
_DOG_RIGHT_SPREAD = [
    r"      __      _",
    r"   o-''|\_____/)",
    r"    \_/|_|_|_/",
    r"     //  ||  \\",
]

_DOG_RIGHT_TOGETHER = [
    r"      __      _",
    r"   o-''|\_____/)",
    r"    \_/|_|_|_/",
    r"      ||  ||",
]

# Left-facing frames
_DOG_LEFT_SPREAD = [
    r"  _      __",
    r"(\_____/''-o",
    r"  \_|_|_|_/",
    r"  //  ||  \\",
]

_DOG_LEFT_TOGETHER = [
    r"  _      __",
    r"(\_____/''-o",
    r"  \_|_|_|_/",
    r"    ||  ||",
]

_DOG_FRAMES = [
    _DOG_RIGHT_SPREAD,
    _DOG_RIGHT_TOGETHER,
    _DOG_LEFT_SPREAD,
    _DOG_LEFT_TOGETHER,
]

_DOG_FRAME_A = _DOG_RIGHT_SPREAD
_DOG_FRAME_B = _DOG_RIGHT_TOGETHER


class DogSpinner:
    """A 4-frame ASCII bouncing-dog spinner using rich.live.Live.

    The dog bounces left-to-right across the terminal width.
    A status panel below shows the current task.

    Usage:
        dog = DogSpinner()
        dog.start("Scanning targets")
        dog.update_status("Found 3 hosts")
        dog.stop()
    """

    def __init__(self, console: Console | None = None, disabled: bool = False):
        self._console = console or Console()
        self._disabled = disabled
        self._running = False
        self._thread: threading.Thread | None = None
        self._message = ""
        self._status = ""
        self._pos = 0
        self._direction = 1  # 1 = right, -1 = left
        self._live: Live | None = None
        self._lock = threading.Lock()

    def start(self, message: str = "Working") -> None:
        if self._disabled or self._running:
            return
        self._message = message
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
        """Build a rich Text renderable for the current animation state."""
        going_right = self._direction == 1
        if going_right:
            frames = [_DOG_RIGHT_SPREAD, _DOG_RIGHT_TOGETHER]
        else:
            frames = [_DOG_LEFT_SPREAD, _DOG_LEFT_TOGETHER]

        frame = frames[frame_idx % 2]
        dog_width = max(len(line) for line in frame)

        cols = shutil.get_terminal_size((80, 24)).columns
        max_pos = max(cols - dog_width - 2, 1)
        pos = min(self._pos, max_pos)

        result = Text()
        for line in frame:
            padded = " " * pos + line
            result.append(padded, style="dark_orange")
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
                    dog_text = self._build_frame(frame_idx)

                    with self._lock:
                        status_text = self._status

                    panel = Panel(
                        f"[bold bright_cyan]{status_text}[/bold bright_cyan]",
                        border_style="blue",
                        expand=False,
                    )

                    from rich.console import Group
                    display = Group(dog_text, panel)
                    self._live.update(display)

                    cols = shutil.get_terminal_size((80, 24)).columns
                    going_right = self._direction == 1
                    if going_right:
                        dog_width = max(len(l) for l in _DOG_RIGHT_SPREAD)
                    else:
                        dog_width = max(len(l) for l in _DOG_LEFT_SPREAD)
                    max_pos = max(cols - dog_width - 2, 1)

                    self._pos += self._direction * 3
                    if self._pos >= max_pos:
                        self._pos = max_pos
                        self._direction = -1
                    elif self._pos <= 0:
                        self._pos = 0
                        self._direction = 1

                    frame_idx += 1
                    time.sleep(0.25)
        finally:
            self._live = None


RunningDog = DogSpinner
