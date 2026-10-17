"""Tests for auton/ui/ — banner and terminal bot animation."""
import io
import pytest
from unittest.mock import patch, MagicMock

from rich.console import Console

from auton.ui.banner import print_banner, _BANNER_LINES, _TAGLINE, _CREDIT, _ROW_COLORS
from auton.ui.terminal import (
    TerminalBot, RunningDog, DogSpinner,
    _FRAME_A, _FRAME_B, _FRAMES,
    _BOT_BASE, _BOT_HEAD, _BOT_BODY,
    _LEGS_SPREAD, _LEGS_TOGETHER,
)


class TestBanner:
    def _capture_console(self) -> tuple[Console, io.StringIO]:
        buf = io.StringIO()
        return Console(file=buf, force_terminal=True, width=120), buf

    def test_print_banner_runs(self):
        con, buf = self._capture_console()
        print_banner(console=con)
        output = buf.getvalue()
        assert len(output) > 0

    def test_banner_contains_credit(self):
        con, buf = self._capture_console()
        print_banner(console=con)
        output = buf.getvalue()
        assert "Amrit Karki" in output

    def test_banner_contains_tagline(self):
        con, buf = self._capture_console()
        print_banner(console=con)
        output = buf.getvalue()
        assert "Pentesting Agent" in output

    def test_banner_lines_not_empty(self):
        assert len(_BANNER_LINES) == 9

    def test_row_colors_grey(self):
        assert "grey70" in _ROW_COLORS

    def test_banner_contains_version(self):
        buf = io.StringIO()
        con = Console(file=buf, force_terminal=False, width=120, no_color=True)
        print_banner(console=con)
        output = buf.getvalue()
        assert "v0.1.0" in output


class TestTerminalBot:
    def test_two_frames_exist(self):
        assert len(_FRAMES) == 2
        assert _FRAMES[0] is _FRAME_A
        assert _FRAMES[1] is _FRAME_B

    def test_frame_a_has_spread_legs(self):
        assert _FRAME_A[-1] is _LEGS_SPREAD

    def test_frame_b_has_together_legs(self):
        assert _FRAME_B[-1] is _LEGS_TOGETHER

    def test_frames_same_line_count(self):
        assert len(_FRAME_A) == len(_FRAME_B) == 4

    def test_bot_base_structure(self):
        assert len(_BOT_BASE) == 3
        assert "o_o" in _BOT_HEAD
        assert "###" in _BOT_BODY

    def test_disabled_bot_does_not_start(self):
        bot = TerminalBot(disabled=True)
        bot.start("test")
        assert not bot._running
        assert bot._thread is None

    def test_running_dog_alias(self):
        assert RunningDog is TerminalBot

    def test_dog_spinner_alias(self):
        assert DogSpinner is TerminalBot

    def test_start_stop(self):
        con = Console(file=io.StringIO(), force_terminal=True, width=80)
        bot = TerminalBot(console=con, disabled=False)
        bot.start("Testing")
        assert bot._running is True
        assert bot._thread is not None
        bot.stop()
        assert bot._running is False

    def test_double_start_ignored(self):
        con = Console(file=io.StringIO(), force_terminal=True, width=80)
        bot = TerminalBot(console=con, disabled=False)
        bot.start("First")
        t1 = bot._thread
        bot.start("Second")
        assert bot._thread is t1
        bot.stop()

    def test_stop_when_not_running(self):
        bot = TerminalBot(disabled=True)
        bot.stop()

    def test_update_status(self):
        bot = TerminalBot(disabled=True)
        bot.update_status("new status")
        assert bot._status == "new status"

    def test_update_status_thread_safe(self):
        con = Console(file=io.StringIO(), force_terminal=True, width=80)
        bot = TerminalBot(console=con, disabled=False)
        bot.start("Initial")
        bot.update_status("Updated")
        with bot._lock:
            assert bot._status == "Updated"
        bot.stop()
