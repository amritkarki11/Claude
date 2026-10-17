"""Tests for auton/ui/ — banner and terminal animation."""
import io
import pytest
from unittest.mock import patch, MagicMock

from rich.console import Console

from auton.ui.banner import print_banner, _ASCII_ART, _TAGLINE, _CREDIT
from auton.ui.terminal import RunningDog, _DOG_FRAMES


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

    def test_ascii_art_not_empty(self):
        assert len(_ASCII_ART.strip()) > 50

    def test_no_orange_in_banner(self):
        # Ensure no orange color references in banner source
        import inspect
        src = inspect.getsource(print_banner)
        assert "orange" not in src.lower()


class TestRunningDog:
    def test_frames_exist(self):
        assert len(_DOG_FRAMES) == 2
        assert len(_DOG_FRAMES[0]) == len(_DOG_FRAMES[1])

    def test_disabled_dog_does_not_start(self):
        dog = RunningDog(disabled=True)
        dog.start("test")
        assert not dog._running
        assert dog._thread is None

    def test_start_stop(self):
        con = Console(file=io.StringIO(), force_terminal=True, width=80)
        dog = RunningDog(console=con, disabled=False)
        dog.start("Testing")
        assert dog._running is True
        assert dog._thread is not None
        dog.stop()
        assert dog._running is False

    def test_double_start_ignored(self):
        con = Console(file=io.StringIO(), force_terminal=True, width=80)
        dog = RunningDog(console=con, disabled=False)
        dog.start("First")
        t1 = dog._thread
        dog.start("Second")
        assert dog._thread is t1
        dog.stop()

    def test_stop_when_not_running(self):
        dog = RunningDog(disabled=True)
        dog.stop()  # should not raise
