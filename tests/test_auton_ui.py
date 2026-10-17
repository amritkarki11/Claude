"""Tests for auton/ui/ — banner and terminal animation."""
import io
import pytest
from unittest.mock import patch, MagicMock

from rich.console import Console

from auton.ui.banner import print_banner, _ASCII_ART, _TAGLINE, _CREDIT, _ROW_COLORS
from auton.ui.terminal import (
    DogSpinner, RunningDog,
    _DOG_FRAMES, _DOG_FRAME_A, _DOG_FRAME_B,
    _DOG_RIGHT_SPREAD, _DOG_RIGHT_TOGETHER,
    _DOG_LEFT_SPREAD, _DOG_LEFT_TOGETHER,
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

    def test_ascii_art_not_empty(self):
        assert len(_ASCII_ART.strip()) > 50

    def test_row_colors_defined(self):
        assert len(_ROW_COLORS) == 5
        assert "green" in _ROW_COLORS
        assert "dark_orange" in _ROW_COLORS


class TestDogSpinner:
    def test_four_frames_exist(self):
        assert len(_DOG_FRAMES) == 4
        assert _DOG_FRAMES[0] is _DOG_RIGHT_SPREAD
        assert _DOG_FRAMES[1] is _DOG_RIGHT_TOGETHER
        assert _DOG_FRAMES[2] is _DOG_LEFT_SPREAD
        assert _DOG_FRAMES[3] is _DOG_LEFT_TOGETHER

    def test_frame_a_b_compat(self):
        assert _DOG_FRAME_A is _DOG_RIGHT_SPREAD
        assert _DOG_FRAME_B is _DOG_RIGHT_TOGETHER

    def test_left_right_frames_same_height(self):
        assert len(_DOG_RIGHT_SPREAD) == len(_DOG_LEFT_SPREAD)
        assert len(_DOG_RIGHT_TOGETHER) == len(_DOG_LEFT_TOGETHER)

    def test_disabled_dog_does_not_start(self):
        dog = DogSpinner(disabled=True)
        dog.start("test")
        assert not dog._running
        assert dog._thread is None

    def test_running_dog_alias(self):
        assert RunningDog is DogSpinner

    def test_start_stop(self):
        con = Console(file=io.StringIO(), force_terminal=True, width=80)
        dog = DogSpinner(console=con, disabled=False)
        dog.start("Testing")
        assert dog._running is True
        assert dog._thread is not None
        dog.stop()
        assert dog._running is False

    def test_double_start_ignored(self):
        con = Console(file=io.StringIO(), force_terminal=True, width=80)
        dog = DogSpinner(console=con, disabled=False)
        dog.start("First")
        t1 = dog._thread
        dog.start("Second")
        assert dog._thread is t1
        dog.stop()

    def test_stop_when_not_running(self):
        dog = DogSpinner(disabled=True)
        dog.stop()

    def test_update_status(self):
        dog = DogSpinner(disabled=True)
        dog.update_status("new status")
        assert dog._status == "new status"

    def test_update_status_thread_safe(self):
        con = Console(file=io.StringIO(), force_terminal=True, width=80)
        dog = DogSpinner(console=con, disabled=False)
        dog.start("Initial")
        dog.update_status("Updated")
        with dog._lock:
            assert dog._status == "Updated"
        dog.stop()
