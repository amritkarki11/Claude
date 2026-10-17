"""Tests for auton/cli.py — REPL entry point."""
import pytest
from unittest.mock import patch, MagicMock, AsyncMock

from auton.cli import main, repl


class TestMain:
    @patch("auton.cli.repl")
    @patch("sys.argv", ["auton"])
    def test_main_default(self, mock_repl):
        main()
        mock_repl.assert_called_once_with(no_dog=False)

    @patch("auton.cli.repl")
    @patch("sys.argv", ["auton", "--no-dog"])
    def test_main_no_dog(self, mock_repl):
        main()
        mock_repl.assert_called_once_with(no_dog=True)


class TestRepl:
    @patch("auton.cli.Prompt")
    @patch("auton.cli.print_banner")
    def test_exit_command(self, mock_banner, mock_prompt):
        mock_prompt.ask.return_value = "/exit"
        repl(no_dog=True)
        mock_banner.assert_called_once()

    @patch("auton.cli.print_commands_table")
    @patch("auton.cli.Prompt")
    @patch("auton.cli.print_banner")
    def test_commands_then_exit(self, mock_banner, mock_prompt, mock_cmds_table):
        mock_prompt.ask.side_effect = ["/commands", "/exit"]
        repl(no_dog=True)
        mock_cmds_table.assert_called_once()

    @patch("auton.cli.Prompt")
    @patch("auton.cli.print_banner")
    def test_unknown_command_shows_error(self, mock_banner, mock_prompt):
        mock_prompt.ask.side_effect = ["/bogus", "/exit"]
        repl(no_dog=True)

    @patch("auton.cli.Prompt")
    @patch("auton.cli.print_banner")
    def test_keyboard_interrupt_exits(self, mock_banner, mock_prompt):
        mock_prompt.ask.side_effect = KeyboardInterrupt()
        repl(no_dog=True)

    @patch("auton.cli.Prompt")
    @patch("auton.cli.print_banner")
    def test_eof_exits(self, mock_banner, mock_prompt):
        mock_prompt.ask.side_effect = EOFError()
        repl(no_dog=True)

    @patch("auton.cli._run_recon")
    @patch("auton.cli.Prompt")
    @patch("auton.cli.print_banner")
    def test_recon_dispatches(self, mock_banner, mock_prompt, mock_recon):
        mock_prompt.ask.side_effect = ["/recon example.com", "/exit"]
        mock_recon.return_value = None
        repl(no_dog=True)
        mock_recon.assert_called_once()
        args = mock_recon.call_args[0]
        assert args[0] == "example.com"

    @patch("auton.cli._run_fullscan")
    @patch("auton.cli.Prompt")
    @patch("auton.cli.print_banner")
    def test_fullscan_dispatches(self, mock_banner, mock_prompt, mock_fullscan):
        mock_prompt.ask.side_effect = ["/fullscan example.com", "/exit"]
        mock_fullscan.return_value = None
        repl(no_dog=True)
        mock_fullscan.assert_called_once()
        args = mock_fullscan.call_args[0]
        assert args[0] == "example.com"

    @patch("auton.cli._run_recon")
    @patch("auton.cli.Prompt")
    @patch("auton.cli.print_banner")
    def test_wildcard_passes_through(self, mock_banner, mock_prompt, mock_recon):
        mock_prompt.ask.side_effect = ["/recon *.example.com", "/exit"]
        mock_recon.return_value = None
        repl(no_dog=True)
        args = mock_recon.call_args[0]
        assert args[0] == "*.example.com"
        assert args[1] is True  # is_wildcard
