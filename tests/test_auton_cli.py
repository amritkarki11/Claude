"""Tests for auton/cli.py — REPL entry point."""
import pytest
from unittest.mock import patch, MagicMock, call

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

    @patch("auton.cli.run_nmap")
    @patch("auton.cli.Prompt")
    @patch("auton.cli.print_banner")
    def test_recon_calls_nmap(self, mock_banner, mock_prompt, mock_nmap):
        mock_prompt.ask.side_effect = ["/recon example.com", "/exit"]
        mock_nmap.return_value = "PORT  STATE\n80/tcp open"
        repl(no_dog=True)
        mock_nmap.assert_called_once()
        args, kwargs = mock_nmap.call_args
        assert args[0] == "example.com"

    @patch("auton.cli.enumerate_subdomains")
    @patch("auton.cli.Prompt")
    @patch("auton.cli.print_banner")
    def test_wildcard_triggers_subdomain_enum(self, mock_banner, mock_prompt, mock_enum):
        mock_prompt.ask.side_effect = ["/recon *.example.com", "/exit"]
        mock_enum.return_value = []
        repl(no_dog=True)
        mock_enum.assert_called_once()
        args, kwargs = mock_enum.call_args
        assert args[0] == "*.example.com"
