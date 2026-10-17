"""Tests for auton/cli.py — REPL entry point."""
import pytest
from unittest.mock import patch, MagicMock, AsyncMock

from auton.cli import main, repl


class TestMain:
    @patch("auton.cli.repl")
    @patch("sys.argv", ["auton"])
    def test_main_default(self, mock_repl):
        main()
        mock_repl.assert_called_once()


class TestRepl:
    @patch("auton.cli.Prompt")
    @patch("auton.cli.print_banner")
    def test_exit_command(self, mock_banner, mock_prompt):
        mock_prompt.ask.return_value = "/exit"
        repl()
        mock_banner.assert_called_once()

    @patch("auton.cli.print_commands_table")
    @patch("auton.cli.Prompt")
    @patch("auton.cli.print_banner")
    def test_commands_then_exit(self, mock_banner, mock_prompt, mock_cmds_table):
        mock_prompt.ask.side_effect = ["/commands", "/exit"]
        repl()
        mock_cmds_table.assert_called_once()

    @patch("auton.cli.Prompt")
    @patch("auton.cli.print_banner")
    def test_unknown_command_shows_error(self, mock_banner, mock_prompt):
        mock_prompt.ask.side_effect = ["/bogus", "/exit"]
        repl()

    @patch("auton.cli.Prompt")
    @patch("auton.cli.print_banner")
    def test_keyboard_interrupt_exits(self, mock_banner, mock_prompt):
        mock_prompt.ask.side_effect = KeyboardInterrupt()
        repl()

    @patch("auton.cli.Prompt")
    @patch("auton.cli.print_banner")
    def test_eof_exits(self, mock_banner, mock_prompt):
        mock_prompt.ask.side_effect = EOFError()
        repl()

    @patch("auton.cli._run_recon")
    @patch("auton.cli.Prompt")
    @patch("auton.cli.print_banner")
    def test_recon_dispatches(self, mock_banner, mock_prompt, mock_recon):
        mock_prompt.ask.side_effect = ["/recon example.com", "/exit"]
        mock_recon.return_value = None
        repl()
        mock_recon.assert_called_once()
        args = mock_recon.call_args[0]
        assert args[0] == "example.com"
        assert args[3] is False  # use_nmap=False

    @patch("auton.cli._run_recon")
    @patch("auton.cli.Prompt")
    @patch("auton.cli.print_banner")
    def test_recon_with_nmap(self, mock_banner, mock_prompt, mock_recon):
        mock_prompt.ask.side_effect = ["/recon example.com /nmap", "/exit"]
        mock_recon.return_value = None
        repl()
        args = mock_recon.call_args[0]
        assert args[3] is True  # use_nmap=True

    @patch("auton.cli._run_recon")
    @patch("auton.cli.Prompt")
    @patch("auton.cli.print_banner")
    def test_recon_nmap_allports(self, mock_banner, mock_prompt, mock_recon):
        mock_prompt.ask.side_effect = ["/recon example.com /nmap /allports", "/exit"]
        mock_recon.return_value = None
        repl()
        args = mock_recon.call_args[0]
        assert args[2] is True  # allports=True
        assert args[3] is True  # use_nmap=True

    @patch("auton.cli.asyncio")
    @patch("auton.cli.Prompt")
    @patch("auton.cli.print_banner")
    def test_fullscan_dispatches(self, mock_banner, mock_prompt, mock_asyncio):
        mock_prompt.ask.side_effect = ["/fullscan example.com", "/exit"]
        mock_asyncio.run.return_value = None
        repl()
        mock_asyncio.run.assert_called_once()

    @patch("auton.cli.asyncio")
    @patch("auton.cli.Prompt")
    @patch("auton.cli.print_banner")
    def test_single_scanner_dispatches(self, mock_banner, mock_prompt, mock_asyncio):
        mock_prompt.ask.side_effect = ["/sqli example.com", "/exit"]
        mock_asyncio.run.return_value = None
        repl()
        mock_asyncio.run.assert_called_once()

    @patch("auton.cli._run_recon")
    @patch("auton.cli.Prompt")
    @patch("auton.cli.print_banner")
    def test_wildcard_passes_through(self, mock_banner, mock_prompt, mock_recon):
        mock_prompt.ask.side_effect = ["/recon *.example.com", "/exit"]
        mock_recon.return_value = None
        repl()
        args = mock_recon.call_args[0]
        assert args[0] == "*.example.com"
        assert args[1] is True  # is_wildcard

    @patch("auton.cli.Prompt")
    @patch("auton.cli.print_banner")
    def test_non_slash_input_rejected(self, mock_banner, mock_prompt):
        mock_prompt.ask.side_effect = ["hello", "/exit"]
        repl()

    @patch("auton.cli._add_target_to_scope")
    @patch("auton.cli._resolve_targets")
    @patch("auton.cli._run_nmap_on_targets")
    @patch("auton.cli.Prompt")
    @patch("auton.cli.print_banner")
    def test_standalone_nmap(self, mock_banner, mock_prompt, mock_nmap,
                             mock_resolve, mock_scope):
        mock_prompt.ask.side_effect = ["/nmap example.com", "/exit"]
        mock_resolve.return_value = ["example.com"]
        repl()
        mock_nmap.assert_called_once()
