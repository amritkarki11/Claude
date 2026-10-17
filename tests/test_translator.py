"""Tests for auton/core/translator.py and the hybrid router."""
import pytest
from unittest.mock import patch, MagicMock

from auton.core.translator import translate_to_command, _validate_command, _looks_like_valid_target
from auton.router.parser import route_input


class TestValidateCommand:
    def test_valid_recon(self):
        assert _validate_command("/recon example.com") == "/recon example.com"

    def test_valid_fullscan(self):
        assert _validate_command("/fullscan example.com") == "/fullscan example.com"

    def test_valid_commands(self):
        assert _validate_command("/commands") == "/commands"

    def test_valid_exit(self):
        assert _validate_command("/exit") == "/exit"

    def test_valid_analyze(self):
        assert _validate_command("/analyze report.json") == "/analyze report.json"

    def test_valid_with_flag(self):
        assert _validate_command("/recon /allports example.com") == "/recon /allports example.com"

    def test_invalid_no_slash(self):
        assert _validate_command("scan example.com") is None

    def test_invalid_unknown_command(self):
        assert _validate_command("/hackthis example.com") is None

    def test_strips_whitespace(self):
        assert _validate_command("  /recon example.com  ") == "/recon example.com"

    def test_multiline_picks_valid(self):
        raw = "Here is the command:\n/fullscan target.com\n"
        assert _validate_command(raw) == "/fullscan target.com"

    def test_empty(self):
        assert _validate_command("") is None

    def test_markdown_garbage(self):
        assert _validate_command("```\nsome code\n```") is None

    def test_recon_with_invalid_target_rejected(self):
        assert _validate_command("/recon root") is None

    def test_recon_with_bare_word_rejected(self):
        assert _validate_command("/recon user") is None

    def test_fullscan_needs_valid_target(self):
        assert _validate_command("/fullscan localhost") is None

    def test_commands_no_target_needed(self):
        assert _validate_command("/commands") == "/commands"


class TestLooksLikeValidTarget:
    def test_domain(self):
        assert _looks_like_valid_target("example.com") is True

    def test_ip(self):
        assert _looks_like_valid_target("192.168.1.1") is True

    def test_bare_word(self):
        assert _looks_like_valid_target("root") is False

    def test_reserved_words(self):
        for word in ("root", "user", "admin", "test", "localhost", "self"):
            assert _looks_like_valid_target(word) is False

    def test_empty(self):
        assert _looks_like_valid_target("") is False


class TestRouteInput:
    def test_slash_command_passthrough(self):
        assert route_input("/recon example.com") == "/recon example.com"

    def test_slash_exit_passthrough(self):
        assert route_input("/exit") == "/exit"

    def test_empty_input(self):
        assert route_input("") == ""

    def test_whitespace_only(self):
        assert route_input("   ") == ""

    @patch("auton.core.translator.translate_to_command")
    def test_natural_language_calls_translator(self, mock_translate):
        mock_translate.return_value = "/recon example.com"
        result = route_input("scan example.com for me")
        mock_translate.assert_called_once_with("scan example.com for me")
        assert result == "/recon example.com"

    @patch("auton.core.translator.translate_to_command")
    def test_translator_failure_returns_empty(self, mock_translate):
        mock_translate.return_value = ""
        result = route_input("do something weird")
        assert result == ""


class TestTranslateToCommand:
    @patch("auton.core.translator.httpx.post")
    def test_successful_translation(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"response": "/recon example.com"}
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp

        result = translate_to_command("scan example.com")
        assert result == "/recon example.com"

    @patch("auton.core.translator.httpx.post")
    def test_invalid_llm_output(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"response": "Sure, I'll scan that for you!"}
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp

        result = translate_to_command("scan example.com")
        assert result == ""

    @patch("auton.core.translator.httpx.post")
    def test_hallucinated_command_rejected(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"response": "/exploit example.com"}
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp

        result = translate_to_command("hack example.com")
        assert result == ""

    @patch("auton.core.translator.httpx.post")
    def test_connection_error(self, mock_post):
        import httpx
        mock_post.side_effect = httpx.ConnectError("connection refused")

        result = translate_to_command("scan example.com")
        assert result == ""

    @patch("auton.core.translator.httpx.post")
    def test_timeout(self, mock_post):
        import httpx
        mock_post.side_effect = httpx.ReadTimeout("timed out")

        result = translate_to_command("scan example.com")
        assert result == ""
