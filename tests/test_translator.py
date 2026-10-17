"""Tests for auton/core/translator.py and the hybrid router."""
import pytest
from unittest.mock import patch, MagicMock

from auton.core.translator import translate, _extract_command, _looks_like_valid_target
from auton.router.parser import route_input


class TestExtractCommand:
    def test_valid_recon(self):
        assert _extract_command("/recon example.com") == "/recon example.com"

    def test_valid_fullscan(self):
        assert _extract_command("/fullscan example.com") == "/fullscan example.com"

    def test_valid_commands(self):
        assert _extract_command("/commands") == "/commands"

    def test_valid_exit(self):
        assert _extract_command("/exit") == "/exit"

    def test_valid_analyze(self):
        assert _extract_command("/analyze report.json") == "/analyze report.json"

    def test_valid_with_flag(self):
        assert _extract_command("/recon /allports example.com") == "/recon /allports example.com"

    def test_chat_response_returns_none(self):
        assert _extract_command("Hello! I'm AUTON, how can I help?") is None

    def test_invalid_unknown_command(self):
        assert _extract_command("/hackthis example.com") is None

    def test_multiline_picks_valid(self):
        raw = "Here is the command:\n/fullscan target.com\n"
        assert _extract_command(raw) == "/fullscan target.com"

    def test_empty(self):
        assert _extract_command("") is None

    def test_recon_with_invalid_target_rejected(self):
        assert _extract_command("/recon root") is None

    def test_recon_with_bare_word_rejected(self):
        assert _extract_command("/recon user") is None

    def test_fullscan_needs_valid_target(self):
        assert _extract_command("/fullscan localhost") is None

    def test_commands_no_target_needed(self):
        assert _extract_command("/commands") == "/commands"


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
        assert route_input("/recon example.com") == ("command", "/recon example.com")

    def test_slash_exit_passthrough(self):
        assert route_input("/exit") == ("command", "/exit")

    def test_empty_input(self):
        assert route_input("") == ("command", "")

    def test_whitespace_only(self):
        assert route_input("   ") == ("command", "")

    @patch("auton.core.translator.translate")
    def test_natural_language_calls_translator(self, mock_translate):
        mock_translate.return_value = ("command", "/recon example.com")
        result = route_input("scan example.com for me")
        mock_translate.assert_called_once_with("scan example.com for me")
        assert result == ("command", "/recon example.com")

    @patch("auton.core.translator.translate")
    def test_chat_response_passed_through(self, mock_translate):
        mock_translate.return_value = ("chat", "Hello! How can I help?")
        result = route_input("hey")
        assert result == ("chat", "Hello! How can I help?")


class TestTranslate:
    @patch("auton.core.translator.httpx.post")
    def test_command_translation(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"response": "/recon example.com"}
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp

        result = translate("scan example.com")
        assert result == ("command", "/recon example.com")

    @patch("auton.core.translator.httpx.post")
    def test_chat_response(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"response": "Hello! I'm AUTON. Type /commands to see what I can do."}
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp

        msg_type, content = translate("hey")
        assert msg_type == "chat"
        assert "AUTON" in content

    @patch("auton.core.translator.httpx.post")
    def test_hallucinated_command_becomes_chat(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"response": "/exploit example.com"}
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp

        msg_type, _ = translate("hack example.com")
        assert msg_type == "chat"

    @patch("auton.core.translator.httpx.post")
    def test_connection_error(self, mock_post):
        import httpx
        mock_post.side_effect = httpx.ConnectError("connection refused")

        msg_type, content = translate("scan example.com")
        assert msg_type == "error"
        assert "Ollama" in content

    @patch("auton.core.translator.httpx.post")
    def test_timeout(self, mock_post):
        import httpx
        mock_post.side_effect = httpx.ReadTimeout("timed out")

        msg_type, content = translate("scan example.com")
        assert msg_type == "error"
        assert "timed out" in content
