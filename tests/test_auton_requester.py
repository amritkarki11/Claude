"""Tests for auton/core/requester.py — WAF-evasion HTTP wrapper."""
import pytest
from unittest.mock import patch, MagicMock
import httpx

from auton.core.requester import Requester, RequesterConfig, _USER_AGENTS, _WAF_STATUS_CODES


class TestRequesterConfig:
    def test_defaults(self):
        cfg = RequesterConfig()
        assert cfg.jitter_min == 0.5
        assert cfg.jitter_max == 2.0
        assert cfg.waf_pause == 10.0
        assert cfg.max_retries == 3
        assert cfg.timeout == 15.0
        assert cfg.verify_ssl is True

    def test_custom(self):
        cfg = RequesterConfig(jitter_min=0.0, jitter_max=0.0, max_retries=1)
        assert cfg.jitter_min == 0.0
        assert cfg.max_retries == 1


class TestRequester:
    def _fast_config(self) -> RequesterConfig:
        return RequesterConfig(jitter_min=0.0, jitter_max=0.0, waf_pause=0.0, max_retries=2)

    def test_ua_rotation(self):
        req = Requester(config=self._fast_config())
        first = req.current_ua
        req._rotate_ua()
        second = req.current_ua
        assert first != second
        assert second in _USER_AGENTS

    def test_merge_headers_default(self):
        req = Requester(config=self._fast_config())
        merged = req._merge_headers(None)
        assert "User-Agent" in merged
        assert merged["User-Agent"] in _USER_AGENTS

    def test_merge_headers_custom(self):
        req = Requester(config=self._fast_config())
        merged = req._merge_headers({"X-Custom": "val"})
        assert merged["X-Custom"] == "val"
        assert "User-Agent" in merged

    def test_merge_headers_override_ua(self):
        req = Requester(config=self._fast_config())
        merged = req._merge_headers({"User-Agent": "MyBot/1.0"})
        assert merged["User-Agent"] == "MyBot/1.0"

    @patch("auton.core.requester.httpx.Client")
    def test_get_success(self, mock_client_cls):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_client_cls.return_value.request.return_value = mock_resp

        req = Requester(config=self._fast_config())
        resp = req.get("https://example.com")
        assert resp.status_code == 200

    @patch("auton.core.requester.httpx.Client")
    def test_waf_retry_rotates_ua(self, mock_client_cls):
        waf_resp = MagicMock()
        waf_resp.status_code = 403
        ok_resp = MagicMock()
        ok_resp.status_code = 200

        mock_client_cls.return_value.request.side_effect = [waf_resp, ok_resp]

        req = Requester(config=self._fast_config())
        resp = req.get("https://example.com")
        assert resp.status_code == 200
        assert mock_client_cls.return_value.request.call_count == 2

    @patch("auton.core.requester.httpx.Client")
    def test_waf_exhausts_retries(self, mock_client_cls):
        waf_resp = MagicMock()
        waf_resp.status_code = 429

        mock_client_cls.return_value.request.return_value = waf_resp

        cfg = self._fast_config()
        req = Requester(config=cfg)
        resp = req.get("https://example.com")
        assert resp.status_code == 429
        assert mock_client_cls.return_value.request.call_count == cfg.max_retries + 1

    def test_context_manager(self):
        cfg = self._fast_config()
        with Requester(config=cfg) as req:
            assert req is not None

    def test_user_agents_list_not_empty(self):
        assert len(_USER_AGENTS) >= 5

    def test_waf_status_codes(self):
        assert 403 in _WAF_STATUS_CODES
        assert 429 in _WAF_STATUS_CODES
        assert 503 in _WAF_STATUS_CODES
        assert 200 not in _WAF_STATUS_CODES
