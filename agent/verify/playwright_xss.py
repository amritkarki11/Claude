"""Playwright-based XSS verifier — uses a real browser to confirm JS execution.

This is the gold-standard XSS verification: inject the payload, open the URL
in Chromium, and check if a JavaScript dialog (alert/confirm/prompt) actually
fires. This eliminates false positives from reflected-but-not-executed payloads.

Requires: playwright (pip install playwright && playwright install chromium)
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

from ..scanners.base import Candidate
from .base import Verifier, VerifyResult, Verdict

logger = logging.getLogger(__name__)

# How long to wait for a dialog to fire (seconds)
_DIALOG_TIMEOUT = 5.0
# How long to wait for page to load (ms)
_PAGE_TIMEOUT = 15000


class PlaywrightXssVerifier(Verifier):
    """Verifies XSS by opening the payload URL in a headless browser.

    Confirmation: a JS dialog (alert/confirm/prompt) fires within the timeout.
    """

    def __init__(self, client=None, browser=None):
        """
        Args:
            client: HttpClient instance (passed by base class contract).
            browser: an existing Playwright Browser instance, or None to
                     launch one on demand.
        """
        if client is not None:
            super().__init__(client)
        self._browser = browser
        self._owns_browser = browser is None

    async def _verify(self, candidate: Candidate, replays: int = 1,
                      **context: Any) -> VerifyResult:
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            logger.warning(
                "Playwright not installed — falling back to passive verification. "
                "Install with: pip install playwright && playwright install chromium"
            )
            return self._passive_fallback(candidate)

        dialog_fired = False
        dialog_message = ""
        page_error = None

        try:
            pw = None
            browser = self._browser
            if browser is None:
                pw = await async_playwright().start()
                browser = await pw.chromium.launch(headless=True)

            page = await browser.new_page()

            # Set up dialog handler BEFORE navigating
            async def on_dialog(dialog):
                nonlocal dialog_fired, dialog_message
                dialog_fired = True
                dialog_message = dialog.message
                await dialog.dismiss()

            page.on("dialog", on_dialog)

            # Build the URL with the payload
            target_url = self._build_payload_url(candidate)

            # Navigate and wait
            try:
                await page.goto(target_url, timeout=_PAGE_TIMEOUT, wait_until="domcontentloaded")
            except Exception as e:
                page_error = str(e)

            # Wait a bit for any delayed JS execution
            await asyncio.sleep(_DIALOG_TIMEOUT)

            # Take a screenshot for evidence
            screenshot = None
            try:
                screenshot = await page.screenshot()
            except Exception:
                pass

            await page.close()

            if self._owns_browser and browser:
                await browser.close()
            if pw:
                await pw.stop()

            if dialog_fired:
                return VerifyResult(
                    candidate=candidate,
                    verdict=Verdict.CONFIRMED,
                    reason=f"Playwright confirmed: JS dialog fired with message '{dialog_message}'",
                    replays=1,
                    evidence={
                        "dialog_fired": True,
                        "dialog_message": dialog_message,
                        "verification": "playwright-browser",
                        "screenshot": screenshot is not None,
                    },
                )
            else:
                reason = "Playwright: no JS dialog fired — payload reflected but not executed"
                if page_error:
                    reason += f" (page error: {page_error})"
                return VerifyResult(
                    candidate=candidate,
                    verdict=Verdict.FALSE,
                    reason=reason,
                    replays=1,
                    evidence={
                        "dialog_fired": False,
                        "verification": "playwright-browser",
                        "page_error": page_error,
                    },
                )

        except Exception as exc:
            logger.error("Playwright verification failed: %s", exc)
            return self._passive_fallback(candidate)

    def _build_payload_url(self, candidate: Candidate) -> str:
        """Reconstruct the URL with the XSS payload for browser testing."""
        from urllib.parse import urlparse, urlencode, urlunparse, parse_qs

        req = candidate.request_data
        param = req.get("param", "")
        payload = req.get("payload", "")
        id_location = req.get("id_location", "query")
        siblings = req.get("siblings", req.get("sibling_fields", {}))

        if id_location == "query" and param and payload:
            parsed = urlparse(candidate.endpoint)
            params = dict(siblings) if siblings else {}
            params[param] = payload
            qs = urlencode(params)
            return urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, qs, parsed.fragment,
            ))

        # For body-based XSS, we can't easily test via URL navigation
        # Fall back to passive verification
        return candidate.endpoint

    def _passive_fallback(self, candidate: Candidate) -> VerifyResult:
        """Fallback when Playwright isn't available."""
        if candidate.confidence == "high":
            return VerifyResult(
                candidate=candidate,
                verdict=Verdict.NEEDS_HUMAN,
                reason="Passive check: payload reflected but browser verification unavailable",
                replays=0,
                evidence={"verification": "passive-fallback"},
            )
        return VerifyResult(
            candidate=candidate,
            verdict=Verdict.FALSE,
            reason="Low confidence without browser verification",
            replays=0,
            evidence={"verification": "passive-fallback"},
        )
