"""Brute force scanner — tests login forms for weak credentials and account lockout.

Detection chain:
  1. BASELINE    → send known-bad creds, record the failure response
  2. LOCKOUT     → send 100 wrong passwords, check if account gets locked
  3. BRUTEFORCE  → try common passwords (with valid one at end if provided)
  4. VERIFY      → confirm successful login by checking response differs from baseline

Account lockout is reported separately — if the account locks after N attempts,
that's a finding (missing lockout = vuln, lockout present = noted).
"""
from __future__ import annotations

import asyncio
import logging
import re
from typing import Any

from ..http import HttpClient, Session
from ..recipes.schema import Recipe
from .base import Scanner, Candidate

logger = logging.getLogger(__name__)

# ── Common weak passwords ─────────────────────────────────────

_COMMON_PASSWORDS = [
    "123456", "password", "12345678", "qwerty", "abc123",
    "monkey", "1234567", "letmein", "trustno1", "dragon",
    "baseball", "iloveyou", "master", "sunshine", "ashley",
    "bailey", "shadow", "123123", "654321", "superman",
    "qazwsx", "michael", "football", "password1", "password123",
    "batman", "login", "welcome", "admin", "admin123",
    "admin@123", "root", "toor", "pass", "test",
    "guest", "master", "changeme", "1234", "12345",
    "123456789", "1234567890", "0987654321", "abcdef",
    "111111", "000000", "666666", "888888", "999999",
    "passw0rd", "p@ssword", "P@ssw0rd", "Pa$$w0rd",
    "password!", "qwerty123", "qwerty1", "q1w2e3r4",
    "abc@123", "a]b@c#123", "test123", "test@123",
    "user", "user123", "user@123", "demo", "demo123",
    "sample", "manager", "oracle", "postgres", "mysql",
    "sa", "sysadmin", "tomcat", "cisco", "nginx",
    "ftp", "anonymous", "info", "support", "helpdesk",
    "operator", "backup", "monitor", "nagios", "jenkins",
    "hudson", "service", "default", "guest123", "temp",
    "temp123", "temporary", "public", "private", "secret",
    "access", "enable", "disabled", "web", "website",
    "www", "internet", "intranet", "network", "server",
    "computer", "laptop", "desktop", "mobile", "phone",
    "spring2024", "summer2024", "fall2024", "winter2024",
    "company", "company123", "corporate", "business",
    "office", "office365", "microsoft", "windows",
    "linux", "apple", "google", "amazon", "azure",
]

# Login success indicators
_SUCCESS_INDICATORS = [
    "welcome", "dashboard", "home", "profile", "account",
    "logout", "sign out", "signout", "log out", "my account",
    "session", "redirect", "success", "authenticated",
]

# Login failure indicators
_FAILURE_INDICATORS = [
    "invalid", "incorrect", "failed", "wrong", "error",
    "denied", "unauthorized", "bad credentials", "try again",
    "login failed", "authentication failed", "not found",
    "does not exist", "no account", "not recognized",
]

# Lockout indicators
_LOCKOUT_INDICATORS = [
    "locked", "lockout", "lock out", "too many attempts",
    "too many tries", "account disabled", "account suspended",
    "temporarily blocked", "try again later", "wait",
    "exceeded", "maximum attempts", "brute force",
    "captcha", "verify you are human", "rate limit",
]


class BruteforceScanner(Scanner):
    """Tests login forms for weak credentials and account lockout mechanism."""

    vuln_classes = ["brute-force", "weak-credentials", "account-lockout"]

    def __init__(self, client: HttpClient, session: Session):
        super().__init__(client)
        self.session = session

    async def _detect(self, target: str, recipe: Recipe, **context: Any) -> list[Candidate]:
        params = context.get("params", [])
        method = context.get("method", "POST")
        id_location = context.get("id_location", "body")
        injection_points = context.get("injection_points", [])

        # Only test POST login forms
        if method.upper() != "POST":
            return []

        # Find username and password fields
        username_field = None
        password_field = None
        siblings = {}

        if injection_points:
            for point in injection_points:
                pname = point["param"].lower()
                sib = point.get("sibling_fields", {})
                siblings.update(sib)
                if any(x in pname for x in ("user", "email", "login", "uid", "name", "account")):
                    username_field = point["param"]
                if any(x in pname for x in ("pass", "pwd", "secret", "key")):
                    password_field = point["param"]
        else:
            for p in params:
                pl = p.lower()
                if any(x in pl for x in ("user", "email", "login", "uid", "name", "account")):
                    username_field = p
                if any(x in pl for x in ("pass", "pwd", "secret", "key")):
                    password_field = p

        if not username_field or not password_field:
            return []

        # Get valid credentials from context if provided
        valid_username = context.get("valid_username", context.get("username", "admin"))
        valid_password = context.get("valid_password", context.get("password", ""))

        candidates = []

        # ── Step 1: BASELINE — get failure response signature ──
        baseline = await self._send_login(
            target, username_field, password_field,
            valid_username, "auton_invalid_pass_xyz123",
            method, id_location, siblings,
        )
        if baseline is None:
            return []

        baseline_status = baseline.status_code
        baseline_body = baseline.text[:5000].lower()
        baseline_len = len(baseline.text)
        baseline_has_failure = any(ind in baseline_body for ind in _FAILURE_INDICATORS)

        logger.info("Bruteforce baseline: status=%d, len=%d, has_failure=%s",
                     baseline_status, baseline_len, baseline_has_failure)

        # ── Step 2: LOCKOUT TEST — send many wrong passwords ──
        lockout_detected = False
        lockout_threshold = 0

        for i in range(1, 101):
            resp = await self._send_login(
                target, username_field, password_field,
                valid_username, f"lockout_test_pass_{i}",
                method, id_location, siblings,
            )
            if resp is None:
                continue

            resp_body = resp.text[:5000].lower()

            # Check for lockout indicators
            if any(ind in resp_body for ind in _LOCKOUT_INDICATORS):
                lockout_detected = True
                lockout_threshold = i
                logger.info("Account lockout detected after %d attempts", i)
                break

            # Check if response changed drastically (CAPTCHA, block page)
            if resp.status_code == 429 or resp.status_code == 403:
                lockout_detected = True
                lockout_threshold = i
                break

            # Small delay to avoid rate limiting false positives
            if i % 20 == 0:
                await asyncio.sleep(0.5)

        if not lockout_detected:
            # No lockout after 100 attempts — that's a finding
            candidates.append(self._make_candidate(
                recipe=recipe, endpoint=target, method=method,
                evidence={
                    "technique": "no-account-lockout",
                    "detail": (
                        f"No account lockout mechanism detected after 100 failed login attempts "
                        f"for user '{valid_username}'. Application is vulnerable to brute force attacks."
                    ),
                    "attempts": 100,
                    "lockout_detected": False,
                },
                confidence="high",
                request_data={
                    "param": password_field,
                    "username_field": username_field,
                    "username": valid_username,
                    "payload": "100 invalid passwords",
                    "technique": "no-account-lockout",
                    "id_location": id_location,
                    "sibling_fields": siblings,
                },
                response_data={
                    "status": baseline_status,
                    "body_snippet": "No lockout after 100 failed attempts",
                },
            ))
        else:
            # Lockout exists — log it but not as vuln unless threshold is very high
            logger.info("Account lockout exists (threshold=%d) — not vulnerable to brute force", lockout_threshold)
            if lockout_threshold > 20:
                candidates.append(self._make_candidate(
                    recipe=recipe, endpoint=target, method=method,
                    evidence={
                        "technique": "weak-lockout",
                        "detail": (
                            f"Account lockout triggers after {lockout_threshold} failed attempts. "
                            f"Threshold is too high — attacker can try {lockout_threshold} passwords before lockout."
                        ),
                        "attempts": lockout_threshold,
                        "lockout_detected": True,
                    },
                    confidence="medium",
                    request_data={
                        "param": password_field,
                        "username_field": username_field,
                        "username": valid_username,
                        "payload": f"{lockout_threshold} invalid passwords before lockout",
                        "technique": "weak-lockout",
                        "id_location": id_location,
                        "sibling_fields": siblings,
                    },
                    response_data={
                        "status": baseline_status,
                        "body_snippet": f"Lockout after {lockout_threshold} attempts",
                    },
                ))
            # If locked, wait before continuing (or skip bruteforce)
            return candidates

        # ── Step 3: BRUTEFORCE — try common passwords ──
        # Build password list: 100 common + valid password at end
        passwords = list(_COMMON_PASSWORDS[:99])
        if valid_password:
            passwords.append(valid_password)

        for pwd in passwords:
            resp = await self._send_login(
                target, username_field, password_field,
                valid_username, pwd,
                method, id_location, siblings,
            )
            if resp is None:
                continue

            resp_body = resp.text[:5000].lower()
            resp_len = len(resp.text)

            # Check if login succeeded
            is_success = False

            # Method 1: redirect after login
            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("location", "").lower()
                if any(ind in location for ind in ("dashboard", "home", "profile", "account", "welcome")):
                    is_success = True

            # Method 2: success indicators in body
            if any(ind in resp_body for ind in _SUCCESS_INDICATORS):
                if not any(ind in resp_body for ind in _FAILURE_INDICATORS):
                    is_success = True

            # Method 3: significant body length change
            if abs(resp_len - baseline_len) > 500 and not any(ind in resp_body for ind in _FAILURE_INDICATORS):
                is_success = True

            # Method 4: different status code from baseline
            if resp.status_code != baseline_status and resp.status_code < 400:
                is_success = True

            if is_success:
                candidates.append(self._make_candidate(
                    recipe=recipe, endpoint=target, method=method,
                    evidence={
                        "technique": "weak-credentials",
                        "detail": (
                            f"Login succeeded with weak credentials: "
                            f"{valid_username}:{pwd}"
                        ),
                        "username": valid_username,
                        "password": pwd,
                    },
                    confidence="high",
                    request_data={
                        "param": password_field,
                        "username_field": username_field,
                        "username": valid_username,
                        "payload": pwd,
                        "technique": "weak-credentials",
                        "id_location": id_location,
                        "sibling_fields": {**siblings, username_field: valid_username},
                    },
                    response_data={
                        "status": resp.status_code,
                        "body_snippet": resp.text[:300],
                    },
                ))
                break  # Found valid creds, stop

        return candidates

    async def _send_login(self, target, user_field, pass_field,
                          username, password, method, id_location, siblings):
        """Send a login request."""
        try:
            data = dict(siblings)
            data[user_field] = username
            data[pass_field] = password

            if id_location == "body":
                return await self.client.request(
                    method, target, session=self.session,
                    data=data,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    follow_redirects=False,
                )
            elif id_location == "json":
                return await self.client.request(
                    method, target, session=self.session,
                    json=data,
                    follow_redirects=False,
                )
            else:
                return await self.client.request(
                    method, target, session=self.session,
                    data=data,
                    follow_redirects=False,
                )
        except Exception as e:
            logger.debug("Login request failed: %s", e)
            return None
