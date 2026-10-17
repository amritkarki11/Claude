"""Engagement model — dual-mode configuration for Bug Bounty vs Client VAPT.

Bug Bounty mode: precision-first, dedupe findings, platform-export ready.
VAPT mode: completeness-first, compliance mapping, full evidence chain.

Usage:
    eng = Engagement.bug_bounty(targets=["*.example.com"])
    eng = Engagement.vapt(targets=["10.0.0.0/24"], client="Acme Corp")
"""
from __future__ import annotations

import ipaddress
import fnmatch
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from urllib.parse import urlparse


class EngagementMode(Enum):
    BUG_BOUNTY = "bug_bounty"
    VAPT = "vapt"


@dataclass(frozen=True)
class TargetSpec:
    """A single target specification — can be a URL, wildcard domain, or CIDR.

    Examples:
        TargetSpec("https://example.com")
        TargetSpec("*.example.com")
        TargetSpec("10.0.0.0/24")
        TargetSpec("192.168.1.1")
    """
    raw: str
    _kind: str = field(init=False, repr=False)
    _parsed: Any = field(init=False, repr=False)

    def __post_init__(self):
        kind, parsed = self._classify(self.raw)
        object.__setattr__(self, "_kind", kind)
        object.__setattr__(self, "_parsed", parsed)

    @staticmethod
    def _classify(raw: str) -> tuple[str, Any]:
        stripped = raw.strip()
        # CIDR notation
        if "/" in stripped and not stripped.startswith("http"):
            try:
                net = ipaddress.ip_network(stripped, strict=False)
                return ("cidr", net)
            except ValueError:
                pass
        # Bare IP
        try:
            addr = ipaddress.ip_address(stripped)
            return ("ip", addr)
        except ValueError:
            pass
        # Wildcard domain (e.g. *.example.com)
        if "*" in stripped and not stripped.startswith("http"):
            return ("wildcard", stripped.lower())
        # URL
        if "://" in stripped:
            parsed = urlparse(stripped)
            return ("url", parsed)
        # Plain hostname
        return ("host", stripped.lower())

    @property
    def kind(self) -> str:
        return self._kind

    def matches(self, target: str) -> bool:
        """Check if a URL/host/IP falls within this target spec."""
        target = target.strip()
        if self._kind == "url":
            return self._matches_url(target)
        if self._kind == "host":
            return self._matches_host(target)
        if self._kind == "wildcard":
            return self._matches_wildcard(target)
        if self._kind == "cidr":
            return self._matches_cidr(target)
        if self._kind == "ip":
            return self._matches_ip(target)
        return False

    def _extract_host(self, target: str) -> str:
        if "://" in target:
            return (urlparse(target).hostname or "").lower()
        return target.split(":")[0].split("/")[0].lower()

    def _matches_url(self, target: str) -> bool:
        host = self._extract_host(target)
        parsed_host = (self._parsed.hostname or "").lower()
        return host == parsed_host

    def _matches_host(self, target: str) -> bool:
        host = self._extract_host(target)
        return host == self._parsed

    def _matches_wildcard(self, target: str) -> bool:
        host = self._extract_host(target)
        return fnmatch.fnmatch(host, self._parsed)

    def _matches_cidr(self, target: str) -> bool:
        host = self._extract_host(target)
        try:
            addr = ipaddress.ip_address(host)
            return addr in self._parsed
        except ValueError:
            return False

    def _matches_ip(self, target: str) -> bool:
        host = self._extract_host(target)
        try:
            return ipaddress.ip_address(host) == self._parsed
        except ValueError:
            return False

    def hosts(self) -> list[str]:
        """Return concrete hosts for scope registration.

        For CIDRs, returns the network string (scope must handle).
        For wildcards, returns the pattern (scope must handle).
        For URLs/hosts, returns the hostname.
        """
        if self._kind == "url":
            return [(self._parsed.hostname or "").lower()]
        if self._kind == "host":
            return [self._parsed]
        if self._kind == "wildcard":
            return [self._parsed]
        if self._kind == "cidr":
            return [str(self._parsed)]
        if self._kind == "ip":
            return [str(self._parsed)]
        return []


@dataclass
class Engagement:
    """Top-level engagement configuration."""
    mode: EngagementMode
    targets: list[TargetSpec]
    client: str = ""
    engagement_id: str = ""

    # Bug bounty specifics
    platform: str = ""  # hackerone, bugcrowd, intigriti, etc.
    program_scope: str = ""
    out_of_scope: list[TargetSpec] = field(default_factory=list)
    reward_range: str = ""

    # VAPT specifics
    compliance_frameworks: list[str] = field(default_factory=list)
    rules_of_engagement: str = ""
    testing_window: str = ""
    emergency_contact: str = ""

    # Shared tuning
    max_concurrency: int = 10
    verify_replays: int = 3
    stealth: bool = False

    @classmethod
    def bug_bounty(
        cls,
        targets: list[str],
        platform: str = "",
        out_of_scope: list[str] | None = None,
        **kwargs: Any,
    ) -> Engagement:
        return cls(
            mode=EngagementMode.BUG_BOUNTY,
            targets=[TargetSpec(t) for t in targets],
            platform=platform,
            out_of_scope=[TargetSpec(t) for t in (out_of_scope or [])],
            stealth=True,
            **kwargs,
        )

    @classmethod
    def vapt(
        cls,
        targets: list[str],
        client: str = "",
        compliance: list[str] | None = None,
        **kwargs: Any,
    ) -> Engagement:
        return cls(
            mode=EngagementMode.VAPT,
            targets=[TargetSpec(t) for t in targets],
            client=client,
            compliance_frameworks=compliance or [],
            verify_replays=kwargs.pop("verify_replays", 5),
            **kwargs,
        )

    def is_in_scope(self, target: str) -> bool:
        """Check if a target URL/host is in scope for this engagement."""
        for oos in self.out_of_scope:
            if oos.matches(target):
                return False
        return any(ts.matches(target) for ts in self.targets)

    def all_hosts(self) -> list[str]:
        """Collect all concrete hosts for scope registration."""
        hosts = []
        for ts in self.targets:
            hosts.extend(ts.hosts())
        return hosts

    @property
    def is_bug_bounty(self) -> bool:
        return self.mode == EngagementMode.BUG_BOUNTY

    @property
    def is_vapt(self) -> bool:
        return self.mode == EngagementMode.VAPT
