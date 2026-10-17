"""Hard scope guard. Nothing gets probed for a host not on the allowlist.
Call check() before every outbound request the agent makes.

The allowlist has two layers:
  - _CONFIG_ALLOWED: the base allowlist from config.yaml (static, loaded once).
  - ALLOWED: the EFFECTIVE allowlist for this run = config hosts plus
    whatever is added at runtime via set_scope()/add_to_scope() (e.g. from
    CLI flags). ALLOWED is mutated in place (never reassigned) so existing
    `from agent.scope import ALLOWED` imports stay live after a runtime
    change.

Supports wildcards (*.example.com) and CIDR notation (10.0.0.0/24).

Fail closed: if ALLOWED ends up empty (no config hosts, no runtime hosts),
check() refuses every target instead of silently allowing anything.
"""
from urllib.parse import urlparse
import fnmatch
import ipaddress
import pathlib
import yaml

_CFG = yaml.safe_load((pathlib.Path(__file__).parent.parent / "config.yaml").read_text())
_CONFIG_ALLOWED = {h.lower() for h in (_CFG.get("scope", {}).get("allowed_hosts") or [])}

# Effective allowlist for this run. Starts as a copy of the config allowlist;
# set_scope()/add_to_scope() mutate it in place.
ALLOWED = set(_CONFIG_ALLOWED)


class ScopeError(Exception):
    """Raised when a target falls outside the authorized allowlist."""


def host_of(target: str) -> str:
    # Normalize backslashes to forward slashes to prevent parser confusion
    target = target.replace("\\", "/")
    p = urlparse(target if "//" in target else f"//{target}")
    return (p.hostname or "").lower()


def set_scope(hosts) -> None:
    """Set the runtime allowlist for this run to exactly `hosts`, plus
    whatever config.yaml already allows. Replaces any previously-set
    runtime hosts (config hosts are never dropped by this call).
    """
    ALLOWED.clear()
    ALLOWED.update(_CONFIG_ALLOWED)
    ALLOWED.update(h.lower() for h in hosts or [] if h)


def add_to_scope(host: str) -> None:
    """Add a single host to the current runtime allowlist without
    disturbing anything already set (e.g. for --target)."""
    if host:
        ALLOWED.add(host.lower())


def _host_matches_allowed(h: str, port: int | None = None) -> bool:
    """Check if host (with optional port) matches any entry in ALLOWED.

    Handles exact match, wildcard patterns (*.example.com), and CIDR ranges.
    """
    # Exact match (fastest path)
    if h in ALLOWED:
        return True
    if port is not None:
        if f"{h}:{port}" in ALLOWED:
            return True

    for entry in ALLOWED:
        # Wildcard match
        if "*" in entry:
            if fnmatch.fnmatch(h, entry):
                return True
            continue
        # CIDR match
        if "/" in entry:
            try:
                net = ipaddress.ip_network(entry, strict=False)
                addr = ipaddress.ip_address(h)
                if addr in net:
                    return True
            except ValueError:
                continue

    return False


def in_scope(target: str) -> bool:
    h = host_of(target)
    return _host_matches_allowed(h)


def check(target: str) -> str:
    """Return target if authorized, else raise ScopeError. Fail closed:
    an empty allowlist refuses everything, not just unmatched hosts."""
    if not ALLOWED:
        raise ScopeError(
            "OUT OF SCOPE: no allowlist configured — refusing to run. "
            "Set scope.allowed_hosts in config.yaml or pass --scope/--target."
        )

    # Only allow http and https schemes
    normalized = target.replace("\\", "/")
    parsed = urlparse(normalized if "//" in normalized else f"//{normalized}")
    if parsed.scheme and parsed.scheme not in ("http", "https", ""):
        raise ScopeError(f"OUT OF SCOPE: scheme {parsed.scheme!r} not allowed (http/https only)")

    h = host_of(target)
    try:
        port = parsed.port
    except ValueError:
        raise ScopeError(f"OUT OF SCOPE: malformed URL {target!r}")

    if port is not None:
        host_with_port = f"{h}:{port}"
        # Check if host (with or without port) matches
        if not _host_matches_allowed(h, port):
            raise ScopeError(f"OUT OF SCOPE: {host_with_port!r} not in allowlist {sorted(ALLOWED)}")
        # Non-standard ports need explicit entry (exact, wildcard, or CIDR)
        if port not in (80, 443) and not _host_matches_allowed(h, port):
            raise ScopeError(f"OUT OF SCOPE: non-standard port {host_with_port!r} not in allowlist {sorted(ALLOWED)}")
    elif not _host_matches_allowed(h):
        raise ScopeError(f"OUT OF SCOPE: {h!r} not in allowlist {sorted(ALLOWED)}")

    return target


def set_scope_from_engagement(engagement: "Engagement") -> None:
    """Configure scope from an Engagement object."""
    hosts = engagement.all_hosts()
    set_scope(hosts)
