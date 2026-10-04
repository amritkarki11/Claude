"""Hard scope guard. Nothing gets probed for a host not on the allowlist.
Call check() before every outbound request the agent makes."""
from urllib.parse import urlparse
import pathlib
import yaml

_CFG = yaml.safe_load((pathlib.Path(__file__).parent.parent / "config.yaml").read_text())
ALLOWED = {h.lower() for h in _CFG["scope"]["allowed_hosts"]}


class ScopeError(Exception):
    """Raised when a target falls outside the authorized allowlist."""


def host_of(target: str) -> str:
    p = urlparse(target if "//" in target else f"//{target}")
    return (p.hostname or "").lower()


def in_scope(target: str) -> bool:
    return host_of(target) in ALLOWED


def check(target: str) -> str:
    """Return target if authorized, else raise ScopeError. Fail closed."""
    h = host_of(target)
    if h not in ALLOWED:
        raise ScopeError(f"OUT OF SCOPE: {h!r} not in allowlist {sorted(ALLOWED)}")
    return target
