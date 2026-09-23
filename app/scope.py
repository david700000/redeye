"""
Scope management. This is the single gate every scan (and, later, every
exploitation action) has to pass through. Keep it boring and strict.
"""

from urllib.parse import urlparse
from .config import DEFAULT_LAB_SCOPE

# In-memory for now — swap for a persisted table keyed by user/org
# when auth lands. Shape matches the frontend's ScopeManager exactly:
# a flat list of hostnames/IPs, no ports, no schemes.
_scope: list[str] = list(DEFAULT_LAB_SCOPE)


def host_of(target: str) -> str:
    """Extract a bare hostname from a URL or host:port string."""
    target = target.strip()
    if "://" not in target:
        target = "http://" + target
    parsed = urlparse(target)
    return parsed.hostname or ""


def get_scope() -> list[str]:
    return list(_scope)


def add_to_scope(host: str) -> list[str]:
    host = host_of(host) or host.strip()
    if host and host not in _scope:
        _scope.append(host)
    return get_scope()


def remove_from_scope(host: str) -> list[str]:
    global _scope
    _scope = [h for h in _scope if h != host]
    return get_scope()


def is_in_scope(target: str) -> bool:
    host = host_of(target)
    if not host:
        return False
    return any(host == s or host.endswith("." + s) for s in _scope)
