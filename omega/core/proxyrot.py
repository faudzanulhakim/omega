"""omega/core/proxyrot.py — proxy pool rotation for scan traffic.

Loads proxies from OMEGA_PROXY_FILE (one ``http://host:port`` per
line; ``#`` comments ignored) or the single OMEGA_PROXY env var, and
round-robins them per request. Used by deepchecks.default_fetch to
spread scan traffic across egress IPs — the answer to IP-based
lockouts (paired with the noise governor and brute lockout backoff).

HTTPS targets are NOT tunneled through the pool (CONNECT handling is
out of scope here): requests fall back to the direct path when a proxy
is assigned but the target is https. Never raises.
"""

from __future__ import annotations

import os
import threading
import urllib.parse

__all__ = ["ProxyPool", "get_pool", "assigned_proxy"]


class ProxyPool:
    """Round-robin proxy rotation, thread-safe, always non-raising."""

    def __init__(self, proxies=None):
        self._items = [p for p in (proxies or []) if self._valid(p)]
        self._lock = threading.Lock()
        self._idx = 0

    @staticmethod
    def _valid(p):
        try:
            u = urllib.parse.urlsplit(p if "://" in p else "http://" + p)
            return bool(u.hostname) and bool(u.port)
        except ValueError:
            return False

    def __len__(self):
        return len(self._items)

    def next(self):
        """Return the next proxy URL (http://host:port) or None."""
        if not self._items:
            return None
        with self._lock:
            p = self._items[self._idx % len(self._items)]
            self._idx += 1
            return p

    def next_parts(self):
        """Return (host, port) for the next proxy, or None."""
        p = self.next()
        if not p:
            return None
        u = urllib.parse.urlsplit(p if "://" in p else "http://" + p)
        return u.hostname, u.port


def load_from_env():
    """Build a ProxyPool from OMEGA_PROXY_FILE / OMEGA_PROXY."""
    items = []
    path = os.environ.get("OMEGA_PROXY_FILE")
    if path and os.path.isfile(path):
        try:
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        items.append(line)
        except OSError:
            pass
    single = os.environ.get("OMEGA_PROXY")
    if single:
        items.append(single)
    return ProxyPool(items)


_POOL = None


def get_pool():
    """Process-wide pool singleton (rebuilt when env changes)."""
    global _POOL
    if _POOL is None:
        _POOL = load_from_env()
    return _POOL


def reset_pool():
    """Force a rebuild (tests / env changes)."""
    global _POOL
    _POOL = None


def assigned_proxy(url):
    """Return (proxy_host, proxy_port, absolute_url) for a request, or
    None when no pool is configured or the target is https."""
    pool = get_pool()
    if not pool or len(pool) == 0:
        return None
    parts = urllib.parse.urlsplit(url)
    if parts.scheme == "https":
        return None
    nxt = pool.next_parts()
    if not nxt:
        return None
    absolute = "%s://%s%s" % (parts.scheme, parts.netloc,
                              parts.path or "/")
    if parts.query:
        absolute += "?" + parts.query
    return nxt[0], nxt[1], absolute
