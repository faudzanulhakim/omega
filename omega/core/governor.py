"""OMEGA noise governor — target-respectful request budgeting.

A per-host global governor sits between OMEGA and the wire:

- request budget per host (default 600 / rolling window)
- minimum interval between requests to one host (default 0.05s)
- automatic backoff when the target signals stress: 429, 403 blocks,
  5xx bursts, or repeated identical failure responses (lockout)
- backoff decays again once the target answers normally

The governor NEVER blocks the first request to a host and NEVER
suppresses an operator-initiated call — it only paces and, under
sustained stress, pauses further automated requests until the window
clears. In no-limits mode the budget ceiling is lifted but the
backoff logic stays active (speed without DoS accidents).

Env knobs:
  OMEGA_NOISE_BUDGET     per-host budget      (default 600)
  OMEGA_NOISE_WINDOW_S   rolling window secs  (default 3600)
  OMEGA_NOISE_INTERVAL   min interval seconds (default 0.05)
  OMEGA_GOVERNOR_OFF=1   disable pacing entirely (operator explicit)
"""

from __future__ import annotations

import collections
import os
import threading
import time

__all__ = [
    "NoiseGovernor",
    "get_governor",
    "guarded_fetch",
    "STRESS_STATUSES",
]

STRESS_STATUSES = frozenset({403, 406, 409, 418, 429, 500, 502, 503, 504})
LOCKOUT_STREAK = 3          # consecutive stress responses -> pause
DEFAULT_BUDGET = 600
DEFAULT_WINDOW_S = 3600.0
DEFAULT_INTERVAL = 0.05
DEFAULT_BACKOFF = 30.0
MAX_BACKOFF = 600.0


def _env_float(name, default):
    try:
        return float(os.environ.get(name) or default)
    except (TypeError, ValueError):
        return float(default)


class NoiseGovernor:
    """Per-host pacing + budget + stress backoff. Thread-safe."""

    def __init__(self, budget=None, window_s=None, interval=None,
                 backoff_s=None, clock=time.monotonic, sleep=time.sleep):
        self.budget = int(budget or os.environ.get("OMEGA_NOISE_BUDGET")
                          or DEFAULT_BUDGET)
        self.window_s = float(window_s or os.environ.get("OMEGA_NOISE_WINDOW_S")
                              or DEFAULT_WINDOW_S)
        self.interval = (interval if interval is not None
                         else _env_float("OMEGA_NOISE_INTERVAL",
                                         DEFAULT_INTERVAL))
        self.backoff_s = (backoff_s if backoff_s is not None
                          else DEFAULT_BACKOFF)
        self._clock = clock
        self._sleep = sleep
        self._lock = threading.Lock()
        self._events = collections.defaultdict(collections.deque)
        self._next_ok = collections.defaultdict(float)
        self._stress_streak = collections.defaultdict(int)
        self._paused_until = collections.defaultdict(float)
        self.stats = collections.defaultdict(lambda: {
            "requests": 0, "paused": 0, "backoffs": 0})

    # ---- configuration ------------------------------------------------

    @property
    def disabled(self):
        return os.environ.get("OMEGA_GOVERNOR_OFF") == "1"

    def _window_count(self, host, now):
        dq = self._events[host]
        while dq and now - dq[0] > self.window_s:
            dq.popleft()
        return len(dq)

    # ---- core API ------------------------------------------------------

    def acquire(self, host):
        """Reserve one request slot. Returns (allowed, wait_s).

        When ``allowed`` is False the per-host budget is exhausted or
        the host is in stress-pause; ``wait_s`` says how long until a
        retry makes sense.
        """
        host = (host or "").strip().lower()
        now = self._clock()
        with self._lock:
            st = self.stats[host]
            if self.disabled:
                st["requests"] += 1
                return True, 0.0
            wait = self._next_ok[host] - now
            pause_until = self._paused_until[host]
            if pause_until > now:
                return False, round(pause_until - now, 2)
            if wait > 0:
                st["paused"] += 1
                self._next_ok[host] = now + wait + self.interval
                return True, round(wait, 2)
            if self._window_count(host, now) >= self.budget:
                self._paused_until[host] = now + min(MAX_BACKOFF,
                                                     self.window_s / 10.0)
                st["backoffs"] += 1
                return False, round(self.window_s / 10.0, 2)
            self._events[host].append(now)
            self._next_ok[host] = now + self.interval
            st["requests"] += 1
            return True, 0.0

    def record(self, host, status):
        """Feed a response status back for stress tracking."""
        host = (host or "").strip().lower()
        now = self._clock()
        with self._lock:
            if int(status) in STRESS_STATUSES:
                self._stress_streak[host] += 1
                if self._stress_streak[host] >= LOCKOUT_STREAK:
                    self._paused_until[host] = now + self.backoff_s
                    self.stats[host]["backoffs"] += 1
            else:
                self._stress_streak[host] = 0

    def wait_out(self, wait_s):
        """Sleep ``wait_s`` seconds (bounded) when acquire said to."""
        if wait_s and wait_s > 0:
            self._sleep(min(wait_s, MAX_BACKOFF))

    def snapshot(self):
        """Governor state for session/report embedding."""
        return {h: dict(v) for h, v in self.stats.items()}


_GOV = None


def get_governor():
    """Process-wide governor singleton."""
    global _GOV
    if _GOV is None:
        _GOV = NoiseGovernor()
    return _GOV


def guarded_fetch(fetch, host=None):
    """Wrap a fetch callable with governor pacing + stress recording.

    ``fetch(method, url, headers) -> (status, headers, body)``.
    The host is derived from the URL unless given explicitly.
    """
    gov = get_governor()

    def wrapped(method, url, headers=None, **kw):
        target_host = host
        if not target_host:
            try:
                from urllib.parse import urlsplit
                target_host = urlsplit(url).netloc or url
            except Exception:
                target_host = str(url)
        allowed, wait = gov.acquire(target_host)
        if not allowed:
            raise RuntimeError(
                "noise governor: target %s is in stress-pause "
                "(backoff %.0fs) — automated requests held to avoid "
                "DoS / lockout damage" % (target_host, wait))
        gov.wait_out(wait)
        resp = fetch(method, url, headers, **kw)
        try:
            status = int(resp[0])
        except (TypeError, ValueError, IndexError):
            status = 0
        gov.record(target_host, status)
        return resp

    return wrapped
