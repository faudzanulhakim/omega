"""Compatibility alias: real module is omega.core.watch."""
import sys as _sys
from omega.core.watch import *  # noqa: F401,F403
_m = __import__("omega.core.watch", fromlist=["__trash__"])
_sys.modules[__name__] = _m
