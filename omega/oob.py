"""Compatibility alias: real module is omega.core.oob."""
import sys as _sys
from omega.core.oob import *  # noqa: F401,F403
_m = __import__("omega.core.oob", fromlist=["__trash__"])
_sys.modules[__name__] = _m
