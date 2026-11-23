"""Compatibility alias: real module is omega.core.intent."""
import sys as _sys
from omega.core.intent import *  # noqa: F401,F403
_m = __import__("omega.core.intent", fromlist=["__trash__"])
_sys.modules[__name__] = _m
