"""Compatibility alias: real module is omega.scanning.timing."""
import sys as _sys
from omega.scanning.timing import *  # noqa: F401,F403
_m = __import__("omega.scanning.timing", fromlist=["__trash__"])
_sys.modules[__name__] = _m
