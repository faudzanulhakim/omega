"""Compatibility alias: real module is omega.scanning.jsrender."""
import sys as _sys
from omega.scanning.jsrender import *  # noqa: F401,F403
_m = __import__("omega.scanning.jsrender", fromlist=["__trash__"])
_sys.modules[__name__] = _m
