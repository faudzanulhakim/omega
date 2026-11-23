"""Compatibility alias: real module is omega.scanning.fusion."""
import sys as _sys
from omega.scanning.fusion import *  # noqa: F401,F403
_m = __import__("omega.scanning.fusion", fromlist=["__trash__"])
_sys.modules[__name__] = _m
