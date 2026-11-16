"""Compatibility alias: real module is omega.scanning.ssti."""
import sys as _sys
from omega.scanning.ssti import *  # noqa: F401,F403
_m = __import__("omega.scanning.ssti", fromlist=["__trash__"])
_sys.modules[__name__] = _m
