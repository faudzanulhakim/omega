"""Compatibility alias: real module is omega.scanning.chaos."""
import sys as _sys
from omega.scanning.chaos import *  # noqa: F401,F403
_m = __import__("omega.scanning.chaos", fromlist=["__trash__"])
_sys.modules[__name__] = _m
