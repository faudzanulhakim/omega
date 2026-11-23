"""Compatibility alias: real module is omega.scanning.mobandroid."""
import sys as _sys
from omega.scanning.mobandroid import *  # noqa: F401,F403
_m = __import__("omega.scanning.mobandroid", fromlist=["__trash__"])
_sys.modules[__name__] = _m
