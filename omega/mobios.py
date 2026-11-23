"""Compatibility alias: real module is omega.scanning.mobios."""
import sys as _sys
from omega.scanning.mobios import *  # noqa: F401,F403
_m = __import__("omega.scanning.mobios", fromlist=["__trash__"])
_sys.modules[__name__] = _m
