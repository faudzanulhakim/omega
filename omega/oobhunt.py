"""Compatibility alias: real module is omega.scanning.oobhunt."""
import sys as _sys
from omega.scanning.oobhunt import *  # noqa: F401,F403
_m = __import__("omega.scanning.oobhunt", fromlist=["__trash__"])
_sys.modules[__name__] = _m
