"""Compatibility alias: real module is omega.scanning.oobscan."""
import sys as _sys
from omega.scanning.oobscan import *  # noqa: F401,F403
_m = __import__("omega.scanning.oobscan", fromlist=["__trash__"])
_sys.modules[__name__] = _m
