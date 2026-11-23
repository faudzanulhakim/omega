"""Compatibility alias: real module is omega.scanning.redirects."""
import sys as _sys
from omega.scanning.redirects import *  # noqa: F401,F403
_m = __import__("omega.scanning.redirects", fromlist=["__trash__"])
_sys.modules[__name__] = _m
