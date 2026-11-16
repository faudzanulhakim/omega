"""Compatibility alias: real module is omega.scanning.apimap."""
import sys as _sys
from omega.scanning.apimap import *  # noqa: F401,F403
_m = __import__("omega.scanning.apimap", fromlist=["__trash__"])
_sys.modules[__name__] = _m
