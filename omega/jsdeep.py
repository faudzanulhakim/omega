"""Compatibility alias: real module is omega.scanning.jsdeep."""
import sys as _sys
from omega.scanning.jsdeep import *  # noqa: F401,F403
_m = __import__("omega.scanning.jsdeep", fromlist=["__trash__"])
_sys.modules[__name__] = _m
