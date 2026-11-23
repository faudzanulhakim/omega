"""Compatibility alias: real module is omega.scanning.subperm."""
import sys as _sys
from omega.scanning.subperm import *  # noqa: F401,F403
_m = __import__("omega.scanning.subperm", fromlist=["__trash__"])
_sys.modules[__name__] = _m
