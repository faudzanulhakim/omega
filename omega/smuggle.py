"""Compatibility alias: real module is omega.scanning.smuggle."""
import sys as _sys
from omega.scanning.smuggle import *  # noqa: F401,F403
_m = __import__("omega.scanning.smuggle", fromlist=["__trash__"])
_sys.modules[__name__] = _m
