"""Compatibility alias: real module is omega.scanning.sentinel."""
import sys as _sys
from omega.scanning.sentinel import *  # noqa: F401,F403
_m = __import__("omega.scanning.sentinel", fromlist=["__trash__"])
_sys.modules[__name__] = _m
