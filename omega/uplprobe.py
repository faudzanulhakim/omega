"""Compatibility alias: real module is omega.scanning.uplprobe."""
import sys as _sys
from omega.scanning.uplprobe import *  # noqa: F401,F403
_m = __import__("omega.scanning.uplprobe", fromlist=["__trash__"])
_sys.modules[__name__] = _m
