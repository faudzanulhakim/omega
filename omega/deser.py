"""Compatibility alias: real module is omega.scanning.deser."""
import sys as _sys
from omega.scanning.deser import *  # noqa: F401,F403
_m = __import__("omega.scanning.deser", fromlist=["__trash__"])
_sys.modules[__name__] = _m
