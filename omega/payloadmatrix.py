"""Compatibility alias: real module is omega.scanning.payloadmatrix."""
import sys as _sys
from omega.scanning.payloadmatrix import *  # noqa: F401,F403
_m = __import__("omega.scanning.payloadmatrix", fromlist=["__trash__"])
_sys.modules[__name__] = _m
