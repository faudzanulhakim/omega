"""Compatibility alias: real module is omega.scanning.cicdsec."""
import sys as _sys
from omega.scanning.cicdsec import *  # noqa: F401,F403
_m = __import__("omega.scanning.cicdsec", fromlist=["__trash__"])
_sys.modules[__name__] = _m
