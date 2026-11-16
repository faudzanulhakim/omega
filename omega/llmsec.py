"""Compatibility alias: real module is omega.scanning.llmsec."""
import sys as _sys
from omega.scanning.llmsec import *  # noqa: F401,F403
_m = __import__("omega.scanning.llmsec", fromlist=["__trash__"])
_sys.modules[__name__] = _m
