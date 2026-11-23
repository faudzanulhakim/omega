"""Compatibility alias: real module is omega.scanning.pytools_scan."""
import sys as _sys
from omega.scanning.pytools_scan import *  # noqa: F401,F403
_m = __import__("omega.scanning.pytools_scan", fromlist=["__trash__"])
_sys.modules[__name__] = _m
