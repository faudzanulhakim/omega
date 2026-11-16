"""Compatibility alias: real module is omega.scanning.secops."""
import sys as _sys
from omega.scanning.secops import *  # noqa: F401,F403
_m = __import__("omega.scanning.secops", fromlist=["__trash__"])
_sys.modules[__name__] = _m
