"""Compatibility alias: real module is omega.scanning.pytools."""
import sys as _sys
from omega.scanning.pytools import *  # noqa: F401,F403
_m = __import__("omega.scanning.pytools", fromlist=["__trash__"])
_sys.modules[__name__] = _m
