"""Compatibility alias: real module is omega.scanning.mobgeneral."""
import sys as _sys
from omega.scanning.mobgeneral import *  # noqa: F401,F403
_m = __import__("omega.scanning.mobgeneral", fromlist=["__trash__"])
_sys.modules[__name__] = _m
