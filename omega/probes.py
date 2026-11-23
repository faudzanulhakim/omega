"""Compatibility alias: real module is omega.scanning.probes."""
import sys as _sys
from omega.scanning.probes import *  # noqa: F401,F403
_m = __import__("omega.scanning.probes", fromlist=["__trash__"])
_sys.modules[__name__] = _m
