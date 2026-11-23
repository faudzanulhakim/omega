"""Compatibility alias: real module is omega.scanning.racecheck."""
import sys as _sys
from omega.scanning.racecheck import *  # noqa: F401,F403
_m = __import__("omega.scanning.racecheck", fromlist=["__trash__"])
_sys.modules[__name__] = _m
