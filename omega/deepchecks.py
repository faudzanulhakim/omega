"""Compatibility alias: real module is omega.scanning.deepchecks."""
import sys as _sys
from omega.scanning.deepchecks import *  # noqa: F401,F403
_m = __import__("omega.scanning.deepchecks", fromlist=["__trash__"])
_sys.modules[__name__] = _m
