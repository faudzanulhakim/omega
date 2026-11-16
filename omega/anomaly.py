"""Compatibility alias: real module is omega.scanning.anomaly."""
import sys as _sys
from omega.scanning.anomaly import *  # noqa: F401,F403
_m = __import__("omega.scanning.anomaly", fromlist=["__trash__"])
_sys.modules[__name__] = _m
