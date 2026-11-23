"""Compatibility alias: real module is omega.scanning.cloudsec."""
import sys as _sys
from omega.scanning.cloudsec import *  # noqa: F401,F403
_m = __import__("omega.scanning.cloudsec", fromlist=["__trash__"])
_sys.modules[__name__] = _m
