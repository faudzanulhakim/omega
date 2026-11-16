"""Compatibility alias: real module is omega.scanning.dbsec."""
import sys as _sys
from omega.scanning.dbsec import *  # noqa: F401,F403
_m = __import__("omega.scanning.dbsec", fromlist=["__trash__"])
_sys.modules[__name__] = _m
