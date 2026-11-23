"""Compatibility alias: real module is omega.scanning.graphqldeep."""
import sys as _sys
from omega.scanning.graphqldeep import *  # noqa: F401,F403
_m = __import__("omega.scanning.graphqldeep", fromlist=["__trash__"])
_sys.modules[__name__] = _m
