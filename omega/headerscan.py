"""Compatibility alias: real module is omega.scanning.headerscan."""
import sys as _sys
from omega.scanning.headerscan import *  # noqa: F401,F403
_m = __import__("omega.scanning.headerscan", fromlist=["__trash__"])
_sys.modules[__name__] = _m
