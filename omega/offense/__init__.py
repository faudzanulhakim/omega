"""Compatibility alias: real module is omega.offensive.offense."""
import sys as _sys
from omega.offensive.offense import *  # noqa: F401,F403
_m = __import__("omega.offensive.offense", fromlist=["__trash__"])
_sys.modules[__name__] = _m
