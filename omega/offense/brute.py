"""Compatibility alias: real module is omega.offensive.offense.brute."""
import sys as _sys
from omega.offensive.offense.brute import *  # noqa: F401,F403
_m = __import__("omega.offensive.offense.brute", fromlist=["__trash__"])
_sys.modules[__name__] = _m
