"""Compatibility alias: real module is omega.offensive.offense.injection."""
import sys as _sys
from omega.offensive.offense.injection import *  # noqa: F401,F403
_m = __import__("omega.offensive.offense.injection", fromlist=["__trash__"])
_sys.modules[__name__] = _m
