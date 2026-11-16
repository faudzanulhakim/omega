"""Compatibility alias: real module is omega.scanning.dsl."""
import sys as _sys
from omega.scanning.dsl import *  # noqa: F401,F403
_m = __import__("omega.scanning.dsl", fromlist=["__trash__"])
_sys.modules[__name__] = _m
