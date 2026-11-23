"""Compatibility alias: real module is omega.core.brain."""
import sys as _sys
from omega.core.brain import *  # noqa: F401,F403
_m = __import__("omega.core.brain", fromlist=["__trash__"])
_sys.modules[__name__] = _m
