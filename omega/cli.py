"""Compatibility alias: real module is omega.core.cli."""
import sys as _sys
from omega.core.cli import *  # noqa: F401,F403
_m = __import__("omega.core.cli", fromlist=["__trash__"])
_sys.modules[__name__] = _m
