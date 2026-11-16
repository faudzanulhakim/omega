"""Compatibility alias: real module is omega.core.auth."""
import sys as _sys
from omega.core.auth import *  # noqa: F401,F403
_m = __import__("omega.core.auth", fromlist=["__trash__"])
_sys.modules[__name__] = _m
