"""Compatibility alias: real module is omega.core.session."""
import sys as _sys
from omega.core.session import *  # noqa: F401,F403
_m = __import__("omega.core.session", fromlist=["__trash__"])
_sys.modules[__name__] = _m
