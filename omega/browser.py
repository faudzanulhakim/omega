"""Compatibility alias: real module is omega.core.browser."""
import sys as _sys
from omega.core.browser import *  # noqa: F401,F403
_m = __import__("omega.core.browser", fromlist=["__trash__"])
_sys.modules[__name__] = _m
