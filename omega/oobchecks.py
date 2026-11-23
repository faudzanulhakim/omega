"""Compatibility alias: real module is omega.core.oobchecks."""
import sys as _sys
from omega.core.oobchecks import *  # noqa: F401,F403
_m = __import__("omega.core.oobchecks", fromlist=["__trash__"])
_sys.modules[__name__] = _m
