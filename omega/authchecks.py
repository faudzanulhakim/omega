"""Compatibility alias: real module is omega.core.authchecks."""
import sys as _sys
from omega.core.authchecks import *  # noqa: F401,F403
_m = __import__("omega.core.authchecks", fromlist=["__trash__"])
_sys.modules[__name__] = _m
