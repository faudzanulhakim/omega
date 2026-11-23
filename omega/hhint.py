"""Compatibility alias: real module is omega.scanning.hhint."""
import sys as _sys
from omega.scanning.hhint import *  # noqa: F401,F403
_m = __import__("omega.scanning.hhint", fromlist=["__trash__"])
_sys.modules[__name__] = _m
