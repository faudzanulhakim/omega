"""Compatibility alias: real module is omega.scanning.tfinger."""
import sys as _sys
from omega.scanning.tfinger import *  # noqa: F401,F403
_m = __import__("omega.scanning.tfinger", fromlist=["__trash__"])
_sys.modules[__name__] = _m
