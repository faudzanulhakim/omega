"""Compatibility alias: real module is omega.offensive.offense.payloadgen."""
import sys as _sys
from omega.offensive.offense.payloadgen import *  # noqa: F401,F403
_m = __import__("omega.offensive.offense.payloadgen", fromlist=["__trash__"])
_sys.modules[__name__] = _m
