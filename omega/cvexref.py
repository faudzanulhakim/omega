"""Compatibility alias: real module is omega.scanning.cvexref."""
import sys as _sys
from omega.scanning.cvexref import *  # noqa: F401,F403
_m = __import__("omega.scanning.cvexref", fromlist=["__trash__"])
_sys.modules[__name__] = _m
