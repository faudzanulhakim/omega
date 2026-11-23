"""Compatibility alias: real module is omega.reporting.report."""
import sys as _sys
from omega.reporting.report import *  # noqa: F401,F403
_m = __import__("omega.reporting.report", fromlist=["__trash__"])
_sys.modules[__name__] = _m
