"""Compatibility alias: real module is omega.scanning.k8ssec."""
import sys as _sys
from omega.scanning.k8ssec import *  # noqa: F401,F403
_m = __import__("omega.scanning.k8ssec", fromlist=["__trash__"])
_sys.modules[__name__] = _m
