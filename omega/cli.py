"""Compatibility alias: real module is omega.core.cli."""
import sys as _sys
from omega.core.cli import *  # noqa: F401,F403
_m = __import__("omega.core.cli", fromlist=["__trash__"])
_sys.modules[__name__] = _m

if __name__ == "__main__":
    # python -m omega.cli must run the CLI (the sys.modules swap above
    # replaces the alias module, but runpy still executes THIS file).
    import sys as _cli_sys
    _cli_sys.exit(_m.main())
