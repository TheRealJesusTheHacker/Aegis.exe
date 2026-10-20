"""Run the Aegis interface: ``python -m aegis.ui``."""

import sys

from . import run, self_check

if __name__ == "__main__":
    if "--self-check" in sys.argv:
        sys.exit(self_check())
    sys.exit(run())
