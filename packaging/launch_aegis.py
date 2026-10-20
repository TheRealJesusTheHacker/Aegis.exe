"""PyInstaller entry point for Aegis.exe.

Kept outside the ``aegis`` package so PyInstaller's analysis
starts from a plain script (the same pattern as the rest of the
medic kit's portable builds). This file is the packaged app's
front door, not a way to run a source checkout — from a checkout,
run ``python -m aegis.ui`` instead.

Routing is deliberately small:

- No arguments (a person double-clicking the app) opens the
  Aegis window.
- ``--self-check`` builds the whole window offscreen and reports
  success — the release workflow's launch smoke test, so a build
  that cannot open its own window fails there, not on a person's
  machine.
- ``--version`` prints the version and exits.
- ``--install`` / ``--uninstall`` put the packaged copy in place
  (or remove it) using :mod:`packaging.install`-equivalent code
  bundled beside this script as ``install.py``; installing is an
  offer, never a gate — the app runs the same without it.
"""

import sys

if __name__ == "__main__":
    argv = sys.argv[1:]
    if "--self-check" in argv:
        from aegis.ui import self_check

        sys.exit(self_check())
    if "--install" in argv or "--uninstall" in argv:
        import os
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import install as _install

        if "--install" in argv:
            ok, message = _install.install(
                os.path.dirname(os.path.abspath(sys.executable))
                if getattr(sys, "frozen", False)
                else os.path.dirname(os.path.abspath(__file__))
            )
        else:
            ok, message = _install.uninstall()
        print(message)
        sys.exit(0 if ok else 1)
    if "--version" in argv:
        import aegis

        print("Aegis %s" % aegis.__version__)
        sys.exit(0)
    from aegis.ui import run

    sys.exit(run())
