# PyInstaller spec for AEGIS.EXE — packaging PREP (Phase 4).
#
# The public release itself belongs to Phase 5, after the
# independent security audit gate passes; this spec exists now so
# the packaging is designed alongside the interface, in the kit's
# pattern, and so the launch smoke test (--self-check) can run
# against a real build before the gate.
#
# Build (from the repo root, on Windows):
#     pyinstaller packaging/Aegis.spec --noconfirm
# Output: dist/Aegis/  (a one-folder build: Aegis.exe plus its
# runtime libraries in the same folder)
#
# One-FOLDER, not one-file, on purpose: it matches the kit's
# portable pattern (the Phase 5 portable edition unzips anywhere
# and runs), starts faster, and shows its contents honestly —
# nothing is unpacked to a temp folder at launch.
#
# No console window: the app is the window. The launcher
# (packaging/launch_aegis.py) opens the interface with no
# arguments and handles --self-check / --version.
#
# PySide6 is bundled by PyInstaller's Qt hooks; the printing
# support the recovery sheet uses is part of the same Essentials
# set. The cryptography and argon2 backends are pulled by their
# own hooks. Aegis ships no data files: the theme is code, the
# palette is code, and the test fixtures are not part of the
# product — so datas is empty and that is correct, not an omission.

from pathlib import Path

# PyInstaller 6 does NOT inject the Windows version-info classes
# into the spec namespace — they must be imported explicitly, or
# the build dies with NameError the first time the spec runs
# (the lesson Argus and Charon both recorded). Import exactly the
# classes used below. The import needs pefile, which PyInstaller
# carries on Windows; where it is absent (a Linux smoke build of
# this spec), the build proceeds without the version resource
# rather than dying — the resource is a Windows artifact anyway.
try:
    from PyInstaller.utils.win32.versioninfo import (
        FixedFileInfo,
        StringFileInfo,
        StringStruct,
        StringTable,
        VSVersionInfo,
        VarFileInfo,
        VarStruct,
    )
except ImportError:
    VSVersionInfo = None

ROOT = Path(SPECPATH).parent

# Windows version resource for the exe: File Explorer, the task
# manager, and SmartScreen all read THIS — an exe with no version
# info looks anonymous. Version 0.5.0 matches aegis.__version__
# for this phase; Phase 5 keeps them from drifting at release.
version_info = None if VSVersionInfo is None else VSVersionInfo(
    ffi=FixedFileInfo(
        filevers=(0, 5, 0, 0),
        prodvers=(0, 5, 0, 0),
        mask=0x3F,
        flags=0x0,
        OS=0x40004,
        fileType=0x1,
        subtype=0x0,
        date=(0, 0),
    ),
    kids=[
        StringFileInfo(
            [
                StringTable(
                    "040904B0",
                    [
                        StringStruct("CompanyName", "Sentinel Safeguard LLC"),
                        StringStruct("FileDescription", "AEGIS.EXE — file vault and password manager"),
                        StringStruct("FileVersion", "0.5.0"),
                        StringStruct("InternalName", "Aegis"),
                        StringStruct("OriginalFilename", "Aegis.exe"),
                        StringStruct("ProductName", "AEGIS.EXE"),
                        StringStruct("ProductVersion", "0.5.0"),
                    ],
                )
            ]
        ),
        VarFileInfo([VarStruct("Translation", [0x0409, 1200])]),
    ],
)

a = Analysis(
    [str(ROOT / "packaging" / "launch_aegis.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="Aegis",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    # A crash in the windowed build must never paint a raw
    # traceback (paths, internals) on the person's screen;
    # debugging belongs to the development build.
    disable_windowed_traceback=True,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version=version_info,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="Aegis",
)
