"""Build AegisPortable.zip from a one-folder PyInstaller build.

Usage: python tools/build_portable.py dist/Aegis AegisPortable.zip
The zip opens to ONE folder (Aegis/) holding the whole kit, plus
README-PORTABLE.txt at the top of that folder. Tests, fixtures,
keys, and vault files are refused, never shipped.
"""
import sys, zipfile
from pathlib import Path

FORBIDDEN_SUFFIXES = (".aegis", ".aegis-send", ".aegis-armored", ".key", ".pem")
FORBIDDEN_PARTS = {"tests", "fixtures", "__pycache__", "recovery-keys", "vaults"}

def build(source: Path, out: Path, readme: Path) -> None:
    files = [p for p in sorted(source.rglob("*")) if p.is_file()]
    assert files, "empty build folder"
    for p in files:
        rel = p.relative_to(source)
        assert not (set(rel.parts) & FORBIDDEN_PARTS), f"refusing to ship {rel}"
        assert not p.name.endswith(FORBIDDEN_SUFFIXES), f"refusing to ship {rel}"
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.write(readme, "Aegis/README-PORTABLE.txt")
        for p in files:
            z.write(p, str(Path("Aegis") / p.relative_to(source)))

if __name__ == "__main__":
    build(Path(sys.argv[1]), Path(sys.argv[2]), Path(__file__).parent.parent / "packaging" / "README-PORTABLE.txt")
    print("wrote", sys.argv[2])
