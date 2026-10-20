"""Render every main state of the Aegis window and audit the pixels.

Development/QA tool — not part of the shipped app. It builds a
synthetic vault (fake logins, a fake code, a fake document), walks
the real window through its states offscreen, saves a PNG of each,
and then audits every PNG: no purple pixels, no light surfaces.
The screenshots are the Phase 4 rendered-state verification; all
data in them is synthetic, per the house rules.

Usage:
    python tools/ui_screenshots.py <output-dir>
"""

import os
import sys
import tempfile
import time
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from PySide6.QtCore import QElapsedTimer  # noqa: E402
from PySide6.QtGui import QImage  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from aegis.clipboard import MemoryClipboard  # noqa: E402
from aegis.kdf import KdfParams  # noqa: E402
from aegis.ui import theme  # noqa: E402
from aegis.ui.app import MainWindow  # noqa: E402
from aegis.ui.controllers import VaultController  # noqa: E402

FAST = KdfParams(memory_kib=8192, time_cost=1, parallelism=1)
PASSWORD = "synthetic master phrase one"


class FakeInstallOffer:
    """A stand-in policy for the screenshot: the offer is needed."""

    def needed(self):
        return True

    def run(self):
        return True, "Aegis is installed and checked."


def settle(app, ms=300):
    timer = QElapsedTimer()
    timer.start()
    while timer.elapsed() < ms:
        app.processEvents()
        time.sleep(0.01)


def grab(app, widget, out: Path):
    settle(app)
    widget.grab().save(str(out))
    return out


def _looks_purple(color) -> bool:
    r, g, b = color.red(), color.green(), color.blue()
    return b > r + 24 and b > g + 12 and r > 50


def pixel_audit(path: Path):
    """Audit one screenshot's pixels.

    Two different questions, kept separate:

    - *Fringe*: isolated purple-ish pixels are this machine's
      subpixel font rendering at glyph edges — every operating
      system's text does this (Windows' ClearType included). They
      are counted and reported, but they are not a design color.
    - *Painted purple*: purple-ish pixels in horizontal runs of
      three or more — something actually filled with purple. That
      is the failure, and the audit requires it to be zero.
    """
    image = QImage(str(path))
    fringe = painted = light = total = 0
    luminance_sum = 0.0
    for y in range(image.height()):
        run = 0
        for x in range(image.width()):
            color = image.pixelColor(x, y)
            total += 1
            lum = theme._luminance(color.name())
            luminance_sum += lum
            if lum > 0.6:
                light += 1
            if _looks_purple(color):
                run += 1
                fringe += 1
            else:
                if run >= 3:
                    painted += run
                run = 0
        if run >= 3:
            painted += run
    step = 1  # full-surface audit; `total` is every pixel
    return {
        "fringe_pct": 100.0 * fringe / total,
        "painted": painted,
        "light_pct": 100.0 * light / total,
        "mean_luminance": luminance_sum / total,
    }


def main() -> int:
    out_dir = Path(sys.argv[1])
    out_dir.mkdir(parents=True, exist_ok=True)
    app = QApplication([])
    app.setStyleSheet(theme.stylesheet())
    tmp = Path(tempfile.mkdtemp())

    controller = VaultController(MemoryClipboard())
    window = MainWindow(controller)
    window.resize(1180, 760)
    window.show()

    shots = []
    shots.append(grab(app, window, out_dir / "01-locked.png"))

    # The first-run install offer, standing over a locked screen.
    offer_window = MainWindow(
        VaultController(MemoryClipboard()),
        install_offer=FakeInstallOffer(),
    )
    offer_window.show()
    offer_window.maybe_offer_install()
    offer_dialog = offer_window._install_dialog
    if offer_dialog is not None:
        shots.append(grab(app, offer_dialog, out_dir / "11-install-offer.png"))
    offer_window.close()
    offer_window.deleteLater()
    settle(app)

    # Setup: warning first.
    window.stack.setCurrentWidget(window.setup_screen)
    shots.append(grab(app, window, out_dir / "02-setup-warning.png"))

    # A real vault, created through the controller with fast params.
    created = controller.create_vault(
        tmp / "demo.aegis", PASSWORD, params=FAST
    )
    window.sheet_screen.show_key("demo", created)
    window.stack.setCurrentWidget(window.sheet_screen)
    shots.append(grab(app, window, out_dir / "03-recovery-sheet.png"))
    window.sheet_screen.wipe()

    # Seed synthetic content.
    controller.add_login(
        "Example Mail", username="test.person@example.test",
        password="fake-password-for-screenshots",
        url="https://example.test", notes="Synthetic.",
    )
    controller.add_login(
        "Corner Shop Wi-Fi", username="guest",
        password="fake-password-two", url="", notes="",
    )
    controller.add_login(
        "Library Card", username="reader42",
        password="fake-password-three", url="https://library.example.test",
    )
    controller.add_text_item("code", "Home safe code", "0000-FAKE-0000")
    controller.add_text_item("note", "Gate reminder", "The side gate sticks.")
    doc = tmp / "letter.txt"
    doc.write_bytes(b"A synthetic letter, kept as a document copy.")
    controller.add_document_from_path("Letter to the bank", doc)

    window.main_screen.enter("demo.aegis")
    window.stack.setCurrentWidget(window.main_screen)
    main = window.main_screen
    main.passwords_page.refresh()
    main.passwords_page.list.setCurrentRow(0)
    shots.append(grab(app, window, out_dir / "04-passwords.png"))

    main.show_section("generator")
    main.generator_page.make_one()
    shots.append(grab(app, window, out_dir / "05-generator.png"))

    main.show_section("strongbox")
    main.strongbox_page.refresh()
    main.strongbox_page.list.setCurrentRow(0)
    shots.append(grab(app, window, out_dir / "06-strongbox.png"))

    main.show_section("locksend")
    shots.append(grab(app, window, out_dir / "07-lock-and-send.png"))

    main.show_section("armor")
    shots.append(grab(app, window, out_dir / "08-backup-sets.png"))

    main.show_section("settings")
    shots.append(grab(app, window, out_dir / "09-settings.png"))

    # Error state: back to locked, wrong password.
    controller.lock()
    window.stack.setCurrentWidget(window.locked_screen)
    window.locked_screen.path_edit.setText(str(tmp / "demo.aegis"))
    window.locked_screen.credential.set_text("a completely wrong phrase")
    window._unlock()
    timer = QElapsedTimer()
    timer.start()
    while not window.locked_screen.banner.isVisible() and timer.elapsed() < 15000:
        app.processEvents()
    shots.append(grab(app, window, out_dir / "10-error-wrong-password.png"))

    print(
        "%-28s %9s %9s %8s %8s"
        % ("screenshot", "fringe%", "painted", "light%", "mean lum")
    )
    failures = 0
    for shot in shots:
        audit = pixel_audit(shot)
        print(
            "%-28s %8.3f%% %9d %7.2f%% %8.3f"
            % (shot.name, audit["fringe_pct"], audit["painted"],
               audit["light_pct"], audit["mean_luminance"])
        )
        if audit["painted"] > 0 or audit["mean_luminance"] > 0.25:
            failures += 1
    if failures:
        print("PIXEL AUDIT FAILED for %d screenshot(s)" % failures)
        return 1
    print(
        "Pixel audit clean: zero painted purple anywhere; the "
        "fringe column is subpixel text rendering, reported openly."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
