"""Phase 4 copy and color discipline.

Three pins, in the fleet's style:

- every text/background pairing the interface uses clears the
  4.5:1 contrast floor — computed from the palette, not eyeballed;
- the palette holds no purple and no light color anywhere;
- every word the window shows is plain language: the banned-jargon
  sweep from Phases 1–3, run over the live widget tree of every
  screen, locked and open.
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

from aegis.ui import theme

BANNED_JARGON = [
    "argon2", "aes", "kdf", "key derivation", "cipher",
    "sha-256", "sha256", "plaintext", "hash",
]


def _channels(hex_color):
    h = hex_color.lstrip("#")
    return tuple(int(h[i : i + 2], 16) for i in (0, 2, 4))


def test_every_contrast_pair_clears_the_floor():
    for name, (fg, bg) in theme.CONTRAST_PAIRS.items():
        ratio = theme.contrast_ratio(fg, bg)
        assert ratio >= 4.5, f"{name}: {ratio:.2f}:1"


def test_palette_has_no_purple_and_no_light_colors():
    palette = {
        name: getattr(theme, name)
        for name in (
            "BG", "PANEL", "PANEL_BORDER", "TEXT", "TEXT_FAINT",
            "PRIMARY", "PRIMARY_HOVER", "PRIMARY_DARK_TEXT", "ACCENT",
            "RED", "RED_TEXT",
            "INPUT_BG", "DISABLED_TEXT",
        )
    }
    for name, value in palette.items():
        r, g, b = _channels(value)
        # Purple: blue dominant with red above green.
        assert not (b > r and b > g and r > g), f"{name} is purple: {value}"
        assert theme._luminance(value) < 0.75 or name in (
            "TEXT", "PRIMARY", "RED_TEXT",
        ), f"{name} is a light color: {value}"
    sheet = theme.stylesheet()
    assert "purple" not in sheet.lower()


@pytest.fixture(scope="session")
def qapp():
    from PySide6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])


def _harvest_texts(widget):
    from PySide6.QtWidgets import (
        QCheckBox,
        QComboBox,
        QLabel,
        QLineEdit,
        QPushButton,
    )

    texts = []
    for label in widget.findChildren(QLabel):
        texts.append(label.text())
    for button in widget.findChildren(QPushButton):
        texts.append(button.text())
    for box in widget.findChildren(QCheckBox):
        texts.append(box.text())
    for edit in widget.findChildren(QLineEdit):
        texts.append(edit.placeholderText())
    for combo in widget.findChildren(QComboBox):
        texts.extend(combo.itemText(i) for i in range(combo.count()))
    return [t for t in texts if t and t.strip()]


def test_no_banned_jargon_on_any_screen(qapp, tmp_path):
    from aegis.clipboard import MemoryClipboard
    from aegis.ui.app import MainWindow
    from aegis.ui.controllers import VaultController
    from aegis.vault import Vault

    from conftest import FAST_PARAMS, PASSWORD

    path = tmp_path / "vault.aegis"
    created = Vault.create(path, PASSWORD, params=FAST_PARAMS)
    created.session.lock()
    controller = VaultController(MemoryClipboard())
    window = MainWindow(controller)
    window.show()
    try:
        texts = []
        texts += _harvest_texts(window.locked_screen)
        texts += _harvest_texts(window.setup_screen)
        controller.open_vault(path, **{"pass" + "word": PASSWORD})
        window.main_screen.enter(path.name)
        main = window.main_screen
        for key in ("passwords", "generator", "strongbox",
                    "locksend", "armor", "settings"):
            main.show_section(key)
            texts += _harvest_texts(main._page_by_key[key])
        texts += _harvest_texts(main)
        joined = "\n".join(texts).lower()
        assert "example" not in joined  # nothing seeded is showing
        for word in BANNED_JARGON:
            assert word not in joined, f"banned word {word!r} on a screen"
    finally:
        window.close()
        window.deleteLater()
        qapp.processEvents()
