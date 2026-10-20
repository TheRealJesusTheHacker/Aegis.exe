"""The Aegis look: Sentinel green and black, nothing else.

One palette for the whole medic kit, shared with Argus, Charon,
and Beerus: near-black green surfaces, one Sentinel green for the
actions that matter, white-green text. No purple anywhere, no light
backgrounds anywhere. Every text/background pairing in this file
clears the fleet's 4.5:1 contrast floor — the pairing table is
computed, not eyeballed, and the test suite pins it:

- TEXT on BG / PANEL / INPUT_BG          ≈ 13–15:1
- TEXT_FAINT on BG / PANEL               ≈ 7:1
- GREEN on BG / PANEL                    ≈ 8:1
- GREEN_DARK_TEXT on GREEN (buttons)     ≈ 9:1
- RED_TEXT on RED (rare accent)         ≈ 6:1
"""

from __future__ import annotations

__all__ = [
    "BG",
    "PANEL",
    "PANEL_BORDER",
    "TEXT",
    "TEXT_FAINT",
    "GREEN",
    "GREEN_HOVER",
    "GREEN_DARK_TEXT",
    "RED",
    "RED_TEXT",
    "ERROR_TEXT",
    "ERROR_BG",
    "INPUT_BG",
    "DISABLED_TEXT",
    "CONTRAST_PAIRS",
    "contrast_ratio",
    "stylesheet",
]

BG = "#060a07"  # window background, near-black green
PANEL = "#0c130d"  # raised panels
PANEL_BORDER = "#1d2b1f"
TEXT = "#e8f2ea"  # primary text
TEXT_FAINT = "#8fae94"  # secondary text (still >= 4.5:1 on BG/PANEL)
GREEN = "#2ee06f"  # the Sentinel green: primary actions, headings
GREEN_HOVER = "#46f086"  # the green, hovered
GREEN_DARK_TEXT = "#04150a"  # text on the green itself
RED = "#b03a2e"  # rare accent only: destructive confirmations
RED_TEXT = "#ffffff"  # text on the red accent
ERROR_TEXT = "#ff9d8f"  # words on the error banner
ERROR_BG = "#2a100d"  # the error banner's ground
INPUT_BG = "#0a0f0a"
DISABLED_TEXT = "#718671"  # disabled controls only, never body copy;
# still clears the 4.5:1 floor on both dark grounds (pinned below)


def _luminance(hex_color: str) -> float:
    """WCAG relative luminance of an ``#rrggbb`` color."""
    h = hex_color.lstrip("#")
    r, g, b = (int(h[i : i + 2], 16) / 255.0 for i in (0, 2, 4))

    def channel(c: float) -> float:
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4

    return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)


def contrast_ratio(foreground: str, background: str) -> float:
    """The WCAG contrast ratio between two ``#rrggbb`` colors."""
    l1, l2 = _luminance(foreground), _luminance(background)
    lighter, darker = max(l1, l2), min(l1, l2)
    return (lighter + 0.05) / (darker + 0.05)


#: Every foreground/background pairing the interface renders text
#: in, named for the audit. The test suite requires each to clear
#: 4.5:1.
CONTRAST_PAIRS = {
    "text on window": (TEXT, BG),
    "text on panel": (TEXT, PANEL),
    "text in field": (TEXT, INPUT_BG),
    "faint text on window": (TEXT_FAINT, BG),
    "faint text on panel": (TEXT_FAINT, PANEL),
    "green on window": (GREEN, BG),
    "green on panel": (GREEN, PANEL),
    "button text on green": (GREEN_DARK_TEXT, GREEN),
    "button text on hovered green": (GREEN_DARK_TEXT, GREEN_HOVER),
    "accent text on red": (RED_TEXT, RED),
    "green in field": (GREEN, INPUT_BG),
    "error words on error ground": (ERROR_TEXT, ERROR_BG),
    "disabled words on window": (DISABLED_TEXT, BG),
    "disabled words on panel": (DISABLED_TEXT, PANEL),
}


def stylesheet() -> str:
    """The application-wide stylesheet, built from the palette."""
    return f"""
QMainWindow, QDialog {{
    background: {BG};
}}
QWidget {{
    color: {TEXT};
    font-family: "Segoe UI", "DejaVu Sans", sans-serif;
    font-size: 13px;
}}
QLabel#Brand {{
    font-size: 34px;
    font-weight: 700;
    letter-spacing: 6px;
    color: {TEXT};
}}
QLabel#Tagline {{
    font-size: 13px;
    color: {TEXT_FAINT};
}}
QLabel#ScreenTitle {{
    font-size: 20px;
    font-weight: 600;
    color: {TEXT};
}}
QLabel#SectionTitle {{
    font-size: 15px;
    font-weight: 600;
    color: {GREEN};
}}
QLabel#Faint {{
    color: {TEXT_FAINT};
}}
QLabel#ErrorText {{
    color: {ERROR_TEXT};
}}
QFrame#Panel {{
    background: {PANEL};
    border: 1px solid {PANEL_BORDER};
    border-radius: 10px;
}}
QFrame#Sidebar {{
    background: {PANEL};
    border-right: 1px solid {PANEL_BORDER};
}}
QFrame#Seam {{
    background: {GREEN};
    border: none;
    border-radius: 1px;
}}
QFrame#ErrorBanner {{
    background: {ERROR_BG};
    border: 1px solid {RED};
    border-radius: 8px;
}}
QPushButton {{
    background: {PANEL};
    color: {TEXT};
    border: 1px solid {PANEL_BORDER};
    border-radius: 8px;
    padding: 8px 16px;
}}
QPushButton:hover {{
    border-color: {GREEN};
    color: {GREEN};
}}
QPushButton:disabled {{
    color: {DISABLED_TEXT};
}}
QPushButton#Peek {{
    padding: 8px 4px;
}}
QPushButton#Primary {{
    background: {GREEN};
    color: {GREEN_DARK_TEXT};
    border: 1px solid {GREEN};
    font-weight: 700;
}}
QPushButton#Primary:hover {{
    background: {GREEN_HOVER};
    color: {GREEN_DARK_TEXT};
}}
QPushButton#Primary:disabled {{
    background: {PANEL};
    color: {DISABLED_TEXT};
    border-color: {PANEL_BORDER};
}}
QPushButton#Danger {{
    background: {RED};
    color: {RED_TEXT};
    border: 1px solid {RED};
    font-weight: 600;
}}
QPushButton#Nav {{
    background: transparent;
    border: none;
    border-radius: 8px;
    padding: 10px 14px;
    text-align: left;
    color: {TEXT_FAINT};
    font-size: 14px;
}}
QPushButton#Nav:hover {{
    color: {TEXT};
}}
QPushButton#Nav:checked {{
    background: {INPUT_BG};
    color: {GREEN};
    font-weight: 600;
}}
QLineEdit, QPlainTextEdit, QTextEdit, QSpinBox, QComboBox {{
    background: {INPUT_BG};
    color: {TEXT};
    border: 1px solid {PANEL_BORDER};
    border-radius: 8px;
    padding: 8px 10px;
    selection-background-color: {GREEN};
    selection-color: {GREEN_DARK_TEXT};
}}
QLineEdit:focus, QPlainTextEdit:focus, QTextEdit:focus,
QSpinBox:focus, QComboBox:focus {{
    border-color: {GREEN};
}}
QListWidget {{
    background: {INPUT_BG};
    border: 1px solid {PANEL_BORDER};
    border-radius: 8px;
    padding: 4px;
    outline: 0;
}}
QListWidget::item {{
    padding: 8px 10px;
    border-radius: 6px;
}}
QListWidget::item:selected {{
    background: {PANEL};
    color: {GREEN};
}}
QComboBox QAbstractItemView {{
    background: {PANEL};
    color: {TEXT};
    selection-background-color: {INPUT_BG};
    selection-color: {GREEN};
}}
QCheckBox {{
    spacing: 8px;
}}
QCheckBox::indicator {{
    width: 16px;
    height: 16px;
    border: 1px solid {PANEL_BORDER};
    border-radius: 4px;
    background: {INPUT_BG};
}}
QCheckBox::indicator:checked {{
    background: {GREEN};
    border-color: {GREEN};
}}
QSlider::groove:horizontal {{
    height: 4px;
    background: {PANEL_BORDER};
    border-radius: 2px;
}}
QSlider::handle:horizontal {{
    width: 16px;
    height: 16px;
    margin: -6px 0;
    border-radius: 8px;
    background: {GREEN};
}}
QProgressBar {{
    background: {INPUT_BG};
    border: 1px solid {PANEL_BORDER};
    border-radius: 6px;
    height: 10px;
    text-align: center;
    color: transparent;
}}
QProgressBar::chunk {{
    background: {GREEN};
    border-radius: 5px;
}}
QScrollBar:vertical {{
    background: {BG};
    width: 10px;
}}
QScrollBar::handle:vertical {{
    background: {PANEL_BORDER};
    border-radius: 5px;
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0;
}}
QToolTip {{
    background: {PANEL};
    color: {TEXT};
    border: 1px solid {PANEL_BORDER};
}}
"""
