"""The Aegis window: one Lock, one Unlock, no jargon.

Every screen in this module is wired to the real core through
:class:`aegis.ui.controllers.VaultController` — there are no
decorative controls and no placeholder actions. Slow work (the
unlock itself, sealing, opening sets) runs on a worker thread so
the window never freezes mid-thought, and its result lands on the
same screen that asked for it.

Screen discipline, per the house rules:

- The window title never carries content: not a login's name, not
  an item's title — ``Aegis``, always. A locked vault exposes
  nothing, and neither does a taskbar.
- Password fields clear themselves the moment they are used, and
  again whenever the vault locks.
- Every failure arrives as a designed banner in the core's own
  plain words (see :func:`aegis.ui.controllers.user_text`), never
  a raw error, never a dead end.
- Locking puts every list, field, and detail back to blank before
  the locked screen shows.
"""

from __future__ import annotations

import os
from pathlib import Path

from PySide6.QtCore import (
    QEvent,
    QObject,
    QPropertyAnimation,
    Qt,
    QThread,
    QTimer,
    Signal,
)
from PySide6.QtGui import QColor, QKeySequence, QPainter, QPen, QPixmap
from PySide6.QtPrintSupport import QPrintDialog, QPrinter
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGraphicsOpacityEffect,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSlider,
    QSpinBox,
    QSplitter,
    QStackedWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from ..errors import AegisError
from ..generator import DEFAULT_GENERATED_LENGTH, MAX_GENERATED_LENGTH, MIN_GENERATED_LENGTH
from ..install_state import InstallOffer
from ..passwords import password_feedback
from ..setup import MASTER_PASSWORD_WARNING, printable_recovery_sheet
from ..strongbox import KIND_DOCUMENT, KIND_LABELS
from . import theme
from .controllers import VaultController, user_text

WINDOW_TITLE = "Aegis"
TAGLINE = "It does not open — for anyone but you."


# ---------------------------------------------------------------------------
# Small shared pieces
# ---------------------------------------------------------------------------


def shield_pixmap(size: int = 84) -> QPixmap:
    """The shield mark, drawn in code: a bronze outline on nothing.

    Drawn, not shipped as an image file, so the mark is exactly the
    shield bronze at any size and no asset can drift from it.
    """
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing)
    pen = QPen(QColor(theme.PRIMARY), max(2.0, size / 22.0))
    pen.setJoinStyle(Qt.RoundJoin)
    painter.setPen(pen)
    m = size * 0.14
    w, h = size - 2 * m, size - 2 * m
    from PySide6.QtCore import QPointF
    from PySide6.QtGui import QPainterPath

    path = QPainterPath()
    path.moveTo(m + w / 2, m)
    path.lineTo(m + w, m + h * 0.18)
    path.lineTo(m + w, h * 0.52 + m)
    path.cubicTo(m + w, m + h * 0.86, m + w * 0.68, m + h * 0.94, m + w / 2, m + h)
    path.cubicTo(m + w * 0.32, m + h * 0.94, m, m + h * 0.86, m, m + h * 0.52)
    path.lineTo(m, m + h * 0.18)
    path.closeSubpath()
    painter.drawPath(path)
    # The keyhole: a filled dot and stem at the shield's heart.
    painter.setBrush(QColor(theme.PRIMARY))
    painter.setPen(Qt.NoPen)
    cx, cy = m + w / 2, m + h * 0.42
    r = size * 0.055
    painter.drawEllipse(QPointF(cx, cy), r, r)
    painter.drawRect(int(cx - r * 0.45), int(cy), int(r * 0.9), int(size * 0.16))
    painter.end()
    return pixmap


class Worker(QThread):
    """Runs one callable off the window's thread."""

    done = Signal(object)
    failed = Signal(object)

    def __init__(self, fn, parent=None):
        super().__init__(parent)
        self._fn = fn

    def run(self):
        try:
            result = self._fn()
        except BaseException as exc:  # surfaced through user_text
            self.failed.emit(exc)
        else:
            self.done.emit(result)


class _CopyGuard(QObject):
    """Routes or swallows the native Copy gesture on one widget.

    Widgets that merely SHOW a secret (a revealed password, a
    Strongbox body, the recovery sheet, a generated password)
    normally let a person select the text and press Ctrl+C — a
    write to the system clipboard that bypasses the auto-clear
    clock entirely, so the secret would outlive the lock. The
    guard closes that road: with no ``on_copy``, the gesture does
    nothing; with one, it runs Aegis's own copy path — the one
    the clock watches.
    """

    def __init__(self, widget, on_copy=None):
        super().__init__(widget)
        self._on_copy = on_copy

    def eventFilter(self, watched, event):
        if event.type() == QEvent.KeyPress:
            if event.matches(QKeySequence.Copy):
                if self._on_copy is not None:
                    self._on_copy()
                return True
            if event.matches(QKeySequence.Cut):
                # Cut is a copy that also erases — the same
                # untracked road out. Swallowed everywhere this
                # guard stands; plain Delete still works.
                return True
        return False


def _lock_down_copy(widget, on_copy=None) -> None:
    """Take the untracked-copy roads away from a secret surface.

    No context menu (its Copy item writes natively), no dragging
    a selection out, and the Copy key gesture itself is caught by
    a guard and routed or swallowed. Selection itself is removed
    separately at each site, where the widget allows it.
    """
    widget.setContextMenuPolicy(Qt.NoContextMenu)
    if hasattr(widget, "setDragEnabled"):
        widget.setDragEnabled(False)
    widget.installEventFilter(_CopyGuard(widget, on_copy))


class ErrorBanner(QFrame):
    """The one designed failure state: a calm panel with plain words."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("ErrorBanner")
        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        self._label = QLabel("")
        self._label.setObjectName("ErrorText")
        self._label.setWordWrap(True)
        layout.addWidget(self._label)
        self.hide()

    def show_error(self, exc_or_text) -> None:
        if isinstance(exc_or_text, str):
            self._label.setText(exc_or_text)
        else:
            self._label.setText(user_text(exc_or_text))
        self.show()

    def clear(self) -> None:
        self._label.setText("")
        self.hide()


class PasswordEdit(QWidget):
    """A password field with a press-to-peek eye and self-clearing.

    The text is visible only while the Show button is held down —
    and the peek ends on release, on focus loss, on disable, and
    on hide, so a password is never left sitting readable on a
    screen by any road. The field's own copy gesture is locked
    down too: text leaves a password field by being typed into
    the thing it opens, never via the clipboard.
    """

    def __init__(self, placeholder="", parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.edit = QLineEdit()
        self.edit.setEchoMode(QLineEdit.Password)
        self.edit.setPlaceholderText(placeholder)
        _lock_down_copy(self.edit)
        layout.addWidget(self.edit, 1)
        self._peek_allowed = True
        self._show = QPushButton("Show")
        self._show.setObjectName("Peek")
        self._show.setFixedWidth(78)
        self._show.pressed.connect(self._peek_on)
        self._show.released.connect(self._peek_off)
        layout.addWidget(self._show)

    def _peek_on(self) -> None:
        if self._peek_allowed:
            self.edit.setEchoMode(QLineEdit.Normal)

    def _peek_off(self) -> None:
        if self._peek_allowed:
            self.edit.setEchoMode(QLineEdit.Password)

    def set_peek_allowed(self, allowed: bool) -> None:
        """Turn the peek off entirely (the recovery-key field).

        A recovery key is typed in the open by design; the Show
        button hides, and nothing can flip the field's echo mode.
        """
        self._peek_allowed = allowed
        self._show.setVisible(allowed)
        if not allowed:
            self.edit.setEchoMode(QLineEdit.Normal)

    def focusOutEvent(self, event) -> None:
        self._peek_off()
        super().focusOutEvent(event)

    def hideEvent(self, event) -> None:
        self._peek_off()
        super().hideEvent(event)

    def setEnabled(self, enabled: bool) -> None:
        if not enabled:
            self._peek_off()
        super().setEnabled(enabled)

    def text(self) -> str:
        return self.edit.text()

    def set_text(self, value: str) -> None:
        self.edit.setText(value)

    def clear(self) -> None:
        self.edit.clear()
        # Respect the field's mode: a recovery-key field (peek
        # disallowed) is typed in the open by design, even empty.
        self.edit.setEchoMode(
            QLineEdit.Password if self._peek_allowed else QLineEdit.Normal
        )

    def set_placeholder(self, text: str) -> None:
        self.edit.setPlaceholderText(text)


class BusyBar(QWidget):
    """An indeterminate progress bar with a plain status line."""

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self._label = QLabel("")
        self._label.setObjectName("Faint")
        self._bar = QProgressBar()
        self._bar.setRange(0, 0)
        layout.addWidget(self._label)
        layout.addWidget(self._bar)
        self.hide()

    def start(self, text: str) -> None:
        self._label.setText(text)
        self.show()

    def stop(self) -> None:
        self.hide()
        self._label.setText("")


def panel() -> QFrame:
    frame = QFrame()
    frame.setObjectName("Panel")
    return frame


def form_row(form: QFormLayout, label: str, widget: QWidget) -> None:
    label_widget = QLabel(label)
    form.addRow(label_widget, widget)


# ---------------------------------------------------------------------------
# The locked screen — home of the one Unlock button
# ---------------------------------------------------------------------------


class LockedScreen(QWidget):
    """Open a vault, or start making one. Nothing else lives here."""

    unlock_requested = Signal()
    create_requested = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(48, 36, 48, 36)
        root.addStretch(1)

        center = QVBoxLayout()
        center.setSpacing(10)
        self._shield = QLabel()
        self._shield.setPixmap(shield_pixmap(84))
        self._shield.setAlignment(Qt.AlignCenter)
        center.addWidget(self._shield)
        brand = QLabel("AEGIS")
        brand.setObjectName("Brand")
        brand.setAlignment(Qt.AlignCenter)
        center.addWidget(brand)
        tagline = QLabel(TAGLINE)
        tagline.setObjectName("Tagline")
        tagline.setAlignment(Qt.AlignCenter)
        center.addWidget(tagline)

        self._seam = QFrame()
        self._seam.setObjectName("Seam")
        self._seam.setFixedHeight(2)
        self._seam.setMaximumWidth(48)
        seam_row = QHBoxLayout()
        seam_row.addStretch(1)
        seam_row.addWidget(self._seam)
        seam_row.addStretch(1)
        center.addLayout(seam_row)
        root.addLayout(center)
        root.addSpacing(18)

        box = panel()
        box_layout = QVBoxLayout(box)
        box_layout.setContentsMargins(20, 18, 20, 18)
        box_layout.setSpacing(10)
        title = QLabel("Open your vault")
        title.setObjectName("SectionTitle")
        box_layout.addWidget(title)

        path_row = QHBoxLayout()
        self.path_edit = QLineEdit()
        self.path_edit.setPlaceholderText("Where your vault file is")
        path_row.addWidget(self.path_edit, 1)
        browse = QPushButton("Browse…")
        browse.clicked.connect(self._browse)
        self._browse_button = browse
        path_row.addWidget(browse)
        box_layout.addLayout(path_row)

        self.credential = PasswordEdit("Your master password")
        box_layout.addWidget(self.credential)
        self.use_recovery = QCheckBox("I have a recovery key instead")
        self.use_recovery.toggled.connect(self._swap_credential)
        box_layout.addWidget(self.use_recovery)

        self.banner = ErrorBanner()
        box_layout.addWidget(self.banner)
        self.busy = BusyBar()
        box_layout.addWidget(self.busy)

        self.unlock_button = QPushButton("Unlock")
        self.unlock_button.setObjectName("Primary")
        self.unlock_button.clicked.connect(self.unlock_requested)
        box_layout.addWidget(self.unlock_button)

        make = QPushButton("Make a new vault")
        make.clicked.connect(self.create_requested)
        self._make_button = make
        box_layout.addWidget(make)
        root.addWidget(box)
        root.addStretch(1)

        self.setAcceptDrops(True)
        self.credential.edit.returnPressed.connect(self.unlock_requested)
        self._seam_animation = None

    # -- behavior ----------------------------------------------------

    def _browse(self) -> None:
        start = self.path_edit.text().strip() or str(Path.home())
        chosen, _ = QFileDialog.getOpenFileName(
            self, "Choose your vault file", start,
            "Aegis vaults (*.aegis);;All files (*)",
        )
        if chosen:
            self.path_edit.setText(chosen)

    def _swap_credential(self, use_recovery: bool) -> None:
        self.credential.clear()
        if use_recovery:
            self.credential.set_placeholder("Your recovery key")
            self.credential.set_peek_allowed(False)
            self.credential.edit.setFont(_mono_font())
        else:
            self.credential.set_placeholder("Your master password")
            self.credential.set_peek_allowed(True)
            self.credential.edit.setEchoMode(QLineEdit.Password)
            self.credential.edit.setFont(QWidget().font())

    def using_recovery(self) -> bool:
        return self.use_recovery.isChecked()

    def vault_path(self) -> str:
        return self.path_edit.text().strip()

    def credential_text(self) -> str:
        return self.credential.text()

    def wipe_credential(self) -> None:
        self.credential.clear()

    def set_busy(self, busy: bool, text: str = "") -> None:
        # Busy means ALL of it: a second unlock started from the
        # still-live Enter key or Browse while one is running
        # would open the vault twice and orphan a live session.
        for widget in (
            self.unlock_button,
            self._make_button,
            self._browse_button,
            self.path_edit,
            self.credential,
            self.use_recovery,
        ):
            widget.setEnabled(not busy)
        if busy:
            self.busy.start(text)
        else:
            self.busy.stop()

    def play_seam(self, opening: bool) -> None:
        """The seam line breathes once when the vault state changes."""
        animation = QPropertyAnimation(self._seam, b"maximumWidth", self)
        animation.setDuration(420)
        animation.setStartValue(48 if opening else 220)
        animation.setEndValue(220 if opening else 48)
        animation.start()
        self._seam_animation = animation

    def dragEnterEvent(self, event) -> None:
        urls = event.mimeData().urls() if event.mimeData() else []
        if any(u.isLocalFile() for u in urls):
            event.acceptProposedAction()

    def dropEvent(self, event) -> None:
        for url in event.mimeData().urls():
            if url.isLocalFile():
                self.path_edit.setText(url.toLocalFile())
                self.banner.clear()
                return


def _mono_font():
    from PySide6.QtGui import QFont

    font = QFont("Consolas")
    font.setStyleHint(QFont.Monospace)
    font.setPointSize(11)
    return font


# ---------------------------------------------------------------------------
# Setup — the warning first, exactly as Phase 1 designed it
# ---------------------------------------------------------------------------


class SetupScreen(QWidget):
    """Make a new vault: warning, place, password, then the key sheet."""

    back_requested = Signal()
    created = Signal(object, str)  # recovery key, vault display name

    def __init__(self, controller: VaultController, parent=None):
        super().__init__(parent)
        self._controller = controller
        root = QVBoxLayout(self)
        root.setContentsMargins(48, 32, 48, 32)
        back = QPushButton("← Back")
        back.setObjectName("Nav")
        back.clicked.connect(self.back_requested)
        root.addWidget(back, alignment=Qt.AlignLeft)
        title = QLabel("Make a new vault")
        title.setObjectName("ScreenTitle")
        root.addWidget(title)
        root.addSpacing(8)

        warning_box = panel()
        warning_layout = QVBoxLayout(warning_box)
        warning_layout.setContentsMargins(18, 14, 18, 14)
        warning = QLabel(MASTER_PASSWORD_WARNING)
        warning.setWordWrap(True)
        warning_layout.addWidget(warning)
        root.addWidget(warning_box)
        root.addSpacing(12)

        form_box = panel()
        form_layout = QVBoxLayout(form_box)
        form_layout.setContentsMargins(18, 14, 18, 14)
        form = QFormLayout()
        form.setSpacing(10)
        self.name_edit = QLineEdit("my-vault")
        form_row(form, "Vault name", self.name_edit)
        folder_row = QHBoxLayout()
        self.folder_edit = QLineEdit(str(Path.home()))
        folder_row.addWidget(self.folder_edit, 1)
        browse = QPushButton("Browse…")
        browse.clicked.connect(self._browse_folder)
        folder_row.addWidget(browse)
        form_row(form, "Where to keep it", _wrap(folder_row))
        self.password = PasswordEdit("A short phrase you can remember")
        form_row(form, "Master password", self.password)
        self.confirm = PasswordEdit("Type it once more")
        form_row(form, "Confirm password", self.confirm)
        form_layout.addLayout(form)
        self.feedback_label = QLabel("")
        self.feedback_label.setObjectName("Faint")
        self.feedback_label.setWordWrap(True)
        form_layout.addWidget(self.feedback_label)
        self.banner = ErrorBanner()
        form_layout.addWidget(self.banner)
        self.busy = BusyBar()
        form_layout.addWidget(self.busy)
        self.create_button = QPushButton("Make my vault")
        self.create_button.setObjectName("Primary")
        self.create_button.clicked.connect(self._make)
        form_layout.addWidget(self.create_button)
        root.addWidget(form_box)
        root.addStretch(1)

        self.password.edit.textChanged.connect(self._feedback)
        self._worker = None
        # Set by the window: the shared one-at-a-time gate for
        # opening and creating, so the two can never run together.
        self.auth_gate = None

    def wipe_secrets(self) -> None:
        """Take the typed passwords off this screen."""
        self.password.clear()
        self.confirm.clear()

    def _browse_folder(self) -> None:
        chosen = QFileDialog.getExistingDirectory(
            self, "Where to keep the vault", self.folder_edit.text().strip()
        )
        if chosen:
            self.folder_edit.setText(chosen)

    def _feedback(self, text: str) -> None:
        if not text:
            self.feedback_label.setText("")
            return
        feedback = password_feedback(text)
        self.feedback_label.setText(feedback.message)

    def vault_display_name(self) -> str:
        return self.name_edit.text().strip()

    def target_path(self) -> Path:
        name = self.vault_display_name() or "my-vault"
        if not name.endswith(".aegis"):
            name += ".aegis"
        return Path(self.folder_edit.text().strip() or str(Path.home())) / name

    def _make(self) -> None:
        self.banner.clear()
        password = self.password.text()
        if password != self.confirm.text():
            self.banner.show_error("The two passwords don't match. Type them both again.")
            return
        target = self.target_path()
        if self.auth_gate is not None and not self.auth_gate[0]():
            return
        self.create_button.setEnabled(False)
        self.busy.start("Making your vault…")
        worker = Worker(
            lambda: self._controller.create_vault(target, password), self
        )
        worker.done.connect(self._made)
        worker.failed.connect(self._failed)
        worker.start()
        self._worker = worker

    def _made(self, recovery_key) -> None:
        if self.auth_gate is not None:
            self.auth_gate[1]()
        self.busy.stop()
        self.create_button.setEnabled(True)
        self.password.clear()
        self.confirm.clear()
        name = self.vault_display_name()
        self.created.emit(recovery_key, name)

    def _failed(self, exc) -> None:
        if self.auth_gate is not None:
            self.auth_gate[1]()
        self.busy.stop()
        self.create_button.setEnabled(True)
        # A failed create leaves nothing typed behind either: the
        # phrase in these fields is a master password, and it does
        # not sit on a screen the person may walk away from.
        self.password.clear()
        self.confirm.clear()
        self.banner.show_error(exc)


def _wrap(layout) -> QWidget:
    widget = QWidget()
    widget.setLayout(layout)
    return widget


# ---------------------------------------------------------------------------
# The recovery key sheet — shown once, printed, never stored
# ---------------------------------------------------------------------------


class RecoverySheet(QWidget):
    """Shows the printable recovery sheet; gates continuing on care."""

    done = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(48, 32, 48, 32)
        title = QLabel("Your recovery key")
        title.setObjectName("ScreenTitle")
        root.addWidget(title)
        note = QLabel(
            "This key is shown once. It is not saved anywhere in Aegis."
        )
        note.setObjectName("Faint")
        root.addWidget(note)
        self.sheet = QTextEdit()
        self.sheet.setReadOnly(True)
        self.sheet.setFont(_mono_font())
        # The sheet holds a full-access key. Its designed way out
        # is the printed page — never the clipboard, where a copy
        # would outlive every lock. Selection itself is off.
        self.sheet.setTextInteractionFlags(Qt.NoTextInteraction)
        _lock_down_copy(self.sheet)
        root.addWidget(self.sheet, 1)
        row = QHBoxLayout()
        print_button = QPushButton("Print this sheet")
        print_button.clicked.connect(self._print)
        row.addWidget(print_button)
        row.addStretch(1)
        root.addLayout(row)
        self.care = QCheckBox(
            "I have printed this sheet or written the key down somewhere safe"
        )
        root.addWidget(self.care)
        self.continue_button = QPushButton("Continue")
        self.continue_button.setObjectName("Primary")
        self.continue_button.setEnabled(False)
        self.care.toggled.connect(self.continue_button.setEnabled)
        self.continue_button.clicked.connect(self.done)
        root.addWidget(self.continue_button)

    def show_key(self, vault_name: str, recovery_key: str) -> None:
        self.care.setChecked(False)
        self.sheet.setPlainText(printable_recovery_sheet(vault_name, recovery_key))

    def wipe(self) -> None:
        self.sheet.clear()
        self.care.setChecked(False)

    def _print(self) -> None:
        printer = QPrinter()
        dialog = QPrintDialog(printer, self)
        # Under the window's dialog discipline, like every other
        # dialog: a lock closes it instead of leaving it standing
        # over the locked screen with the sheet behind it.
        if _exec_dialog(self, dialog) == QDialog.Accepted:
            self.sheet.print_(printer)


# ---------------------------------------------------------------------------
# Dialogs
# ---------------------------------------------------------------------------


class InstallOfferDialog(QDialog):
    """The first-run offer: put a copy in its permanent place.

    Shown modeless over the locked screen, once per run, and never
    a gate — the Unlock path works exactly the same whether this
    is standing or not. It holds nothing secret: a heading, the
    offer in plain words, a status line for the result, and its
    buttons. That is why it needs no wipe: closing it at a lock
    leaves nothing of the vault's behind, because it never held
    any. The window wires the Install button; saying "Not now"
    and, once a result is in, "Close" simply end the dialog, and
    the window's tracking takes care of the rest.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Aegis")
        self.setModal(False)
        self.setMinimumWidth(460)
        layout = QVBoxLayout(self)
        self.heading_label = QLabel("Put Aegis in its permanent place?")
        self.heading_label.setObjectName("SectionTitle")
        layout.addWidget(self.heading_label)
        self.body_label = QLabel(
            "You are running Aegis from the folder it was opened in. "
            "If you like, Aegis can put a copy in your Programs folder, "
            "where it stays — and try to add “Aegis” to your Start Menu. "
            "Your vault files are not moved or changed; they stay exactly "
            "where you keep them. You can also keep running Aegis from "
            "here — the app works the same either way."
        )
        self.body_label.setWordWrap(True)
        layout.addWidget(self.body_label)
        self.status_label = QLabel("")
        self.status_label.setObjectName("Faint")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)
        buttons = QHBoxLayout()
        buttons.addStretch(1)
        self.not_now_button = QPushButton("Not now")
        self.not_now_button.clicked.connect(self.reject)
        buttons.addWidget(self.not_now_button)
        self.install_button = QPushButton("Install Aegis")
        self.install_button.setObjectName("Primary")
        buttons.addWidget(self.install_button)
        self.close_button = QPushButton("Close")
        self.close_button.clicked.connect(self.accept)
        self.close_button.hide()
        buttons.addWidget(self.close_button)
        layout.addLayout(buttons)

    def begin_install(self) -> None:
        """Set the working state: no more choices, a status line."""
        self.install_button.setEnabled(False)
        self.not_now_button.setEnabled(False)
        self.status_label.setText(
            "Putting Aegis in place — this takes a moment…"
        )

    def show_result(self, ok, message) -> None:
        """Show the install's own words, and offer only Close.

        The message is the mechanism's, shown word for word,
        whether it reports success or failure — the dialog adds
        nothing to it and takes nothing away.
        """
        self.status_label.setText(message)
        self.install_button.hide()
        self.not_now_button.hide()
        self.close_button.show()


class LoginEditor(QDialog):
    """Add or change one saved login, with a built-in password maker."""

    def __init__(self, controller: VaultController, parent=None, entry=None,
                 prefill_password=""):
        super().__init__(parent)
        self._controller = controller
        self._entry = entry
        self.setWindowTitle("Aegis")
        self.setMinimumWidth(460)
        layout = QVBoxLayout(self)
        title = QLabel("Change this login" if entry else "Save a new login")
        title.setObjectName("SectionTitle")
        layout.addWidget(title)
        form = QFormLayout()
        form.setSpacing(10)
        self.title_edit = QLineEdit(entry.title if entry else "")
        form_row(form, "Site or app", self.title_edit)
        self.username_edit = QLineEdit(entry.username if entry else "")
        form_row(form, "User name", self.username_edit)
        self.password = PasswordEdit("The password for it")
        if entry is not None:
            self.password.set_text(controller.get_login(entry.id).password)
        elif prefill_password:
            self.password.set_text(prefill_password)
        form_row(form, "Password", self.password)
        self.url_edit = QLineEdit(entry.url if entry else "")
        form_row(form, "Web address", self.url_edit)
        self.notes_edit = QPlainTextEdit(entry.notes if entry else "")
        self.notes_edit.setMaximumHeight(70)
        # Notes live inside the vault because they can hold
        # things worth keeping — same lockdown as the Strongbox
        # editor: no native copy or cut out of here.
        _lock_down_copy(self.notes_edit)
        form_row(form, "Notes", self.notes_edit)
        layout.addLayout(form)

        maker = QHBoxLayout()
        maker.addWidget(QLabel("Length"))
        self.length_spin = QSpinBox()
        self.length_spin.setRange(MIN_GENERATED_LENGTH, MAX_GENERATED_LENGTH)
        self.length_spin.setValue(DEFAULT_GENERATED_LENGTH)
        maker.addWidget(self.length_spin)
        make_button = QPushButton("Make one for me")
        make_button.clicked.connect(self._make)
        maker.addWidget(make_button)
        maker.addStretch(1)
        layout.addLayout(maker)

        self.banner = ErrorBanner()
        layout.addWidget(self.banner)
        buttons = QHBoxLayout()
        buttons.addStretch(1)
        cancel = QPushButton("Cancel")
        cancel.clicked.connect(self.reject)
        buttons.addWidget(cancel)
        save = QPushButton("Save login")
        save.setObjectName("Primary")
        save.clicked.connect(self._save)
        buttons.addWidget(save)
        layout.addLayout(buttons)

    def _make(self) -> None:
        try:
            made = self._controller.make_password(self.length_spin.value())
        except ValueError as exc:
            # The maker's own plain refusal (its length bounds) —
            # authored at that one call site, safe to show.
            self.banner.show_error(str(exc))
            return
        except Exception as exc:
            self.banner.show_error(exc)
            return
        self.password.set_text(made)

    def wipe(self) -> None:
        """Empty every field — a closed dialog keeps nothing."""
        self.title_edit.clear()
        self.username_edit.clear()
        self.password.clear()
        self.url_edit.clear()
        self.notes_edit.clear()

    def _save(self) -> None:
        try:
            if self._entry is None:
                self._controller.add_login(
                    self.title_edit.text(),
                    username=self.username_edit.text(),
                    password=self.password.text(),
                    url=self.url_edit.text(),
                    notes=self.notes_edit.toPlainText(),
                )
            else:
                self._controller.update_login(
                    self._entry.id,
                    title=self.title_edit.text(),
                    username=self.username_edit.text(),
                    password=self.password.text(),
                    url=self.url_edit.text(),
                    notes=self.notes_edit.toPlainText(),
                )
        except Exception as exc:
            self.banner.show_error(exc)
            return
        self.password.clear()
        self.accept()


class ItemEditor(QDialog):
    """Add or change one Strongbox item."""

    def __init__(self, controller: VaultController, parent=None, item=None):
        super().__init__(parent)
        self._controller = controller
        self._item = item
        self.setWindowTitle("Aegis")
        self.setMinimumWidth(460)
        layout = QVBoxLayout(self)
        title = QLabel("Change this item" if item else "Keep something in the Strongbox")
        title.setObjectName("SectionTitle")
        layout.addWidget(title)
        form = QFormLayout()
        form.setSpacing(10)
        self.kind_combo = QComboBox()
        for key in ("code", "key", "note", "document"):
            self.kind_combo.addItem(KIND_LABELS[key], key)
        if item is not None:
            self.kind_combo.setCurrentIndex(
                self.kind_combo.findData(item.kind)
            )
            self.kind_combo.setEnabled(False)
        form_row(form, "Kind", self.kind_combo)
        self.title_edit = QLineEdit(item.title if item else "")
        form_row(form, "Name for it", self.title_edit)
        self.body_edit = QPlainTextEdit(item.body if item and item.kind != KIND_DOCUMENT else "")
        self.body_edit.setMaximumHeight(90)
        # The body is a Strongbox secret shown for editing; its
        # way out is the Strongbox page's tracked Copy, not a
        # native copy from here.
        _lock_down_copy(self.body_edit)
        form_row(form, "The code, key, or note", self.body_edit)
        file_row = QHBoxLayout()
        self.file_label = QLabel("No file chosen")
        self.file_label.setObjectName("Faint")
        file_row.addWidget(self.file_label, 1)
        pick = QPushButton("Choose a file…")
        pick.clicked.connect(self._pick)
        file_row.addWidget(pick)
        form_row(form, "Document copy", _wrap(file_row))
        layout.addLayout(form)
        self._file_path = None
        if item is not None and item.kind == KIND_DOCUMENT:
            self.file_label.setText(item.filename)
        self._sync_kind()
        self.kind_combo.currentIndexChanged.connect(self._sync_kind)

        self.banner = ErrorBanner()
        layout.addWidget(self.banner)
        buttons = QHBoxLayout()
        buttons.addStretch(1)
        cancel = QPushButton("Cancel")
        cancel.clicked.connect(self.reject)
        buttons.addWidget(cancel)
        save = QPushButton("Save item")
        save.setObjectName("Primary")
        save.clicked.connect(self._save)
        buttons.addWidget(save)
        layout.addLayout(buttons)

    def _sync_kind(self) -> None:
        is_document = self.kind_combo.currentData() == KIND_DOCUMENT
        self.body_edit.setEnabled(not is_document)

    def _pick(self) -> None:
        chosen, _ = QFileDialog.getOpenFileName(self, "Choose the document")
        if chosen:
            self._file_path = chosen
            self.file_label.setText(Path(chosen).name)

    def _save(self) -> None:
        kind = self.kind_combo.currentData()
        try:
            if self._item is None:
                if kind == KIND_DOCUMENT:
                    if not self._file_path:
                        self.banner.show_error(
                            "Choose the document to keep a copy of first."
                        )
                        return
                    self._controller.add_document_from_path(
                        self.title_edit.text(), self._file_path
                    )
                else:
                    self._controller.add_text_item(
                        kind, self.title_edit.text(),
                        self.body_edit.toPlainText(),
                    )
            else:
                if kind == KIND_DOCUMENT:
                    # The document first, the name last: if the
                    # new copy is refused (too big, unreadable),
                    # nothing about the item has changed at all.
                    if self._file_path:
                        self._controller.replace_document_from_path(
                            self._item.id, self._file_path
                        )
                    self._controller.update_item(
                        self._item.id, title=self.title_edit.text()
                    )
                else:
                    self._controller.update_item(
                        self._item.id,
                        title=self.title_edit.text(),
                        body=self.body_edit.toPlainText(),
                    )
        except Exception as exc:
            self.banner.show_error(exc)
            return
        self.accept()

    def wipe(self) -> None:
        """Empty every field — a closed dialog keeps nothing."""
        self.title_edit.clear()
        self.body_edit.clear()
        self.file_label.setText("No file chosen")
        self._file_path = None


def _confirm(widget: QWidget, text: str) -> bool:
    """Ask a yes/no question under the window's lock discipline.

    A static question box cannot be tracked, so it would survive
    a lock standing over the locked screen. This builds the same
    question as a real dialog and runs it through the tracked
    path: a lock closes it (which answers "no"), and however it
    ends it is disposed of, never left as a hidden child.
    """
    box = QMessageBox(
        QMessageBox.Question, "Aegis", text,
        QMessageBox.Yes | QMessageBox.No, widget,
    )
    box.setDefaultButton(QMessageBox.No)
    return _exec_dialog(widget, box) == QMessageBox.Yes


def _exec_dialog(widget: QWidget, dialog: QDialog) -> int:
    """Run a dialog under the window's lock discipline.

    The window tracks the dialog so a lock — button, idle, or
    close — closes and empties it first: a modal left standing
    over the locked screen would keep its contents on display.
    However the dialog ends (Save, Cancel, or a lock closing it),
    its fields are wiped and it is disposed of, never left as a
    hidden child holding what was typed.
    """
    window = widget.window()
    tracked = isinstance(window, MainWindow)
    if tracked:
        window._track_dialog(dialog)
    try:
        return dialog.exec()
    finally:
        if tracked:
            window._release_dialog(dialog)
        wipe = getattr(dialog, "wipe", None)
        if wipe is not None:
            wipe()
        dialog.deleteLater()


# ---------------------------------------------------------------------------
# Section pages
# ---------------------------------------------------------------------------


class PasswordsPage(QWidget):
    """Search, see, copy, and care for the saved logins."""

    def __init__(self, controller: VaultController, parent=None):
        super().__init__(parent)
        self._controller = controller
        self._current_id = None
        root = QVBoxLayout(self)
        root.setContentsMargins(22, 18, 22, 18)
        root.setSpacing(10)
        head = QHBoxLayout()
        title = QLabel("Passwords")
        title.setObjectName("ScreenTitle")
        head.addWidget(title)
        head.addStretch(1)
        add = QPushButton("Save a new login")
        add.setObjectName("Primary")
        add.clicked.connect(self._add)
        head.addWidget(add)
        root.addLayout(head)

        self.search = QLineEdit()
        self.search.setPlaceholderText("Search by name, user name, or web address")
        self.search.textChanged.connect(lambda _t: self.refresh())
        root.addWidget(self.search)
        self.banner = ErrorBanner()
        root.addWidget(self.banner)

        split = QSplitter(Qt.Horizontal)
        self.list = QListWidget()
        self.list.currentItemChanged.connect(self._selected)
        split.addWidget(self.list)
        detail = panel()
        detail_layout = QVBoxLayout(detail)
        detail_layout.setContentsMargins(16, 14, 16, 14)
        detail_layout.setSpacing(8)
        self.detail_title = QLabel("Pick a login to see it here")
        self.detail_title.setObjectName("SectionTitle")
        detail_layout.addWidget(self.detail_title)
        self.detail_lines = QLabel("")
        self.detail_lines.setWordWrap(True)
        detail_layout.addWidget(self.detail_lines)
        self.revealed = QLabel("")
        self.revealed.setFont(_mono_font())
        # A revealed password is for looking at, not copying:
        # the Copy button beside it is the tracked road out.
        self.revealed.setTextInteractionFlags(Qt.NoTextInteraction)
        detail_layout.addWidget(self.revealed)
        self._hide_timer = QTimer(self)
        self._hide_timer.setSingleShot(True)
        self._hide_timer.timeout.connect(self._auto_hide)
        row = QHBoxLayout()
        self.show_button = QPushButton("Show password")
        self.show_button.clicked.connect(self._toggle_reveal)
        row.addWidget(self.show_button)
        self.copy_button = QPushButton("Copy password")
        self.copy_button.clicked.connect(self._copy)
        row.addWidget(self.copy_button)
        row.addStretch(1)
        detail_layout.addLayout(row)
        row2 = QHBoxLayout()
        self.edit_button = QPushButton("Change")
        self.edit_button.clicked.connect(self._edit)
        row2.addWidget(self.edit_button)
        self.delete_button = QPushButton("Delete")
        self.delete_button.clicked.connect(self._delete)
        row2.addWidget(self.delete_button)
        row2.addStretch(1)
        detail_layout.addLayout(row2)
        detail_layout.addStretch(1)
        split.addWidget(detail)
        split.setSizes([320, 460])
        root.addWidget(split, 1)
        self._set_detail_enabled(False)

    # -- data ---------------------------------------------------------

    def refresh(self) -> None:
        current = self._current_id
        self.list.clear()
        self._current_id = None
        if not self._controller.is_open:
            # Built before any vault is open: an empty page, not
            # an error.
            self._show_empty_detail()
            self.banner.clear()
            return
        try:
            summaries = self._controller.search_logins(self.search.text())
        except Exception as exc:
            self.banner.show_error(exc)
            return
        self.banner.clear()
        for summary in summaries:
            lines = [summary.title]
            extra = " — ".join(p for p in (summary.username, summary.url) if p)
            if extra:
                lines.append(extra)
            item = QListWidgetItem("\n".join(lines))
            item.setData(Qt.UserRole, summary.id)
            self.list.addItem(item)
            if summary.id == current:
                self.list.setCurrentItem(item)
        if self.list.currentItem() is None:
            self._show_empty_detail()

    def wipe(self) -> None:
        self.list.clear()
        self.search.clear()
        self._hide_timer.stop()
        self.revealed.setText("")
        self._current_id = None
        self.banner.clear()

    # -- detail ---------------------------------------------------------

    def _set_detail_enabled(self, enabled: bool) -> None:
        for button in (
            self.show_button, self.copy_button,
            self.edit_button, self.delete_button,
        ):
            button.setEnabled(enabled)

    def _show_empty_detail(self) -> None:
        self.detail_title.setText("Pick a login to see it here")
        self.detail_lines.setText("")
        self.revealed.setText("")
        self.show_button.setText("Show password")
        self._set_detail_enabled(False)

    def _selected(self, item, _previous) -> None:
        self.revealed.setText("")
        self.show_button.setText("Show password")
        if item is None:
            self._show_empty_detail()
            return
        entry_id = item.data(Qt.UserRole)
        self._current_id = entry_id
        try:
            entry = self._controller.get_login(entry_id)
        except Exception as exc:
            self.banner.show_error(exc)
            return
        self.detail_title.setText(entry.title)
        self.detail_lines.setText(entry.describe().split("\n", 1)[1] if "\n" in entry.describe() else "")
        self._set_detail_enabled(True)

    def _toggle_reveal(self) -> None:
        if self._current_id is None:
            return
        if self.revealed.text():
            self._hide_timer.stop()
            self.revealed.setText("")
            self.show_button.setText("Show password")
            return
        try:
            entry = self._controller.get_login(self._current_id)
        except Exception as exc:
            self.banner.show_error(exc)
            return
        self.revealed.setText(entry.password)
        self.show_button.setText("Hide password")
        self._hide_timer.start(15000)

    def _auto_hide(self) -> None:
        if self.revealed.text():
            self.revealed.setText("")
            self.show_button.setText("Show password")

    def _copy(self) -> None:
        if self._current_id is None:
            return
        try:
            self._controller.copy_login_password(self._current_id)
        except Exception as exc:
            self.banner.show_error(exc)
            return
        self.banner.clear()

    # -- changes ---------------------------------------------------------

    def _add(self) -> None:
        dialog = LoginEditor(self._controller, self)
        if _exec_dialog(self, dialog) == QDialog.Accepted:
            self.refresh()

    def _edit(self) -> None:
        if self._current_id is None:
            return
        try:
            entry = self._controller.get_login(self._current_id)
        except Exception as exc:
            self.banner.show_error(exc)
            return
        dialog = LoginEditor(self._controller, self, entry=entry)
        if _exec_dialog(self, dialog) == QDialog.Accepted:
            self.refresh()

    def _delete(self) -> None:
        if self._current_id is None:
            return
        if not _confirm(self, "Delete this login from the vault? This can't be undone."):
            return
        try:
            self._controller.delete_login(self._current_id)
        except Exception as exc:
            self.banner.show_error(exc)
            return
        self._current_id = None
        self.refresh()


class GeneratorPage(QWidget):
    """Make a strong password — the easy choice is the strong one."""

    use_in_login = Signal()

    def __init__(self, controller: VaultController, parent=None):
        super().__init__(parent)
        self._controller = controller
        self.last_made = ""
        root = QVBoxLayout(self)
        root.setContentsMargins(22, 18, 22, 18)
        root.setSpacing(12)
        title = QLabel("Make a password")
        title.setObjectName("ScreenTitle")
        root.addWidget(title)
        note = QLabel(
            "Made fresh on this computer, from pure chance. "
            "Nothing is kept unless you save it in a login."
        )
        note.setObjectName("Faint")
        note.setWordWrap(True)
        root.addWidget(note)

        box = panel()
        box_layout = QVBoxLayout(box)
        box_layout.setContentsMargins(18, 16, 18, 16)
        box_layout.setSpacing(12)
        self.display = QLineEdit()
        self.display.setReadOnly(True)
        self.display.setFont(_mono_font())
        self.display.setMinimumHeight(44)
        # A made password is copied through the tracked road
        # only: Ctrl+C here runs the same copy as the button.
        _lock_down_copy(self.display, on_copy=lambda: self._copy())
        box_layout.addWidget(self.display)
        controls = QHBoxLayout()
        controls.addWidget(QLabel("Length"))
        self.length = QSpinBox()
        self.length.setRange(MIN_GENERATED_LENGTH, MAX_GENERATED_LENGTH)
        self.length.setValue(DEFAULT_GENERATED_LENGTH)
        controls.addWidget(self.length)
        slider = QSlider(Qt.Horizontal)
        slider.setRange(MIN_GENERATED_LENGTH, 64)
        slider.setValue(DEFAULT_GENERATED_LENGTH)
        slider.valueChanged.connect(self.length.setValue)
        self.length.valueChanged.connect(
            lambda v: slider.setValue(min(v, 64))
        )
        controls.addWidget(slider, 1)
        box_layout.addLayout(controls)
        kinds = QHBoxLayout()
        self.lower = QCheckBox("Small letters")
        self.lower.setChecked(True)
        self.upper = QCheckBox("Capital letters")
        self.upper.setChecked(True)
        self.digits = QCheckBox("Numbers")
        self.digits.setChecked(True)
        self.symbols = QCheckBox("Symbols")
        self.symbols.setChecked(True)
        for box_widget in (self.lower, self.upper, self.digits, self.symbols):
            kinds.addWidget(box_widget)
        kinds.addStretch(1)
        box_layout.addLayout(kinds)
        self.banner = ErrorBanner()
        box_layout.addWidget(self.banner)
        row = QHBoxLayout()
        make = QPushButton("Make a new one")
        make.setObjectName("Primary")
        make.clicked.connect(self.make_one)
        row.addWidget(make)
        copy = QPushButton("Copy it")
        copy.clicked.connect(self._copy)
        row.addWidget(copy)
        use = QPushButton("Use it in a new login")
        use.clicked.connect(lambda: self.use_in_login.emit())
        row.addWidget(use)
        row.addStretch(1)
        box_layout.addLayout(row)
        root.addWidget(box)
        root.addStretch(1)

    def make_one(self) -> None:
        try:
            made = self._controller.make_password(
                self.length.value(),
                lowercase=self.lower.isChecked(),
                uppercase=self.upper.isChecked(),
                digits=self.digits.isChecked(),
                symbols=self.symbols.isChecked(),
            )
        except ValueError as exc:
            # The maker's own plain refusals (length, no kind
            # picked) — authored at that one call site.
            self.banner.show_error(str(exc))
            return
        except Exception as exc:
            self.banner.show_error(exc)
            return
        self.banner.clear()
        self.last_made = made
        self.display.setText(made)

    def _copy(self) -> None:
        if not self.last_made:
            self.banner.show_error("Make a password first, then copy it.")
            return
        self._controller.copy_text(self.last_made)

    def wipe(self) -> None:
        self.last_made = ""
        self.display.clear()
        self.banner.clear()


class StrongboxPage(QWidget):
    """The compartment for codes, keys, notes, and document copies."""

    def __init__(self, controller: VaultController, parent=None):
        super().__init__(parent)
        self._controller = controller
        self._current_id = None
        root = QVBoxLayout(self)
        root.setContentsMargins(22, 18, 22, 18)
        root.setSpacing(10)
        head = QHBoxLayout()
        title = QLabel("Strongbox")
        title.setObjectName("ScreenTitle")
        head.addWidget(title)
        head.addStretch(1)
        add = QPushButton("Keep something")
        add.setObjectName("Primary")
        add.clicked.connect(self._add)
        head.addWidget(add)
        root.addLayout(head)
        note = QLabel(
            "For the small things that matter most: recovery codes, "
            "keys, private notes, and copies of documents."
        )
        note.setObjectName("Faint")
        note.setWordWrap(True)
        root.addWidget(note)
        self.kind_filter = QComboBox()
        self.kind_filter.addItem("Everything", None)
        for key in ("code", "key", "note", "document"):
            self.kind_filter.addItem(KIND_LABELS[key] + "s", key)
        self.kind_filter.currentIndexChanged.connect(lambda _i: self.refresh())
        root.addWidget(self.kind_filter)
        self.banner = ErrorBanner()
        root.addWidget(self.banner)

        split = QSplitter(Qt.Horizontal)
        self.list = QListWidget()
        self.list.currentItemChanged.connect(self._selected)
        split.addWidget(self.list)
        detail = panel()
        detail_layout = QVBoxLayout(detail)
        detail_layout.setContentsMargins(16, 14, 16, 14)
        detail_layout.setSpacing(8)
        self.detail_title = QLabel("Pick an item to see it here")
        self.detail_title.setObjectName("SectionTitle")
        detail_layout.addWidget(self.detail_title)
        self.detail_lines = QLabel("")
        self.detail_lines.setWordWrap(True)
        detail_layout.addWidget(self.detail_lines)
        self.revealed = QPlainTextEdit()
        self.revealed.setReadOnly(True)
        self.revealed.setMaximumHeight(110)
        self.revealed.hide()
        # Shown for looking; the Copy button is the tracked road
        # out, so selection and native copy are off here too.
        self.revealed.setTextInteractionFlags(Qt.NoTextInteraction)
        _lock_down_copy(self.revealed)
        detail_layout.addWidget(self.revealed)
        self._hide_timer = QTimer(self)
        self._hide_timer.setSingleShot(True)
        self._hide_timer.timeout.connect(self._auto_hide)
        row = QHBoxLayout()
        self.reveal_button = QPushButton("Show it")
        self.reveal_button.clicked.connect(self._toggle_reveal)
        row.addWidget(self.reveal_button)
        self.copy_button = QPushButton("Copy it")
        self.copy_button.clicked.connect(self._copy)
        row.addWidget(self.copy_button)
        self.save_copy_button = QPushButton("Save a copy…")
        self.save_copy_button.clicked.connect(self._save_copy)
        row.addWidget(self.save_copy_button)
        row.addStretch(1)
        detail_layout.addLayout(row)
        row2 = QHBoxLayout()
        self.edit_button = QPushButton("Change")
        self.edit_button.clicked.connect(self._edit)
        row2.addWidget(self.edit_button)
        self.delete_button = QPushButton("Delete")
        self.delete_button.clicked.connect(self._delete)
        row2.addWidget(self.delete_button)
        row2.addStretch(1)
        detail_layout.addLayout(row2)
        detail_layout.addStretch(1)
        split.addWidget(detail)
        split.setSizes([320, 460])
        root.addWidget(split, 1)
        self._set_detail_enabled(False)

    def refresh(self) -> None:
        current = self._current_id
        self.list.clear()
        self._current_id = None
        if not self._controller.is_open:
            self._show_empty_detail()
            self.banner.clear()
            return
        try:
            summaries = self._controller.list_items(self.kind_filter.currentData())
        except Exception as exc:
            self.banner.show_error(exc)
            return
        self.banner.clear()
        for summary in summaries:
            lines = [summary.title, summary.kind_label]
            if summary.kind == KIND_DOCUMENT:
                lines[1] = "Document copy — %s" % summary.filename
            item = QListWidgetItem("\n".join(lines))
            item.setData(Qt.UserRole, summary.id)
            self.list.addItem(item)
            if summary.id == current:
                self.list.setCurrentItem(item)
        if self.list.currentItem() is None:
            self._show_empty_detail()

    def wipe(self) -> None:
        self.list.clear()
        self._hide_timer.stop()
        self.revealed.clear()
        self.revealed.hide()
        self._current_id = None
        self.banner.clear()

    def _set_detail_enabled(self, enabled: bool) -> None:
        for button in (
            self.reveal_button, self.copy_button, self.save_copy_button,
            self.edit_button, self.delete_button,
        ):
            button.setEnabled(enabled)

    def _show_empty_detail(self) -> None:
        self.detail_title.setText("Pick an item to see it here")
        self.detail_lines.setText("")
        self.revealed.clear()
        self.revealed.hide()
        self._set_detail_enabled(False)

    def _current_entry(self):
        if self._current_id is None:
            return None
        try:
            return self._controller.get_item(self._current_id)
        except Exception as exc:
            self.banner.show_error(exc)
            return None

    def _selected(self, item, _previous) -> None:
        self.revealed.clear()
        self.revealed.hide()
        self.reveal_button.setText("Show it")
        if item is None:
            self._show_empty_detail()
            return
        self._current_id = item.data(Qt.UserRole)
        entry = self._current_entry()
        if entry is None:
            self._show_empty_detail()
            return
        self.detail_title.setText(entry.title)
        self.detail_lines.setText(entry.describe().split("\n", 1)[1] if "\n" in entry.describe() else "")
        is_document = entry.kind == KIND_DOCUMENT
        self.reveal_button.setEnabled(not is_document)
        self.copy_button.setEnabled(not is_document)
        self.save_copy_button.setEnabled(is_document)
        self.edit_button.setEnabled(True)
        self.delete_button.setEnabled(True)

    def _toggle_reveal(self) -> None:
        if self.revealed.isVisible():
            self._hide_timer.stop()
            self.revealed.clear()
            self.revealed.hide()
            self.reveal_button.setText("Show it")
            return
        if self._current_id is None:
            return
        try:
            body = self._controller.reveal_item(self._current_id)
        except Exception as exc:
            self.banner.show_error(exc)
            return
        self.revealed.setPlainText(body)
        self.revealed.show()
        self.reveal_button.setText("Hide it")
        self._hide_timer.start(15000)

    def _auto_hide(self) -> None:
        if self.revealed.isVisible():
            self.revealed.clear()
            self.revealed.hide()
            self.reveal_button.setText("Show it")

    def _copy(self) -> None:
        if self._current_id is None:
            return
        try:
            body = self._controller.reveal_item(self._current_id)
            self._controller.copy_text(body)
        except Exception as exc:
            self.banner.show_error(exc)

    def _save_copy(self) -> None:
        entry = self._current_entry()
        if entry is None:
            return
        chosen, _ = QFileDialog.getSaveFileName(
            self, "Save a copy of the document", entry.filename
        )
        if not chosen:
            return
        try:
            self._controller.save_document_copy(entry.id, chosen)
        except Exception as exc:
            self.banner.show_error(exc)

    def _add(self) -> None:
        dialog = ItemEditor(self._controller, self)
        if _exec_dialog(self, dialog) == QDialog.Accepted:
            self.refresh()

    def _edit(self) -> None:
        entry = self._current_entry()
        if entry is None:
            return
        dialog = ItemEditor(self._controller, self, item=entry)
        if _exec_dialog(self, dialog) == QDialog.Accepted:
            self.refresh()

    def _delete(self) -> None:
        if self._current_id is None:
            return
        if not _confirm(self, "Delete this item from the Strongbox? This can't be undone."):
            return
        try:
            self._controller.delete_item(self._current_id)
        except Exception as exc:
            self.banner.show_error(exc)
            return
        self._current_id = None
        self.refresh()


class LockSendPage(QWidget):
    """Seal one file for sending; open one that was sent to you."""

    def __init__(self, controller: VaultController, parent=None):
        super().__init__(parent)
        self._controller = controller
        self._worker = None
        self._epoch = 0
        root = QVBoxLayout(self)
        root.setContentsMargins(22, 18, 22, 18)
        root.setSpacing(12)
        title = QLabel("Lock and send")
        title.setObjectName("ScreenTitle")
        root.addWidget(title)
        self.banner = ErrorBanner()
        root.addWidget(self.banner)

        seal_box = panel()
        seal_layout = QVBoxLayout(seal_box)
        seal_layout.setContentsMargins(18, 14, 18, 14)
        seal_layout.setSpacing(10)
        seal_title = QLabel("Seal a file to send")
        seal_title.setObjectName("SectionTitle")
        seal_layout.addWidget(seal_title)
        from ..locksend import LOCK_AND_SEND_PASSWORD_NOTE

        note = QLabel(LOCK_AND_SEND_PASSWORD_NOTE)
        note.setObjectName("Faint")
        note.setWordWrap(True)
        seal_layout.addWidget(note)
        row = QHBoxLayout()
        self.seal_source = QLineEdit()
        self.seal_source.setPlaceholderText("The file to seal")
        row.addWidget(self.seal_source, 1)
        pick = QPushButton("Choose…")
        pick.clicked.connect(self._pick_seal_source)
        row.addWidget(pick)
        seal_layout.addLayout(row)
        self.seal_password = PasswordEdit("A password for this file")
        seal_layout.addWidget(self.seal_password)
        self.seal_result = QLabel("")
        self.seal_result.setObjectName("Faint")
        self.seal_result.setWordWrap(True)
        seal_layout.addWidget(self.seal_result)
        self.seal_busy = BusyBar()
        seal_layout.addWidget(self.seal_busy)
        self.seal_button = QPushButton("Seal this file")
        self.seal_button.setObjectName("Primary")
        self.seal_button.clicked.connect(self._seal)
        seal_layout.addWidget(self.seal_button)
        root.addWidget(seal_box)

        open_box = panel()
        open_layout = QVBoxLayout(open_box)
        open_layout.setContentsMargins(18, 14, 18, 14)
        open_layout.setSpacing(10)
        open_title = QLabel("Open a sealed file")
        open_title.setObjectName("SectionTitle")
        open_layout.addWidget(open_title)
        row = QHBoxLayout()
        self.open_source = QLineEdit()
        self.open_source.setPlaceholderText("The sealed file you were sent")
        row.addWidget(self.open_source, 1)
        pick = QPushButton("Choose…")
        pick.clicked.connect(self._pick_open_source)
        row.addWidget(pick)
        open_layout.addLayout(row)
        row = QHBoxLayout()
        self.open_dest = QLineEdit()
        self.open_dest.setPlaceholderText("Folder to open it into (blank = same folder)")
        row.addWidget(self.open_dest, 1)
        pick_dir = QPushButton("Choose…")
        pick_dir.clicked.connect(self._pick_open_dest)
        row.addWidget(pick_dir)
        open_layout.addLayout(row)
        self.open_password = PasswordEdit("The password for this file")
        open_layout.addWidget(self.open_password)
        self.open_result = QLabel("")
        self.open_result.setObjectName("Faint")
        self.open_result.setWordWrap(True)
        open_layout.addWidget(self.open_result)
        self.open_busy = BusyBar()
        open_layout.addWidget(self.open_busy)
        self.open_button = QPushButton("Open this file")
        self.open_button.setObjectName("Primary")
        self.open_button.clicked.connect(self._open)
        open_layout.addWidget(self.open_button)
        root.addWidget(open_box)
        root.addStretch(1)
        self.setAcceptDrops(True)

    def _pick_seal_source(self) -> None:
        chosen, _ = QFileDialog.getOpenFileName(self, "Choose the file to seal")
        if chosen:
            self.seal_source.setText(chosen)

    def _pick_open_source(self) -> None:
        chosen, _ = QFileDialog.getOpenFileName(
            self, "Choose the sealed file", "",
            "Sealed files (*.aegis-send);;All files (*)",
        )
        if chosen:
            self.open_source.setText(chosen)

    def _pick_open_dest(self) -> None:
        chosen = QFileDialog.getExistingDirectory(self, "Choose the folder")
        if chosen:
            self.open_dest.setText(chosen)

    def dragEnterEvent(self, event) -> None:
        if event.mimeData() and event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event) -> None:
        for url in event.mimeData().urls():
            if url.isLocalFile():
                path = url.toLocalFile()
                if path.endswith(".aegis-send"):
                    self.open_source.setText(path)
                else:
                    self.seal_source.setText(path)
                return

    def _seal(self) -> None:
        self.banner.clear()
        source = self.seal_source.text().strip()
        password = self.seal_password.text()
        if not source:
            self.banner.show_error("Choose the file to seal first.")
            return
        self.seal_button.setEnabled(False)
        self.seal_busy.start("Sealing…")
        epoch = self._epoch
        worker = Worker(
            lambda: self._controller.seal_a_file(source, password), self
        )
        worker.done.connect(lambda path: self._sealed(path, epoch))
        worker.failed.connect(lambda exc: self._seal_failed(exc, epoch))
        worker.start()
        self._worker = worker

    def _sealed(self, path, epoch) -> None:
        if epoch != self._epoch:
            return  # the screen was wiped (a lock) while this ran
        self.seal_busy.stop()
        self.seal_button.setEnabled(True)
        self.seal_password.clear()
        self.seal_result.setText("Sealed and ready to send: %s" % path)

    def _seal_failed(self, exc, epoch) -> None:
        if epoch != self._epoch:
            return
        self.seal_busy.stop()
        self.seal_button.setEnabled(True)
        self.seal_password.clear()
        self.banner.show_error(exc)

    def _open(self) -> None:
        self.banner.clear()
        source = self.open_source.text().strip()
        password = self.open_password.text()
        dest = self.open_dest.text().strip() or None
        if not source:
            self.banner.show_error("Choose the sealed file first.")
            return
        self.open_button.setEnabled(False)
        self.open_busy.start("Opening…")
        epoch = self._epoch
        worker = Worker(
            lambda: self._controller.open_a_sealed_file(
                source, password, dest,
                place_guard=lambda: self._epoch == epoch,
            ),
            self,
        )
        worker.done.connect(lambda path: self._opened(path, epoch))
        worker.failed.connect(lambda exc: self._open_failed(exc, epoch))
        worker.start()
        self._worker = worker

    def _opened(self, path, epoch) -> None:
        if epoch != self._epoch:
            return
        self.open_busy.stop()
        self.open_button.setEnabled(True)
        self.open_password.clear()
        self.open_result.setText("Opened: %s" % path)

    def _open_failed(self, exc, epoch) -> None:
        if epoch != self._epoch:
            return
        self.open_busy.stop()
        self.open_button.setEnabled(True)
        self.open_password.clear()
        self.banner.show_error(exc)

    def wipe(self) -> None:
        # A new epoch: output work still running from before this
        # wipe is stopped at the placing step. A worker that was
        # opening a file checks the epoch before the opened file
        # is moved into place; if the epoch has moved, the held
        # copy is removed and nothing is placed — locking the app
        # must never be followed by new plain files appearing on
        # disk behind the locked screen. (This reverses the Phase 4
        # choice, on the Phase 5 audit's finding.)
        self._epoch += 1
        self.seal_busy.stop()
        self.open_busy.stop()
        self.seal_button.setEnabled(True)
        self.open_button.setEnabled(True)
        self.seal_password.clear()
        self.open_password.clear()
        self.seal_result.setText("")
        self.open_result.setText("")
        self.banner.clear()


class ArmorPage(QWidget):
    """Backup sets: seal a whole folder; open one back into a folder."""

    def __init__(self, controller: VaultController, parent=None):
        super().__init__(parent)
        self._controller = controller
        self._worker = None
        root = QVBoxLayout(self)
        root.setContentsMargins(22, 18, 22, 18)
        root.setSpacing(12)
        title = QLabel("Backup sets")
        title.setObjectName("ScreenTitle")
        self._epoch = 0
        self._summary_timer = QTimer(self)
        self._summary_timer.setSingleShot(True)
        self._summary_timer.setInterval(250)
        self._summary_timer.timeout.connect(self._folder_summary)
        root.addWidget(title)
        intro = QLabel(
            "Seal a whole folder — a Lazarus backup above all — into "
            "one sealed file, so a lost drive is not a lost life. "
            "Nothing inside the folder is changed."
        )
        intro.setObjectName("Faint")
        intro.setWordWrap(True)
        root.addWidget(intro)
        self.banner = ErrorBanner()
        root.addWidget(self.banner)

        seal_box = panel()
        seal_layout = QVBoxLayout(seal_box)
        seal_layout.setContentsMargins(18, 14, 18, 14)
        seal_layout.setSpacing(10)
        seal_title = QLabel("Seal a folder")
        seal_title.setObjectName("SectionTitle")
        seal_layout.addWidget(seal_title)
        from ..armor import ARMOR_PASSWORD_NOTE

        note = QLabel(ARMOR_PASSWORD_NOTE)
        note.setObjectName("Faint")
        note.setWordWrap(True)
        seal_layout.addWidget(note)
        row = QHBoxLayout()
        self.seal_source = QLineEdit()
        self.seal_source.setPlaceholderText("The folder to seal")
        self.seal_source.textChanged.connect(
            lambda _t: self._summary_timer.start()
        )
        row.addWidget(self.seal_source, 1)
        pick = QPushButton("Choose…")
        pick.clicked.connect(self._pick_folder)
        row.addWidget(pick)
        seal_layout.addLayout(row)
        self.summary = QLabel("")
        self.summary.setObjectName("Faint")
        self.summary.hide()
        seal_layout.addWidget(self.summary)
        self.seal_password = PasswordEdit("A password for this set")
        seal_layout.addWidget(self.seal_password)
        self.seal_result = QLabel("")
        self.seal_result.setObjectName("Faint")
        self.seal_result.setWordWrap(True)
        seal_layout.addWidget(self.seal_result)
        self.seal_busy = BusyBar()
        seal_layout.addWidget(self.seal_busy)
        self.seal_button = QPushButton("Seal this folder")
        self.seal_button.setObjectName("Primary")
        self.seal_button.clicked.connect(self._seal)
        seal_layout.addWidget(self.seal_button)
        root.addWidget(seal_box)

        open_box = panel()
        open_layout = QVBoxLayout(open_box)
        open_layout.setContentsMargins(18, 14, 18, 14)
        open_layout.setSpacing(10)
        open_title = QLabel("Open a sealed set")
        open_title.setObjectName("SectionTitle")
        open_layout.addWidget(open_title)
        row = QHBoxLayout()
        self.open_source = QLineEdit()
        self.open_source.setPlaceholderText("The sealed set")
        row.addWidget(self.open_source, 1)
        pick = QPushButton("Choose…")
        pick.clicked.connect(self._pick_set)
        row.addWidget(pick)
        open_layout.addLayout(row)
        self.open_password = PasswordEdit("The password for this set")
        open_layout.addWidget(self.open_password)
        look = QPushButton("Look inside")
        look.clicked.connect(self._look)
        open_layout.addWidget(look)
        self.contents = QListWidget()
        self.contents.setMaximumHeight(130)
        self.contents.hide()
        open_layout.addWidget(self.contents)
        row = QHBoxLayout()
        self.dest_parent = QLineEdit()
        self.dest_parent.setPlaceholderText("Folder to open it into")
        row.addWidget(self.dest_parent, 1)
        pick_dir = QPushButton("Choose…")
        pick_dir.clicked.connect(self._pick_dest_parent)
        row.addWidget(pick_dir)
        open_layout.addLayout(row)
        self.dest_name = QLineEdit()
        self.dest_name.setPlaceholderText("New folder name for it")
        open_layout.addWidget(self.dest_name)
        self.open_result = QLabel("")
        self.open_result.setObjectName("Faint")
        self.open_result.setWordWrap(True)
        open_layout.addWidget(self.open_result)
        self.open_busy = BusyBar()
        open_layout.addWidget(self.open_busy)
        self.unseal_button = QPushButton("Open this set")
        self.unseal_button.setObjectName("Primary")
        self.unseal_button.clicked.connect(self._unseal)
        open_layout.addWidget(self.unseal_button)
        root.addWidget(open_box)
        root.addStretch(1)

    def _pick_folder(self) -> None:
        chosen = QFileDialog.getExistingDirectory(self, "Choose the folder to seal")
        if chosen:
            self.seal_source.setText(chosen)

    def _folder_summary(self) -> None:
        folder = Path(self.seal_source.text().strip())
        if not folder.is_dir():
            self.summary.setText("")
            self.summary.hide()
            return
        # Mirror the core's own scan: links are never sealed, so
        # they are never counted here either — the summary says
        # what sealing will actually do, links named plainly.
        count, total, links = 0, 0, 0
        for root_dir, dirs, files in os.walk(folder):
            for name in dirs:
                if os.path.islink(os.path.join(root_dir, name)):
                    links += 1
            dirs[:] = [
                d for d in dirs
                if not os.path.islink(os.path.join(root_dir, d))
            ]
            for name in files:
                path = os.path.join(root_dir, name)
                if os.path.islink(path):
                    links += 1
                    continue
                count += 1
                try:
                    total += os.path.getsize(path)
                except OSError:
                    pass
        text = "%d files, about %s to seal." % (count, _human_size(total))
        if links:
            text += (
                " This folder also holds %d link%s — Aegis never "
                "seals links, so take them out first."
                % (links, "s" if links != 1 else "")
            )
        self.summary.setText(text)
        self.summary.show()

    def _pick_set(self) -> None:
        chosen, _ = QFileDialog.getOpenFileName(
            self, "Choose the sealed set", "",
            "Sealed sets (*.aegis-armored);;All files (*)",
        )
        if chosen:
            self.open_source.setText(chosen)
            name = Path(chosen).name
            if name.endswith(".aegis-armored"):
                self.dest_name.setText(name[: -len(".aegis-armored")])
            self.dest_parent.setText(str(Path(chosen).parent))

    def _pick_dest_parent(self) -> None:
        chosen = QFileDialog.getExistingDirectory(self, "Choose the folder")
        if chosen:
            self.dest_parent.setText(chosen)

    def _seal(self) -> None:
        self.banner.clear()
        folder = self.seal_source.text().strip()
        password = self.seal_password.text()
        if not folder:
            self.banner.show_error("Choose the folder to seal first.")
            return
        self.seal_button.setEnabled(False)
        self.seal_busy.start("Sealing the folder…")
        epoch = self._epoch
        worker = Worker(
            lambda: self._controller.seal_a_folder(folder, password), self
        )
        worker.done.connect(lambda path: self._sealed(path, epoch))
        worker.failed.connect(lambda exc: self._failed(exc, epoch))
        worker.start()
        self._worker = worker

    def _look(self) -> None:
        self.banner.clear()
        source = self.open_source.text().strip()
        password = self.open_password.text()
        if not source:
            self.banner.show_error("Choose the sealed set first.")
            return
        try:
            manifest = self._controller.look_inside_set(source, password)
        except Exception as exc:
            self.banner.show_error(exc)
            return
        self.contents.clear()
        self.contents.show()
        for info in manifest.files:
            self.contents.addItem(
                "%s — %s" % (info.path, _human_size(info.size))
            )
        self.contents.addItem(
            "In all: %d files, %s"
            % (len(manifest.files), _human_size(manifest.total_bytes))
        )

    def _unseal(self) -> None:
        self.banner.clear()
        source = self.open_source.text().strip()
        password = self.open_password.text()
        parent = self.dest_parent.text().strip()
        name = self.dest_name.text().strip()
        if not source:
            self.banner.show_error("Choose the sealed set first.")
            return
        if not parent or not name:
            self.banner.show_error(
                "Choose where the folder should open, and its new name."
            )
            return
        destination = Path(parent) / name
        self.unseal_button.setEnabled(False)
        self.open_busy.start("Opening the set…")
        epoch = self._epoch
        worker = Worker(
            lambda: self._controller.unseal_a_set(
                source, password, destination,
                place_guard=lambda: self._epoch == epoch,
            ),
            self,
        )
        worker.done.connect(lambda path: self._unsealed(path, epoch))
        worker.failed.connect(lambda exc: self._failed_open(exc, epoch))
        worker.start()
        self._worker = worker

    def _sealed(self, path, epoch) -> None:
        if epoch != self._epoch:
            return  # wiped (a lock) while this ran; land nowhere
        self.seal_busy.stop()
        self.seal_button.setEnabled(True)
        self.seal_password.clear()
        self.seal_result.setText("Sealed: %s" % path)

    def _failed(self, exc, epoch) -> None:
        if epoch != self._epoch:
            return
        self.seal_busy.stop()
        self.seal_button.setEnabled(True)
        self.seal_password.clear()
        self.banner.show_error(exc)

    def _unsealed(self, path, epoch) -> None:
        if epoch != self._epoch:
            return
        self.open_busy.stop()
        self.unseal_button.setEnabled(True)
        self.open_password.clear()
        self.open_result.setText("Opened into: %s" % path)

    def _failed_open(self, exc, epoch) -> None:
        if epoch != self._epoch:
            return
        self.open_busy.stop()
        self.unseal_button.setEnabled(True)
        self.open_password.clear()
        self.banner.show_error(exc)

    def wipe(self) -> None:
        self._epoch += 1
        self.seal_busy.stop()
        self.open_busy.stop()
        self.seal_button.setEnabled(True)
        self.unseal_button.setEnabled(True)
        self.seal_password.clear()
        self.open_password.clear()
        self.contents.clear()
        self.contents.hide()
        self.summary.setText("")
        self.summary.hide()
        self.seal_result.setText("")
        self.open_result.setText("")
        self.banner.clear()


def _human_size(size: int) -> str:
    if size < 1024:
        return "%d bytes" % size
    if size < 1024 * 1024:
        return "%.1f KB" % (size / 1024)
    if size < 1024 * 1024 * 1024:
        return "%.1f MB" % (size / (1024 * 1024))
    return "%.2f GB" % (size / (1024 * 1024 * 1024))


class SettingsPage(QWidget):
    """Timing, vault care: password change, recovery key, copies."""

    recovery_sheet_requested = Signal(str)  # new recovery key

    def __init__(self, controller: VaultController, parent=None):
        super().__init__(parent)
        self._controller = controller
        root = QVBoxLayout(self)
        root.setContentsMargins(22, 18, 22, 18)
        root.setSpacing(12)
        title = QLabel("Settings and vault care")
        title.setObjectName("ScreenTitle")
        root.addWidget(title)
        self.banner = ErrorBanner()
        root.addWidget(self.banner)
        self.status = QLabel("")
        self.status.setObjectName("Faint")
        root.addWidget(self.status)

        timing = panel()
        timing_layout = QVBoxLayout(timing)
        timing_layout.setContentsMargins(18, 14, 18, 14)
        timing_layout.setSpacing(10)
        t = QLabel("Locking and the clipboard")
        t.setObjectName("SectionTitle")
        timing_layout.addWidget(t)
        form = QFormLayout()
        form.setSpacing(10)
        self.idle_minutes = QSpinBox()
        self.idle_minutes.setRange(1, 120)
        self.idle_minutes.setMaximumWidth(180)
        self.idle_minutes.setValue(int(controller.idle_seconds // 60) or 5)
        form_row(form, "Lock after quiet minutes", self.idle_minutes)
        self.clear_seconds = QSpinBox()
        self.clear_seconds.setRange(5, 300)
        self.clear_seconds.setMaximumWidth(180)
        self.clear_seconds.setValue(int(controller.clear_after_seconds))
        form_row(form, "Seconds a copied password stays", self.clear_seconds)
        timing_layout.addLayout(form)
        apply_button = QPushButton("Use these settings")
        apply_button.clicked.connect(self._apply)
        timing_layout.addWidget(apply_button)
        root.addWidget(timing)

        care = panel()
        care_layout = QVBoxLayout(care)
        care_layout.setContentsMargins(18, 14, 18, 14)
        care_layout.setSpacing(10)
        c = QLabel("Care for this vault")
        c.setObjectName("SectionTitle")
        care_layout.addWidget(c)
        self.new_password = PasswordEdit("A new master password")
        care_layout.addWidget(self.new_password)
        self.new_confirm = PasswordEdit("Type it once more")
        care_layout.addWidget(self.new_confirm)
        change = QPushButton("Change master password")
        change.clicked.connect(self._change_password)
        care_layout.addWidget(change)
        new_key = QPushButton("Make a new recovery key")
        new_key.clicked.connect(self._new_key)
        care_layout.addWidget(new_key)
        note = QLabel(
            "A new recovery key replaces the old one — the old sheet "
            "stops working. Print the new sheet and keep it safe."
        )
        note.setObjectName("Faint")
        note.setWordWrap(True)
        care_layout.addWidget(note)
        copy_button = QPushButton("Save a sealed copy of this vault…")
        copy_button.clicked.connect(self._export)
        care_layout.addWidget(copy_button)
        import_button = QPushButton("Bring in logins from another vault…")
        import_button.clicked.connect(self._import)
        care_layout.addWidget(import_button)
        root.addWidget(care)
        root.addStretch(1)

    def _apply(self) -> None:
        self._controller.apply_settings(
            idle_seconds=self.idle_minutes.value() * 60,
            clear_after_seconds=self.clear_seconds.value(),
        )
        self.status.setText("Settings are in use for this time in Aegis.")

    def _change_password(self) -> None:
        self.banner.clear()
        if self.new_password.text() != self.new_confirm.text():
            self.banner.show_error(
                "The two passwords don't match. Type them both again."
            )
            return
        try:
            self._controller.change_password(self.new_password.text())
        except Exception as exc:
            self.banner.show_error(exc)
        else:
            self.status.setText("Your master password has been changed.")
        finally:
            self.new_password.clear()
            self.new_confirm.clear()

    def _new_key(self) -> None:
        if not _confirm(self, "Make a new recovery key? The old one stops working right away."):
            return
        try:
            key = self._controller.new_recovery_key()
        except Exception as exc:
            self.banner.show_error(exc)
            return
        self.recovery_sheet_requested.emit(key)

    def _export(self) -> None:
        chosen, _ = QFileDialog.getSaveFileName(
            self, "Save a sealed copy of this vault", "vault-copy.aegis",
            "Aegis vaults (*.aegis)",
        )
        if not chosen:
            return
        try:
            path = self._controller.export_copy(chosen)
        except Exception as exc:
            self.banner.show_error(exc)
            return
        self.status.setText("Sealed copy saved: %s" % path)

    def _import(self) -> None:
        chosen, _ = QFileDialog.getOpenFileName(
            self, "Choose the other vault", "",
            "Aegis vaults (*.aegis);;All files (*)",
        )
        if not chosen:
            return
        dialog = QDialog(self)
        dialog.setWindowTitle("Aegis")
        layout = QVBoxLayout(dialog)
        layout.addWidget(QLabel("What is that vault's master password?"))
        field = PasswordEdit("Its master password")
        layout.addWidget(field)
        row = QHBoxLayout()
        row.addStretch(1)
        cancel = QPushButton("Cancel")
        cancel.clicked.connect(dialog.reject)
        row.addWidget(cancel)
        go = QPushButton("Bring them in")
        go.setObjectName("Primary")
        go.clicked.connect(dialog.accept)
        row.addWidget(go)
        layout.addLayout(row)
        banner = ErrorBanner()
        layout.addWidget(banner)
        # Under the window's dialog discipline: a lock closes it,
        # and however it ends — brought in, cancelled, or closed
        # by a lock — the other vault's password leaves the field
        # and the dialog is disposed of.
        window = self.window()
        tracked = isinstance(window, MainWindow)
        if tracked:
            window._track_dialog(dialog)
        try:
            while True:
                if dialog.exec() != QDialog.Accepted:
                    return
                try:
                    count = self._controller.import_logins(chosen, field.text())
                except Exception as exc:
                    banner.show_error(exc)
                    field.clear()
                    continue
                self.status.setText(
                    "Brought in %d login%s."
                    % (count, "" if count == 1 else "s")
                )
                return
        finally:
            if tracked:
                window._release_dialog(dialog)
            field.clear()
            dialog.deleteLater()

    def wipe(self) -> None:
        self.new_password.clear()
        self.new_confirm.clear()
        self.banner.clear()
        self.status.setText("")


# ---------------------------------------------------------------------------
# The main screen — everything in the vault, and the one Lock button
# ---------------------------------------------------------------------------


class MainScreen(QWidget):
    """The opened vault: sections on the left, work on the right."""

    lock_requested = Signal()
    recovery_sheet_requested = Signal(str)

    SECTIONS = (
        ("Passwords", "passwords"),
        ("Make a password", "generator"),
        ("Strongbox", "strongbox"),
        ("Lock and send", "locksend"),
        ("Backup sets", "armor"),
        ("Settings", "settings"),
    )

    def __init__(self, controller: VaultController, parent=None):
        super().__init__(parent)
        self._controller = controller
        root = QHBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(216)
        side = QVBoxLayout(sidebar)
        side.setContentsMargins(14, 18, 14, 14)
        side.setSpacing(6)
        mark = QLabel()
        mark.setPixmap(shield_pixmap(40))
        side.addWidget(mark)
        brand = QLabel("AEGIS")
        brand.setObjectName("SectionTitle")
        side.addWidget(brand)
        self.vault_label = QLabel("")
        self.vault_label.setObjectName("Faint")
        self.vault_label.setWordWrap(True)
        side.addWidget(self.vault_label)
        side.addSpacing(12)

        self._nav = {}
        for label, key in self.SECTIONS:
            button = QPushButton(label)
            button.setObjectName("Nav")
            button.setCheckable(True)
            button.clicked.connect(lambda _c, k=key: self.show_section(k))
            side.addWidget(button)
            self._nav[key] = button
        side.addStretch(1)
        self.lock_button = QPushButton("Lock")
        self.lock_button.setObjectName("Primary")
        self.lock_button.clicked.connect(self.lock_requested)
        side.addWidget(self.lock_button)
        root.addWidget(sidebar)

        self.pages = QStackedWidget()
        self.passwords_page = PasswordsPage(controller)
        self.generator_page = GeneratorPage(controller)
        self.strongbox_page = StrongboxPage(controller)
        self.locksend_page = LockSendPage(controller)
        self.armor_page = ArmorPage(controller)
        self.settings_page = SettingsPage(controller)
        self.settings_page.recovery_sheet_requested.connect(
            self.recovery_sheet_requested
        )
        self.generator_page.use_in_login.connect(self._use_in_login)
        self._page_by_key = {
            "passwords": self.passwords_page,
            "generator": self.generator_page,
            "strongbox": self.strongbox_page,
            "locksend": self.locksend_page,
            "armor": self.armor_page,
            "settings": self.settings_page,
        }
        for _label, key in self.SECTIONS:
            self.pages.addWidget(self._page_by_key[key])
        root.addWidget(self.pages, 1)
        self.show_section("passwords")

    def show_section(self, key: str) -> None:
        for nav_key, button in self._nav.items():
            button.setChecked(nav_key == key)
        page = self._page_by_key[key]
        self.pages.setCurrentWidget(page)
        _fade_in(page)
        if key == "passwords":
            self.passwords_page.refresh()
        elif key == "strongbox":
            self.strongbox_page.refresh()
        elif key == "generator" and not self.generator_page.last_made:
            self.generator_page.make_one()

    def _use_in_login(self) -> None:
        self.show_section("passwords")
        dialog = LoginEditor(
            self._controller, self,
            prefill_password=self.generator_page.last_made,
        )
        if _exec_dialog(self, dialog) == QDialog.Accepted:
            self.generator_page.wipe()
            self.passwords_page.refresh()

    def enter(self, vault_name: str) -> None:
        self.vault_label.setText(vault_name)
        self.show_section("passwords")

    def wipe(self) -> None:
        """Blank every page before the locked screen shows."""
        self.vault_label.setText("")
        self.passwords_page.wipe()
        self.generator_page.wipe()
        self.strongbox_page.wipe()
        self.locksend_page.wipe()
        self.armor_page.wipe()
        self.settings_page.wipe()
        self.show_section("passwords")


def _fade_in(widget: QWidget) -> None:
    effect = QGraphicsOpacityEffect(widget)
    widget.setGraphicsEffect(effect)
    animation = QPropertyAnimation(effect, b"opacity", widget)
    animation.setDuration(160)
    animation.setStartValue(0.25)
    animation.setEndValue(1.0)
    animation.finished.connect(lambda: widget.setGraphicsEffect(None))
    animation.start()
    widget._fade_animation = animation


# ---------------------------------------------------------------------------
# The window
# ---------------------------------------------------------------------------


class _ActivityFilter(QObject):
    """Reports real activity — keys and pointer — to the idle guard."""

    def __init__(self, callback, parent=None):
        super().__init__(parent)
        self._callback = callback

    def eventFilter(self, obj, event) -> bool:
        if event.type() in (
            QEvent.KeyPress,
            QEvent.MouseButtonPress,
            QEvent.Wheel,
            QEvent.TouchBegin,
        ):
            self._callback()
        return False


class MainWindow(QMainWindow):
    """The Aegis window: locked screen, setup, key sheet, main."""

    def __init__(self, controller: VaultController = None, parent=None,
                 install_offer=None):
        super().__init__(parent)
        self._controller = controller or VaultController()
        self._install_offer = (
            install_offer if install_offer is not None else InstallOffer()
        )
        self.setWindowTitle(WINDOW_TITLE)
        self.resize(1120, 720)
        self.setMinimumSize(900, 600)

        self.stack = QStackedWidget()
        self.setCentralWidget(self.stack)
        self.locked_screen = LockedScreen()
        self.setup_screen = SetupScreen(self._controller)
        self.sheet_screen = RecoverySheet()
        self.main_screen = MainScreen(self._controller)
        for screen in (
            self.locked_screen,
            self.setup_screen,
            self.sheet_screen,
            self.main_screen,
        ):
            self.stack.addWidget(screen)
        self.stack.setCurrentWidget(self.locked_screen)

        self.locked_screen.unlock_requested.connect(self._unlock)
        self.locked_screen.create_requested.connect(
            lambda: self._go(self.setup_screen)
        )
        self.setup_screen.back_requested.connect(self._leave_setup)
        self.setup_screen.created.connect(self._vault_created)
        self.sheet_screen.done.connect(self._sheet_done)
        self.main_screen.lock_requested.connect(self._lock_now)
        self.main_screen.recovery_sheet_requested.connect(
            self._show_new_key_sheet
        )
        self._controller.on_lock = self._locked_by_guard
        self._controller.on_error = self._guard_error

        self._timer = QTimer(self)
        self._timer.setInterval(400)
        self._timer.timeout.connect(self._controller.tick)
        self._timer.start()
        self._activity = _ActivityFilter(self._controller.touch, self)
        from PySide6.QtWidgets import QApplication

        app = QApplication.instance()
        if app is not None:
            app.installEventFilter(self._activity)
        self._unlock_worker = None
        self._pending_vault_name = ""
        self._auth_busy = False
        self._open_dialogs = []
        self._install_offer_handled = False
        self._install_dialog = None
        self._install_worker = None
        self.setup_screen.auth_gate = (
            self._try_begin_auth,
            self._end_auth,
        )

    def _leave_setup(self) -> None:
        # Typed master passwords never linger on a screen the
        # person has walked away from — including via Back.
        self.setup_screen.wipe_secrets()
        self._go(self.locked_screen)

    # -- navigation ----------------------------------------------------

    def _go(self, screen: QWidget) -> None:
        if screen is not self.locked_screen:
            self._dismiss_install_offer()
        self.stack.setCurrentWidget(screen)
        _fade_in(screen)

    # -- the one-at-a-time gate for opening and creating --------------

    def _try_begin_auth(self) -> bool:
        """Claim the single auth slot; False if one is running.

        An unlock and a create can never be in flight together,
        and neither can start twice: two opens racing would race
        the controller's session, and the loser would be orphaned
        unlocked, its key never wiped.
        """
        if self._auth_busy:
            return False
        self._auth_busy = True
        return True

    def _end_auth(self) -> None:
        self._auth_busy = False

    # -- dialog tracking (a lock closes what is open) -------------------

    def _track_dialog(self, dialog: QDialog) -> None:
        self._open_dialogs.append(dialog)

    def _release_dialog(self, dialog: QDialog) -> None:
        if dialog in self._open_dialogs:
            self._open_dialogs.remove(dialog)

    def _close_open_dialogs(self) -> None:
        for dialog in list(self._open_dialogs):
            wipe = getattr(dialog, "wipe", None)
            if wipe is not None:
                wipe()
            dialog.reject()

    # -- the first-run install offer --------------------------------

    def maybe_offer_install(self) -> None:
        """Offer to install this copy, once, over the locked screen.

        Modeless, by design: the offer never stands in the way of
        the one Unlock. It is made only while the locked screen is
        showing, only when the policy for this copy says it is
        needed, and only once per run — accepted, declined, or
        dismissed, it does not come back.
        """
        if self._install_offer_handled:
            return
        if self.stack.currentWidget() is not self.locked_screen:
            return
        if not self._install_offer.needed():
            return
        self._install_offer_handled = True
        dialog = InstallOfferDialog(self)
        self._install_dialog = dialog
        self._track_dialog(dialog)
        dialog.install_button.clicked.connect(
            lambda _checked=False, d=dialog: self._accept_install_offer(d)
        )
        dialog.finished.connect(
            lambda _result, d=dialog: self._install_dialog_finished(d)
        )
        dialog.show()

    def _install_dialog_finished(self, dialog) -> None:
        self._release_dialog(dialog)
        if self._install_dialog is dialog:
            self._install_dialog = None
        dialog.deleteLater()

    def _dismiss_install_offer(self) -> None:
        """End the offer if it is standing; its cleanup runs itself."""
        dialog = self._install_dialog
        if dialog is not None:
            dialog.reject()

    def _accept_install_offer(self, dialog) -> None:
        if self._install_dialog is not dialog:
            return
        if self._install_worker is not None and self._install_worker.isRunning():
            return
        dialog.begin_install()
        worker = Worker(self._install_offer.run, self)
        worker.done.connect(
            lambda result, d=dialog: self._install_done(result, d)
        )
        worker.failed.connect(
            lambda exc, d=dialog: self._install_failed(exc, d)
        )
        worker.start()
        self._install_worker = worker

    def _install_done(self, result, dialog) -> None:
        # A result that lands after the dialog has gone — closed,
        # or closed by a lock — lands nowhere: the person has
        # moved on, and nothing pops back up behind them.
        if self._install_dialog is not dialog:
            return
        ok, message = result
        dialog.show_result(ok, message)

    def _install_failed(self, exc, dialog) -> None:
        if self._install_dialog is not dialog:
            return
        dialog.show_result(False, user_text(exc))

    # -- unlock / create -------------------------------------------------

    def _unlock(self) -> None:
        self._dismiss_install_offer()
        screen = self.locked_screen
        screen.banner.clear()
        path = screen.vault_path()
        if not path:
            screen.banner.show_error(
                "Choose your vault file first — Browse to find it."
            )
            return
        if not self._try_begin_auth():
            return
        credential = screen.credential_text()
        screen.set_busy(True, "Opening your vault…")
        if screen.using_recovery():
            fn = lambda: self._controller.open_vault(
                path, recovery_key=credential
            )
        else:
            fn = lambda: self._controller.open_vault(
                path, password=credential
            )
        worker = Worker(fn, self)
        worker.done.connect(lambda _r: self._unlocked(path))
        worker.failed.connect(self._unlock_failed)
        worker.start()
        self._unlock_worker = worker

    def _unlocked(self, path: str) -> None:
        self._end_auth()
        screen = self.locked_screen
        screen.set_busy(False)
        screen.wipe_credential()
        screen.play_seam(True)
        self._pending_vault_name = Path(path).name
        self.main_screen.enter(self._pending_vault_name)
        self._go(self.main_screen)

    def _unlock_failed(self, exc) -> None:
        self._end_auth()
        screen = self.locked_screen
        screen.set_busy(False)
        screen.wipe_credential()
        screen.banner.show_error(exc)

    def _vault_created(self, recovery_key, display_name) -> None:
        self._pending_vault_name = (
            self._controller.vault_path.name
            if self._controller.vault_path
            else display_name
        )
        self.sheet_screen.show_key(display_name or "my-vault", recovery_key)
        self._go(self.sheet_screen)

    def _show_new_key_sheet(self, recovery_key) -> None:
        name = (
            self._controller.vault_path.name
            if self._controller.vault_path
            else "my-vault"
        )
        self.sheet_screen.show_key(name, recovery_key)
        self._go(self.sheet_screen)

    def _sheet_done(self) -> None:
        self.sheet_screen.wipe()
        if self._controller.is_open:
            self.main_screen.enter(self._pending_vault_name)
            self._go(self.main_screen)
        else:
            self._go(self.locked_screen)

    # -- locking ----------------------------------------------------------

    def _lock_now(self) -> None:
        try:
            self._controller.lock()
        except Exception as exc:
            QMessageBox.warning(self, "Aegis", user_text(exc))
            return
        self._after_lock()

    def _locked_by_guard(self) -> None:
        self._after_lock()

    def _after_lock(self) -> None:
        # The funnel every lock passes through — button, idle,
        # close. Order matters: dialogs first (they float above
        # everything, holding what was typed), then every screen,
        # so nothing from inside the vault survives anywhere.
        # The vault's path stays in its field deliberately: it is
        # the person's own file, in the place they keep it, and
        # the locked screen must offer one-step re-entry — the
        # name of a file is not the vault's contents.
        self._close_open_dialogs()
        self.sheet_screen.wipe()
        self.setup_screen.wipe_secrets()
        self.main_screen.wipe()
        self.locked_screen.wipe_credential()
        self.locked_screen.play_seam(False)
        self._go(self.locked_screen)

    def _guard_error(self, exc) -> None:
        # An idle lock failed (the core could not save). Say so on
        # the main screen; the guard retries on its own rhythm.
        if self.stack.currentWidget() is self.main_screen:
            self.main_screen.passwords_page.banner.show_error(exc)
            self.main_screen.show_section("passwords")

    def closeEvent(self, event) -> None:
        # Workers first, before anything else — even before the
        # final lock, which must never race work in flight. A
        # worker thread (a seal, an unlock) is this window's
        # child, and a QThread destroyed while it is still
        # running aborts the whole process. Most workers are
        # short, so give each a bounded wait to finish; but a
        # long one — sealing a very large file can run for
        # minutes — must not be waited out and then closed over
        # anyway. If any worker is still running after its wait,
        # the close is refused and the window stays open with
        # the work's own busy display showing; closing again
        # once the work has finished closes normally. (The same
        # refusal the medic kit's other windows make: a run in
        # flight is never interrupted by closing.)
        running = [
            thread for thread in self.findChildren(QThread)
            if thread.isRunning()
        ]
        for thread in running:
            thread.wait(5000)
        if any(thread.isRunning() for thread in running):
            event.ignore()
            return
        self._close_open_dialogs()
        try:
            self._controller.lock()
        except Exception:
            # The vault file on disk is sealed at all times; a
            # failed final save is reported the next time the vault
            # is opened, by the core's own freshness checks.
            pass
        super().closeEvent(event)


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------


def build_window(controller: VaultController = None) -> MainWindow:
    """Build the main window (used by the app and the smoke checks)."""
    from .clipboard_qt import QtClipboard

    if controller is None:
        controller = VaultController(QtClipboard())
    return MainWindow(controller)


def self_check() -> int:
    """Construct the whole window offscreen and report success.

    The packaging smoke hook: proves the app imports, the window
    builds, and every screen constructs, without showing anything.
    Offscreen is forced, not conditional — a set-but-dead display
    must not fail a check that never shows a window. The window is
    built the way run() builds it: the real clipboard seam and
    the real stylesheet in place.
    """
    import os as _os

    _os.environ["QT_QPA_PLATFORM"] = "offscreen"
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([])
    app.setStyleSheet(theme.stylesheet())
    window = build_window()
    for key in ("passwords", "generator", "strongbox", "locksend",
                "armor", "settings"):
        window.main_screen.show_section(key)
    window.main_screen.show_section("passwords")
    app.processEvents()
    print("Aegis self-check OK: the window and every screen build.")
    return 0


def run(argv=None) -> int:
    """Run the Aegis app."""
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([])
    app.setApplicationName("Aegis")
    app.setStyleSheet(theme.stylesheet())
    window = build_window()
    window.show()
    QTimer.singleShot(0, window.maybe_offer_install)
    return app.exec()
