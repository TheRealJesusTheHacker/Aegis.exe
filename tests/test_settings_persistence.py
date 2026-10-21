"""Saved timings: the settings screen's two numbers, kept
between runs.

The settings are preferences, never secrets, and they are held
to the settings screen's own ranges wherever they come from.
A missing or damaged settings file changes nothing — the
built-in defaults stand and nothing raises — because a damaged
preferences file must never stand between a person and their
vault.
"""

import json

from aegis.clipboard import DEFAULT_CLEAR_AFTER_SECONDS, MemoryClipboard
from aegis.idle import DEFAULT_IDLE_SECONDS
from aegis.settings import load_settings, save_settings
from aegis.ui.controllers import VaultController


def _controller(path=None):
    if path is None:
        return VaultController(MemoryClipboard())
    return VaultController(MemoryClipboard(), settings_path=path)


def test_applied_settings_are_saved_and_reloaded(tmp_path):
    path = tmp_path / "settings.json"
    first = _controller(path)
    first.apply_settings(idle_seconds=900, clear_after_seconds=45)
    assert json.loads(path.read_text(encoding="utf-8")) == {
        "idle_seconds": 900.0,
        "clear_after_seconds": 45.0,
    }
    second = _controller(path)
    assert second.idle_seconds == 900.0
    assert second.clear_after_seconds == 45.0


def test_no_settings_file_means_the_defaults(tmp_path):
    controller = _controller(tmp_path / "absent.json")
    assert controller.idle_seconds == DEFAULT_IDLE_SECONDS
    assert controller.clear_after_seconds == DEFAULT_CLEAR_AFTER_SECONDS


def test_without_a_settings_path_nothing_is_written(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    controller = _controller()
    controller.apply_settings(idle_seconds=600, clear_after_seconds=60)
    assert controller.idle_seconds == 600.0
    assert not list(tmp_path.iterdir())


def test_a_damaged_settings_file_is_ignored_not_fatal(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text("{ this is not json", encoding="utf-8")
    controller = _controller(path)
    assert controller.idle_seconds == DEFAULT_IDLE_SECONDS
    assert controller.clear_after_seconds == DEFAULT_CLEAR_AFTER_SECONDS


def test_out_of_range_saved_values_are_ignored_one_by_one(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text(
        json.dumps({"idle_seconds": 30, "clear_after_seconds": 120}),
        encoding="utf-8",
    )
    controller = _controller(path)
    # 30 seconds is below the screen's own floor: default stands.
    assert controller.idle_seconds == DEFAULT_IDLE_SECONDS
    # 120 seconds is inside its range: it is used.
    assert controller.clear_after_seconds == 120.0


def test_a_failed_save_is_reported_and_the_run_still_applies(tmp_path):
    # A directory where the file should go cannot be written.
    controller = _controller(tmp_path)
    controller.apply_settings(idle_seconds=600, clear_after_seconds=60)
    assert controller.settings_save_failed
    assert controller.idle_seconds == 600.0
    assert controller.clear_after_seconds == 60.0


def test_save_settings_refuses_out_of_range_values(tmp_path):
    path = tmp_path / "settings.json"
    assert not save_settings(path, idle_seconds=10, clear_after_seconds=30)
    assert not path.exists()
    assert load_settings(path) == {}
