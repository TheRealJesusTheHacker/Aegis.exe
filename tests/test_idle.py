"""Phase 2 lock-on-idle tests: the policy, driven by a fake clock.

The promise under test: leave an open vault alone past the period
the person set, and it locks itself — the session wipes its keys
(the Phase 1 lock) and the credential store forgets its list.
Activity starts the quiet period over.
"""

import pytest

from aegis import Vault
from aegis.credentials import CredentialStore
from aegis.errors import VaultLockedError
from aegis.idle import IdleGuard
from tests.conftest import PASSWORD
from tests.test_clipboard import FakeClock
from tests.test_credentials_store import FAKE


@pytest.fixture
def rig(create_vault):
    created, path = create_vault()
    store = CredentialStore(created.session)
    store.add(**FAKE)
    clock = FakeClock()
    guard = IdleGuard([store.lock], idle_seconds=120.0, clock=clock)
    return guard, store, created, clock


def test_no_lock_before_the_period(rig):
    guard, store, created, clock = rig
    clock.advance(119.0)
    assert guard.check() is False
    assert not created.session.is_locked
    assert len(store) == 1


def test_locks_at_the_period(rig):
    guard, store, created, clock = rig
    clock.advance(120.0)
    assert guard.check() is True
    assert created.session.is_locked
    # The store forgot its list at the same moment.
    assert store._entries is None
    with pytest.raises(VaultLockedError):
        store.summaries()


def test_check_fires_only_once(rig):
    guard, _, _, clock = rig
    clock.advance(120.0)
    assert guard.check() is True
    assert guard.check() is False


def test_activity_starts_the_quiet_over(rig):
    guard, _, created, clock = rig
    clock.advance(100.0)
    guard.touch()
    clock.advance(100.0)
    assert guard.check() is False
    assert not created.session.is_locked
    clock.advance(20.0)
    assert guard.check() is True


def test_disabled_guard_never_locks(rig):
    guard, _, created, clock = rig
    guard.set_enabled(False)
    clock.advance(10000.0)
    assert guard.check() is False
    assert not created.session.is_locked


def test_reenabling_starts_a_fresh_period(rig):
    guard, _, created, clock = rig
    guard.set_enabled(False)
    clock.advance(10000.0)
    guard.set_enabled(True)
    clock.advance(119.0)
    assert guard.check() is False
    clock.advance(1.0)
    assert guard.check() is True


def test_idle_lock_preserves_the_vault(rig, tmp_path):
    guard, store, created, clock = rig
    clock.advance(120.0)
    assert guard.check() is True
    reopened = CredentialStore(
        Vault.open(created.session.path, password=PASSWORD)
    )
    assert len(reopened) == 1


def test_invalid_period_refused():
    with pytest.raises(ValueError):
        IdleGuard([lambda: None], idle_seconds=0)


def test_failing_lockable_does_not_starve_the_rest():
    # Audit regression (Phase 2, A-1): every lockable runs even if
    # an earlier one fails, the failure is raised, and the guard
    # does not count itself fired — the next check retries, because
    # a vault that would not lock is still open.
    calls = []
    state = {"fail": True}

    def flaky():
        calls.append("flaky")
        if state["fail"]:
            raise RuntimeError("save failed")

    def other():
        calls.append("other")

    clock = FakeClock()
    guard = IdleGuard([flaky, other], idle_seconds=10.0, clock=clock)
    clock.advance(11.0)
    with pytest.raises(RuntimeError):
        guard.check()
    assert calls == ["flaky", "other"]
    state["fail"] = False
    assert guard.check() is True
    assert calls == ["flaky", "other", "flaky", "other"]
