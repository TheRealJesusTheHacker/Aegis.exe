"""Lock-on-idle: the vault relocks itself when left alone.

Copying a password should never leave an open vault sitting behind
the person who walked away. The idle guard watches a simple clock:
any real activity (opening, saving, searching, copying) counts as
a touch; when the quiet stretches past the period the person set,
the guard locks everything it was given — the credential store
forgets its list and the session wipes its keys, exactly the lock
Phase 1 built.

This module is policy and timing only. The interface (Phase 4)
calls :meth:`IdleGuard.check` on its own rhythm and reports real
activity through :meth:`IdleGuard.touch`; the clock is injectable
so the policy is testable without waiting, which is how the test
suite drives it.
"""

from __future__ import annotations

import time

__all__ = ["DEFAULT_IDLE_SECONDS", "IdleGuard"]

DEFAULT_IDLE_SECONDS = 300.0


class IdleGuard:
    """Locks a set of lockables when activity stops for too long.

    ``lockables`` are zero-argument callables run, in order, when
    the idle period expires — typically the store's ``lock`` method,
    which locks its session and forgets its cache together.
    """

    def __init__(
        self,
        lockables,
        *,
        idle_seconds=DEFAULT_IDLE_SECONDS,
        clock=time.monotonic,
        enabled=True,
    ):
        if idle_seconds <= 0:
            raise ValueError("The idle period must be more than zero.")
        self._lockables = list(lockables)
        self._idle_seconds = float(idle_seconds)
        self._clock = clock
        self._enabled = bool(enabled)
        self._last_touch = clock()
        self._fired = False

    @property
    def idle_seconds(self) -> float:
        return self._idle_seconds

    @property
    def enabled(self) -> bool:
        return self._enabled

    def set_enabled(self, enabled: bool) -> None:
        self._enabled = bool(enabled)
        if self._enabled:
            # Re-arming starts a fresh quiet period, so turning the
            # guard back on never locks anyone out instantly.
            self._fired = False
            self._last_touch = self._clock()

    def touch(self) -> None:
        """Record real activity; the quiet period starts over."""
        self._last_touch = self._clock()
        self._fired = False

    def seconds_idle(self) -> float:
        return max(0.0, self._clock() - self._last_touch)

    def check(self) -> bool:
        """Run the policy once; lock if the quiet period has expired.

        Returns True on the one call that does the locking. Once
        fired, later calls do nothing until :meth:`touch` re-arms
        the guard (which the interface does when a vault is opened
        again — a locked vault has nothing left to protect).

        Every lockable runs, even if an earlier one fails — a
        half-done lock is worse than a reported one. If any
        lockable failed, the first failure is raised after all of
        them have run, and the guard does *not* count itself as
        fired: the next check tries the lock again, because a vault
        that would not lock is still open and still needs locking.
        (Phase 1's lock raises on a failed save and deliberately
        stays unlocked so the person can retry; this guard honors
        that instead of hiding it.)
        """
        if not self._enabled or self._fired:
            return False
        if self.seconds_idle() < self._idle_seconds:
            return False
        failures = []
        for lock in self._lockables:
            try:
                lock()
            except Exception as exc:  # keep locking the rest
                failures.append(exc)
        if failures:
            raise failures[0]
        self._fired = True
        return True
