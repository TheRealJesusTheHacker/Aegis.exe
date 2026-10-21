"""B-13: the rollback tripwire — regression tests.

The design (docs/ROADMAP.md, Phase 1 note): the app remembers the
newest vault state it has seen, outside the vault file, as one
more tripwire against silent rollback. These tests pin the
behavior:

- a vault file replaced wholesale by a state this copy of Aegis
  has seen and moved past is REFUSED (the tripwire trips), on
  both credential paths, before any password work runs;
- the current vault opens exactly as before;
- a first run with no remembered state works, and remembers;
- a state this copy has never seen (the same vault changed on
  another computer, say) is taken as current — a check value
  cannot tell time, and that limit is stated in the docs — and
  from then on it is the remembered newest state;
- a damaged remembered-state file fails closed: vaults it
  covers are refused, it is never silently replaced, and other
  vaults are unaffected;
- the remembered state holds check values only — no vault
  content, no entry names, no plain file names.

Synthetic fixtures only, like the rest of the suite.
"""

import pytest

from aegis import Vault
from aegis.errors import VaultRolledBackError, WrongPasswordError

from conftest import PASSWORD, WRONG_PASSWORD


@pytest.fixture(autouse=True)
def freshness_file(tmp_path, monkeypatch):
    """Point the remembered state at a throwaway file per test."""
    target = tmp_path / "aegis-state" / "vault-state.json"
    monkeypatch.setenv("AEGIS_FRESHNESS_PATH", str(target))
    return target


def _open(path, password=PASSWORD):
    return Vault.open(path, password=password)


# -- the tripwire trips -------------------------------------------------------


def test_older_vault_file_after_newer_state_trips(create_vault, vault_path):
    created, path = create_vault()
    created.session.lock()
    older_bytes = path.read_bytes()

    session = _open(path)
    session.write("newer.txt", b"the newer state")
    session.save()
    session.lock()
    assert path.read_bytes() != older_bytes

    path.write_bytes(older_bytes)  # the silent rollback
    with pytest.raises(VaultRolledBackError):
        _open(path)


def test_rollback_trips_on_the_recovery_key_path_too(create_vault):
    created, path = create_vault()
    recovery_key = created.recovery_key
    created.session.lock()
    older_bytes = path.read_bytes()

    session = _open(path)
    session.write("newer.txt", b"the newer state")
    session.save()
    session.lock()

    path.write_bytes(older_bytes)
    with pytest.raises(VaultRolledBackError):
        Vault.open(path, recovery_key=recovery_key)


def test_rollback_trips_before_password_work(create_vault):
    """A rolled-back vault is refused even with a wrong password:
    the tripwire runs before the password is ever tried, so a
    refusal reveals nothing about the older copy's password."""
    created, path = create_vault()
    created.session.lock()
    older_bytes = path.read_bytes()

    session = _open(path)
    session.write("newer.txt", b"the newer state")
    session.save()
    session.lock()

    path.write_bytes(older_bytes)
    with pytest.raises(VaultRolledBackError):
        _open(path, password=WRONG_PASSWORD)


def test_password_change_rolls_the_tripwire_forward(create_vault):
    created, path = create_vault()
    old_bytes = path.read_bytes()
    created.session.change_password("a brand new master phrase")
    created.session.lock()

    # The current file opens with the new password, as before.
    session = Vault.open(path, password="a brand new master phrase")
    session.lock()

    # The pre-change copy — which the OLD password still opens on
    # its own — is a rollback now and is refused outright.
    path.write_bytes(old_bytes)
    with pytest.raises(VaultRolledBackError):
        _open(path)


# -- the normal paths are unaffected -------------------------------------------


def test_first_run_with_no_record_works(create_vault, freshness_file):
    created, path = create_vault(entries={"a.txt": b"alpha"})
    created.session.lock()
    assert freshness_file.exists()  # creation remembered the state

    freshness_file.unlink()  # no remembered state at all
    session = _open(path)
    assert session.read("a.txt") == b"alpha"
    session.lock()
    assert freshness_file.exists()  # opening adopted and remembered it


def test_normal_open_of_the_current_vault_is_unaffected(create_vault):
    created, path = create_vault(entries={"a.txt": b"alpha"})
    created.session.write("b.txt", b"beta")
    created.session.save()
    created.session.lock()

    session = _open(path)
    assert session.read("a.txt") == b"alpha"
    assert session.read("b.txt") == b"beta"
    session.lock()


def test_wrong_password_on_the_current_vault_is_still_a_wrong_password(
    create_vault,
):
    created, path = create_vault()
    created.session.lock()
    with pytest.raises(WrongPasswordError):
        _open(path, password=WRONG_PASSWORD)


def test_one_vaults_rollback_does_not_block_another(tmp_path, create_vault):
    first, first_path = create_vault(name="one.aegis")
    first.session.lock()
    first_older = first_path.read_bytes()
    second, second_path = create_vault(name="two.aegis")
    second.session.lock()

    session = _open(first_path)
    session.write("newer.txt", b"newer")
    session.save()
    session.lock()
    first_path.write_bytes(first_older)

    with pytest.raises(VaultRolledBackError):
        _open(first_path)
    other = _open(second_path)  # a different vault opens fine
    other.lock()


def test_moved_vault_opens_and_is_remembered_at_its_new_home(
    create_vault, tmp_path
):
    created, path = create_vault(entries={"a.txt": b"alpha"})
    created.session.lock()

    moved = tmp_path / "elsewhere" / "moved.aegis"
    moved.parent.mkdir()
    moved.write_bytes(path.read_bytes())
    session = _open(moved)  # same vault, new home: adopted there
    assert session.read("a.txt") == b"alpha"
    session.write("b.txt", b"beta")
    session.save()
    session.lock()

    older_at_new_home = path.read_bytes()
    moved.write_bytes(older_at_new_home)
    with pytest.raises(VaultRolledBackError):
        _open(moved)
    original = _open(path)  # the original home is unaffected
    original.lock()


# -- states this copy has never seen --------------------------------------------


def test_unseen_state_is_adopted_and_then_protected(
    create_vault, tmp_path, monkeypatch
):
    """The same vault changed on another computer arrives as a
    state this copy has never seen. A check value cannot tell
    time, so it is taken as current (the documented limit) — and
    once seen, rolling back past it trips like any other."""
    created, path = create_vault()
    created.session.lock()
    state_seen_here = path.read_bytes()

    # "Another computer": its own remembered state, same vault.
    other_state = tmp_path / "other" / "vault-state.json"
    monkeypatch.setenv("AEGIS_FRESHNESS_PATH", str(other_state))
    session = _open(path)
    session.write("from-elsewhere.txt", b"changed on another computer")
    session.save()
    session.lock()
    state_from_elsewhere = path.read_bytes()
    assert state_from_elsewhere != state_seen_here

    # Back on this computer: the unseen state opens and is adopted.
    monkeypatch.setenv(
        "AEGIS_FRESHNESS_PATH",
        str(tmp_path / "aegis-state" / "vault-state.json"),
    )
    session = _open(path)
    assert session.read("from-elsewhere.txt") == b"changed on another computer"
    session.lock()

    # And the state this computer saw before is now a rollback.
    path.write_bytes(state_seen_here)
    with pytest.raises(VaultRolledBackError):
        _open(path)


# -- a damaged remembered state fails closed -------------------------------------


def test_corrupt_record_refuses_the_vaults_it_covers(
    create_vault, freshness_file
):
    created, path = create_vault()
    created.session.lock()

    freshness_file.write_bytes(b"this is not the remembered state")
    with pytest.raises(VaultRolledBackError):
        _open(path)


def test_wrong_shape_record_refuses(create_vault, freshness_file):
    created, path = create_vault()
    created.session.lock()

    freshness_file.write_text('{"version": 99, "vaults": {}}', encoding="utf-8")
    with pytest.raises(VaultRolledBackError):
        _open(path)


def test_damaged_record_is_never_silently_replaced(
    create_vault, freshness_file, tmp_path
):
    created, path = create_vault()
    created.session.lock()
    damaged = b"damaged beyond reading"
    freshness_file.write_bytes(damaged)

    # Creating a different vault still works — and the damaged
    # record is left exactly as it was, still refusing its own
    # vaults, rather than being wiped to make the error go away.
    other_path = tmp_path / "other.aegis"
    other = Vault.create(other_path, PASSWORD)
    other.session.lock()
    assert freshness_file.read_bytes() == damaged
    with pytest.raises(VaultRolledBackError):
        _open(path)


def test_record_with_duplicate_keys_refuses(create_vault, freshness_file):
    """Audit fix: the record is parsed with the same duplicate-
    key refusal as the vault header — last-wins parsing would
    let two readers disagree about what was remembered."""
    created, path = create_vault()
    created.session.lock()

    text = freshness_file.read_text(encoding="utf-8")
    freshness_file.write_text(
        text.replace('"vaults"', '"vaults": {}, "vaults"', 1),
        encoding="utf-8",
    )
    with pytest.raises(VaultRolledBackError):
        _open(path)


def test_record_path_under_a_file_is_a_first_run(
    create_vault, tmp_path, monkeypatch
):
    """Audit fix: a record path under something that is not a
    folder means no record could ever have been written there —
    that is the first-run case, not a damaged record."""
    blocker = tmp_path / "blocker"
    blocker.write_bytes(b"a file, not a folder")
    monkeypatch.setenv(
        "AEGIS_FRESHNESS_PATH", str(blocker / "vault-state.json")
    )
    created, path = create_vault(entries={"a.txt": b"alpha"})
    created.session.lock()
    session = _open(path)
    assert session.read("a.txt") == b"alpha"
    session.lock()


def test_tripwire_messages_speak_plain_language():
    from aegis.errors import VaultRolledBackError as Tripwire

    banned = ["argon2", "aes", "encrypt", "kdf", "key derivation",
              "cipher", "sha-256", "sha256", "hash"]
    for text in (str(Tripwire()), Tripwire.user_message):
        for word in banned:
            assert word not in text.lower(), f"{word!r} in tripwire copy"


# -- what the record holds --------------------------------------------------------


def test_record_holds_no_vault_contents_or_names(create_vault, freshness_file):
    created, path = create_vault(
        entries={"quarterly-secrets.txt": b"synthetic secret contents"}
    )
    created.session.lock()

    text = freshness_file.read_text(encoding="utf-8")
    assert "quarterly-secrets" not in text
    assert "synthetic secret contents" not in text
    assert path.name not in text
    assert PASSWORD not in text
