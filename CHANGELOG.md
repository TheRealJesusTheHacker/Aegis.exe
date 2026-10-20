# Changelog

All notable changes to AEGIS.EXE are recorded here. Versions follow
the build phases in [docs/ROADMAP.md](docs/ROADMAP.md). No public
release ships before the Phase 5 independent security audit gate —
pre-release versions below are development milestones, not releases.

## [0.2.0] — 2026-10-20

Phase 1 — the Vault core.

### Added

- **Sealed vault files** (`.aegis`): files and folders kept in a
  single encrypted vault behind one master password. Locked, the
  vault shows nothing — not even file names. The file on disk stays
  sealed even while a vault session is open.
- **Vault format v1**: a random 256-bit vault key per vault, stored
  only as two AES-256-GCM wrapped copies — one opened by the master
  password, one by the recovery key. Contents are sealed in 1 MiB
  authenticated chunks bound to the vault and to the current
  wrapped keys; a single changed byte anywhere means the vault does
  not open.
- **Argon2id key derivation** at the RFC 9106 first recommended
  profile (64 MiB memory, 3 passes, 4 lanes). The parameters travel
  in the vault header and are range-checked before use, so future
  versions can raise them without breaking old vaults.
- **The setup flow, as designed**: the plain-language warning that
  a lost master password means a vault nobody can open, a printable
  recovery key generated at setup and shown exactly once, and
  plain-language password-strength guidance while the password is
  chosen.
- **Recovery as a first-class path**: the recovery key opens the
  vault at full strength, can set a new master password, and can
  itself be replaced while the vault is open. Password and
  recovery-key changes rotate that credential's salt and re-bind
  the contents to the new seal.
- **Session discipline**: locking saves and wipes the keys from
  memory; a locked session refuses every operation until the vault
  is opened again.
- **Test suite**: 179 tests — round-trips at every file size class,
  wrong-password and wrong-recovery-key refusal, tamper detection
  on header and payload, header-parameter integrity, splice and
  rollback regressions, and session-lock behavior. Synthetic
  fixtures only.

### Security

- One full adversarial self-audit cycle (audit → fix → re-audit) ran
  before this version was cut. It changed the design in three ways:
  each wrapped key is now authenticated under its own context,
  credential changes rotate their salt, and the sealed contents are
  bound to the current wrapped keys so older contents cannot be
  spliced under newer credentials. It also closed a recovery-key
  leak through an auto-generated object `repr`, plus a round of
  parser and file-handling hardening. The re-audit's own follow-up
  round added a guard against a stale session saving over a vault
  that changed on disk, and made every failure a designed,
  plain-language error — never a raw system error.
- This self-audit does not replace the Phase 5 independent security
  audit gate.

## [0.1.0] — 2026-10-20

### Added

- Repository kickoff: README, build roadmap (encryption core first,
  one audited core for both sides, Phase 5 security audit gate),
  proprietary license, and package stub.
