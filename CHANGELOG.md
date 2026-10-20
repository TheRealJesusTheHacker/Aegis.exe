# Changelog

All notable changes to AEGIS.EXE are recorded here. Versions follow
the build phases in [docs/ROADMAP.md](docs/ROADMAP.md). No public
release ships before the Phase 5 independent security audit gate —
pre-release versions below are development milestones, not releases.

## [0.3.0] — 2026-10-20

Phase 2 — the password vault core.

### Added

- **The credential store**: saved logins (site/app name, user name,
  password, web address, notes) held inside an ordinary Aegis vault
  as one sealed item — same master password, same recovery key,
  same password changes and tamper checks as the files beside
  them. No second format, no second cryptography. An entry's
  printed form never shows its password.
- **Password generator**: cryptographically secure random
  passwords (`secrets`), 20 characters by default, with plain
  controls for length and for the kinds of character to include.
  Every kind switched on is guaranteed to appear. A generated
  password is never logged or stored anywhere except the login
  the person saves.
- **Search and copy**: fast search across names, user names, and
  web addresses — never across passwords or notes, so a search
  can't be used to test whether a password is inside. Passwords
  leave the store through one deliberate reveal path, onto a
  clipboard that clears itself a short while later — only if it
  still holds exactly what Aegis put there; a newer thing the
  person copied is never erased.
- **Lock-on-idle**: the vault locks itself after a quiet period
  the person sets — the store forgets its list at the same moment
  the session wipes its keys. If locking itself fails, the failure
  is raised and retried, never hidden.
- **Sealed moving only**: export is a sealed `.aegis` copy of the
  vault, published the same no-overwrite way a vault is created;
  import merges logins from another open Aegis vault. There is no
  plain-text import or export. The written review behind that
  decision is `docs/IMPORT-EXPORT-SAFETY.md`.
- **Test suite**: 257 tests (179 Phase 1 + 78 new) — store CRUD
  and persistence across lock, password change, and recovery-key
  opens; generator properties over thousands of samples; search
  exclusions; clipboard clearing and its races; idle-lock policy;
  sealed-export and merge round-trips; a damaged-store refusal;
  and the plain-language sweep over all new wording.

### Security

- One adversarial self-audit cycle ran before this version was
  cut. It verified the generator draws only on the `secrets`
  source, that no artifact on disk ever carries a readable login,
  and that imports from a damaged store are refused whole. It
  fixed two defects: an idle lock whose first failing step could
  silently leave the rest unlocked and unretried, and a clipboard
  clear that could raise into the caller's rhythm instead of
  reporting "not cleared."
- This self-audit does not replace the Phase 5 independent
  security audit gate.

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
