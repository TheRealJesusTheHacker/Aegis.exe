# Changelog

All notable changes to AEGIS.EXE are recorded here. Versions follow
the build phases in [docs/ROADMAP.md](docs/ROADMAP.md). No public
release ships before the Phase 5 independent security audit gate —
pre-release versions below are development milestones, not releases.

## [1.0.5] — 2026-10-21

### Added

- **The rollback tripwire (roadmap B-13).** Aegis now
  remembers the newest state of each vault it has seen on
  this computer, in a small record kept outside the vault
  file — check values only: no file names, no paths in plain
  text, nothing about a vault's contents. Opening a vault
  checks the record before any password work: a vault file
  that comes back as a state this copy of Aegis has seen and
  moved past — an old copy quietly put back in place, by sync
  software or by a person — is refused, on both the password
  and the recovery-key paths, and a password change moves the
  remembered state forward like any other save. A damaged
  record refuses too, and is never silently replaced. The
  honest limits are stated in the threat model: a state this
  copy has never seen (the same vault changed on another
  computer) is taken as current, because a check value cannot
  tell time; and an older record put back together with an
  older vault defeats the tripwire. A first run, with no
  record at all, works exactly as before. 14 new tests pin
  the trip, the normal paths, and the failure shapes.

### Decisions

- **Browser autofill is closed permanently (roadmap B-12).**
  The vault's isolation is the product — "It does not open" —
  and a browser-bridge surface is the credential-theft vector
  the design exists to refuse. It will not be scheduled.

## [1.0.4] — 2026-10-21

### Fixed

- **Closing the window while work is still running can no
  longer tear the app down.** Every background job (sealing,
  opening, unlocking, installing) runs on a thread the window
  owns, and a thread destroyed while it is still running
  aborts the whole process. The close path waited a few
  seconds for jobs to finish and then closed anyway — and
  sealing a very large file, one of Aegis's headline jobs,
  can run far longer than that. The window now waits briefly
  for short jobs and refuses the close while any job is
  still running, staying open with the job's progress on
  screen; closing again once the work has finished closes
  normally. The final lock also runs only after no job is
  in flight, so it can never race one.

### Added

- **The timing settings are saved between runs.** The
  quiet-time lock and the clipboard stay, set on the Settings
  screen, are written to a small settings file (the two
  numbers and nothing else — no vault content, no file
  names) and loaded again at the next start, held to the
  same ranges the screen offers. A settings file that is
  missing or damaged is ignored and the built-in defaults
  apply; if a save cannot be made, the screen says the
  settings are in use for this time only.

## [1.0.3] — 2026-10-20

### Changed

- **Aegis has its own colors now: bronze and steel on
  near-black.** The green the whole kit shared is retired.
  Panels sit on deep bronze-black, words are polished steel,
  and the buttons, headings, and shield mark wear the
  shield's bronze. Every screen is laid out exactly as
  before and every word is unchanged — this release changes
  colors and nothing else. The red kept for destructive
  confirmations is the same red as always, and every
  text/background pairing was measured again in the new
  colors: all of them still clear the fleet's readability
  floor.

## [1.0.2] — 2026-10-20

### Fixed

- **Creating a vault or a sealed file on a drive that can't
  hold links — a USB stick above all — no longer fails.**
  Putting a finished file in place normally links it there;
  drives without links now get the finished bytes copied into
  a name claimed for Aegis alone. Nothing is ever overwritten,
  on any drive, and a copy cut short is removed.
- **A save that meets a briefly busy file now waits and tries
  again.** A file just written is often being looked over by
  the machine's own safety checks at the moment it should move
  into place; that refusal is brief, and a save now waits it
  out over about a second before reporting a failure.
- **Names carrying a colon are refused wherever Aegis reads
  or writes a name**, alongside the device names and trailing
  dots and spaces refused before — a colon is how Windows
  spells a drive or a hidden side-stream, so such a name
  would land somewhere other than where it says. The
  console's own names are refused as device names too.
- **Sealing refuses those names up front.** A folder or file
  whose name Windows can't use is now refused at sealing
  time, in plain language, instead of producing a sealed set
  or file that could never be opened — and a name Aegis is
  asked to write to (a new vault, a sealed file, an opened
  folder, a saved document copy) is checked the same way.

## [1.0.1] — 2026-10-20

### Added

- **The first-run install offer, in the window itself**: when
  Aegis is not running from its installed home, the locked
  screen offers — once per run, standing modeless over it,
  never a gate on unlocking — to put a copy in its permanent
  place. Accepting runs the same checked launcher install;
  declining, or a lock closing the offer, leaves the app
  running exactly as it was.

### Fixed

- **Install failure messages now state what actually happened.**
  Where a failure used to say nothing was changed even when it
  had been, the message now says so when an earlier installed
  copy was taken out to make room, and whether a partial copy
  was removed or is still at the place it names — instead of
  saying nothing was changed when it had been.

## [1.0.0] — 2026-10-20 — FIRST PUBLIC RELEASE

### Added

- `docs/THREAT-MODEL.md`: who Aegis protects you from and who
  it cannot, in plain language, matched to the program's actual
  behavior — including the honest limits (a compromised running
  machine, losing both the master password and the recovery
  key, a whole vault file swapped for an older copy).
- Windows release workflow: version triangulation, the full
  suite on Windows, the PyInstaller build with a warning gate,
  the staged-exe launch smoke test, `AegisPortable.zip`, and
  `SHA256SUMS.txt`. The independent security audit's verdict
  is PASS WITH DOCUMENTED RESIDUALS, and this release shipped
  on that pass.
- Portable edition: one folder, no installation, with an honest
  data-footprint statement inside the zip.
- Launcher `--install` / `--uninstall`: self-placement with a
  read-back check; a copy that does not check out is removed,
  never reported as installed. Installing is offered, never
  required — the app runs the same without it.

### Changed

- If Aegis locks while a sealed file is being opened or a
  sealed backup set is being restored, the result is no longer
  placed: the held work is removed and nothing new appears on
  disk behind the locked screen. (This reverses the Phase 4
  behavior on the Phase 5 audit's finding.)
- Every confirmation question and the recovery-sheet print
  dialog now run under the same lock discipline as all other
  dialogs: a lock closes them.
- File names that Windows would collapse or treat as devices
  (trailing dots or spaces; CON, NUL, COM1–COM9, LPT1–LPT9,
  with or without an extension) are refused when a sealed file,
  a backup set, or a Strongbox document is opened.
- Memory handling: staged copies in the sealed-file reader and
  writer, the saved-login list, and a session's held contents
  are now emptied in place at close and lock, in addition to
  the key buffers that were already wiped. (What the language
  itself keeps copies of cannot be scrubbed; the threat model
  says so plainly.)

## [0.5.0] — 2026-10-20

Phase 4 — the interface: the whole core, in one window.

### Added

- **The Aegis window (PySide6)**: a locked screen with the one
  Unlock — master password or recovery key, with drag-and-drop
  of vault files — setup with the Phase 1 warning word for word
  and the printable recovery-key sheet, and the open vault in
  six sections: Passwords (search, a reveal that hides itself
  after 15 seconds, copy), Make a password (the generator, with
  a road straight into a new login), Strongbox, Lock and send,
  Backup sets (seal a folder, look inside a set, open one back),
  and Settings and vault care (lock and clipboard timings,
  change master password, new recovery key, save a sealed copy,
  bring in logins from another vault). Every control is wired
  to the real core; every failure lands on a designed state in
  the core's plain words.
- **Real wiring behind Phase 2's seams**: the actual OS clipboard
  under the auto-clear clock (a copied secret is cleared on
  time, and at once on lock — and only ever if the clipboard
  still holds exactly what Aegis put there), and idle locking
  driven by real activity — keys, pointer, wheel, touch.
- **One lock, everywhere**: the Lock button, the idle guard, and
  closing the window all pass through a single funnel that
  closes any open dialog first, then wipes every screen —
  lists, fields, reveals, the recovery sheet, the setup fields.
- **Packaging prep** (`packaging/`): the one-folder PyInstaller
  spec in the kit pattern, with the launcher's `--self-check`
  smoke hook — the build proves its own window constructs
  before anything ships. The release itself belongs to Phase 5,
  after the audit gate.

### Security

- **Copy discipline**: a secret can reach the clipboard only
  through the tracked Copy buttons. Surfaces that merely show
  one — a revealed password, a Strongbox body, the recovery
  sheet, a generated password, the editors' secret fields —
  refuse native copy, cut, selection, and drag; the generator's
  own Ctrl+C is routed into the same tracked copy.
- **Single-flight opening**: an unlock or a create can never run
  twice or together; mid-flight, every input on the locked
  screen is disabled, so no session can be orphaned unlocked.
- **Failed locks stay honest and quiet**: an idle lock that
  cannot save is reported once per episode while the guard
  retries underneath — never spammed, never hidden.
- **Rendered-state verification**: ten screenshots of the real
  window audited pixel by pixel (zero painted purple, dark
  surfaces throughout) and every text/background pairing
  computed — all clear 4.5:1, weakest 4.80:1.
- **The doubled audit cycle ran**: a first independent audit
  returned FAIL (2 HIGH, 6 MEDIUM, 9 LOW findings); all were
  fixed; the re-audit probed every fix and returned
  PASS-WITH-FIXES on three narrow residuals in the copy seam;
  those are fixed and pinned as regression tests. Suite: 420
  tests (369 core + 51 interface and audit tests).

## [0.4.0] — 2026-10-20

Phase 3 — the Strongbox, Lock-and-send, and Lazarus's armor.

### Added

- **The Strongbox**: a compartment inside the vault for what
  isn't a login — recovery codes, keys, private notes, and copies
  of documents — typed, listed without their contents, and opened
  through one deliberate reveal path (documents through their own
  read path). Same vault, same master password and recovery key,
  no second format. A document copy keeps its original file name
  and is checked against its recorded size and check value every
  time it is read; copies are capped at 10 MB each, and the
  refusal past the cap says why, plainly.
- **Lock-and-send**: one file sealed with a password of its own,
  for files that travel. The file's name stays inside the seal;
  the sealed file's own name gives nothing away unless the sender
  chooses one. Opening never overwrites. The flow copy states the
  design's truth up front: the password is the whole lock, and it
  must travel a different way than the file.
- **Lazarus's armor**: a whole folder — a Lazarus backup set
  above all — sealed into one `.aegis-armored` file and unsealed
  back byte for byte, whole at the boundary, exactly as the
  roadmap's interface point defines. Sealing never follows links;
  unsealing checks every file against the set's recorded check
  values and puts the folder in place only once the whole set
  checks out.
- **One standalone construction for both**: Argon2id settings in
  the header, checked before use; a random file key, wrapped;
  contents sealed in authenticated chunks, streamed both ways.
  Each product's files carry their own format marker, and no
  Aegis reader opens another product's files — the separation is
  tested in both directions for every pair.
- **Test suite**: 369 tests (257 prior + 112 new) — Strongbox
  CRUD, document round-trips at and past the cap, crafted-list
  refusals; Lock-and-send round-trips (empty, binary, multi-chunk,
  unicode names), tamper and splice refusals, derivation-setting
  attacks; armor round-trips of multi-file trees, crafted
  manifests (escape paths, duplicates, lying sizes and check
  values), no-overwrite and link refusals; a hostile-input battery
  that lets only designed, plain-language errors escape any
  opener; and the plain-language sweep over all new wording.

### Security

- The doubled adversarial self-audit cycle ran before this
  version was cut: leakage scans over sealed bytes, truncation
  sweeps at every boundary, header/payload splices even between
  files sharing a password, parameter-ceiling probes refused
  before any derivation ran, and Strongbox lists crafted to lie
  about their documents (caught by the recorded check values). It
  fixed two defects: a failed unsealing move could have surfaced
  a raw system error instead of the designed one, and a refused
  open could leave a file handle behind. Both are pinned as
  regression tests.
- This self-audit does not replace the Phase 5 independent
  security audit gate.

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
