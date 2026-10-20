# AEGIS.EXE — Build Roadmap

The shield wall. Phases run in order, and the order is the point:
**the encryption core is built and proven first**, and everything
else — the password vault included — stands on that one audited core.
Nothing in Aegis gets its own private cryptography.

**The two sides (one core):**
File encryption → Password manager, both sealed by one master
password, derived once, through one core.

**Safety law:** Aegis is built only from vetted cryptographic
libraries — never a hand-rolled primitive; the master password is
never stored, transmitted, or recoverable by anyone, including
Sentinel; and no public release ships before the Phase 5 security
audit gate passes. No exceptions, no settings that weaken them.

---

## Phase 1 — Encryption vault core (The Vault)

**Status: COMPLETE — shipped as v0.2.0 (2026-10-20).**

*As built:* a vault is a single sealed `.aegis` file — an
authenticated header (format version, a per-vault id, the Argon2id
parameters, and two wrapped copies of the vault's random 256-bit
key: one sealed by the master password, one by the recovery key)
followed by the contents sealed in 1 MiB AES-256-GCM chunks, each
chunk bound to the vault's id and to the current wrapped keys, so a
credential change re-binds the contents and older contents cannot be
spliced under newer credentials. Argon2id runs at the RFC 9106
first recommended profile (64 MiB, 3 passes, 4 lanes); parameters
are stored in the header and validated — floors and ceilings —
before any derivation runs, so a tampered header can only ever
produce a refusal. The setup flow ships as designed: the
plain-language warning, the printable recovery key (generated once,
shown once, never stored), and plain-language password-strength
guidance. Sessions lock by saving and wiping keys; the file on disk
is a sealed vault at all times, even while a session is open. 179
tests cover the suite named below plus the audit regressions. One
adversarial self-audit cycle ran before the version was cut and
changed the design (per-credential wrap contexts, salt rotation on
credential change, payload-to-credential binding) — that cycle is
house process, **not** the Phase 5 gate; the independent audit
still stands between this core and any public release. Recorded
limits, stated honestly: a vault file replaced wholesale by an
older copy opens as that older copy (no offline file can tell
time); passwords are taken exactly as typed, with no silent
normalization; and Python cannot guarantee every in-memory copy of
a key is erasable — the primary buffers are wiped, and the full
memory-handling review belongs to Phase 5. Phase 4 note: the app
should remember the newest vault state it has seen, outside the
vault file, as one more tripwire against silent rollback.

The heart of the product, built first and built carefully.

- **Vault format** — files and folders sealed into AES-256 encrypted
  vaults. Locked, a vault is opaque and its contents invisible;
  unlocked with the master password, it presents like a normal drive
  for the length of the session.
- **Key derivation** — Argon2id turns the master password into the
  vault keys. Parameters (memory, iterations, parallelism) set to
  current published guidance and recorded in the vault header so
  future versions can raise them without breaking old vaults.
- **Setup flow — the recovery story is core design, not a later
  phase:**
  - Plain-language warning, shown before the first vault exists:
    lose the master password and nobody — not Sentinel, not anyone —
    can open the vault. That is the point of a shield, and the user
    hears it *before* trusting it with anything.
  - A **printable recovery key** generated and offered at setup,
    with guidance to print it and store it somewhere physically
    safe. The recovery key is the one sanctioned way back in, and
    the user holds the only copy.
  - Master password strength feedback in plain language — no
    jargon, no shaming, just honest guidance.
- **Session behavior** — unlock, work, lock. Locking wipes keys from
  memory; a locked vault exposes nothing, not even file names.
- Vault core test suite from day one: round-trip integrity on every
  file size class, wrong-password refusal, tamper detection on
  modified vault bytes, recovery-key unlock path.

## Phase 2 — Password vault core

**Status: COMPLETE — shipped as v0.3.0 (2026-10-20).**

*As built:* the credential store is a convention inside the vault,
not a new format — the logins live as one reserved item
(`passwords/manifest.json`) in an ordinary vault, sealed by the
Phase 1 core and covered by its password changes, recovery path,
tamper checks, and stale-session guard unchanged. Entries carry a
name, user name, password, web address, notes, and first-saved /
last-changed stamps; an entry's printed form never shows its
password, and passwords leave the store through one deliberate
reveal path. The generator draws only on the `secrets` source,
guarantees every switched-on kind of character appears, and never
logs or keeps what it makes. Search covers names, user names, and
web addresses only — passwords and notes are never searched, so a
search can't test whether a password is inside. Copying runs
through a clipboard seam whose auto-clear takes a copied password
back off after a short window, only when the clipboard still holds
exactly what Aegis put there. Lock-on-idle locks through Phase 1's
session lock and drops the store's list at the same moment; a lock
that fails is raised and retried, never hidden. **Import/export,
decided per the written review in
`docs/IMPORT-EXPORT-SAFETY.md`:** export is a sealed `.aegis` copy
only; import merges logins from another open Aegis vault; there is
no plain-text import or export in any direction. 257 tests total
(179 Phase 1 + 78 new), plus an adversarial self-audit cycle whose
two fixes (idle-lock failure handling, clipboard-clear
containment) are pinned as regression tests. Recorded limit,
stated honestly: the store's parsed logins sit in memory while the
vault is open — the same posture as the session itself — and are
dropped, not scrubbed, at lock; the full memory review remains
Phase 5's gate.

The credential store, built on the Phase 1 core — same Argon2id
derivation, same AES-256 sealing, same session discipline. No second
crypto stack, ever.

- **Credential store** — logins (site/app, username, password, notes)
  held in the encrypted vault; nothing readable exists on disk while
  locked.
- **Password generator** — cryptographically secure random passwords
  with plain-language controls (length, symbols) and sensible
  defaults, so a strong password is the easiest choice.
- **Search and copy** — fast search across entries; copy to clipboard
  with automatic clipboard clearing after a short interval.
- **Lock-on-idle design** — the vault relocks itself after an idle
  period the user sets; copying a password never leaves the vault
  open behind you.
- Entry import/export design reviewed for safety before it is built:
  exports are themselves an encryption decision, never a plain-text
  default.

## Phase 3 — The Strongbox, Lock-and-send, and Lazarus's armor

**Status: COMPLETE — shipped as v0.4.0 (2026-10-20).**

*As built:* all three features stand on the audited core, and the
two that needed files of their own share one construction rather
than inventing two. **The Strongbox** is a convention inside the
vault, like the password store before it: its list is one reserved
item (`strongbox/manifest.json`), its items are typed — recovery
code, key, private note, document copy — and a document copy's
bytes are one vault item of their own, with the original file
name, size, and SHA-256 check value recorded in the list and
verified on every read. Document copies are capped at **10 MB
each**; past the cap the refusal says so plainly, because the file
itself belongs in the vault as a file. **Lock-and-send** and
**Lazarus's armor** share a standalone sealed-file construction
(`aegis/sealed.py`): the Phase 1 vault construction re-shaped for
one file and one password — Argon2id parameters in the header,
validated before any derivation; a fresh random file key wrapped
under the derived key in its own authenticated context; contents
in 1 MiB authenticated chunks bound to the file's random id and to
its wrapped key — streamed in both directions, so sealed files are
not bounded by memory. Each product has its own format and its own
magic — a vault (`AEGISVLT`), a file for sending (`AEGISSND`), an
armored set (`AEGISARM`) — and **no reader opens another product's
files**: a vault is not openable as a send file or a set, a send
file is not openable as a vault or a set, a set is not openable as
anything but a set; that separation is pinned by tests in both
directions for every pair. A standalone opener for Lock-and-send
recipients was *not* built: the phase's design review did not
approve shipping a second implementation of the format, so a
recipient opens a send file in their own copy of Aegis, and the
copy says exactly that.

*Lock-and-send:* the file's name lives inside the seal, and the
sealed file's own name is a plain default that repeats nothing
about what is inside. Opening writes the file under its original
name, never overwriting what is already there; the flow copy
states the truth of the design — the password is the whole lock,
and it must travel a different way than the file. *Lazarus's
armor:* the interface point below held exactly — a folder (a
Lazarus store above all) is sealed whole into one `.aegis-armored`
file, its contents a manifest (every folder, and every file's
place, size, and check value) followed by the files' bytes, and
unsealed whole back into a folder. Aegis was not modified to know
Lazarus's layout, and Lazarus was not modified at all. Sealing
never follows links and refuses a folder holding one; unsealing
validates every manifest path (no absolute paths, no `..`, no
backslashes, no duplicates even across capitalization), checks
each file against its recorded check value as it lands, and
builds the folder in a holding place that is only moved into
place once the whole set checks out — a failed unsealing puts
nothing in place. Recorded limits, stated honestly: sealing reads
each file twice (once for its check value, once to seal), so a
file changed mid-seal produces a set that refuses to unseal —
the safe direction; and a set replaced wholesale by an older set
opens as that older set, the same no-offline-file-can-tell-time
limit the vault carries. 369 tests total (257 prior + 112 new),
plus the doubled adversarial self-audit (leakage scans, splice and
truncation batteries, crafted-manifest and crafted-list attacks,
parameter-ceiling probes) whose two fixes — the unseal move's
failure behavior and a handle left open on a refused open — are
pinned as regression tests. That self-audit does **not** replace
the Phase 5 independent audit gate.

- **The Strongbox** — a sealed compartment for recovery codes, keys,
  private notes, and document copies. Same core, smaller door:
  optimized for quick in-and-out access to small, critical items.
- **Lock-and-send** — single-file encryption with its own password,
  for files that leave the machine: contracts, reports, client
  documents. Output is one sealed file the recipient opens with the
  agreed password in their own copy of Aegis (or a small standalone
  opener, if the phase's design review approves one). The file's name
  and contents stay sealed in transit.
- **Lazarus's armor** — Aegis encrypts backup sets, including
  Lazarus.exe snapshot stores, so a lost backup drive is not a
  privacy disaster. **Interface point, defined here:** Lazarus writes
  its snapshot store in its documented layout; Aegis seals a
  completed store (or a whole backup target volume's Aegis-designated
  container) as a vault-class object under the Aegis core, and
  unseals it before Lazarus reads it back. Neither tool reaches
  inside the other's format — the store is sealed and unsealed as a
  whole, at the boundary, by Aegis.

## Phase 4 — The animated UI

**Status: COMPLETE — shipped as v0.5.0 (2026-10-20).**

The futuristic animated PySide6 interface in the medic-kit style —
built on the real, finished pipeline, never on mock behavior.

- **One Lock button. One Unlock button.** The interface speaks plain
  language end to end: no crypto vocabulary on any screen a user
  sees. "Sealed" and "open," not "encrypted container mounted."
- Vault list, Strongbox, password vault with search, generator —
  every control wired to the real core; no decorative buttons, no
  placeholder actions.
- Setup flow presents the Phase 1 warning and recovery-key printing
  exactly as designed — the honesty rules are UI copy, reviewed like
  code.
- Sentinel green and black; no purple anywhere; rendered-screenshot
  verification of every main state before the phase closes.

**As built.** The whole core is reachable through one window: a
locked screen with the one Unlock (master password or recovery
key, drag-and-drop of vault files included), setup with the Phase 1
warning verbatim and the printable recovery-key sheet, and an open
vault with six sections — Passwords (search, reveal that hides
itself, copy), Make a password (the generator, with a road into a
new login), Strongbox, Lock and send, Backup sets (the armor,
with a link-aware folder summary and a look-inside view), and
Settings and vault care (timings, change master password, new
recovery key, sealed-copy export, sealed-only import). The UI sits
in `aegis/ui/` over a Qt-free controller, so the core's suite never
touches Qt; the real OS clipboard works through Phase 2's seam with
its auto-clear judgment intact, and Phase 2's idle guard is driven
by real activity (keys, pointer, wheel, touch). A copied secret
can leave only through the tracked Copy buttons — every surface
that merely shows a secret refuses native copy, cut, selection,
and drag — and every lock (button, idle, close) funnels through one
path that closes open dialogs first, then wipes every screen.
Premium bar, verified not asserted: ten rendered states screenshot-
audited (zero painted purple; dark surfaces throughout), every
text/background pairing computed at 4.5:1 or better — the weakest
is disabled text on a panel at 4.80:1 — and the jargon sweep runs
over the live widget tree of every screen. The phase went through
the doubled audit cycle: a first independent audit returned FAIL
on two HIGH findings (native-copy bypass; dialogs surviving a
lock), every finding was fixed, a re-audit probed the fixes and
returned PASS-WITH-FIXES on three narrow residuals in the same
seam, and those are fixed and pinned too. Packaging prep ships in
`packaging/` (one-folder spec in the kit pattern + a `--self-check`
launch smoke hook, proven against a real build) — the release
itself waits for Phase 5's gate, exactly as planned. Honest
unproven items: settings are per-run, not yet saved between runs;
the real-desktop clipboard and idle behavior are wired to the real
Qt seams and proven offscreen, and a first run on real Windows
hardware is still owed; the vault's file path stays visible on the
locked screen by deliberate choice (it is the person's own file
location, not the vault's contents — the credential and all
content are wiped).

## Phase 5 — Hardening, the security audit gate, and packaging

**Status: COMPLETE — THE GATE PASSED, AND v1.0.0 SHIPPED
2026-10-20 (the first public release). The independent
security audit's final verdict is PASS WITH DOCUMENTED
RESIDUALS on the release candidate.**

*As built so far:* the threat model is written
(`docs/THREAT-MODEL.md`); the memory-handling review is done —
key buffers were already wiped at lock/close, and Phase 5 added
in-place emptying of the sealed reader/writer staging buffers,
the saved-login list, and a session's held contents, with the
language-level limit (interpreter-kept copies cannot be
scrubbed) stated honestly in the threat model. The sign-in work
factor was re-verified against its floors and ceilings and
measured on the build machine and in the Windows workflow.
Packaging follows the kit pattern: a tag-gated Windows workflow
builds the one-file `Aegis.exe` (self-install offered through
the launcher, verified by read-back, never a gate), the portable
zip, and `SHA256SUMS.txt`; a dispatch run of that workflow is
the end-to-end proof. The audit's first round returned no
critical or high findings; its medium finding (work finishing
after a lock still placed plain files) and three low findings
are fixed in this version. Round 2 (the re-audit) verified
every fix live — the first round's lock-mid-work attack,
re-run under its original timing, places nothing — and
returned PASS WITH DOCUMENTED RESIDUALS with no open
critical, high, medium, or low findings; the notes that
remain are information-level and are recorded in the audit.

**THE GATE: no public release of Aegis ships before this phase
passes. This is a hard gate, not a milestone.**

- **Independent security audit** of the finished product:
  - Threat model written and reviewed — who Aegis defends against
    (a stranger at the machine, a stolen drive, a copied vault file)
    and, honestly, who it does not.
  - Cryptographic review — construction, nonce/IV handling, vault
    format, integrity protection, all checked against the Phase 1
    design commitments.
  - KDF parameter verification — Argon2id parameters measured on
    real hardware and confirmed against current guidance.
  - Memory-handling review — keys and plaintext passwords are not
    left sitting in memory, swap, crash dumps, or logs longer than
    the work requires.
- Findings are fixed and **re-audited** — the house audit cycle
  (build → audit → fix → re-audit) closes the phase, not the first
  pass.
- **Packaging** — the kit's single self-installing exe pattern: one
  file, one admin prompt, self-placement, verified install, truthful
  reporting in the interface. *(As built: self-install is
  per-user — no admin prompt — offered through the launcher's
  `--install`, verified by read-back, with the outcome reported
  plainly; the exe also runs without installing.)*
- **Portable edition (named deliverable):** a portable no-install
  edition of Aegis — runs from a folder or USB drive with no
  installation, following the Argus Portable pattern
  (ArgusPortable.zip) — ships alongside the installer at Phase 5,
  as part of this phase's packaging deliverables, and only after
  this phase's security audit gate passes. A portable password
  vault — your vault on a USB stick, no install, usable on the
  machine in front of you — is a headline use case for Aegis, not
  an afterthought, and the portable edition is built and audited
  for exactly that use.

## Later / backlog

- **Browser autofill integration** — browser extension / native
  messaging so the password vault can fill logins in place. Later by
  design: it widens the attack surface, and it gets its own security
  review before it is scheduled.
- Technician's Toolkit USB bundling — the Phase 5 portable edition
  (see above) packaged into the Technician's Toolkit USB set,
  alongside the rest of the medic kit.

## Standing rules

- **Audit everything, all the time.** Build → audit → fix →
  re-audit is the permanent cycle, and Phase 5's gate is its
  sharpest form: a product that guards people's passwords does not
  ship on its builder's say-so.
- **No corners cut on crypto.** Vetted libraries only; never
  hand-roll a primitive; never invent a format detail that a
  published construction already settles.
- **The honesty rules are features.** The master-password warning
  and the printable recovery key ship in Phase 1, in plain language,
  up front — not in fine print, not in a later patch.
- **Plain language everywhere a user reads.** If a screen needs a
  glossary, the screen is wrong.
- **Synthetic fixtures only.** Tests use generated fake credentials
  and throwaway vaults. Real credentials, real vaults, and real user
  data never enter this repository — not in fixtures, not in
  screenshots, not ever.
- **Functionality first, truthfully reported.** Every control works
  or is not shipped; every failure state is a designed screen with
  one clear next step, never a raw error.
