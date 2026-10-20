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

## Phase 5 — Hardening, the security audit gate, and packaging

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
  reporting in the interface.
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
