# AEGIS.EXE

**Sentinel Safeguard LLC — file encryption and password manager for Windows.**

[![Version](https://img.shields.io/badge/version-v0.3.0-2ee06f?style=flat-square)](https://github.com/TheRealJesusTheHacker/Aegis.exe/blob/main/aegis/__init__.py)
[![Platform](https://img.shields.io/badge/platform-Windows-0078D6?style=flat-square&logo=windows&logoColor=white)](https://github.com/TheRealJesusTheHacker/Aegis.exe)
[![Python](https://img.shields.io/badge/Python-3-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-Proprietary-b03a2e?style=flat-square)](https://github.com/TheRealJesusTheHacker/Aegis.exe/blob/main/LICENSE)

*It does not open.*

---

## Overview

The aegis was the shield of Zeus, carried by Athena — the one defense
in the old stories that nothing ever got through. It did not win
fights. It made fights pointless.

AEGIS.EXE is Sentinel Safeguard's shield for Windows: a file
encryption tool and a password manager in one product. One master
password guards everything behind it — your sealed files, your
documents in transit, your recovery codes, and every login you own.

Aegis is local-first. Your vault lives on your machine, under your
key. There is no account to make, no cloud your secrets are copied to,
and no company — including us — that can open it for you. That is not
a limitation of the design. That **is** the design.

## Side one — file encryption

### The Vault

Files and folders sealed into encrypted vaults behind your master
password. Unlocked, a vault opens like a normal drive — your files,
where you left them. Locked, it is invisible to anyone else who sits
down at the machine.

### Lock-and-send

Encrypt a single file with a password before it leaves the machine —
contracts, reports, client documents that have to travel by email or
USB and should not travel in the clear. The file that arrives is
sealed; only the person with the password opens it.

### The Strongbox

A sealed space inside Aegis for the things that cannot live in a
notebook or a sticky note: recovery codes, license keys, private
notes, and copies of documents you cannot afford to lose. Small,
important, and shut.

### Lazarus's armor

Aegis encrypts backups themselves — including backup sets made by
[Lazarus.exe](https://github.com/TheRealJesusTheHacker/Lazarus.exe),
Sentinel's backup and recovery tool. A backup drive that gets lost or
stolen should be an inconvenience, not a privacy disaster. Sealed by
Aegis, it is.

## Side two — password manager

- **One vault for every login** — all your credentials in one
  encrypted store, guarded by the same master password as everything
  else in Aegis.
- **Strong password generator** — proper random passwords, generated
  on the spot, so no login ever has to reuse one again.
- **Fast search and copy** — find the login you need in seconds, copy
  it, get on with your day. A copied password is taken back off the
  clipboard a short while later, and the vault locks itself when
  left alone — copying a password never leaves an open vault
  sitting behind you.
- **Sealed moving only** — logins move between vaults as sealed
  copies, or by merging one open vault into another. Aegis never
  writes your logins out in plain text — the reasoning is written
  down in [the import/export safety review](docs/IMPORT-EXPORT-SAFETY.md).

Browser autofill integration is planned as a later phase — it is in
the [roadmap](docs/ROADMAP.md) backlog, not promised for launch.

## The crypto, stated plainly

These are design commitments, written down so they can be audited
against the code:

- **AES-256** encryption for vaults, sealed files, and the credential
  store.
- **Argon2id** key derivation turns your master password into the
  keys — deliberately slow and memory-hard, so guessing passwords in
  bulk is expensive for an attacker and unnoticeable for you.
- **Vetted libraries only.** Aegis never hand-rolls a cryptographic
  primitive. The encryption is built on established, reviewed
  implementations — the same rule the rest of the Sentinel kit is
  built under.
- **One vault key, wrapped two ways.** Each vault has its own random
  256-bit key. The vault file stores two sealed copies of it: one
  that only your master password can open, one that only your
  recovery key can open, each behind Argon2id at the RFC 9106
  recommended settings (64 MiB, 3 passes, 4 lanes), with those
  settings recorded in the vault's header. Changing your password
  or recovery key re-seals that copy — and re-binds the vault's
  contents to the new seal, so yesterday's contents can't be slipped
  under today's password.
- **Tampering is refusal.** Every part of a vault is authenticated.
  Change a single byte — in the header, in a wrapped key, in the
  contents — and Aegis will not open it. It never "repairs," never
  guesses, never opens a vault that doesn't check out.
- **Two truths, stated plainly.** Changing your password does not
  re-encrypt your files, and a copy of the vault made before the
  change still opens with the old password — no sealed file can
  unsend its copies. And if a vault file is ever replaced wholesale
  with an older copy of itself, Aegis opens the older copy: a sealed
  file can't tell time. Keep your own backups straight, and treat
  old copies like old keys.

Before any public release, Aegis passes an independent security audit
gate — threat model, crypto review, key-derivation parameter
verification, memory-handling review. See the roadmap: it is a hard
gate, not a milestone.

## The honesty rules

A shield that can be opened by anyone who asks nicely is not a
shield. So, stated up front, the way Aegis itself will state it at
setup:

- **Lose your master password and nobody can open your vault.** Not
  Sentinel, not support, not a backdoor — there isn't one. That is the
  point of the product, and Aegis says it in plain language before
  you store a single thing.
- **A printable recovery key is offered at setup** for exactly that
  reason. Print it, put it somewhere safe, and the warning never has
  to become a tragedy.
- **One Lock button. One Unlock button.** No crypto jargon in the
  interface, ever. You should not need to know what a key derivation
  function is to keep your files safe — that part is our job.

## Local-first, always

No forced cloud account. No telemetry on your vault's contents —
there is nothing to phone home *about*. Your data stays on your
machine; sync, if it ever comes, will be your choice and your copy.

## The medic kit

Aegis is part of Sentinel Safeguard's medic-kit line of Windows
tools, built to one standard: premium, plain-spoken, and functional —
every control does what it says.

- **Argus.exe** — antivirus and malware detection
- **Charon.exe** — driver updates, with a verified restore point
  before anything changes
- **Lazarus.exe** — backup, restore, and file recovery
- **Aegis.exe** — encryption vault and password manager

## Status

**v0.3.0 — Phase 2 complete: the password vault.** The credential
store stands on the Phase 1 core, exactly as the roadmap demands —
the logins live inside an ordinary vault as one sealed item, opened
by the same master password and recovery key, with no second
cryptography anywhere. On top of it: a proper random password
generator, fast search that never touches password values,
copying with automatic clipboard clearing, and lock-on-idle, so
walking away from an open vault is safe. Logins move only as
sealed copies or vault-to-vault merges — never in plain text; the
written safety review behind that decision is
[docs/IMPORT-EXPORT-SAFETY.md](docs/IMPORT-EXPORT-SAFETY.md). The
suite is now 257 tests, and Phase 2 went through the same
adversarial self-audit cycle as Phase 1 before this version was
cut. That self-audit does **not** replace the Phase 5 independent
security audit gate: no public release ships before that gate
passes. Next is Phase 3 — the Strongbox, Lock-and-send, and
Lazarus's armor. The build order is in [docs/ROADMAP.md](docs/ROADMAP.md).

### Running the core and its tests

The vault core is a Python package (`aegis/`) with two dependencies,
both vetted cryptographic libraries:

```
pip install -r requirements.txt
python -m pytest tests/ -q
```

`aegis.Vault.create(path, password)` makes a sealed vault and hands
back the one-time recovery key; `aegis.Vault.open(path, ...)` opens
one with either the master password or the recovery key. The
interface is deliberately small — Phases 2 through 4 build on it,
and nothing else in Aegis invents its own cryptography. The
password vault is `aegis.CredentialStore(session)` over an open
session, with `aegis.generate_password(...)`,
`aegis.AutoClearClipboard(...)`, and `aegis.IdleGuard(...)`
beside it.

A portable no-install edition (folder/USB, Argus Portable pattern) — including the portable password vault on a USB stick — is a named Phase 5 deliverable and will ship alongside the installer, after the security audit gate — see the roadmap.

## License

Proprietary — © 2026 Sentinel Safeguard LLC. All rights reserved.
See [LICENSE](LICENSE).
