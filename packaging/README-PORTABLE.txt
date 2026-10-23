AEGIS.EXE — Portable edition
Sentinel Safeguard LLC

Run Aegis.exe from this folder. Nothing is installed: no admin
prompt, no Start Menu entry, nothing written to the system
folders. It runs from a USB stick exactly as it runs here.

WHAT THIS EDITION WRITES, AND WHERE — the honest list:

- Your vault files (.aegis) live wherever YOU put them, and
  Aegis opens them in place. It does not copy them into this
  folder or anywhere else.
- Files you open out of a vault, and folders you restore from a
  sealed backup set, are written where you choose at that
  moment — and only if Aegis has not locked in the meantime; if
  it locks while the work runs, nothing is placed.
- Two small per-person files are kept outside this folder,
  in Aegis's per-person folder on the machine (the Aegis
  folder under %LOCALAPPDATA% on Windows): settings.json,
  holding only the two timing choices (the idle-lock time
  and how long a copied password stays) — saved between
  runs since v1.0.4 — and, since v1.0.5, vault-state.json,
  the rollback tripwire's record: check values of the
  newest vault states this copy of Aegis has seen, and of
  the states it moved past. Neither file holds any vault
  content or file names.
- The working copies Aegis holds in memory while a vault is
  open are the operating system's business (any running program
  can be paged to disk by the system); the vault files on disk
  stay sealed at all times.

That is the whole footprint. There is no hidden data folder and
no claim of one: "portable" here means no installation, not
invisibility.
