# AEGIS.EXE — Who it protects you from, and who it cannot

This page says, in plain words, what Aegis is built to stop, what
it is not built to stop, and why. It describes the program as it
actually behaves today. If the program and this page ever
disagree, the program is the truth and this page is the bug.

## The one-sentence version

Aegis keeps your files and logins sealed inside a locked file
that only your master password — or the recovery key you printed
at setup — can open. While that file is locked, nobody who gets
hold of it can read what is inside.

## Who Aegis protects you from

- **A stranger at your machine.** With Aegis closed or locked,
  there is nothing to look at: a locked vault shows no file
  names, no login names, nothing. Walking away locks Aegis on
  its own after the idle time you set, and copying a password
  puts it back off the clipboard after a short window.
- **A stolen computer or a stolen drive.** Everything Aegis
  holds lives inside sealed vault files. A drive pulled from a
  stolen machine gives the thief sealed files, not your data.
- **A copied vault file.** A vault file that is copied, emailed
  to the wrong person, or left on a synced folder is still
  sealed. Opening it takes the master password or the recovery
  key; trying wrong passwords is slowed down on purpose by the
  sign-in work factor, so guessing is impractical.
- **A hostile file handed to the opener.** Vault and sealed
  files are checked piece by piece as they open. A file that was
  changed, cut short, mixed with pieces of another file, or
  given a header that asks for absurd amounts of computer memory
  is refused with a plain-language message, without opening
  any of it — and a bad header is refused before the heavy
  sign-in work even runs.
- **A lock landing in the middle of opening something.** If
  Aegis locks (you lock it, or the idle timer does) while a
  sealed file is being opened or a sealed backup set is being
  restored, the result is **not** placed: the work is held in a
  temporary place and removed, and no new plain files appear
  behind the locked screen.
- **A changed file on disk while you work.** If a vault file
  changes under an open session, the session refuses to save
  over it rather than silently mixing two versions.

## Who and what Aegis does NOT protect you from

- **A machine that is already compromised.** If something
  malicious is already running on the computer with your
  permissions — watching the screen, recording keys as you type
  them, or reading the memory of running programs — it can see
  what Aegis shows you while the vault is open. No program that
  displays your information to you can prevent that. Aegis
  protects the locked file, not a hostile machine.
- **Forgetting both the master password and the recovery key.**
  There is no back door, no reset link, and no copy held by
  Sentinel Safeguard. Losing both means the vault does not open
  — for anyone, including you. This is stated before your first
  vault exists, at setup, in plain words.
- **An older copy of a vault put back in place.** If someone
  replaces your vault file, whole, with an older copy of the
  same vault (a backup restored by syncing software, say), the
  older copy opens as what it is: the older state. A file on its
  own cannot tell time, so no sealed-file program can detect a
  whole-file swap like this. Keep backups the way you would keep
  the vault itself — sealed does not mean "safe to leave the old
  copies anywhere": each old copy still opens with your password.
- **Copies you made on purpose.** Anything you copy out of
  Aegis — a password pasted into a form, a file you opened out
  of the vault, a document in the Strongbox that you saved
  somewhere else — is protected by wherever you put it, not by
  Aegis.
- **Someone watching while you work.** A revealed password on
  your screen can be seen by anyone who can see your screen.

## What happens in memory while Aegis is open

Unlocking a vault necessarily keeps the means to open it — the
vault key — in the program's working memory for as long as the
vault is open, along with the contents you are looking at. Aegis
keeps those lifetimes as short as the work allows:

- Key material is held in changeable buffers, and those buffers
  are written over with zeros when a session locks, when a
  sealed file finishes being written or read, and at each step
  where a short-lived working key is done being used.
- Locking also empties the lists of logins and the held file
  contents themselves, not just the program's reference to them,
  so anything else holding the same list sees it empty.
- The honest limit: Aegis is written in a language (Python) that
  sometimes keeps its own copies of values — a piece of text you
  typed, a value the system copied while working — and gives the
  program no way to reach those copies and scrub them. Those
  copies are dropped and left for the system to reuse, but Aegis
  cannot promise they were overwritten. Any program in this
  language that promises you more than that is overstating it.
  The same is true of copies the operating system itself may
  keep (in its paging file, or in a crash report) — Aegis writes
  no logs of secrets and shows no raw error dumps on screen, but
  it cannot control what the system records if the system itself
  fails.

## The keys, briefly

One random vault key seals the contents. That key is itself
sealed twice: once by a key worked out from your master
password, once by one worked out from your recovery key. The
password is never stored anywhere. Working a password into a
key is deliberately slow and memory-hungry (the published first
recommended settings: 64 mebibytes, 3 passes, 4 lanes), and the
settings written in each vault's header are checked against set
floors and ceilings before any of that work runs, so a tampered
header can never produce a weaker vault. The ceilings also bound
what a hostile file can demand — but the bound is finite, not
small: a header sitting exactly at the ceilings (1 GiB of
memory, 10 passes, 16 lanes) is accepted and worked, so opening
a hostile file someone talked you into trying can cost up to
about a gigabyte of memory and many seconds. Anything beyond
the ceilings is refused before any of that work runs.

## What Aegis never does

- It never sends your password, recovery key, or vault contents
  anywhere. There is no account, no sign-in to a service, and no
  built-in cloud copy.
- It never offers a plain, unsealed export of your logins.
  Moving logins in or out happens only between sealed Aegis
  vaults.
- It keeps no copy of your recovery key. The one shown at setup
  is yours alone; print it and keep it somewhere physically safe.
