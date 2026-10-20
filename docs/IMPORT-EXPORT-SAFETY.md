# Import / Export Safety Review — Phase 2

Written before the Phase 2 credential store was built, as the
roadmap requires: *"Entry import/export design reviewed for safety
before it is built: exports are themselves an encryption decision,
never a plain-text default."*

This document records the dangers considered, the decision taken
for Phase 2, and the conditions any future phase must meet before
the decision can change.

## The dangers

**1. Plain-text exports are the number-one way password managers
leak.** A spreadsheet or text file holding every login in the clear
defeats the entire vault the moment it exists: it sits in a
downloads folder, gets swept into a synced folder or a backup, is
attached to an email "just for a minute," and outlives the moment
it was made — long after the person has forgotten it exists. Every
copy is a full copy of everything, readable by anyone who finds
it, forever. A password manager that produces one casually has
undone its own core promise.

**2. The clipboard is an export channel.** Anything copied out of
the vault can be pasted into a document, a message, or a cloud note
that syncs off the machine. Phase 2 already treats the clipboard
as hostile territory (copied passwords are cleared again after a
short window); an "export to clipboard" feature would spray the
whole vault through that same channel with no clearing discipline
that could possibly keep up.

**3. Spreadsheet formula injection.** Login fields are
attacker-chosen text — a site name, a user name, a note. In a
plain-text table (CSV and friends), a field beginning with `=`,
`+`, `-`, or `@` is interpreted as a *formula* by spreadsheet
programs when the file is opened: it can run calculations, pull in
outside data, or phish the person who opened it. So even a
plain-text export made "just for the owner" can be a weapon
against the owner if any entry in it was crafted by someone else.
Any future plain-text table format would have to neutralize every
such field — and the safe-looking result still leaves danger 1
fully intact.

**4. Plain-text imports teach the worst habit.** Accepting a
spreadsheet of logins means the person's whole password list
existed in the clear before Aegis ever saw it — usually in exactly
the downloads-folder conditions of danger 1. Importing it cleanly
does not un-expose it; the file is still there afterwards.

## The Phase 2 decision

- **Export: sealed copies only.** Phase 2 exports a vault as a
  sealed `.aegis` copy — the same sealed file format, opened by the
  same master password and recovery key. It is never written in
  plain text, in whole or in part. An exported copy is a *full*
  copy: whoever holds it and the password holds everything, and
  the copy feature says so in plain language.
- **Import: from Aegis vaults only.** Phase 2 can bring logins in
  from another Aegis vault (both vaults open, entries merged into
  the current one). There is nothing readable to intercept: the
  source is sealed until the owner opens it.
- **No plain-text import or export in Phase 2.** No CSV, no
  spreadsheet, no text file — in either direction.

## Conditions for any future change

A later phase may revisit plain-text formats only with its own
written review, and only with all of the following: a loud,
plain-language warning flow that names the danger before anything
is written (the person must understand the file they are making
can be read by anyone who finds it); formula-injection
neutralization on every exported field; and a design that treats
the plain-text file as the exception the person asked for by name,
never a default, never one click among equals. Absent that review,
this decision stands.
