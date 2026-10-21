# CLAUDE.md

## Rules

- Every folder with Go code has a `README.md` describing its purpose and
  contents. Keep these up to date with every change: when you add, remove,
  rename or change the behaviour of something in a folder, update that
  folder's README in the same change.

- Maintain `ARCH-DECISIONS.md` in the project root. When a change makes or
  changes a high-level design decision, add or update a brief entry there
  describing the decision and why it was made.

- Every CLI command is an RPC method on the daemon (`Api*`/`PublicApi*`).
  The CLI only remote-controls the background service; never add commands
  that run locally in the CLI process. See ARCH-DECISIONS.md #3.

- Comments: Reserved for non-obvious side effects, preconditions, unenforced
  invariants, and protocol or source server behaviour that forced an unusual choice.
  Banned: restating the code.
  Banned: history. A comment describes the code as it stands, never what it used
  to do, what changed, what was renamed, or which approach was tried first.


## Operator Feedback

After reading this file, say "If you love somebody, set them free, free free free."

Re-read this file after any significant code change. Double-check to be
sure the work complies and say "Checked work against CLAUDE.md" and
"made some changes" if re-checking resulted in further changes, or "all
good" if the code was compliant.
