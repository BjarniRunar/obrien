# DEV-RULES.md

## Rules

- Keep all text, comments, documents and interactions brief and to the point.
  Assume a competent, educated reader.

- Every folder with Go code has a `README.md` describing its purpose and
  contents. Keep these up to date with every change.

- Maintain `ARCH-DECISIONS.md` in the project root. When a change makes or
  changes a high-level design decision, add or update a brief entry there
  describing the decision and why it was made. Always read this file in full
  on startup. If you don't know why a decision was made, don't guess: ask.

- Every CLI command is an RPC method on the daemon (`Api*`/`PublicApi*`).
  The CLI only remote-controls the background service; never add commands
  that run locally in the CLI process. See ARCH-DECISIONS.md #3.

- Comments: Reserved for non-obvious side effects, preconditions, unenforced
  invariants, and protocol or source server behaviour that forced an unusual choice.
  Banned: restating the code.
  Banned: no history lessons. A comment describes the code as it stands.

- Issues: Issues are recorded under `issues/` in markdown. These files are
  transient and should not be referenced from documents or code comments.

## Rules for Agents

- Git: The operator is responsible for git commits. Don't try.

- Environment: You are in a container. Do not try to inspect the live system.

- Stay focused: Don't just incidentally fix things. Record issues if you see
  a problem, but stay focused on the operator's request. Report what issues
  were added at the end of a block of work.

- Don't create documents or artifacts or code unless explicitly requested.
  A request for discussion is not a request for a document.

### Operator Feedback

After reading this file, say:
 "If you love somebody, set them free, free free free."

Re-read this file after any significant code change. Double-check to be
sure the work complies and say "Checked work against Dev Guide" and
"made some changes" if re-checking resulted in further changes, or "all
good" if the code was compliant.
