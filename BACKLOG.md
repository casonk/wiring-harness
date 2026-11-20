# BACKLOG.md

Portfolio backlog for this repository. Pending items are candidates for execution —
manually or via crew-chief. Entries sourced from archility audit are tagged
`[archility:YYYY-MM-DD]`; manual entries use `[manual:YYYY-MM-DD]`.

The archility twice-weekly job populates this file automatically via `archility audit --write-backlog`.
To execute a backlog item with crew-chief: `crew-chief agent "Work on item: <item text>"`.
Mark items `[x]` when complete and move them to Done.

## Pending

- [ ] [manual:2026-11-20] **Change the 16 default PINs** — every `pin = true` site still
  uses the placeholder `0000`. Open each site, use **Change PIN** on its keypad, and
  pick a PIN that `pin_gate.py` accepts (no repeats or runs). Needs the auto-pass daemon
  unlocked and `writable_paths` for `portfolio/pin/*` in the local allowlist. Done when
  `auto-pass provision-get --db infra portfolio/pin/<site>` no longer returns `0000` for
  any site. See `docs/pin-gate.md`.
- [ ] [manual:2026-11-20] **Decide whether PINs need periodic rotation** — the Change PIN
  page covers on-demand changes. Decide whether to add a reminder or an age report (for
  example flagging a PIN unchanged for 90 days) and, if so, where it should live.
  Lockout alerts already go to Signal, Telegram and Gmail.

- [ ] [manual:2026-10-15] **Ask GitHub Support to purge pre-rewrite commits** — this
  repository's published history was rewritten (most recently on 2026-10-15,
  to remove per-commit AI attribution trailers). GitHub keeps serving the old
  commits to anyone with a hash, and through the read-only `refs/pull/*` refs
  of earlier pull requests, until Support garbage-collects them. The request
  is filed once for the whole portfolio from traction-control's backlog; mark
  this done when an old hash returns 404 here. Never push an old clone's
  history back.

## In Progress

## Done
