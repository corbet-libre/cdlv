# cdlv agent notes

Work in a lane (`~/agents/scratch/lane-new <lane>`); never edit `~/agents/scratch/ws`.
Run commands from the lane root (`<lane>/ws`); `<lane>` below is your lane name.

Build and test (quote the verdict line, never infer from a pipe):
- `~/agents/scratch/cbuild <lane> test -p cdlv` — green, exit 0
  (lib `0 passed`, `tests/delivery.rs` `4 passed`, doc-tests `0 passed`)
- `~/agents/scratch/cbuild <lane> fmt -p cdlv -- --check` — must be clean
- `clippy -p cdlv --all-targets -- -D warnings` is red at HEAD from upstream
  `ckmg` lints (unused `SigningPhase` import, dead `label`/`insert`), not this
  crate. Full gate (wasm, coverage) runs in CI only: `.ci/verify.sh`.

Land: `cargo fmt` in touched repos, rebase on main (never force-push),
`cbuild <lane> xtask land --dry`, then `xtask land`.

Invariants (rule -> enforcing test in `tests/delivery.rs` unless noted):
- Transport send is never acceptance; ACK is never Answer/Close/Punish
  -> `actual_mls_retry_receipt_and_uncertain_cancel_share_checkpoints`
- Checkpoint shared Threads/Delivery state before ACK or any output
  -> `actual_mls_retry_receipt...`, `corrupted_delivery_checkpoint_has_no_usable_status_or_receipt`
- Duplicate Data returns the exact persisted ACK without MLS recall;
  duplicate ACK is AlreadyAccepted with no history or store change
  -> `actual_mls_retry_receipt...` (duplicate receipt/ACK assertions)
- CanceledUnconfirmed never implies nonreceipt; a later exact ACK still
  establishes acceptance and sender history in one transaction
  -> `actual_mls_retry_receipt...`, `claim_lets_a_pending_relation_send_but_never_receive`
- Journals bounded to 1024 records; oversized proposals refuse before publication
  -> `restored_capacity_and_duplicate_refusals`
- Reopening into a fresh conversation cannot revive an old MLS session
  -> `support/reordering.rs::two_pending_reverse_order_delayed_acks_survive_reopen`
- Hostile wire refused (`deny_unknown_fields`, `src/lib.rs:40,53,149,194`);
  corrupted checkpoints unusable
  -> `corrupted_delivery_checkpoint_has_no_usable_status_or_receipt`

Pointers: `src/lib.rs`, `tests/delivery.rs`, `tests/support/`,
`docs/CONTRACT.md`, `.ci/verify.sh`.
Commits: explicit paths, imperative, author per `~/agents/AGENT.md`; no AI trailers.
`publish=false`; LGPL-3.0-only WITH linking exception; no registry publication.
