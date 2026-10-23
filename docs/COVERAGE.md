# Coverage

Every reachable emitted production source line and branch must execute. CI retains raw
LLVM JSON and LCOV from the same actual test execution, using floating nightly
only for branch instrumentation. Stable native and actual Chrome/Wasm vectors
remain mandatory. Only the two proposed branch-arm exceptions below are present; thresholds remain100%.

The shared source checker requires exact JSON/LCOV file and branch inventories,
agreed raw summaries, nonempty source lines and positive DA/BRDA counts. Original
JSON generic-instantiation totals remain visible diagnostics; source coverage
does not claim every possible generic instantiation. Tests are under tests/ and
excluded from production counts. Cargo.lock is resolved once and reused locked.

## Inbound record state invariant

The two exact native branch-arm exceptions in
`.github/coverage-exclusions.json` are proposals requiring independent
review. They do not omit any line, function, file, live authority check or input
refusal. Before exceptions, actual native and Chrome/Wasm vectors at
382e2acc00a1d81f5c3c122ea70b99eb67bcbb59 exercise584/584 emitted source lines and
180/182 branch arms; the raw reports remain in
[CI36918282371](https://github.com/corbet-foss/cdlv/actions/runs/36918282371).
The remaining two arms contradict the same private-state invariant:

- `Record`, `Journal`, `Delivery.journal` and `Candidate.journal` are private.
  `received` creates every inbound record with `outgoing=false`, `Accepted`, no
  wire and an ACK. `load` rejects an inbound record with another status or a wire,
  and requires every Accepted record to contain its exact verified ACK.
- `outgoing` creates only outbound Pending records. `acknowledged` can only set
  Accepted; `cancel` requires an outbound Pending record before setting
  CanceledUnconfirmed. `wrap` and `resume_wrap` share one helper that changes only stored wire bytes. Candidate commit
  reloads through the same validation. No operation can make inbound Pending or
  CanceledUnconfirmed state usable.
- In `wrap`, the status comparison first rejects everything except Pending.
  Therefore its subsequent `!record.outgoing` true arm cannot execute. In `ack`,
  the first comparison rejects outbound records; an inbound record necessarily
  has Accepted status, so the subsequent non-Accepted true arm cannot execute.

Malformed inbound status/wire/ACK checkpoints are real encrypted-Store refusal
vectors, not omitted tests. Outbound ACK lookup, late acceptance after uncertain
cancellation, and both true and false live authorization paths remain measured.
The guards remain defensive source code. The shared opt-in policy checker pins
all of src/lib.rs (including every constructor, validator and mutator), each
source line and the exact emitted branch coordinates. Any source change, missing
counter or execution of an excluded arm fails. Complete JSON/LCOV/text inventories
and the opposite branch arms remain mandatory. Thirteen checker regression
methods verify these constraints. No browser coverage exclusion is declared;
actual browser vectors remain required separately from native source coverage.
