# Coverage

Every emitted production source line and branch must execute. CI retains raw
LLVM JSON and LCOV from the same actual test execution, using floating nightly
only for branch instrumentation. Stable native and actual Chrome/Wasm vectors
remain mandatory. No production exclusions or lowered thresholds are present.

The shared source checker requires exact JSON/LCOV file and branch inventories,
agreed raw summaries, nonempty source lines and positive DA/BRDA counts. Original
JSON generic-instantiation totals remain visible diagnostics; source coverage
does not claim every possible generic instantiation. Tests are under tests/ and
excluded from production counts. Cargo.lock is resolved once and reused locked.
