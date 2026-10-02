#!/usr/bin/env bash
set -euo pipefail
# A changed classification must never inherit the informational exception.
curl --fail --silent --show-error --max-time 30 \
  https://api.osv.dev/v1/vulns/RUSTSEC-2026-0173 |
  jq -e '.id == "RUSTSEC-2026-0173" and (.affected | length > 0) and
    all(.affected[]; .package.name == "proc-macro-error2" and
      .database_specific.informational == "unmaintained" and
      .database_specific.cvss == null) and ((.severity // []) | length == 0)'
cargo deny --locked check advisories
