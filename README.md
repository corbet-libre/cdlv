# cdlv — Delivery

Authenticated message delivery and recipient acceptance on member devices.

## Scope

Own live/offline delivery sessions, stable message IDs, pending outbox, retry,
recipient ACK/refusal and accepted-delivery evidence. Consume committed Threads
ciphertext, existing Mesh messages and opaque Records. Checkpoint candidate MLS,
Delivery and outputs together before publication or ACK.

Never decide Wave outcomes, identity, membership or accounting. Never treat a
transport return as acceptance, create an operator mailbox, or add a second Tor
or frame layer. First contacts stay live; offline retains established encrypted
pending messages without promising retention.

**States.** Disconnected → Authenticating → Live; pending ciphertext becomes
queued/stored/sent, acknowledged, unavailable, failed or cancelled. The current
journal exposes Pending, Accepted and CanceledUnconfirmed; transport states await
real adapters. ACK and DHT storage never imply Answer.

**Ports.** Threads candidates and committed outputs, Keys custody and current
device authority, Contacts, encrypted Store, Mesh messages and opaque Records.

**Invariants and tests.** Private history stays on members' devices. Real Tor and
DHT roundtrips, duplicate/lost-ACK restart, commit-before-ACK, block/revocation,
retention failure and operator-storage inspection are required for full scope.
Data owners compress and pad with Compression before Records encrypts.

## Reuse and status

Extract the tested cmsg live/session/ACK retry semantics, replace obsolete
identity authority with scoped Keys capabilities, and consume Threads' durable
outputs. Stream A was committed first. Established-contact journal, combined Threads checkpoint and exact signed retry/ACK paths are validated by real native and Chrome/Wasm vectors; strict coverage and dependency audit remain open. First-contact release and Mesh/Records integration remain unavailable; no full delivery acceptance is claimed.
See [the contract](docs/CONTRACT.md) and [licensing](LICENSE.md).
