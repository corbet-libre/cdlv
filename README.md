# cdlv — Delivery

Authenticated message delivery and recipient acceptance on member devices.

## Scope

### Purpose

Carries committed Threads ciphertext to recipients live over Mesh, or as sealed Records for existing contacts who are away, with receipts and retries.

### Owns

Authenticated sessions, stable message identifiers, pending outbox, retry and cancellation, recipient acknowledgement or refusal, and offline queueing through Records.

### Never

Does not advance balances on acknowledgement, invent contact consent, permit offline first contact, treat a stored record as recipient acceptance, keep an operator mailbox, or add a second framing or transport layer.

### States

Disconnected to Authenticating to Live; each output moves from Pending to queued offline, stored, or sent, then to acknowledged, or to unavailable, failed, or cancelled.

### Test obligations

Real live and Records-backed offline round trips; duplicates and lost acknowledgements still yield one history item; acknowledgement follows committed history; blocking and revocation stop new acceptance; queued writes survive restart; evicted replicas report failure, never false delivery; operator storage inspection shows no message kept there. Native and Wasm builds share identical test vectors; state machines use injected clock, randomness, storage, and network; full line and branch coverage uses real round trips with injected delay, duplication, loss, cancellation, clock regression, corruption, and storage conflicts; acknowledgement follows durable acceptance with reconciliation of unknown outcomes; keys, sessions, stores, and locators stay isolated per community; sizes and work are bounded and errors omit identifiers, plaintext, and secrets; maintained third-party code only with no own crypto; outbound requests carry no personal identifiers.

## Reuse and status

Extract the tested cmsg live/session/ACK retry semantics, replace obsolete
identity authority with scoped Keys capabilities, and consume Threads' durable
outputs. Stream A was committed first. Established-contact journal, combined Threads checkpoint and exact signed retry/ACK paths are validated by real native and Chrome/Wasm vectors; strict coverage and dependency audit remain open. First-contact release and Mesh/Records integration remain unavailable; no full delivery acceptance is claimed.
See [the contract](docs/CONTRACT.md) and [licensing](LICENSE.md).
