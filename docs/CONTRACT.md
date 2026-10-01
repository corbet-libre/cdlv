# Delivery contract

Consume committed Threads ciphertext and recipient acceptance capabilities.
Transport send success is not recipient acceptance. Signatures/current device
authority belong to Keys; message encryption/history belong to Threads; Waves
owns first-contact authorization and domain outcomes. No duplicated framing.

Prepared → Pending → Accepted or CanceledUnconfirmed. Preserve exact ciphertext,
original identifiers and uncertain outcomes across retry/restart. Persist the
shared Threads/Delivery checkpoint before ACK or any output. Offline established
messages use opaque Records; first contact requires authenticated live peers.

No implementation acceptance yet. Real Mesh/Records and owner capabilities are
required. No successful fixture substitutes for unavailable production evidence.

## Current implementation boundary

Established contacts have real signed ciphertext/ACK envelopes using scoped Keys
certificates and VLD0 signatures. Delivery receives Threads' sealed description,
retains the actual Threads Candidate, and saves the two owner records together.
Recipient ACK bytes are stored in that same transaction as decrypted accepted
history. A transport consumer can retrieve them only from committed Delivery.
Outgoing ciphertext remains in Threads' durable output while its signed transport
wrapper is checkpointed; retry preserves the exact wrapper and MLS bytes.

CanceledUnconfirmed never implies recipient nonreceipt. A later exact authenticated
ACK may still establish acceptance and sender history in one shared transaction.
ACK does not Answer, Close or Punish. Only the new signed evidence is rechecked;
accepted historical records survive credential changes. Enqueue/retry requires
current established Contacts, the exact shared version, and current MLS recipient
certificate. First-contact release refuses until Waves supplies real accepted
reservations and current record evidence; no test-only positive production path.

Mesh and Records adapters remain owner integration work. The current Wire is one
complete application message, not a new frame or transport. Public-room delivery,
authenticated live first-contact handshake and offline record publication are not
claimed implemented by this established-contact journal. Actual external transport
and restore/retention acceptance require the owners' real runtime, never a mock.

An authenticated duplicate Data envelope returns the exact persisted ACK without
calling MLS again. An authenticated duplicate ACK returns AlreadyAccepted without
changing history or the store version. Fresh Contacts and device checks still run
before duplicate Data releases an ACK. Journals are bounded to 1024 records and
Store's per-value byte limit; the authenticated Store bounds restored bytes and
oversized proposed journals fail before publication. The current established
Contacts conversation must equal the MLS conversation at enqueue, receive, retry
and publication. Reopening into a fresh conversation cannot revive an old MLS
session.

Incoming is a sealed data capability with concrete ciphertext fields, so an ACK
cannot reach its ciphertext getter. Threads refusals keep their original typed
error instead of being reported as a storage failure. The complete wire envelope
is byte-bounded before parsing; JSON byte-array encoding necessarily bounds its
inner payload more tightly, so there is no redundant larger inner allocation cap.
