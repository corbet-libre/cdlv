//! Authenticated encrypted-message retry and recipient ACK checkpoints.
//! Transport completion never establishes delivery or a Waves outcome.
use ckmg::{
    Authority, Binding, Clock, Entropy, KeyCertificate, KeyHandle, Keys, Purpose, Scope,
    SecureStore, Signature,
};
use ctcs::{Contacts, DeviceAuthority};
use cwst::{Change, Store, backend::Backend};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub type Result<T> = std::result::Result<T, Error>;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub enum Error {
    Scope,
    Encoding,
    Limit,
    Authority,
    Unavailable,
    Conflict,
    Storage,
    State,
    Threads(cthr::Error),
}
const OWNER: &str = "cdlv";
const KEY: &[u8] = b"journal.v1";
const MAX_WIRE: usize = 2 * 1024 * 1024;
const MAX_RECORDS: usize = 1024;
const MAX_JOURNAL: usize = cwst::MAX_VALUE_BYTES;
pub fn purpose() -> Purpose {
    Purpose::new(Scope::Device, "cdlv.delivery", 1).expect("static purpose")
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub enum Status {
    Pending,
    Accepted,
    CanceledUnconfirmed,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
enum Body {
    Data {
        id: [u8; 32],
        epoch: u64,
        wire: Vec<u8>,
    },
    Ack {
        id: [u8; 32],
        epoch: u64,
    },
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u8,
    certificate: KeyCertificate,
    peer: String,
    conversation: [u8; 32],
    body: Body,
    signature: Signature,
}
impl Envelope {
    fn transcript(
        certificate: &KeyCertificate,
        peer: &str,
        conversation: &[u8; 32],
        body: &Body,
    ) -> Result<Vec<u8>> {
        serde_json::to_vec(&("cdlv.envelope.v1", certificate, peer, conversation, body))
            .map_err(encoding_error)
    }
    fn id(&self) -> &[u8; 32] {
        match &self.body {
            Body::Data { id, .. } | Body::Ack { id, .. } => id,
        }
    }
    fn epoch(&self) -> u64 {
        match &self.body {
            Body::Data { epoch, .. } | Body::Ack { epoch, .. } => *epoch,
        }
    }
    async fn verify(&self, devices: &mut impl DeviceAuthority) -> Result<()> {
        if self.version != 1
            || self.conversation == [0; 32]
            || self.id() == &[0; 32]
            || self.peer == self.certificate.binding.member()
        {
            return Err(Error::Scope);
        }
        Binding::new(self.certificate.binding.community(), &self.peer).map_err(scope_error)?;
        let current = devices
            .current(&self.certificate.binding)
            .await
            .map_err(authority_error)?;
        self.certificate
            .verify(&current, &purpose())
            .map_err(authority_error)?;
        ckmg::verify(
            &self.certificate.key,
            &Self::transcript(
                &self.certificate,
                &self.peer,
                &self.conversation,
                &self.body,
            )?,
            &self.signature,
        )
        .map_err(authority_error)?;
        if let Body::Data { id, wire, .. } = &self.body {
            // The bounded JSON byte-array envelope already limits this payload.
            if wire.is_empty() {
                return Err(Error::Limit);
            }
            if ckmg::hash(wire).value() != id {
                return Err(Error::Authority);
            }
        }
        Ok(())
    }
}
async fn sign<S: SecureStore, C: Clock, R: Entropy, A: Authority>(
    keys: &mut Keys<S, C, R, A>,
    handle: &KeyHandle,
    peer: String,
    conversation: [u8; 32],
    body: Body,
) -> Result<Envelope> {
    let certificate = handle.certificate().clone();
    if certificate.purpose != purpose() {
        return Err(Error::Scope);
    }
    let signature = keys
        .sign(
            handle,
            &Envelope::transcript(&certificate, &peer, &conversation, &body)?,
        )
        .await
        .map_err(authority_error)?;
    Ok(Envelope {
        version: 1,
        certificate,
        peer,
        conversation,
        body,
        signature,
    })
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    peer: String,
    peer_certificate: KeyCertificate,
    conversation: [u8; 32],
    id: [u8; 32],
    epoch: u64,
    outgoing: bool,
    status: Status,
    wire: Option<Vec<u8>>,
    ack: Option<Envelope>,
}
impl Record {
    fn envelope_matches(
        &self,
        envelope: &Envelope,
        sender: &Binding,
        recipient: &Binding,
    ) -> Result<()> {
        if envelope.version != 1
            || &envelope.certificate.binding != sender
            || envelope.certificate.purpose != purpose()
            || envelope.peer != recipient.member()
            || envelope.conversation != self.conversation
            || envelope.id() != &self.id
            || envelope.epoch() != self.epoch
        {
            return Err(Error::Encoding);
        }
        // Historical receipts stay valid after rotation; this checks the exact
        // retained signature, while publication/retry separately checks lineage.
        ckmg::verify(
            &envelope.certificate.key,
            &Envelope::transcript(
                &envelope.certificate,
                &envelope.peer,
                &envelope.conversation,
                &envelope.body,
            )?,
            &envelope.signature,
        )
        .map_err(authority_error)
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u8,
    binding: Binding,
    records: BTreeMap<String, Record>,
}
fn id_key(id: &[u8; 32]) -> String {
    id.iter().map(|byte| format!("{byte:02x}")).collect()
}
pub struct Delivery {
    journal: Journal,
    expected: u64,
    base: Option<Vec<u8>>,
}
/// Authentic bytes remain unaccepted until real Threads decryption and the
/// combined recipient checkpoint have succeeded.
pub struct Incoming {
    certificate: KeyCertificate,
    conversation: [u8; 32],
    id: [u8; 32],
    epoch: u64,
    wire: Vec<u8>,
}
impl Incoming {
    pub fn ciphertext(&self) -> &[u8] {
        &self.wire
    }
    pub fn conversation(&self) -> &[u8; 32] {
        &self.conversation
    }
}
/// The recipient signed this only after preparing its real MLS acceptance.
/// The enclosing recipient transaction persisted history and this exact ACK.
pub struct VerifiedAck {
    binding: Binding,
    envelope: Envelope,
}
impl cthr::Acceptance for VerifiedAck {
    fn verify(
        &self,
        binding: &Binding,
        peer: &str,
        conversation: &[u8; 32],
        message: &[u8; 32],
        epoch: u64,
    ) -> cthr::Result<()> {
        if binding != &self.binding
            || peer != self.envelope.certificate.binding.member()
            || conversation != &self.envelope.conversation
            || message != self.envelope.id()
            || epoch != self.envelope.epoch()
        {
            return Err(cthr::Error::Authority);
        }
        Ok(())
    }
}
/// A durable transport item. Contains already encrypted MLS bytes or a signed
/// ACK, never plaintext. Network adapters must send it as one Mesh message.
pub struct Wire(Vec<u8>);
impl Wire {
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
}
pub enum Authenticated {
    Data(Incoming),
    Ack(VerifiedAck),
    /// Exact prior acceptance: return this durable ACK without advancing MLS.
    Duplicate(Wire),
    /// An authenticated ACK for a message already in committed sender history.
    AlreadyAccepted([u8; 32]),
}
pub struct Candidate {
    threads: cthr::Candidate,
    journal: Journal,
    expected: u64,
    base: Option<Vec<u8>>,
    message: [u8; 32],
    requires_contact: bool,
}
pub struct Committed {
    pub threads: cthr::Committed,
    pub delivery: Delivery,
}
impl Delivery {
    pub fn load<B: Backend>(binding: Binding, store: &Store<B>) -> Result<Self> {
        if !store.is_scope(binding.community()) {
            return Err(Error::Scope);
        }
        let expected = store.version().map_err(storage_error)?;
        let base = store
            .read(OWNER, KEY)
            .expect("immutable store and static key checked")
            .map(<[u8]>::to_vec);
        let journal = match &base {
            Some(bytes) => serde_json::from_slice::<Journal>(bytes).map_err(encoding_error)?,
            None => Journal {
                version: 1,
                binding: binding.clone(),
                records: BTreeMap::new(),
            },
        };
        if journal.version != 1 || journal.binding != binding {
            return Err(Error::Scope);
        }
        if journal.records.len() > MAX_RECORDS {
            return Err(Error::Limit);
        }
        for (id, record) in &journal.records {
            if *id != id_key(&record.id)
                || record.id == [0; 32]
                || record.conversation == [0; 32]
                || record.peer == binding.member()
            {
                return Err(Error::Encoding);
            }
            let peer = Binding::new(binding.community(), &record.peer).map_err(encoding_error)?;
            let expected_purpose = if record.outgoing {
                cthr::purpose()
            } else {
                purpose()
            };
            if record.peer_certificate.binding != peer
                || record.peer_certificate.purpose != expected_purpose
            {
                return Err(Error::Encoding);
            }
            if !record.outgoing && (record.status != Status::Accepted || record.wire.is_some()) {
                return Err(Error::Encoding);
            }
            if record.status == Status::Accepted && record.ack.is_none() {
                return Err(Error::Encoding);
            }
            if let Some(wire) = &record.wire {
                let envelope: Envelope = serde_json::from_slice(wire).map_err(encoding_error)?;
                if !matches!(envelope.body, Body::Data { .. }) {
                    return Err(Error::Encoding);
                }
                record.envelope_matches(&envelope, &binding, &peer)?;
            }
            if let Some(ack) = &record.ack {
                if record.status != Status::Accepted || !matches!(ack.body, Body::Ack { .. }) {
                    return Err(Error::Encoding);
                }
                let (sender, recipient) = if record.outgoing {
                    (&peer, &binding)
                } else {
                    (&binding, &peer)
                };
                record.envelope_matches(ack, sender, recipient)?;
            }
        }
        Ok(Self {
            journal,
            expected,
            base,
        })
    }
    pub fn status(&self, id: &[u8; 32]) -> Option<Status> {
        self.journal.records.get(&id_key(id)).map(|r| r.status)
    }
    fn contacts(&self, contacts: &Contacts, peer: &str, conversation: &[u8; 32]) -> Result<()> {
        if contacts.binding() != &self.journal.binding || contacts.version() != self.expected {
            return Err(Error::Conflict);
        }
        // Waves owns first-contact release; there is no accepting substitute.
        let relation = contacts.relation(peer).map_err(scope_error)?;
        if relation.state != ctcs::State::Established
            || relation.conversation.as_ref() != Some(conversation)
        {
            return Err(Error::Unavailable);
        }
        Ok(())
    }
    pub async fn authenticate(
        &self,
        wire: &[u8],
        devices: &mut impl DeviceAuthority,
        contacts: &Contacts,
    ) -> Result<Authenticated> {
        if wire.is_empty() || wire.len() > MAX_WIRE {
            return Err(Error::Limit);
        }
        let envelope: Envelope = serde_json::from_slice(wire).map_err(encoding_error)?;
        if envelope.certificate.binding.community() != self.journal.binding.community()
            || envelope.peer != self.journal.binding.member()
        {
            return Err(Error::Scope);
        }
        envelope.verify(devices).await?;
        match envelope {
            Envelope {
                certificate,
                conversation,
                body: Body::Data { id, epoch, wire },
                ..
            } => {
                self.contacts(contacts, certificate.binding.member(), &conversation)?;
                if let Some(record) = self.journal.records.get(&id_key(&id)) {
                    if record.outgoing
                        || record.peer != certificate.binding.member()
                        || record.conversation != conversation
                        || record.epoch != epoch
                    {
                        return Err(Error::Authority);
                    }
                    return self.ack(&id).map(Authenticated::Duplicate);
                }
                Ok(Authenticated::Data(Incoming {
                    certificate,
                    conversation,
                    id,
                    epoch,
                    wire,
                }))
            }
            envelope @ Envelope {
                body: Body::Ack { .. },
                ..
            } => {
                let record = self
                    .journal
                    .records
                    .get(&id_key(envelope.id()))
                    .ok_or(Error::State)?;
                if !record.outgoing
                    || record.peer != envelope.certificate.binding.member()
                    || record.conversation != envelope.conversation
                    || record.epoch != envelope.epoch()
                {
                    return Err(Error::Authority);
                }
                if record.status == Status::Accepted {
                    return Ok(Authenticated::AlreadyAccepted(*envelope.id()));
                }
                Ok(Authenticated::Ack(VerifiedAck {
                    binding: self.journal.binding.clone(),
                    envelope,
                }))
            }
        }
    }
    fn attach(&self, threads: cthr::Candidate, record: Record) -> Result<Candidate> {
        let description = threads.prepared_message().ok_or(Error::State)?;
        if description.binding() != &self.journal.binding
            || description.checkpoint_version() != self.expected
            || description.id() != &record.id
            || description.epoch() != record.epoch
            || description.conversation() != &record.conversation
            || description.peer() != Some(record.peer.as_str())
            || description.receiving() == record.outgoing
        {
            return Err(Error::Scope);
        }
        if self.journal.records.contains_key(&id_key(&record.id)) {
            return Err(Error::Conflict);
        }
        if self.journal.records.len() >= MAX_RECORDS {
            return Err(Error::Limit);
        }
        let message = record.id;
        let mut journal = self.journal.clone();
        journal.records.insert(id_key(&message), record);
        Ok(Candidate {
            threads,
            journal,
            expected: self.expected,
            base: self.base.clone(),
            message,
            requires_contact: true,
        })
    }
    pub fn outgoing(&self, threads: cthr::Candidate, contacts: &Contacts) -> Result<Candidate> {
        let proposed = threads.prepared_message().ok_or(Error::State)?;
        let peer = proposed.peer().ok_or(Error::Unavailable)?.to_owned();
        self.contacts(contacts, &peer, proposed.conversation())?;
        let peer_certificate = proposed.peer_certificate().ok_or(Error::Authority)?;
        let record = Record {
            peer,
            peer_certificate,
            conversation: *proposed.conversation(),
            id: *proposed.id(),
            epoch: proposed.epoch(),
            outgoing: true,
            status: Status::Pending,
            wire: None,
            ack: None,
        };
        self.attach(threads, record)
    }
    pub async fn received<S: SecureStore, C: Clock, R: Entropy, A: Authority>(
        &self,
        threads: cthr::Candidate,
        incoming: Incoming,
        keys: &mut Keys<S, C, R, A>,
        handle: &KeyHandle,
    ) -> Result<Candidate> {
        if handle.certificate().binding != self.journal.binding {
            return Err(Error::Scope);
        }
        let peer = incoming.certificate.binding.member().to_owned();
        let ack = sign(
            keys,
            handle,
            peer.clone(),
            incoming.conversation,
            Body::Ack {
                id: incoming.id,
                epoch: incoming.epoch,
            },
        )
        .await?;
        let record = Record {
            peer,
            peer_certificate: incoming.certificate,
            conversation: incoming.conversation,
            id: incoming.id,
            epoch: incoming.epoch,
            outgoing: false,
            status: Status::Accepted,
            wire: None,
            ack: Some(ack),
        };
        self.attach(threads, record)
    }
    /// Attach a verified recipient ACK to the sender's accepted-history candidate.
    pub fn acknowledged(&self, threads: &cthr::Threads, ack: VerifiedAck) -> Result<Candidate> {
        if ack.binding != self.journal.binding {
            return Err(Error::Scope);
        }
        let id = *ack.envelope.id();
        let candidate = threads.acknowledge(&id, &ack).map_err(Error::Threads)?;
        let mut journal = self.journal.clone();
        let record = journal.records.get_mut(&id_key(&id)).ok_or(Error::State)?;
        record.status = Status::Accepted;
        record.ack = Some(ack.envelope);
        Ok(Candidate {
            threads: candidate,
            journal,
            expected: self.expected,
            base: self.base.clone(),
            message: id,
            requires_contact: false,
        })
    }
    pub async fn wrap<S: SecureStore, C: Clock, R: Entropy, A: Authority, B: Backend>(
        &self,
        outgoing: &cthr::Outgoing<'_>,
        keys: &mut Keys<S, C, R, A>,
        handle: &KeyHandle,
        devices: &mut impl DeviceAuthority,
        store: &mut Store<B>,
        operation: [u8; 32],
    ) -> Result<(Self, Wire)> {
        if outgoing.binding() != &self.journal.binding
            || handle.certificate().binding != self.journal.binding
        {
            return Err(Error::Scope);
        }
        let record = self
            .journal
            .records
            .get(&id_key(outgoing.id()))
            .ok_or(Error::State)?;
        if record.status != Status::Pending
            || !record.outgoing
            || record.conversation != *outgoing.conversation()
            || record.epoch != outgoing.epoch()
            || Some(record.peer.as_str()) != outgoing.peer()
        {
            return Err(Error::Authority);
        }
        self.wrap_payload(
            outgoing.id(),
            outgoing.bytes(),
            (keys, handle, devices),
            store,
            operation,
        )
        .await
    }
    /// Recover a committed send after a crash before its signed envelope existed.
    /// Only the original authenticated Storage outbox can supply the ciphertext;
    /// no new MLS send, generation or message identifier is created.
    pub async fn resume_wrap<S: SecureStore, C: Clock, R: Entropy, A: Authority, B: Backend>(
        &self,
        id: &[u8; 32],
        keys: &mut Keys<S, C, R, A>,
        handle: &KeyHandle,
        devices: &mut impl DeviceAuthority,
        store: &mut Store<B>,
        operation: [u8; 32],
    ) -> Result<(Self, Wire)> {
        self.check_base(store)?;
        let record = self.journal.records.get(&id_key(id)).ok_or(Error::State)?;
        let bytes = store
            .load_pending()
            .map_err(storage_error)?
            .iter()
            .find_map(
                |output| match serde_json::from_slice::<cthr::Event>(&output.bytes) {
                    Ok(cthr::Event::Ciphertext {
                        id: stored,
                        epoch,
                        bytes,
                    }) if stored == *id
                        && epoch == record.epoch
                        && ckmg::hash(&bytes).value() == id =>
                    {
                        Some(bytes)
                    }
                    _ => None,
                },
            )
            .ok_or(Error::State)?;
        self.wrap_payload(id, &bytes, (keys, handle, devices), store, operation)
            .await
    }
    async fn wrap_payload<S: SecureStore, C: Clock, R: Entropy, A: Authority, B: Backend>(
        &self,
        id: &[u8; 32],
        payload: &[u8],
        (keys, handle, devices): (&mut Keys<S, C, R, A>, &KeyHandle, &mut impl DeviceAuthority),
        store: &mut Store<B>,
        operation: [u8; 32],
    ) -> Result<(Self, Wire)> {
        if handle.certificate().binding != self.journal.binding {
            return Err(Error::Scope);
        }
        let mut journal = self.journal.clone();
        let record = journal.records.get_mut(&id_key(id)).ok_or(Error::State)?;
        if !record.outgoing || record.status != Status::Pending || record.wire.is_some() {
            return Err(Error::State);
        }
        self.contacts(
            &Contacts::load(self.journal.binding.clone(), store).map_err(storage_error)?,
            &record.peer,
            &record.conversation,
        )?;
        let current = devices
            .current(&record.peer_certificate.binding)
            .await
            .map_err(authority_error)?;
        record
            .peer_certificate
            .verify(&current, &cthr::purpose())
            .map_err(authority_error)?;
        let envelope = sign(
            keys,
            handle,
            record.peer.clone(),
            record.conversation,
            Body::Data {
                id: record.id,
                epoch: record.epoch,
                wire: payload.to_vec(),
            },
        )
        .await?;
        let wire = serde_json::to_vec(&envelope).map_err(encoding_error)?;
        record.wire = Some(wire.clone());
        let committed = self.persist(journal, store, operation).await?;
        Ok((committed, Wire(wire)))
    }
    /// Identical retry after restart. Fresh authority/contact checks still apply;
    /// no fresh MLS encryption, nonce or inferred acceptance is introduced.
    pub async fn retry(
        &self,
        id: &[u8; 32],
        devices: &mut impl DeviceAuthority,
        contacts: &Contacts,
    ) -> Result<Wire> {
        let record = self.journal.records.get(&id_key(id)).ok_or(Error::State)?;
        if !record.outgoing || record.status != Status::Pending {
            return Err(Error::State);
        }
        self.contacts(contacts, &record.peer, &record.conversation)?;
        let wire = record.wire.as_ref().ok_or(Error::State)?;
        let envelope: Envelope = serde_json::from_slice(wire).map_err(encoding_error)?;
        envelope.verify(devices).await?;
        // The peer must also remain current; its purpose certificate is checked
        // by Threads before enqueue and incoming ACK verification. The owner
        // must supply current peer lineage even when transport has no session.
        let current = devices
            .current(&record.peer_certificate.binding)
            .await
            .map_err(authority_error)?;
        record
            .peer_certificate
            .verify(&current, &cthr::purpose())
            .map_err(authority_error)?;
        Ok(Wire(wire.clone()))
    }
    pub fn ack(&self, id: &[u8; 32]) -> Result<Wire> {
        let record = self.journal.records.get(&id_key(id)).ok_or(Error::State)?;
        if record.outgoing || record.status != Status::Accepted {
            return Err(Error::State);
        }
        Ok(Wire(
            serde_json::to_vec(record.ack.as_ref().ok_or(Error::State)?).map_err(encoding_error)?,
        ))
    }
    pub async fn cancel<B: Backend>(
        &self,
        id: &[u8; 32],
        store: &mut Store<B>,
        operation: [u8; 32],
    ) -> Result<Self> {
        let mut journal = self.journal.clone();
        let record = journal.records.get_mut(&id_key(id)).ok_or(Error::State)?;
        if !record.outgoing || record.status != Status::Pending {
            return Err(Error::State);
        }
        record.status = Status::CanceledUnconfirmed;
        self.persist(journal, store, operation).await
    }
    async fn persist<B: Backend>(
        &self,
        journal: Journal,
        store: &mut Store<B>,
        operation: [u8; 32],
    ) -> Result<Self> {
        self.check_base(store)?;
        let bytes = encode_journal(&journal)?;
        let expected = store
            .commit(
                self.expected,
                operation,
                &[Change::Put {
                    owner: OWNER,
                    key: KEY,
                    value: &bytes,
                }],
                &[],
            )
            .await
            .map_err(storage_error)?;
        Ok(Self {
            journal,
            expected,
            base: Some(bytes),
        })
    }
    fn check_base<B: Backend>(&self, store: &Store<B>) -> Result<()> {
        if !store.is_scope(self.journal.binding.community()) {
            return Err(Error::Scope);
        }
        if store.read(OWNER, KEY).map_err(storage_error)? != self.base.as_deref() {
            return Err(Error::Conflict);
        }
        Ok(())
    }
}
impl Candidate {
    pub async fn commit<B: Backend>(
        self,
        keys: &mut impl cthr::keys::Custody,
        authority: &mut impl cthr::DirectAuthority,
        devices: &mut impl DeviceAuthority,
        store: &mut Store<B>,
        operation: [u8; 32],
    ) -> Result<Committed> {
        let staged = self
            .stage(keys, authority, devices, store, operation)
            .await?;
        let version = store
            .commit(
                staged.expected(),
                operation,
                &staged.changes(),
                staged.outputs(),
            )
            .await
            .map_err(storage_error)?;
        Ok(staged.finish(version))
    }
    /// Run every check `commit` runs and serialize this owner's and Threads'
    /// changes and pending outputs, without writing. The caller commits
    /// `Staged::changes` and `Staged::outputs` with companion owners in ONE
    /// Store transaction at `Staged::expected` and the same `operation`, then
    /// calls `Staged::finish` with the returned version.
    pub async fn stage<B: Backend>(
        self,
        keys: &mut impl cthr::keys::Custody,
        authority: &mut impl cthr::DirectAuthority,
        devices: &mut impl DeviceAuthority,
        store: &Store<B>,
        operation: [u8; 32],
    ) -> Result<Staged> {
        let prior = Delivery {
            journal: self.journal,
            expected: self.expected,
            base: self.base,
        };
        prior.check_base(store)?;
        // Recheck newly accepted signed ACKs before publishing either owner.
        let record = prior
            .journal
            .records
            .get(&id_key(&self.message))
            .ok_or(Error::State)?;
        if self.requires_contact {
            prior.contacts(
                &Contacts::load(prior.journal.binding.clone(), store).map_err(storage_error)?,
                &record.peer,
                &record.conversation,
            )?;
        }
        if let Some(ack) = &record.ack {
            ack.verify(devices).await?;
        }
        let current = devices
            .current(&record.peer_certificate.binding)
            .await
            .map_err(authority_error)?;
        let expected_purpose = if record.outgoing {
            cthr::purpose()
        } else {
            purpose()
        };
        record
            .peer_certificate
            .verify(&current, &expected_purpose)
            .map_err(authority_error)?;
        let bytes = encode_journal(&prior.journal)?;
        let threads = self
            .threads
            .stage(keys, authority, store, operation)
            .await
            .map_err(Error::Threads)?;
        Ok(Staged {
            threads,
            journal: prior.journal,
            bytes,
        })
    }
}
/// A fully checked delivery and thread change that has not been written.
/// Dropping it publishes nothing.
pub struct Staged {
    threads: cthr::Staged,
    journal: Journal,
    bytes: Vec<u8>,
}
impl Staged {
    /// The Store version the shared transaction must be fenced at.
    pub fn expected(&self) -> u64 {
        self.threads.expected()
    }
    /// Delivery's and Threads' changes for the shared transaction.
    pub fn changes(&self) -> Vec<Change<'_>> {
        let mut changes = self.threads.changes();
        changes.push(Change::Put {
            owner: OWNER,
            key: KEY,
            value: &self.bytes,
        });
        changes
    }
    /// The pending outputs the same transaction must carry.
    pub fn outputs(&self) -> &[cwst::Output] {
        self.threads.outputs()
    }
    /// Adopt the version returned by the shared transaction.
    pub fn finish(self, version: u64) -> Committed {
        Committed {
            threads: self.threads.finish(version),
            delivery: Delivery {
                journal: self.journal,
                expected: version,
                base: Some(self.bytes),
            },
        }
    }
}

fn encode_journal(journal: &Journal) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(journal).map_err(encoding_error)?;
    if bytes.len() > MAX_JOURNAL {
        return Err(Error::Limit);
    }
    Ok(bytes)
}

// Keep the boundary's coarse upstream error classification consistent.
fn encoding_error<E>(_: E) -> Error {
    Error::Encoding
}
fn authority_error<E>(_: E) -> Error {
    Error::Authority
}
fn storage_error<E>(_: E) -> Error {
    Error::Storage
}
fn scope_error<E>(_: E) -> Error {
    Error::Scope
}
