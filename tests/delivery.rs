//! Real OpenMLS and scoped Keys vectors. Test issuers are not production G3/G2.
#[path = "support/reordering.rs"]
mod reordering;
mod support;
use cdlv::{Authenticated, Delivery, Status};
use ckmg::{Binding, KeyHandle, Lineage};
use ctcs::DeviceAuthority;
use cthr::{DirectAuthority, Error, Event, Operation, Threads, keys::KeyPort};
use cwst::{Store, backend::Memory};
use ed25519_dalek::{Signer, SigningKey};
use futures::executor::block_on;
use std::{cell::RefCell, collections::BTreeMap, rc::Rc};
use support::{Guard, Machine, Time, create, machine, prf};
#[cfg(target_arch = "wasm32")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);
const SLOT: [u8; 32] = [17; 32];
#[derive(Clone, Default)]
struct Directory(Rc<RefCell<BTreeMap<String, Lineage>>>);
impl DeviceAuthority for Directory {
    async fn current(&mut self, binding: &Binding) -> Result<Lineage, ctcs::Error> {
        self.0
            .borrow()
            .get(binding.member())
            .filter(|lineage| lineage.binding == *binding)
            .cloned()
            .ok_or(ctcs::Error::Authority)
    }
}
// An independent fixture signs exact participants and conversation. The adapter
// verifies it for every operation; it is not a production accounting substitute.
struct Grant {
    bytes: Vec<u8>,
    signature: [u8; 64],
}
impl Grant {
    fn new() -> Self {
        let bytes =
            serde_json::to_vec(&("test.direct.authorization", "alpha", "alice", "bob", SLOT))
                .unwrap();
        Self {
            signature: SigningKey::from_bytes(&[77; 32]).sign(&bytes).to_bytes(),
            bytes,
        }
    }
}
impl DirectAuthority for Grant {
    async fn authorize(
        &mut self,
        binding: &Binding,
        peer: &str,
        conversation: &[u8; 32],
        _: Operation,
    ) -> cthr::Result<()> {
        let (a, b) = if binding.member() < peer {
            (binding.member(), peer)
        } else {
            (peer, binding.member())
        };
        let expected = serde_json::to_vec(&(
            "test.direct.authorization",
            binding.community(),
            a,
            b,
            conversation,
        ))
        .unwrap();
        if expected != self.bytes {
            return Err(Error::Authority);
        }
        ckmg::verify_ed25519(
            &SigningKey::from_bytes(&[77; 32]).verifying_key().to_bytes(),
            &expected,
            &self.signature,
        )
        .map_err(|_| Error::Authority)
    }
}
#[derive(serde::Serialize)]
enum WireClaim {
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
struct Fixture {
    keys: Machine,
    handle: KeyHandle,
    binding: Binding,
    directory: Directory,
    seed: u8,
}
impl Fixture {
    async fn new(member: &str, seed: u8, directory: Directory) -> Self {
        let guard = Guard::default();
        let binding = Binding::new("alpha", member).unwrap();
        let mut keys = machine(&support::Memory::default(), &Time::default(), &guard, seed);
        create(&mut keys, &guard, &prf(seed), &binding).await;
        let handle = keys.key(cthr::purpose()).await.unwrap();
        directory
            .0
            .borrow_mut()
            .insert(member.into(), guard.0.borrow()["alpha"].clone());
        Self {
            keys,
            handle,
            binding,
            directory,
            seed,
        }
    }
    async fn wire_claim(
        &mut self,
        handle: &KeyHandle,
        peer: &str,
        conversation: [u8; 32],
        body: WireClaim,
    ) -> Vec<u8> {
        let cert = handle.certificate().clone();
        let transcript =
            serde_json::to_vec(&("cdlv.envelope.v1", &cert, peer, &conversation, &body)).unwrap();
        let signature = self.keys.sign(handle, &transcript).await.unwrap();
        serde_json::to_vec(&serde_json::json!({"version":1,"certificate":cert,"peer":peer,"conversation":conversation,"body":body,"signature":signature})).unwrap()
    }
    fn port(&mut self) -> KeyPort<'_, support::Memory, Time, support::Random, Guard, Directory> {
        KeyPort {
            keys: &mut self.keys,
            handle: &self.handle,
            devices: &mut self.directory,
        }
    }
    async fn store(&self) -> (Memory, Store<Memory>) {
        let backend = Memory::new();
        let cipher = ckmg::passkey::store_cipher(&prf(self.seed), "alpha").unwrap();
        let store = Store::create(backend.clone(), &cipher, "alpha")
            .await
            .unwrap();
        (backend, store)
    }
}

// Synthetic signed Waves receipt, used only to establish the test contacts.
// It exercises the owner boundary; it is not accepted production accounting.
struct Answers;
fn answer_bytes(binding: &Binding, peer: &str, id: &[u8; 32]) -> Vec<u8> {
    serde_json::to_vec(&("fixture.answer", binding, peer, id)).unwrap()
}
impl ctcs::OutcomeAuthority for Answers {
    async fn answered(
        &mut self,
        b: &Binding,
        p: &str,
        id: &[u8; 32],
        proof: &[u8],
    ) -> Result<(), ctcs::Error> {
        ckmg::verify_ed25519(
            &SigningKey::from_bytes(&[72; 32]).verifying_key().to_bytes(),
            &answer_bytes(b, p, id),
            &proof.try_into().map_err(|_| ctcs::Error::Authority)?,
        )
        .map_err(|_| ctcs::Error::Authority)
    }
}
impl Fixture {
    async fn control(
        &mut self,
        peer: &str,
        action: ctcs::Action,
        store: &mut Store<Memory>,
        operation: u8,
    ) {
        let handle = self.keys.key(ctcs::purpose()).await.unwrap();
        let contacts = ctcs::Contacts::load(self.binding.clone(), store).unwrap();
        let event = contacts.request(peer, action).unwrap();
        let cert = handle.certificate().clone();
        let signature = self
            .keys
            .sign(&handle, &event.signing_bytes(&cert).unwrap())
            .await
            .unwrap();
        contacts
            .prepare(
                event.signed(cert, signature),
                &mut self.directory,
                &mut Answers,
            )
            .await
            .unwrap()
            .commit(
                (&mut self.directory, &mut Answers),
                store,
                [operation; 32],
                &[],
                &[],
            )
            .await
            .unwrap();
    }
    /// First contact begun but never answered: the relation stays Pending.
    async fn begin(&mut self, peer: &str, store: &mut Store<Memory>) {
        let handle = self.keys.key(ctcs::purpose()).await.unwrap();
        let contacts = ctcs::Contacts::load(self.binding.clone(), store).unwrap();
        let event = contacts
            .request(peer, ctcs::Action::Begin { conversation: SLOT })
            .unwrap();
        let cert = handle.certificate().clone();
        let signature = self
            .keys
            .sign(&handle, &event.signing_bytes(&cert).unwrap())
            .await
            .unwrap();
        contacts
            .prepare(
                event.signed(cert, signature),
                &mut self.directory,
                &mut Answers,
            )
            .await
            .unwrap()
            .commit(
                (&mut self.directory, &mut Answers),
                store,
                [99; 32],
                &[],
                &[],
            )
            .await
            .unwrap();
    }
    async fn establish(&mut self, peer: &str, store: &mut Store<Memory>) {
        let handle = self.keys.key(ctcs::purpose()).await.unwrap();
        let proof = SigningKey::from_bytes(&[72; 32])
            .sign(&answer_bytes(&self.binding, peer, &SLOT))
            .to_bytes()
            .to_vec();
        for (index, action) in [
            ctcs::Action::Begin { conversation: SLOT },
            ctcs::Action::Answered {
                conversation: SLOT,
                evidence: proof,
            },
        ]
        .into_iter()
        .enumerate()
        {
            let contacts = ctcs::Contacts::load(self.binding.clone(), store).unwrap();
            let event = contacts.request(peer, action).unwrap();
            let cert = handle.certificate().clone();
            let signature = self
                .keys
                .sign(&handle, &event.signing_bytes(&cert).unwrap())
                .await
                .unwrap();
            contacts
                .prepare(
                    event.signed(cert, signature),
                    &mut self.directory,
                    &mut Answers,
                )
                .await
                .unwrap()
                .commit(
                    (&mut self.directory, &mut Answers),
                    store,
                    [(index + 100) as u8; 32],
                    &[],
                    &[],
                )
                .await
                .unwrap();
        }
    }
}
// Restore real owner-produced checkpoints through the actual encrypted store.
// Altered records must never become a retry or acceptance capability.
async fn restored_record_refusals(fixture: &Fixture, source: &Store<Memory>) {
    let bytes = source.read("cdlv", b"journal.v1").unwrap().unwrap();
    let original: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    let record = original["records"]
        .as_object()
        .unwrap()
        .values()
        .next()
        .unwrap();
    let mut damaged = Vec::new();
    for (path, value) in [
        ("/id", serde_json::to_value([0u8; 32]).unwrap()),
        ("/conversation", serde_json::to_value([0u8; 32]).unwrap()),
        ("/peer", serde_json::json!(fixture.binding.member())),
        ("/peer", serde_json::json!("")),
        (
            "/peer_certificate/binding",
            serde_json::to_value(&fixture.binding).unwrap(),
        ),
        (
            "/peer_certificate/purpose",
            serde_json::to_value(ctcs::purpose()).unwrap(),
        ),
        ("/status", serde_json::json!("Accepted")),
    ] {
        let mut changed = record.clone();
        *changed.pointer_mut(path).unwrap() = value;
        if changed != *record {
            damaged.push(changed);
        }
    }
    if record["outgoing"] == false {
        let mut changed = record.clone();
        changed["status"] = serde_json::json!("Pending");
        damaged.push(changed);
        let mut changed = record.clone();
        changed["wire"] = serde_json::json!([0]);
        damaged.push(changed);
    }
    let envelope_field = if record["wire"].is_null() {
        "ack"
    } else {
        "wire"
    };
    let envelope: serde_json::Value = if envelope_field == "wire" {
        let bytes: Vec<u8> = serde_json::from_value(record["wire"].clone()).unwrap();
        serde_json::from_slice(&bytes).unwrap()
    } else {
        record["ack"].clone()
    };
    let body_kind = if envelope_field == "wire" {
        "Data"
    } else {
        "Ack"
    };
    for (path, value) in [
        ("/version".to_owned(), serde_json::json!(2)),
        (
            "/certificate/binding".into(),
            serde_json::to_value(Binding::new("other", "other").unwrap()).unwrap(),
        ),
        (
            "/certificate/purpose".into(),
            serde_json::to_value(ctcs::purpose()).unwrap(),
        ),
        ("/peer".into(), serde_json::json!("other")),
        (
            "/conversation".into(),
            serde_json::to_value([18u8; 32]).unwrap(),
        ),
        (
            format!("/body/{body_kind}/id"),
            serde_json::to_value([18u8; 32]).unwrap(),
        ),
        (format!("/body/{body_kind}/epoch"), serde_json::json!(100)),
        (
            "/signature".into(),
            serde_json::to_value(ckmg::Signature::new(ckmg::VLD0, [0; 64])).unwrap(),
        ),
        (
            "/body".into(),
            if body_kind == "Data" {
                serde_json::json!({"Ack":{"id":vec![18u8;32],"epoch":1}})
            } else {
                serde_json::json!({"Data":{"id":vec![18u8;32],"epoch":1,"wire":[1]}})
            },
        ),
    ] {
        let mut altered_envelope = envelope.clone();
        *altered_envelope.pointer_mut(&path).unwrap() = value;
        let mut changed = record.clone();
        changed[envelope_field] = if envelope_field == "wire" {
            serde_json::to_value(serde_json::to_vec(&altered_envelope).unwrap()).unwrap()
        } else {
            altered_envelope
        };
        damaged.push(changed);
    }
    if !record["ack"].is_null() {
        let mut changed = record.clone();
        changed["ack"] = serde_json::Value::Null;
        damaged.push(changed);
    } else {
        let mut changed = record.clone();
        changed["wire"] = serde_json::json!([0]);
        damaged.push(changed);
    }
    if record["outgoing"] == true && !record["ack"].is_null() {
        let mut changed = record.clone();
        changed["status"] = serde_json::json!("Pending");
        damaged.push(changed);
    }
    let (_, mut store) = fixture.store().await;
    for (index, changed) in damaged.into_iter().enumerate() {
        let mut journal = original.clone();
        *journal["records"]
            .as_object_mut()
            .unwrap()
            .values_mut()
            .next()
            .unwrap() = changed;
        let bytes = serde_json::to_vec(&journal).unwrap();
        store
            .commit(
                store.version().unwrap(),
                [(index + 1) as u8; 32],
                &[cwst::Change::Put {
                    owner: "cdlv",
                    key: b"journal.v1",
                    value: &bytes,
                }],
                &[],
            )
            .await
            .unwrap();
        assert!(
            Delivery::load(fixture.binding.clone(), &store).is_err(),
            "accepted changed record {index}"
        );
    }
    let mut zero = original.clone();
    let mut zero_record = record.clone();
    zero_record["id"] = serde_json::to_value([0u8; 32]).unwrap();
    zero["records"] = serde_json::json!({});
    zero["records"]["00".repeat(32)] = zero_record;
    let bytes = serde_json::to_vec(&zero).unwrap();
    store
        .commit(
            store.version().unwrap(),
            [99; 32],
            &[cwst::Change::Put {
                owner: "cdlv",
                key: b"journal.v1",
                value: &bytes,
            }],
            &[],
        )
        .await
        .unwrap();
    assert_eq!(
        Delivery::load(fixture.binding.clone(), &store).err(),
        Some(cdlv::Error::Encoding)
    );
}

// Malformed restored owner journals are parser inputs, never proof issuers.
// The sender candidate still comes from the actual MLS provider and Keys port.
async fn restored_capacity_and_duplicate_refusals(f: &mut Fixture, source: &Store<Memory>) {
    let original: serde_json::Value =
        serde_json::from_slice(source.read("cdlv", b"journal.v1").unwrap().unwrap()).unwrap();
    let mut template = original["records"]
        .as_object()
        .unwrap()
        .values()
        .next()
        .unwrap()
        .clone();
    template["wire"] = serde_json::Value::Null;
    let thread_bytes = source.read("cthr", &SLOT).unwrap().unwrap();
    let contact_bytes = source.read("ctcs", b"journal.v1").unwrap().unwrap();
    let mut full = original.clone();
    full["records"] = serde_json::json!({});
    for index in 0u32..1025 {
        let id = *ckmg::hash(&index.to_be_bytes()).value();
        let mut record = template.clone();
        record["id"] = serde_json::to_value(id).unwrap();
        let name: String = id.iter().map(|byte| format!("{byte:02x}")).collect();
        full["records"][name] = record;
    }
    let (_, mut store) = f.store().await;
    let oversized = serde_json::to_vec(&full).unwrap();
    assert!(oversized.len() <= cwst::MAX_VALUE_BYTES);
    store
        .commit(
            0,
            [1; 32],
            &[cwst::Change::Put {
                owner: "cdlv",
                key: b"journal.v1",
                value: &oversized,
            }],
            &[],
        )
        .await
        .unwrap();
    assert_eq!(
        Delivery::load(f.binding.clone(), &store).err(),
        Some(cdlv::Error::Limit)
    );
    let first = full["records"]
        .as_object()
        .unwrap()
        .keys()
        .next()
        .unwrap()
        .clone();
    full["records"].as_object_mut().unwrap().remove(&first);
    let bytes = serde_json::to_vec(&full).unwrap();
    let (_, mut store) = f.store().await;
    store
        .commit(
            0,
            [1; 32],
            &[
                cwst::Change::Put {
                    owner: "cthr",
                    key: &SLOT,
                    value: thread_bytes,
                },
                cwst::Change::Put {
                    owner: "ctcs",
                    key: b"journal.v1",
                    value: contact_bytes,
                },
                cwst::Change::Put {
                    owner: "cdlv",
                    key: b"journal.v1",
                    value: &bytes,
                },
            ],
            &[],
        )
        .await
        .unwrap();
    let threads = Threads::load(f.binding.clone(), SLOT, &store).unwrap();
    let next = threads
        .send(&mut f.port(), &mut Grant::new(), b"capacity")
        .await
        .unwrap();
    assert_eq!(
        Delivery::load(f.binding.clone(), &store)
            .unwrap()
            .outgoing(next, &contacts(f, &store))
            .err(),
        Some(cdlv::Error::Limit)
    );
    let next = threads
        .send(&mut f.port(), &mut Grant::new(), b"duplicate restored id")
        .await
        .unwrap();
    let id = *next.prepared_message().unwrap().id();
    template["id"] = serde_json::to_value(id).unwrap();
    let name: String = id.iter().map(|byte| format!("{byte:02x}")).collect();
    let mut duplicate = original;
    duplicate["records"] = serde_json::json!({});
    duplicate["records"][name] = template;
    let bytes = serde_json::to_vec(&duplicate).unwrap();
    let (_, mut alternate) = f.store().await;
    alternate
        .commit(
            0,
            [1; 32],
            &[
                cwst::Change::Put {
                    owner: "cthr",
                    key: &SLOT,
                    value: thread_bytes,
                },
                cwst::Change::Put {
                    owner: "ctcs",
                    key: b"journal.v1",
                    value: contact_bytes,
                },
                cwst::Change::Put {
                    owner: "cdlv",
                    key: b"journal.v1",
                    value: &bytes,
                },
            ],
            &[],
        )
        .await
        .unwrap();
    assert_eq!(
        Delivery::load(f.binding.clone(), &alternate)
            .unwrap()
            .outgoing(next, &contacts(f, &alternate))
            .err(),
        Some(cdlv::Error::Conflict)
    );
}

async fn copied_store(f: &Fixture, source: &Store<Memory>) -> Store<Memory> {
    let (_, mut store) = f.store().await;
    let mut changes = Vec::new();
    for (owner, key) in [
        ("cthr", SLOT.as_slice()),
        ("ctcs", b"journal.v1".as_slice()),
        ("cdlv", b"journal.v1".as_slice()),
    ] {
        if let Some(value) = source.read(owner, key).unwrap() {
            changes.push(cwst::Change::Put { owner, key, value });
        }
    }
    store.commit(0, [1; 32], &changes, &[]).await.unwrap();
    store
}

async fn reopen(f: &mut Fixture, peer: &str, store: &mut Store<Memory>) {
    f.control(peer, ctcs::Action::Close, store, 10).await;
    f.control(
        peer,
        ctcs::Action::Reopen {
            conversation: [18; 32],
        },
        store,
        11,
    )
    .await;
    let evidence = SigningKey::from_bytes(&[72; 32])
        .sign(&answer_bytes(&f.binding, peer, &[18; 32]))
        .to_bytes()
        .to_vec();
    f.control(
        peer,
        ctcs::Action::Answered {
            conversation: [18; 32],
            evidence,
        },
        store,
        12,
    )
    .await;
}

// A currently authorized peer can sign a wrapper around another conversation's
// real ciphertext. Neither that signature nor an established contact authorizes
// changing the actual MLS sender, epoch, conversation or owner checkpoint.
async fn crossed_envelope_refusals(
    owners: (&mut Fixture, &mut Fixture),
    stores: (&Store<Memory>, &Store<Memory>),
    handles: (&KeyHandle, &KeyHandle),
    wire: &[u8],
) -> Fixture {
    let (a, b) = owners;
    let (astore, bstore) = stores;
    let (ah, bh) = handles;
    let mut outsider = Fixture::new("charlie", 3, a.directory.clone()).await;
    let ch = outsider.keys.key(cdlv::purpose()).await.unwrap();
    let envelope: serde_json::Value = serde_json::from_slice(wire).unwrap();
    let payload: Vec<u8> =
        serde_json::from_value(envelope["body"]["Data"]["wire"].clone()).unwrap();
    let id = *ckmg::hash(&payload).value();
    for case in 0..3 {
        let mut store = copied_store(b, bstore).await;
        let conversation = if case == 2 { [18; 32] } else { SLOT };
        if case == 1 {
            b.establish("charlie", &mut store).await;
        }
        if case == 2 {
            reopen(b, "alice", &mut store).await;
        }
        let claim = WireClaim::Data {
            id,
            epoch: if case == 0 { 2 } else { 1 },
            wire: payload.clone(),
        };
        let malformed = if case == 1 {
            outsider.wire_claim(&ch, "bob", conversation, claim).await
        } else {
            a.wire_claim(ah, "bob", conversation, claim).await
        };
        let delivery = Delivery::load(b.binding.clone(), &store).unwrap();
        let current_contacts = contacts(b, &store);
        let Authenticated::Data(incoming) = delivery
            .authenticate(&malformed, &mut b.directory, &current_contacts)
            .await
            .unwrap()
        else {
            panic!()
        };
        let prepared = Threads::load(b.binding.clone(), SLOT, &store)
            .unwrap()
            .receive(&mut b.port(), &mut Grant::new(), incoming.ciphertext())
            .await
            .unwrap();
        assert_eq!(
            delivery
                .received(prepared, incoming, &mut b.keys, bh)
                .await
                .err(),
            Some(cdlv::Error::Scope)
        );
    }
    let mut store = copied_store(b, bstore).await;
    let old_delivery = Delivery::load(b.binding.clone(), &store).unwrap();
    let old_contacts = contacts(b, &store);
    store
        .commit(store.version().unwrap(), [2; 32], &[], &[])
        .await
        .unwrap();
    let threads = Threads::load(b.binding.clone(), SLOT, &store).unwrap();
    let prepared = threads
        .send(&mut b.port(), &mut Grant::new(), b"new checkpoint")
        .await
        .unwrap();
    assert_eq!(
        old_delivery.outgoing(prepared, &old_contacts).err(),
        Some(cdlv::Error::Scope)
    );
    let (_, mut cstore) = outsider.store().await;
    outsider.establish("alice", &mut cstore).await;
    let prepared = threads
        .send(&mut b.port(), &mut Grant::new(), b"foreign owner")
        .await
        .unwrap();
    assert_eq!(
        Delivery::load(outsider.binding.clone(), &cstore)
            .unwrap()
            .outgoing(prepared, &contacts(&outsider, &cstore))
            .err(),
        Some(cdlv::Error::Scope)
    );
    let wrong_peer_ack = outsider
        .wire_claim(&ch, "alice", SLOT, WireClaim::Ack { id, epoch: 1 })
        .await;
    let current_contacts = contacts(a, astore);
    assert_eq!(
        Delivery::load(a.binding.clone(), astore)
            .unwrap()
            .authenticate(&wrong_peer_ack, &mut a.directory, &current_contacts)
            .await
            .err(),
        Some(cdlv::Error::Authority)
    );
    outsider
}

async fn restored_pending_scope_refusals(
    a: &mut Fixture,
    outsider: &Fixture,
    source: &Store<Memory>,
    outgoing: &cthr::Outgoing<'_>,
    handle: &KeyHandle,
) {
    let original: serde_json::Value =
        serde_json::from_slice(source.read("cdlv", b"journal.v1").unwrap().unwrap()).unwrap();
    for case in 0..3 {
        let mut changed = original.clone();
        let record = changed["records"]
            .as_object_mut()
            .unwrap()
            .values_mut()
            .next()
            .unwrap();
        record["wire"] = serde_json::Value::Null;
        match case {
            0 => record["conversation"] = serde_json::to_value([18u8; 32]).unwrap(),
            1 => record["epoch"] = serde_json::json!(2),
            _ => {
                record["peer"] = serde_json::json!("charlie");
                record["peer_certificate"] =
                    serde_json::to_value(outsider.handle.certificate()).unwrap();
            }
        }
        let mut store = copied_store(a, source).await;
        let bytes = serde_json::to_vec(&changed).unwrap();
        store
            .commit(
                store.version().unwrap(),
                [2; 32],
                &[cwst::Change::Put {
                    owner: "cdlv",
                    key: b"journal.v1",
                    value: &bytes,
                }],
                &[],
            )
            .await
            .unwrap();
        let delivery = Delivery::load(a.binding.clone(), &store).unwrap();
        let before = store.version().unwrap();
        assert_eq!(
            delivery
                .wrap(
                    outgoing,
                    &mut a.keys,
                    handle,
                    &mut a.directory,
                    &mut store,
                    [3; 32]
                )
                .await
                .err(),
            Some(cdlv::Error::Authority)
        );
        assert_eq!(store.version().unwrap(), before);
    }
}

fn contacts(f: &Fixture, store: &Store<Memory>) -> ctcs::Contacts {
    ctcs::Contacts::load(f.binding.clone(), store).unwrap()
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn actual_mls_retry_receipt_and_uncertain_cancel_share_checkpoints() {
    block_on(async {
        let mut directory = Directory::default();
        let mut a = Fixture::new("alice", 1, directory.clone()).await;
        let mut b = Fixture::new("bob", 2, directory.clone()).await;
        let ah = a.keys.key(cdlv::purpose()).await.unwrap();
        let bh = b.keys.key(cdlv::purpose()).await.unwrap();
        let (abackend, mut astore) = a.store().await;
        let (bbackend, mut bstore) = b.store().await;
        let unknown = Delivery::load(a.binding.clone(), &astore).unwrap();
        assert_eq!(unknown.status(&[0; 32]), None);
        assert_eq!(
            unknown
                .authenticate(&[], &mut directory, &contacts(&a, &astore))
                .await
                .err(),
            Some(cdlv::Error::Limit)
        );
        let stale_contacts = contacts(&a, &astore);
        a.establish("bob", &mut astore).await;
        b.establish("alice", &mut bstore).await;
        let at = Threads::load(a.binding.clone(), SLOT, &astore).unwrap();
        let bt = Threads::load(b.binding.clone(), SLOT, &bstore).unwrap();
        let package = bt
            .key_package(&mut b.port())
            .await
            .unwrap()
            .commit(&mut b.port(), &mut Grant::new(), &mut bstore, [1; 32], &[])
            .await
            .unwrap();
        let Event::KeyPackage { bytes } = &package.events()[0] else {
            panic!()
        };
        let invitation = at
            .create_direct(&mut a.port(), &mut Grant::new(), "bob", bytes)
            .await
            .unwrap()
            .commit(&mut a.port(), &mut Grant::new(), &mut astore, [1; 32], &[])
            .await
            .unwrap();
        let Event::Invitation { welcome, .. } = &invitation.events()[0] else {
            panic!()
        };
        let joined = package
            .threads()
            .join_direct(&mut b.port(), &mut Grant::new(), "alice", welcome)
            .await
            .unwrap()
            .commit(&mut b.port(), &mut Grant::new(), &mut bstore, [2; 32], &[])
            .await
            .unwrap();
        let ad = Delivery::load(a.binding.clone(), &astore).unwrap();
        let prepared = invitation
            .threads()
            .send(&mut a.port(), &mut Grant::new(), b"durable hello")
            .await
            .unwrap();
        let id = *prepared.prepared_message().unwrap().id();
        let stale = invitation
            .threads()
            .send(&mut a.port(), &mut Grant::new(), b"stale")
            .await
            .unwrap();
        assert_eq!(
            ad.outgoing(stale, &stale_contacts).err(),
            Some(cdlv::Error::Conflict)
        );
        let candidate = ad.outgoing(prepared, &contacts(&a, &astore)).unwrap();
        assert_eq!(ad.status(&id), None);
        let sent = candidate
            .commit(
                &mut a.port(),
                &mut Grant::new(),
                &mut directory,
                &mut astore,
                [3; 32],
            )
            .await
            .unwrap();
        assert_eq!(sent.delivery.status(&id), Some(Status::Pending));
        assert!(sent.threads.threads().history().is_empty());
        assert_eq!(sent.delivery.ack(&id).err(), Some(cdlv::Error::State));
        assert_eq!(
            sent.delivery
                .retry(&id, &mut directory, &contacts(&a, &astore))
                .await
                .err(),
            Some(cdlv::Error::State)
        );
        assert_eq!(
            sent.delivery
                .wrap(
                    &sent.threads.outgoing()[0],
                    &mut a.keys,
                    &bh,
                    &mut directory,
                    &mut astore,
                    [70; 32]
                )
                .await
                .err(),
            Some(cdlv::Error::Scope)
        );
        let wrong_purpose = a.keys.key(cthr::purpose()).await.unwrap();
        assert_eq!(
            sent.delivery
                .wrap(
                    &sent.threads.outgoing()[0],
                    &mut a.keys,
                    &wrong_purpose,
                    &mut directory,
                    &mut astore,
                    [70; 32]
                )
                .await
                .err(),
            Some(cdlv::Error::Scope)
        );

        let (ad, wire) = sent
            .delivery
            .wrap(
                &sent.threads.outgoing()[0],
                &mut a.keys,
                &ah,
                &mut directory,
                &mut astore,
                [4; 32],
            )
            .await
            .unwrap();
        restored_record_refusals(&a, &astore).await;
        restored_capacity_and_duplicate_refusals(&mut a, &astore).await;
        let (racing_backend, mut racing_store) = a.store().await;
        let checkpoint = astore.read("cdlv", b"journal.v1").unwrap().unwrap();
        racing_store
            .commit(
                0,
                [1; 32],
                &[cwst::Change::Put {
                    owner: "cdlv",
                    key: b"journal.v1",
                    value: checkpoint,
                }],
                &[],
            )
            .await
            .unwrap();
        let racing_delivery = Delivery::load(a.binding.clone(), &racing_store).unwrap();
        let cipher = ckmg::passkey::store_cipher(&prf(1), "alpha").unwrap();
        let mut competing_store = Store::open(racing_backend, &cipher, "alpha").await.unwrap();
        competing_store
            .commit(competing_store.version().unwrap(), [2; 32], &[], &[])
            .await
            .unwrap();
        assert_eq!(
            racing_delivery
                .cancel(&id, &mut racing_store, [3; 32])
                .await
                .err(),
            Some(cdlv::Error::Storage)
        );
        let foreign_cipher = ckmg::passkey::store_cipher(&prf(1), "beta").unwrap();
        let mut foreign_store = Store::create(Memory::new(), &foreign_cipher, "beta")
            .await
            .unwrap();
        assert_eq!(
            ad.cancel(&id, &mut foreign_store, [3; 32]).await.err(),
            Some(cdlv::Error::Scope)
        );

        assert_eq!(
            ad.wrap(
                &sent.threads.outgoing()[0],
                &mut a.keys,
                &ah,
                &mut directory,
                &mut astore,
                [70; 32]
            )
            .await
            .err(),
            Some(cdlv::Error::State)
        );
        assert_eq!(
            sent.delivery.cancel(&id, &mut astore, [70; 32]).await.err(),
            Some(cdlv::Error::Conflict)
        );
        for (conversation, epoch) in [([18; 32], 1), (SLOT, 2)] {
            let bad_ack = b
                .wire_claim(&bh, "alice", conversation, WireClaim::Ack { id, epoch })
                .await;
            assert_eq!(
                ad.authenticate(&bad_ack, &mut directory, &contacts(&a, &astore))
                    .await
                    .err(),
                Some(cdlv::Error::Authority)
            );
        }

        let retry = ad
            .retry(&id, &mut directory, &contacts(&a, &astore))
            .await
            .unwrap();
        assert_eq!(wire.bytes(), retry.bytes());
        let cipher = ckmg::passkey::store_cipher(&prf(1), "alpha").unwrap();
        let mut astore = Store::open(abackend, &cipher, "alpha").await.unwrap();
        let ad = Delivery::load(a.binding.clone(), &astore).unwrap();
        assert_eq!(
            ad.retry(&id, &mut directory, &contacts(&a, &astore))
                .await
                .unwrap()
                .bytes(),
            wire.bytes()
        );
        let current = directory.0.borrow()["bob"].clone();
        directory.0.borrow_mut().get_mut("bob").unwrap().epoch += 1;
        assert_eq!(
            ad.retry(&id, &mut directory, &contacts(&a, &astore))
                .await
                .err(),
            Some(cdlv::Error::Authority)
        );
        directory.0.borrow_mut().insert("bob".into(), current);
        let mut outsider = crossed_envelope_refusals(
            (&mut a, &mut b),
            (&astore, &bstore),
            (&ah, &bh),
            wire.bytes(),
        )
        .await;
        restored_pending_scope_refusals(
            &mut a,
            &outsider,
            &astore,
            &sent.threads.outgoing()[0],
            &ah,
        )
        .await;
        let bd = Delivery::load(b.binding.clone(), &bstore).unwrap();
        assert_eq!(
            bd.authenticate(wire.bytes(), &mut directory, &contacts(&a, &astore))
                .await
                .err(),
            Some(cdlv::Error::Conflict)
        );
        let mut foreign: serde_json::Value = serde_json::from_slice(wire.bytes()).unwrap();
        foreign["certificate"]["binding"] =
            serde_json::to_value(Binding::new("beta", "alice").unwrap()).unwrap();
        assert_eq!(
            bd.authenticate(
                &serde_json::to_vec(&foreign).unwrap(),
                &mut directory,
                &contacts(&b, &bstore)
            )
            .await
            .err(),
            Some(cdlv::Error::Scope)
        );

        let self_addressed = b
            .wire_claim(&bh, "bob", SLOT, WireClaim::Ack { id, epoch: 1 })
            .await;
        assert_eq!(
            bd.authenticate(&self_addressed, &mut directory, &contacts(&b, &bstore))
                .await
                .err(),
            Some(cdlv::Error::Scope)
        );
        assert_eq!(
            bd.wrap(
                &sent.threads.outgoing()[0],
                &mut a.keys,
                &ah,
                &mut directory,
                &mut bstore,
                [70; 32],
            )
            .await
            .err(),
            Some(cdlv::Error::Scope)
        );
        let foreign_candidate = joined
            .threads()
            .send(&mut b.port(), &mut Grant::new(), b"foreign owner")
            .await
            .unwrap();
        assert_eq!(
            ad.outgoing(foreign_candidate, &contacts(&a, &astore)).err(),
            Some(cdlv::Error::Scope)
        );

        for invalid in [vec![0], vec![0; 2 * 1024 * 1024 + 1]] {
            assert!(
                bd.authenticate(&invalid, &mut directory, &contacts(&b, &bstore))
                    .await
                    .is_err()
            );
        }
        let mut bad: serde_json::Value = serde_json::from_slice(wire.bytes()).unwrap();
        bad["peer"] = "someone".into();
        assert_eq!(
            bd.authenticate(
                &serde_json::to_vec(&bad).unwrap(),
                &mut directory,
                &contacts(&b, &bstore)
            )
            .await
            .err(),
            Some(cdlv::Error::Scope)
        );
        for (path, replacement) in [
            ("/version", serde_json::json!(2)),
            ("/conversation", serde_json::to_value([0u8; 32]).unwrap()),
            ("/body/Data/id", serde_json::to_value([0u8; 32]).unwrap()),
        ] {
            let mut changed: serde_json::Value = serde_json::from_slice(wire.bytes()).unwrap();
            *changed.pointer_mut(path).unwrap() = replacement;
            assert_eq!(
                bd.authenticate(
                    &serde_json::to_vec(&changed).unwrap(),
                    &mut directory,
                    &contacts(&b, &bstore)
                )
                .await
                .err(),
                Some(cdlv::Error::Scope)
            );
        }
        let mut changed: serde_json::Value = serde_json::from_slice(wire.bytes()).unwrap();
        changed["body"]["Data"]["wire"][0] = serde_json::json!(255);
        assert_eq!(
            bd.authenticate(
                &serde_json::to_vec(&changed).unwrap(),
                &mut directory,
                &contacts(&b, &bstore)
            )
            .await
            .err(),
            Some(cdlv::Error::Authority)
        );
        assert_eq!(
            bd.retry(&[0; 32], &mut directory, &contacts(&b, &bstore))
                .await
                .err(),
            Some(cdlv::Error::State)
        );
        assert_eq!(
            bd.cancel(&[0; 32], &mut bstore, [77; 32]).await.err(),
            Some(cdlv::Error::State)
        );
        for (claim, expected) in [
            (
                WireClaim::Data {
                    id,
                    epoch: 1,
                    wire: vec![],
                },
                cdlv::Error::Limit,
            ),
            (
                WireClaim::Data {
                    id: [28; 32],
                    epoch: 1,
                    wire: vec![1, 2, 3],
                },
                cdlv::Error::Authority,
            ),
            (
                WireClaim::Ack {
                    id: [28; 32],
                    epoch: 1,
                },
                cdlv::Error::State,
            ),
        ] {
            let malicious = a.wire_claim(&ah, "bob", SLOT, claim).await;
            assert_eq!(
                bd.authenticate(&malicious, &mut directory, &contacts(&b, &bstore))
                    .await
                    .err(),
                Some(expected)
            );
        }
        for case in 0..4 {
            let Authenticated::Data(incoming) = bd
                .authenticate(wire.bytes(), &mut directory, &contacts(&b, &bstore))
                .await
                .unwrap()
            else {
                panic!()
            };
            let prepared = if case == 2 {
                joined
                    .threads()
                    .send(&mut b.port(), &mut Grant::new(), b"wrong direction")
                    .await
                    .unwrap()
            } else {
                joined
                    .threads()
                    .receive(&mut b.port(), &mut Grant::new(), incoming.ciphertext())
                    .await
                    .unwrap()
            };
            if case == 3 {
                assert_eq!(
                    bd.outgoing(prepared, &contacts(&b, &bstore)).err(),
                    Some(cdlv::Error::Scope)
                );
                continue;
            }
            let handle = match case {
                0 => &ah,
                1 => &b.handle,
                _ => &bh,
            };
            assert_eq!(
                bd.received(prepared, incoming, &mut b.keys, handle)
                    .await
                    .err(),
                Some(cdlv::Error::Scope)
            );
        }
        let incoming = match bd
            .authenticate(wire.bytes(), &mut directory, &contacts(&b, &bstore))
            .await
            .unwrap()
        {
            Authenticated::Data(data) => data,
            _ => panic!(),
        };
        assert_eq!(incoming.conversation(), &SLOT);
        let prepared = joined
            .threads()
            .receive(&mut b.port(), &mut Grant::new(), incoming.ciphertext())
            .await
            .unwrap();
        let candidate = bd
            .received(prepared, incoming, &mut b.keys, &bh)
            .await
            .unwrap();
        assert!(bd.ack(&id).is_err());
        assert!(joined.threads().history().is_empty());
        // Another real Store commits after preparation. The recipient's stale
        // CAS must release neither accepted plaintext nor its prepared ACK.
        let bcipher = ckmg::passkey::store_cipher(&prf(2), "alpha").unwrap();
        let mut competitor = Store::open(bbackend.clone(), &bcipher, "alpha")
            .await
            .unwrap();
        competitor
            .commit(competitor.version().unwrap(), [79; 32], &[], &[])
            .await
            .unwrap();
        assert_eq!(
            candidate
                .commit(
                    &mut b.port(),
                    &mut Grant::new(),
                    &mut directory,
                    &mut bstore,
                    [3; 32]
                )
                .await
                .err(),
            Some(cdlv::Error::Threads(Error::Storage))
        );
        assert!(bd.ack(&id).is_err());
        assert!(joined.threads().history().is_empty());
        bstore = Store::open(bbackend.clone(), &bcipher, "alpha")
            .await
            .unwrap();
        let bd = Delivery::load(b.binding.clone(), &bstore).unwrap();
        assert!(bd.ack(&id).is_err());
        let Authenticated::Data(incoming) = bd
            .authenticate(wire.bytes(), &mut directory, &contacts(&b, &bstore))
            .await
            .unwrap()
        else {
            panic!()
        };
        let restored_threads = Threads::load(b.binding.clone(), SLOT, &bstore).unwrap();
        assert!(restored_threads.history().is_empty());
        let prepared = restored_threads
            .receive(&mut b.port(), &mut Grant::new(), incoming.ciphertext())
            .await
            .unwrap();
        let candidate = bd
            .received(prepared, incoming, &mut b.keys, &bh)
            .await
            .unwrap();
        let received = candidate
            .commit(
                &mut b.port(),
                &mut Grant::new(),
                &mut directory,
                &mut bstore,
                [3; 32],
            )
            .await
            .unwrap();
        assert_eq!(
            received.threads.threads().history()[0].bytes,
            b"durable hello"
        );
        restored_record_refusals(&b, &bstore).await;
        assert_eq!(
            received
                .delivery
                .retry(&id, &mut directory, &contacts(&b, &bstore))
                .await
                .err(),
            Some(cdlv::Error::State)
        );
        assert_eq!(
            received
                .delivery
                .cancel(&id, &mut bstore, [70; 32])
                .await
                .err(),
            Some(cdlv::Error::State)
        );
        let wrong_direction = a
            .wire_claim(&ah, "bob", SLOT, WireClaim::Ack { id, epoch: 1 })
            .await;
        assert_eq!(
            received
                .delivery
                .authenticate(&wrong_direction, &mut directory, &contacts(&b, &bstore))
                .await
                .err(),
            Some(cdlv::Error::Authority)
        );
        let copied: serde_json::Value = serde_json::from_slice(wire.bytes()).unwrap();
        let payload: Vec<u8> =
            serde_json::from_value(copied["body"]["Data"]["wire"].clone()).unwrap();
        let mut shadow = copied_store(&b, &bstore).await;
        b.establish("charlie", &mut shadow).await;
        let ch = outsider.keys.key(cdlv::purpose()).await.unwrap();
        let repacked = outsider
            .wire_claim(
                &ch,
                "bob",
                SLOT,
                WireClaim::Data {
                    id,
                    epoch: 1,
                    wire: payload.clone(),
                },
            )
            .await;
        assert_eq!(
            Delivery::load(b.binding.clone(), &shadow)
                .unwrap()
                .authenticate(&repacked, &mut directory, &contacts(&b, &shadow))
                .await
                .err(),
            Some(cdlv::Error::Authority)
        );
        reopen(&mut b, "alice", &mut shadow).await;
        let repacked = a
            .wire_claim(
                &ah,
                "bob",
                [18; 32],
                WireClaim::Data {
                    id,
                    epoch: 1,
                    wire: payload,
                },
            )
            .await;
        assert_eq!(
            Delivery::load(b.binding.clone(), &shadow)
                .unwrap()
                .authenticate(&repacked, &mut directory, &contacts(&b, &shadow))
                .await
                .err(),
            Some(cdlv::Error::Authority)
        );
        let original_envelope: serde_json::Value = serde_json::from_slice(wire.bytes()).unwrap();
        let original_payload: Vec<u8> =
            serde_json::from_value(original_envelope["body"]["Data"]["wire"].clone()).unwrap();
        let wrong_epoch = a
            .wire_claim(
                &ah,
                "bob",
                SLOT,
                WireClaim::Data {
                    id,
                    epoch: 2,
                    wire: original_payload.clone(),
                },
            )
            .await;
        assert_eq!(
            received
                .delivery
                .authenticate(&wrong_epoch, &mut directory, &contacts(&b, &bstore))
                .await
                .err(),
            Some(cdlv::Error::Authority)
        );
        let reversed = b
            .wire_claim(
                &bh,
                "alice",
                SLOT,
                WireClaim::Data {
                    id,
                    epoch: 1,
                    wire: original_payload,
                },
            )
            .await;
        assert_eq!(
            ad.authenticate(&reversed, &mut directory, &contacts(&a, &astore))
                .await
                .err(),
            Some(cdlv::Error::Authority)
        );

        let ack = received.delivery.ack(&id).unwrap();
        let bcipher = ckmg::passkey::store_cipher(&prf(2), "alpha").unwrap();
        let restored = Store::open(bbackend, &bcipher, "alpha").await.unwrap();
        assert_eq!(
            Delivery::load(b.binding.clone(), &restored)
                .unwrap()
                .ack(&id)
                .unwrap()
                .bytes(),
            ack.bytes()
        );
        // A lost ACK followed by an identical retry after restart must not
        // decrypt the same MLS generation or insert history twice.
        let restored_delivery = Delivery::load(b.binding.clone(), &restored).unwrap();
        let old_version = restored.version().unwrap();
        match restored_delivery
            .authenticate(wire.bytes(), &mut directory, &contacts(&b, &restored))
            .await
            .unwrap()
        {
            Authenticated::Duplicate(receipt) => assert_eq!(receipt.bytes(), ack.bytes()),
            _ => panic!("durable duplicate must return the original receipt"),
        }
        assert_eq!(restored.version().unwrap(), old_version);
        assert_eq!(
            Threads::load(b.binding.clone(), SLOT, &restored)
                .unwrap()
                .history()
                .len(),
            1
        );
        // A block also prevents a duplicate message from releasing its receipt.
        b.control("alice", ctcs::Action::Block, &mut bstore, 90)
            .await;
        assert_eq!(
            Delivery::load(b.binding.clone(), &bstore)
                .unwrap()
                .authenticate(wire.bytes(), &mut directory, &contacts(&b, &bstore))
                .await
                .err(),
            Some(cdlv::Error::Unavailable)
        );
        let ack_bytes = ack.bytes().to_vec();
        let ad = ad.cancel(&id, &mut astore, [5; 32]).await.unwrap();
        assert_eq!(ad.status(&id), Some(Status::CanceledUnconfirmed));
        assert_eq!(
            ad.retry(&id, &mut directory, &contacts(&a, &astore))
                .await
                .err(),
            Some(cdlv::Error::State)
        );
        let Authenticated::Ack(foreign_ack) = ad
            .authenticate(&ack_bytes, &mut directory, &contacts(&a, &astore))
            .await
            .unwrap()
        else {
            panic!()
        };
        assert_eq!(
            received
                .delivery
                .acknowledged(sent.threads.threads(), foreign_ack)
                .err(),
            Some(cdlv::Error::Scope)
        );
        let ack = match ad
            .authenticate(ack.bytes(), &mut directory, &contacts(&a, &astore))
            .await
            .unwrap()
        {
            Authenticated::Ack(ack) => ack,
            _ => panic!(),
        };
        for (binding, peer, conversation, message, epoch) in [
            (Binding::new("beta", "alice").unwrap(), "bob", SLOT, id, 1),
            (a.binding.clone(), "other", SLOT, id, 1),
            (a.binding.clone(), "bob", [19; 32], id, 1),
            (a.binding.clone(), "bob", SLOT, [0; 32], 1),
            (a.binding.clone(), "bob", SLOT, id, 2),
        ] {
            assert_eq!(
                cthr::Acceptance::verify(&ack, &binding, peer, &conversation, &message, epoch)
                    .err(),
                Some(Error::Authority)
            );
        }
        let at = Threads::load(a.binding.clone(), SLOT, &astore).unwrap();
        assert!(at.history().is_empty());
        let accepted = ad
            .acknowledged(&at, ack)
            .unwrap()
            .commit(
                &mut a.port(),
                &mut Grant::new(),
                &mut directory,
                &mut astore,
                [6; 32],
            )
            .await
            .unwrap();
        assert_eq!(accepted.delivery.status(&id), Some(Status::Accepted));
        restored_record_refusals(&a, &astore).await;
        assert_eq!(
            accepted
                .delivery
                .wrap(
                    &sent.threads.outgoing()[0],
                    &mut a.keys,
                    &ah,
                    &mut directory,
                    &mut astore,
                    [70; 32]
                )
                .await
                .err(),
            Some(cdlv::Error::Authority)
        );

        match accepted
            .delivery
            .authenticate(&ack_bytes, &mut directory, &contacts(&a, &astore))
            .await
            .unwrap()
        {
            Authenticated::AlreadyAccepted(message) => assert_eq!(message, id),
            _ => panic!("duplicate ACK must not advance sender history"),
        }
        assert_eq!(accepted.threads.threads().history().len(), 1);
        // The real MLS checkpoint can fit while the signed retry journal's
        // nested wire encoding exceeds Store's per-value limit. No bytes escape.
        let large = accepted
            .threads
            .threads()
            .send(&mut a.port(), &mut Grant::new(), &vec![0; 200_000])
            .await
            .unwrap();
        let large = accepted
            .delivery
            .outgoing(large, &contacts(&a, &astore))
            .unwrap()
            .commit(
                &mut a.port(),
                &mut Grant::new(),
                &mut directory,
                &mut astore,
                [71; 32],
            )
            .await
            .unwrap();
        let before = astore.version().unwrap();
        assert_eq!(
            large
                .delivery
                .wrap(
                    &large.threads.outgoing()[0],
                    &mut a.keys,
                    &ah,
                    &mut directory,
                    &mut astore,
                    [72; 32]
                )
                .await
                .err(),
            Some(cdlv::Error::Limit)
        );
        assert_eq!(astore.version().unwrap(), before);
        let held = Threads::load(a.binding.clone(), SLOT, &astore)
            .unwrap()
            .send(&mut a.port(), &mut Grant::new(), b"held before close")
            .await
            .unwrap();
        let held = Delivery::load(a.binding.clone(), &astore)
            .unwrap()
            .outgoing(held, &contacts(&a, &astore))
            .unwrap();
        a.control("bob", ctcs::Action::Close, &mut astore, 91).await;
        assert_eq!(
            held.commit(
                &mut a.port(),
                &mut Grant::new(),
                &mut directory,
                &mut astore,
                [73; 32],
            )
            .await
            .err(),
            Some(cdlv::Error::Conflict)
        );
        assert_eq!(
            large
                .delivery
                .wrap(
                    &large.threads.outgoing()[0],
                    &mut a.keys,
                    &ah,
                    &mut directory,
                    &mut astore,
                    [74; 32],
                )
                .await
                .err(),
            Some(cdlv::Error::Conflict)
        );

        a.control(
            "bob",
            ctcs::Action::Reopen {
                conversation: [19; 32],
            },
            &mut astore,
            92,
        )
        .await;
        let proof = SigningKey::from_bytes(&[72; 32])
            .sign(&answer_bytes(&a.binding, "bob", &[19; 32]))
            .to_bytes()
            .to_vec();
        a.control(
            "bob",
            ctcs::Action::Answered {
                conversation: [19; 32],
                evidence: proof,
            },
            &mut astore,
            93,
        )
        .await;
        let old = Threads::load(a.binding.clone(), SLOT, &astore)
            .unwrap()
            .send(&mut a.port(), &mut Grant::new(), b"old conversation")
            .await
            .unwrap();
        assert_eq!(
            Delivery::load(a.binding.clone(), &astore)
                .unwrap()
                .outgoing(old, &contacts(&a, &astore))
                .err(),
            Some(cdlv::Error::Unavailable)
        );
        assert_eq!(
            accepted.threads.threads().history()[0].bytes,
            b"durable hello"
        );
        assert_eq!(
            accepted
                .delivery
                .cancel(&id, &mut astore, [7; 32])
                .await
                .err(),
            Some(cdlv::Error::State)
        );
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn corrupted_delivery_checkpoint_has_no_usable_status_or_receipt() {
    block_on(async {
        let a = Fixture::new("alice", 1, Directory::default()).await;
        let (_, mut store) = a.store().await;
        assert_eq!(
            Delivery::load(Binding::new("beta", "alice").unwrap(), &store).err(),
            Some(cdlv::Error::Scope)
        );
        let valid = serde_json::json!({"version":1,"binding":a.binding,"records":{}});
        let mut bad_version = valid.clone();
        bad_version["version"] = 2.into();
        let mut bad_scope = valid.clone();
        bad_scope["binding"] = serde_json::to_value(Binding::new("alpha", "bob").unwrap()).unwrap();
        for (index, (bytes, error)) in [
            (b"broken".to_vec(), cdlv::Error::Encoding),
            (
                serde_json::to_vec(&bad_version).unwrap(),
                cdlv::Error::Scope,
            ),
            (serde_json::to_vec(&bad_scope).unwrap(), cdlv::Error::Scope),
        ]
        .into_iter()
        .enumerate()
        {
            store
                .commit(
                    store.version().unwrap(),
                    [(index + 1) as u8; 32],
                    &[cwst::Change::Put {
                        owner: "cdlv",
                        key: b"journal.v1",
                        value: &bytes,
                    }],
                    &[],
                )
                .await
                .unwrap();
            assert_eq!(Delivery::load(a.binding.clone(), &store).err(), Some(error));
        }
    });
}

// A Claimed Answer lets a Pending relation SEND and nothing else: the claim
// must name exactly this peer and conversation, and receiving still needs
// Established.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn claim_lets_a_pending_relation_send_but_never_receive() {
    block_on(async {
        let mut directory = Directory::default();
        let mut a = Fixture::new("alice", 1, directory.clone()).await;
        let mut b = Fixture::new("bob", 2, directory.clone()).await;
        let (_abackend, mut astore) = a.store().await;
        let (_bbackend, mut bstore) = b.store().await;
        a.begin("bob", &mut astore).await;
        let at = Threads::load(a.binding.clone(), SLOT, &astore).unwrap();
        let bt = Threads::load(b.binding.clone(), SLOT, &bstore).unwrap();
        let package = bt
            .key_package(&mut b.port())
            .await
            .unwrap()
            .commit(&mut b.port(), &mut Grant::new(), &mut bstore, [1; 32], &[])
            .await
            .unwrap();
        let Event::KeyPackage { bytes } = &package.events()[0] else {
            panic!()
        };
        let invitation = at
            .create_direct(&mut a.port(), &mut Grant::new(), "bob", bytes)
            .await
            .unwrap()
            .commit(&mut a.port(), &mut Grant::new(), &mut astore, [1; 32], &[])
            .await
            .unwrap();
        macro_rules! prepared {
            () => {
                invitation
                    .threads()
                    .send(&mut a.port(), &mut Grant::new(), b"early hello")
                    .await
                    .unwrap()
            };
        }
        let relation = contacts(&a, &astore).relation("bob").unwrap();
        assert_eq!(relation.state, ctcs::State::Pending);
        let plain = Delivery::load(a.binding.clone(), &astore).unwrap();
        assert_eq!(
            plain.outgoing(prepared!(), &contacts(&a, &astore)).err(),
            Some(cdlv::Error::Unavailable)
        );
        for wrong in [
            cdlv::Claim::new("carol", &SLOT),
            cdlv::Claim::new("bob", &[18; 32]),
        ] {
            let delivery = Delivery::load(a.binding.clone(), &astore)
                .unwrap()
                .with_claim(wrong);
            assert_eq!(
                delivery.outgoing(prepared!(), &contacts(&a, &astore)).err(),
                Some(cdlv::Error::Unavailable)
            );
        }
        let claimed = Delivery::load(a.binding.clone(), &astore)
            .unwrap()
            .with_claim(cdlv::Claim::new("bob", &SLOT));
        let candidate = claimed
            .outgoing(prepared!(), &contacts(&a, &astore))
            .unwrap();
        let sent = candidate
            .commit(
                &mut a.port(),
                &mut Grant::new(),
                &mut directory,
                &mut astore,
                [3; 32],
            )
            .await
            .unwrap();
        let id = *sent.threads.outgoing()[0].id();
        assert_eq!(sent.delivery.status(&id), Some(Status::Pending));
        let handle = a.keys.key(cdlv::purpose()).await.unwrap();
        let (delivery, wire) = sent
            .delivery
            .wrap(
                &sent.threads.outgoing()[0],
                &mut a.keys,
                &handle,
                &mut directory,
                &mut astore,
                [4; 32],
            )
            .await
            .unwrap();
        assert!(!wire.bytes().is_empty());
        // A reloaded delivery has no claim: a retry waits for the settled
        // Answer or a fresh claim, and the durable message stays.
        let reloaded = Delivery::load(a.binding.clone(), &astore).unwrap();
        assert_eq!(
            reloaded
                .retry(&id, &mut directory, &contacts(&a, &astore))
                .await
                .err(),
            Some(cdlv::Error::Unavailable)
        );
        let again = reloaded.with_claim(cdlv::Claim::new("bob", &SLOT));
        assert!(
            again
                .retry(&id, &mut directory, &contacts(&a, &astore))
                .await
                .is_ok()
        );
        drop(delivery);
        assert_eq!(sent.delivery.status(&id), Some(Status::Pending));
    });
}
