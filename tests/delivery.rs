//! Real OpenMLS and scoped Keys vectors. Test issuers are not production G3/G2.
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
        let bd = Delivery::load(b.binding.clone(), &bstore).unwrap();
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
        assert_eq!(Threads::load(b.binding.clone(), SLOT, &restored).unwrap().history().len(), 1);
        let ack_bytes = ack.bytes().to_vec();
        let ad = ad.cancel(&id, &mut astore, [5; 32]).await.unwrap();
        assert_eq!(ad.status(&id), Some(Status::CanceledUnconfirmed));
        assert_eq!(
            ad.retry(&id, &mut directory, &contacts(&a, &astore))
                .await
                .err(),
            Some(cdlv::Error::State)
        );
        let ack = match ad
            .authenticate(ack.bytes(), &mut directory, &contacts(&a, &astore))
            .await
            .unwrap()
        {
            Authenticated::Ack(ack) => ack,
            _ => panic!(),
        };
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
        match accepted.delivery
            .authenticate(&ack_bytes, &mut directory, &contacts(&a, &astore))
            .await
            .unwrap()
        {
            Authenticated::AlreadyAccepted(message) => assert_eq!(message, id),
            _ => panic!("duplicate ACK must not advance sender history"),
        }
        assert_eq!(accepted.threads.threads().history().len(), 1);
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
