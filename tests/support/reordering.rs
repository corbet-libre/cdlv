//! Reordered real MLS messages and durable recipient acknowledgments.
use super::*;

fn history_map(threads: &Threads) -> BTreeMap<[u8; 32], Vec<u8>> {
    let history = threads.history();
    let messages: BTreeMap<_, _> = history.iter().map(|m| (m.id, m.bytes.clone())).collect();
    assert_eq!(
        messages.len(),
        history.len(),
        "history contains duplicate IDs"
    );
    messages
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn two_pending_reverse_order_delayed_acks_survive_reopen() {
    block_on(async {
        let mut directory = Directory::default();
        let mut a = Fixture::new("alice", 1, directory.clone()).await;
        let mut b = Fixture::new("bob", 2, directory.clone()).await;
        let ah = a.keys.key(cdlv::purpose()).await.unwrap();
        let bh = b.keys.key(cdlv::purpose()).await.unwrap();
        let (abackend, mut astore) = a.store().await;
        let (bbackend, mut bstore) = b.store().await;
        let acipher = ckmg::passkey::store_cipher(&prf(1), "alpha").unwrap();
        let bcipher = ckmg::passkey::store_cipher(&prf(2), "alpha").unwrap();
        a.establish("bob", &mut astore).await;
        b.establish("alice", &mut bstore).await;
        let pkg = Threads::load(b.binding.clone(), SLOT, &bstore)
            .unwrap()
            .key_package(&mut b.port())
            .await
            .unwrap()
            .commit(&mut b.port(), &mut Grant::new(), &mut bstore, [21; 32], &[])
            .await
            .unwrap();
        let Event::KeyPackage { bytes } = &pkg.events()[0] else {
            panic!()
        };
        let inv = Threads::load(a.binding.clone(), SLOT, &astore)
            .unwrap()
            .create_direct(&mut a.port(), &mut Grant::new(), "bob", bytes)
            .await
            .unwrap()
            .commit(&mut a.port(), &mut Grant::new(), &mut astore, [11; 32], &[])
            .await
            .unwrap();
        let Event::Invitation { welcome, .. } = &inv.events()[0] else {
            panic!()
        };
        pkg.threads()
            .join_direct(&mut b.port(), &mut Grant::new(), "alice", welcome)
            .await
            .unwrap()
            .commit(&mut b.port(), &mut Grant::new(), &mut bstore, [22; 32], &[])
            .await
            .unwrap();
        let at1 = Threads::load(a.binding.clone(), SLOT, &astore).unwrap();
        let prep1 = at1
            .send(&mut a.port(), &mut Grant::new(), b"first")
            .await
            .unwrap();
        let id1 = *prep1.prepared_message().unwrap().id();
        let cand1 = Delivery::load(a.binding.clone(), &astore)
            .unwrap()
            .outgoing(prep1, &contacts(&a, &astore))
            .unwrap();
        let sent1 = cand1
            .commit(
                &mut a.port(),
                &mut Grant::new(),
                &mut directory,
                &mut astore,
                [13; 32],
            )
            .await
            .unwrap();
        assert!(sent1.threads.threads().history().is_empty());
        // Crash after committing the MLS send but before signing its envelope.
        // The durable outbox, not a copied live ratchet, recovers this send.
        let original_ciphertext = sent1.threads.outgoing()[0].bytes().to_vec();
        let original_epoch = sent1.threads.outgoing()[0].epoch();
        drop(sent1);
        drop(astore);
        let mut astore = Store::open(abackend.clone(), &acipher, "alpha")
            .await
            .unwrap();
        recovery_refusals(
            &mut a,
            &b,
            &astore,
            id1,
            original_epoch,
            &original_ciphertext,
            &mut directory,
        )
        .await;
        let restored = Delivery::load(a.binding.clone(), &astore).unwrap();
        assert!(
            restored
                .retry(&id1, &mut directory, &contacts(&a, &astore))
                .await
                .is_err()
        );
        let (_, wire1) = restored
            .resume_wrap(
                &id1,
                &mut a.keys,
                &ah,
                &mut directory,
                &mut astore,
                [14; 32],
            )
            .await
            .unwrap();
        let envelope: serde_json::Value = serde_json::from_slice(wire1.bytes()).unwrap();
        let recovered_ciphertext: Vec<u8> =
            serde_json::from_value(envelope["body"]["Data"]["wire"].clone()).unwrap();
        assert_eq!(recovered_ciphertext, original_ciphertext);
        let wrapped = Delivery::load(a.binding.clone(), &astore).unwrap();
        assert!(
            wrapped
                .resume_wrap(
                    &id1,
                    &mut a.keys,
                    &ah,
                    &mut directory,
                    &mut astore,
                    [90; 32]
                )
                .await
                .is_err()
        );
        let wire1b = wire1.bytes().to_vec();
        let at2 = Threads::load(a.binding.clone(), SLOT, &astore).unwrap();
        let prep2 = at2
            .send(&mut a.port(), &mut Grant::new(), b"second")
            .await
            .unwrap();
        let id2 = *prep2.prepared_message().unwrap().id();
        assert_ne!(id1, id2);
        let cand2 = Delivery::load(a.binding.clone(), &astore)
            .unwrap()
            .outgoing(prep2, &contacts(&a, &astore))
            .unwrap();
        let sent2 = cand2
            .commit(
                &mut a.port(),
                &mut Grant::new(),
                &mut directory,
                &mut astore,
                [15; 32],
            )
            .await
            .unwrap();
        let (ad2, wire2) = sent2
            .delivery
            .wrap(
                &sent2.threads.outgoing()[0],
                &mut a.keys,
                &ah,
                &mut directory,
                &mut astore,
                [16; 32],
            )
            .await
            .unwrap();
        let wire2b = wire2.bytes().to_vec();
        assert_eq!(ad2.status(&id1), Some(Status::Pending));
        assert_eq!(ad2.status(&id2), Some(Status::Pending));
        assert!(
            Threads::load(a.binding.clone(), SLOT, &astore)
                .unwrap()
                .history()
                .is_empty()
        );
        astore = Store::open(abackend.clone(), &acipher, "alpha")
            .await
            .unwrap();
        let ad2 = Delivery::load(a.binding.clone(), &astore).unwrap();
        assert_eq!(ad2.status(&id1), Some(Status::Pending));
        assert_eq!(ad2.status(&id2), Some(Status::Pending));
        assert!(
            Threads::load(a.binding.clone(), SLOT, &astore)
                .unwrap()
                .history()
                .is_empty()
        );
        assert_eq!(
            ad2.retry(&id1, &mut directory, &contacts(&a, &astore))
                .await
                .unwrap()
                .bytes(),
            wire1b
        );
        assert_eq!(
            ad2.retry(&id2, &mut directory, &contacts(&a, &astore))
                .await
                .unwrap()
                .bytes(),
            wire2b
        );
        let bd0 = Delivery::load(b.binding.clone(), &bstore).unwrap();
        let bt0 = Threads::load(b.binding.clone(), SLOT, &bstore).unwrap();
        let Authenticated::Data(inc_a) = bd0
            .authenticate(&wire2b, &mut directory, &contacts(&b, &bstore))
            .await
            .unwrap()
        else {
            panic!()
        };
        let Authenticated::Data(inc_b) = bd0
            .authenticate(&wire2b, &mut directory, &contacts(&b, &bstore))
            .await
            .unwrap()
        else {
            panic!()
        };
        let ca = inc_a.ciphertext().to_vec();
        let cb = inc_b.ciphertext().to_vec();
        let prep_a = bt0
            .receive(&mut b.port(), &mut Grant::new(), &ca)
            .await
            .unwrap();
        let prep_b = bt0
            .receive(&mut b.port(), &mut Grant::new(), &cb)
            .await
            .unwrap();
        let cand_a = bd0.received(prep_a, inc_a, &mut b.keys, &bh).await.unwrap();
        let cand_b = bd0.received(prep_b, inc_b, &mut b.keys, &bh).await.unwrap();
        assert!(bt0.history().is_empty());
        assert_eq!(bd0.ack(&id2).err(), Some(cdlv::Error::State));
        let first = cand_a
            .commit(
                &mut b.port(),
                &mut Grant::new(),
                &mut directory,
                &mut bstore,
                [23; 32],
            )
            .await
            .unwrap();
        assert_eq!(
            history_map(first.threads.threads()),
            BTreeMap::from([(id2, b"second".to_vec())])
        );
        let ver1 = bstore.version().unwrap();
        assert_eq!(
            cand_b
                .commit(
                    &mut b.port(),
                    &mut Grant::new(),
                    &mut directory,
                    &mut bstore,
                    [24; 32]
                )
                .await
                .err(),
            Some(cdlv::Error::Conflict)
        );
        assert_eq!(bstore.version().unwrap(), ver1);
        assert_eq!(
            Threads::load(b.binding.clone(), SLOT, &bstore)
                .unwrap()
                .history()
                .len(),
            1
        );
        bstore = Store::open(bbackend.clone(), &bcipher, "alpha")
            .await
            .unwrap();
        assert_eq!(
            history_map(&Threads::load(b.binding.clone(), SLOT, &bstore).unwrap()),
            BTreeMap::from([(id2, b"second".to_vec())])
        );
        let ack2b = Delivery::load(b.binding.clone(), &bstore)
            .unwrap()
            .ack(&id2)
            .unwrap()
            .bytes()
            .to_vec();
        let v0 = bstore.version().unwrap();
        match Delivery::load(b.binding.clone(), &bstore)
            .unwrap()
            .authenticate(&wire2b, &mut directory, &contacts(&b, &bstore))
            .await
            .unwrap()
        {
            Authenticated::Duplicate(w) => assert_eq!(w.bytes(), ack2b),
            _ => panic!(),
        }
        assert_eq!(bstore.version().unwrap(), v0);
        assert_eq!(
            Threads::load(b.binding.clone(), SLOT, &bstore)
                .unwrap()
                .history()
                .len(),
            1
        );
        let bd1 = Delivery::load(b.binding.clone(), &bstore).unwrap();
        let Authenticated::Data(inc1) = bd1
            .authenticate(&wire1b, &mut directory, &contacts(&b, &bstore))
            .await
            .unwrap()
        else {
            panic!()
        };
        let c1 = inc1.ciphertext().to_vec();
        let prep1b = Threads::load(b.binding.clone(), SLOT, &bstore)
            .unwrap()
            .receive(&mut b.port(), &mut Grant::new(), &c1)
            .await
            .unwrap();
        let cand1b = bd1.received(prep1b, inc1, &mut b.keys, &bh).await.unwrap();
        let second = cand1b
            .commit(
                &mut b.port(),
                &mut Grant::new(),
                &mut directory,
                &mut bstore,
                [25; 32],
            )
            .await
            .unwrap();
        assert_eq!(
            history_map(second.threads.threads()),
            BTreeMap::from([(id1, b"first".to_vec()), (id2, b"second".to_vec())])
        );
        bstore = Store::open(bbackend.clone(), &bcipher, "alpha")
            .await
            .unwrap();
        assert_eq!(
            history_map(&Threads::load(b.binding.clone(), SLOT, &bstore).unwrap()),
            BTreeMap::from([(id1, b"first".to_vec()), (id2, b"second".to_vec())])
        );
        let ack1b = Delivery::load(b.binding.clone(), &bstore)
            .unwrap()
            .ack(&id1)
            .unwrap()
            .bytes()
            .to_vec();
        let ack2c = Delivery::load(b.binding.clone(), &bstore)
            .unwrap()
            .ack(&id2)
            .unwrap()
            .bytes()
            .to_vec();
        assert_eq!(ack2c, ack2b);
        let v1 = bstore.version().unwrap();
        match Delivery::load(b.binding.clone(), &bstore)
            .unwrap()
            .authenticate(&wire1b, &mut directory, &contacts(&b, &bstore))
            .await
            .unwrap()
        {
            Authenticated::Duplicate(w) => assert_eq!(w.bytes(), ack1b),
            _ => panic!(),
        }
        assert_eq!(bstore.version().unwrap(), v1);
        assert_eq!(
            Threads::load(b.binding.clone(), SLOT, &bstore)
                .unwrap()
                .history()
                .len(),
            2
        );
        assert!(
            Threads::load(a.binding.clone(), SLOT, &astore)
                .unwrap()
                .history()
                .is_empty()
        );
        let Authenticated::Ack(va1) = ad2
            .authenticate(&ack1b, &mut directory, &contacts(&a, &astore))
            .await
            .unwrap()
        else {
            panic!()
        };
        let at = Threads::load(a.binding.clone(), SLOT, &astore).unwrap();
        let accepted1 = ad2
            .acknowledged(&at, va1)
            .unwrap()
            .commit(
                &mut a.port(),
                &mut Grant::new(),
                &mut directory,
                &mut astore,
                [17; 32],
            )
            .await
            .unwrap();
        assert_eq!(accepted1.delivery.status(&id1), Some(Status::Accepted));
        assert_eq!(accepted1.delivery.status(&id2), Some(Status::Pending));
        assert_eq!(
            history_map(accepted1.threads.threads()),
            BTreeMap::from([(id1, b"first".to_vec())])
        );
        astore = Store::open(abackend.clone(), &acipher, "alpha")
            .await
            .unwrap();
        let ad_restart = Delivery::load(a.binding.clone(), &astore).unwrap();
        assert_eq!(
            history_map(&Threads::load(a.binding.clone(), SLOT, &astore).unwrap()),
            BTreeMap::from([(id1, b"first".to_vec())])
        );
        assert_eq!(
            ad_restart
                .retry(&id2, &mut directory, &contacts(&a, &astore))
                .await
                .unwrap()
                .bytes(),
            wire2b
        );
        let va = astore.version().unwrap();
        match ad_restart
            .authenticate(&ack1b, &mut directory, &contacts(&a, &astore))
            .await
            .unwrap()
        {
            Authenticated::AlreadyAccepted(m) => assert_eq!(m, id1),
            _ => panic!(),
        }
        assert_eq!(astore.version().unwrap(), va);
        assert_eq!(
            Threads::load(a.binding.clone(), SLOT, &astore)
                .unwrap()
                .history()
                .len(),
            1
        );
        let Authenticated::Ack(va2) = ad_restart
            .authenticate(&ack2b, &mut directory, &contacts(&a, &astore))
            .await
            .unwrap()
        else {
            panic!()
        };
        let at3 = Threads::load(a.binding.clone(), SLOT, &astore).unwrap();
        let accepted2 = ad_restart
            .acknowledged(&at3, va2)
            .unwrap()
            .commit(
                &mut a.port(),
                &mut Grant::new(),
                &mut directory,
                &mut astore,
                [18; 32],
            )
            .await
            .unwrap();
        assert_eq!(
            history_map(accepted2.threads.threads()),
            BTreeMap::from([(id1, b"first".to_vec()), (id2, b"second".to_vec())])
        );
        astore = Store::open(abackend, &acipher, "alpha").await.unwrap();
        let ad_final = Delivery::load(a.binding.clone(), &astore).unwrap();
        assert_eq!(ad_final.status(&id1), Some(Status::Accepted));
        assert_eq!(ad_final.status(&id2), Some(Status::Accepted));
        let v2 = astore.version().unwrap();
        for (expected_id, ack) in [(id1, &ack1b), (id2, &ack2b)] {
            match ad_final
                .authenticate(ack, &mut directory, &contacts(&a, &astore))
                .await
                .unwrap()
            {
                Authenticated::AlreadyAccepted(id) => assert_eq!(id, expected_id),
                _ => panic!(),
            }
        }
        assert_eq!(astore.version().unwrap(), v2);
        assert_eq!(
            Threads::load(a.binding.clone(), SLOT, &astore)
                .unwrap()
                .history()
                .len(),
            2
        );
    });
}

async fn recovery_refusals(
    a: &mut Fixture,
    b: &Fixture,
    source: &Store<Memory>,
    id: [u8; 32],
    epoch: u64,
    ciphertext: &[u8],
    devices: &mut Directory,
) {
    let handle = a.keys.key(cdlv::purpose()).await.unwrap();
    let mut empty_outbox = copied_store(a, source).await;
    let loaded = Delivery::load(a.binding.clone(), &empty_outbox).unwrap();
    assert_eq!(
        loaded
            .resume_wrap(
                &id,
                &mut a.keys,
                &handle,
                devices,
                &mut empty_outbox,
                [170; 32]
            )
            .await
            .err(),
        Some(cdlv::Error::State)
    );
    assert_eq!(
        loaded
            .resume_wrap(
                &[0; 32],
                &mut a.keys,
                &handle,
                devices,
                &mut empty_outbox,
                [170; 32]
            )
            .await
            .err(),
        Some(cdlv::Error::State)
    );
    let forged = [
        b"not an event".to_vec(),
        serde_json::to_vec(&Event::Joined).unwrap(),
        serde_json::to_vec(&Event::Ciphertext {
            id: [99; 32],
            epoch,
            bytes: ciphertext.to_vec(),
        })
        .unwrap(),
        serde_json::to_vec(&Event::Ciphertext {
            id,
            epoch: epoch + 1,
            bytes: ciphertext.to_vec(),
        })
        .unwrap(),
        serde_json::to_vec(&Event::Ciphertext {
            id,
            epoch,
            bytes: b"changed".to_vec(),
        })
        .unwrap(),
    ];
    for bytes in forged {
        let mut store = copied_store(a, source).await;
        store
            .commit(
                store.version().unwrap(),
                [171; 32],
                &[],
                &[cwst::Output {
                    id: [172; 32],
                    bytes,
                }],
            )
            .await
            .unwrap();
        let loaded = Delivery::load(a.binding.clone(), &store).unwrap();
        assert_eq!(
            loaded
                .resume_wrap(&id, &mut a.keys, &handle, devices, &mut store, [173; 32])
                .await
                .err(),
            Some(cdlv::Error::State)
        );
    }
    let mut store = copied_store(a, source).await;
    store
        .commit(
            store.version().unwrap(),
            [174; 32],
            &[],
            source.load_pending().unwrap(),
        )
        .await
        .unwrap();
    let loaded = Delivery::load(a.binding.clone(), &store).unwrap();
    // A real purpose handle from another member is not publication authority.
    assert_eq!(
        loaded
            .resume_wrap(&id, &mut a.keys, &b.handle, devices, &mut store, [175; 32])
            .await
            .err(),
        Some(cdlv::Error::Scope)
    );
    let canceled = loaded.cancel(&id, &mut store, [176; 32]).await.unwrap();
    assert_eq!(
        canceled
            .resume_wrap(&id, &mut a.keys, &handle, devices, &mut store, [177; 32])
            .await
            .err(),
        Some(cdlv::Error::State)
    );
}
