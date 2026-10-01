#![allow(dead_code)]

use ckmg::*;
use ed25519_dalek::{Signer, SigningKey};
use rand_core::{Rng, SeedableRng};
use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
    rc::Rc,
};

pub fn binding(community: &str) -> Binding {
    Binding::new(community, &format!("pseudonym-{community}")).unwrap()
}
pub fn prf(n: u8) -> passkey::PrfOutput {
    passkey::PrfOutput::from_bytes(&[n; 32]).unwrap()
}
pub fn info() -> DeviceInfo {
    DeviceInfo::new("private-device-name", b"private-authority-reference").unwrap()
}
pub fn purpose(scope: Scope, label: &str) -> Purpose {
    Purpose::new(scope, label, 0).unwrap()
}

#[derive(Clone, Default)]
pub struct Memory(pub Rc<RefCell<MemoryData>>);
#[derive(Default)]
pub struct MemoryData {
    pub records: HashMap<Locator, Vec<u8>>,
    pub fault: Fault,
    pub writes: usize,
    pub read_failure: bool,
}
#[derive(Default, Clone, Copy)]
pub enum Fault {
    #[default]
    None,
    Before,
    After,
    Conflict,
    CancelBefore,
    CancelAfter,
}
impl SecureStore for Memory {
    async fn load(&mut self, location: &Locator) -> Result<Option<Vec<u8>>, Error> {
        let data = self.0.borrow();
        if data.read_failure {
            return Err(Error::Unavailable);
        }
        Ok(data.records.get(location).cloned())
    }
    async fn compare_exchange(
        &mut self,
        location: &Locator,
        expected: Option<[u8; 32]>,
        replacement: &[u8],
    ) -> Result<Commit, Error> {
        let fault = self.0.borrow().fault;
        if matches!(fault, Fault::CancelBefore) {
            std::future::pending::<()>().await;
        }
        if matches!(fault, Fault::Before) {
            return Err(Error::Unavailable);
        }
        if matches!(fault, Fault::Conflict) {
            return Ok(Commit::Conflict);
        }
        {
            let mut data = self.0.borrow_mut();
            let actual = data
                .records
                .get(location)
                .map(|v| *blake3::hash(v).as_bytes());
            if actual != expected {
                return Ok(Commit::Conflict);
            }
            data.records.insert(*location, replacement.into());
            data.writes += 1;
        }
        if matches!(fault, Fault::CancelAfter) {
            std::future::pending::<()>().await;
        }
        if matches!(fault, Fault::After) {
            return Ok(Commit::Unknown);
        }
        Ok(Commit::Committed)
    }
}

#[derive(Clone)]
pub struct Time(pub Rc<Cell<u64>>);
impl Default for Time {
    fn default() -> Self {
        Self(Rc::new(Cell::new(1000)))
    }
}
impl Clock for Time {
    fn now(&mut self) -> Result<u64, Error> {
        Ok(self.0.get())
    }
}

pub struct Random {
    rng: rand_chacha::ChaCha20Rng,
    pub fail: Rc<Cell<bool>>,
}
impl Random {
    pub fn new(seed: u8) -> Self {
        Self {
            rng: rand_chacha::ChaCha20Rng::from_seed([seed; 32]),
            fail: Rc::new(Cell::new(false)),
        }
    }
}
impl Entropy for Random {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
        if self.fail.get() {
            return Err(Error::Randomness);
        }
        self.rng.fill_bytes(bytes);
        Ok(())
    }
}

// This test-only adapter verifies actual signatures from a fixture approval key,
// and holds authenticated current lineage outside the encrypted device stores.
// It is not shipped as a production membership/authorization implementation.
#[derive(Clone, Default)]
pub struct Guard(pub Rc<RefCell<HashMap<String, Lineage>>>);
fn approval_bytes(
    action: Action,
    b: &Binding,
    root: Option<PublicKey>,
    epoch: u64,
    target: Option<PublicKey>,
    statement: Option<[u8; 32]>,
) -> Vec<u8> {
    serde_json::to_vec(&(
        "test-consent-v1",
        format!("{action:?}"),
        b,
        root,
        epoch,
        target,
        statement,
    ))
    .unwrap()
}
pub fn consent(
    action: Action,
    b: &Binding,
    root: Option<PublicKey>,
    epoch: u64,
    target: Option<PublicKey>,
    statement: Option<[u8; 32]>,
) -> Vec<u8> {
    SigningKey::from_bytes(&[111; 32])
        .sign(&approval_bytes(action, b, root, epoch, target, statement))
        .to_bytes()
        .to_vec()
}
impl Authority for Guard {
    async fn check(&mut self, request: Authorization<'_>) -> Result<(), Error> {
        let anchors = self.0.borrow();
        if request.action == Action::Create {
            if anchors.contains_key(request.binding.community()) {
                return Err(Error::Unauthorized);
            }
        } else {
            let anchor = anchors
                .get(request.binding.community())
                .ok_or(Error::Unauthorized)?;
            if anchor.binding != *request.binding
                || Some(anchor.root) != request.root
                || anchor.epoch != request.epoch
            {
                return Err(Error::Unauthorized);
            }
            if matches!(
                request.action,
                Action::Use | Action::Pair | Action::Rotate | Action::Restore
            ) && !anchor.devices.contains(&request.device)
            {
                return Err(Error::Revoked);
            }
        }
        if request.action == Action::Restore
            && request.statement != Some(anchors[request.binding.community()].digest()?)
        {
            return Err(Error::Unauthorized);
        }
        if request.action != Action::Use {
            let evidence: [u8; 64] = request
                .evidence
                .try_into()
                .map_err(|_| Error::Unauthorized)?;
            verify_ed25519(
                &SigningKey::from_bytes(&[111; 32])
                    .verifying_key()
                    .to_bytes(),
                &approval_bytes(
                    request.action,
                    request.binding,
                    request.root,
                    request.epoch,
                    request.target,
                    request.statement,
                ),
                &evidence,
            )
            .map_err(|_| Error::Unauthorized)?;
        }
        Ok(())
    }
}
impl Guard {
    pub fn publish(&self, receipt: &Receipt) {
        let lineage = match &receipt.change {
            Change::Created(v)
            | Change::Restored(v)
            | Change::Paired(v)
            | Change::Adopted(v)
            | Change::Revoked(v) => v,
            Change::DeviceAuthorized(v) => &v.lineage,
            Change::Rotated(v) => &v.lineage,
            Change::PairingRequested(_) => return,
        };
        lineage.verify().unwrap();
        self.0
            .borrow_mut()
            .insert(lineage.binding.community().into(), lineage.clone());
    }
}

pub type Machine = Keys<Memory, Time, Random, Guard>;
pub fn machine(store: &Memory, time: &Time, guard: &Guard, seed: u8) -> Machine {
    Keys::new(
        store.clone(),
        time.clone(),
        Random::new(seed),
        guard.clone(),
    )
}
pub async fn create(
    machine: &mut Machine,
    guard: &Guard,
    p: &passkey::PrfOutput,
    b: &Binding,
) -> Receipt {
    let receipt = machine
        .create_scope(
            p,
            b.clone(),
            info(),
            &consent(Action::Create, b, None, 0, None, None),
        )
        .await
        .unwrap();
    guard.publish(&receipt);
    machine.acknowledge(receipt.operation).await.unwrap();
    receipt
}
pub async fn request(
    new: &mut Machine,
    p: &passkey::PrfOutput,
    anchor: &Lineage,
) -> PairingRequest {
    let receipt = new
        .request_pairing(
            p,
            anchor,
            info(),
            &consent(
                Action::RequestPairing,
                &anchor.binding,
                Some(anchor.root),
                anchor.epoch,
                None,
                Some(anchor.digest().unwrap()),
            ),
        )
        .await
        .unwrap();
    new.acknowledge(receipt.operation).await.unwrap();
    match receipt.change {
        Change::PairingRequested(v) => *v,
        _ => panic!(),
    }
}
pub async fn grant(live: &mut Machine, guard: &Guard, request: &PairingRequest) -> PairingGrant {
    let receipt = live
        .authorize_device(
            request,
            &consent(
                Action::Pair,
                &request.binding,
                Some(request.root),
                request.epoch,
                Some(request.device),
                Some(request.digest().unwrap()),
            ),
        )
        .await
        .unwrap();
    guard.publish(&receipt);
    live.acknowledge(receipt.operation).await.unwrap();
    match receipt.change {
        Change::DeviceAuthorized(v) => *v,
        _ => panic!(),
    }
}
pub async fn accept(new: &mut Machine, grant: &PairingGrant) {
    let r = &grant.request;
    let receipt = new
        .accept_pairing(
            grant,
            &consent(
                Action::Adopt,
                &r.binding,
                Some(r.root),
                r.epoch,
                Some(r.device),
                Some(r.digest().unwrap()),
            ),
        )
        .await
        .unwrap();
    new.acknowledge(receipt.operation).await.unwrap();
}
pub async fn pair(
    live: &mut Machine,
    new: &mut Machine,
    guard: &Guard,
    p: &passkey::PrfOutput,
) -> PairingGrant {
    let anchor = live.lineage().await.unwrap();
    let request = request(new, p, &anchor).await;
    let grant = grant(live, guard, &request).await;
    accept(new, &grant).await;
    grant
}
pub async fn prepare(live: &mut Machine, revoked: PublicKey) {
    let anchor = live.lineage().await.unwrap();
    live.prepare_rotation(
        revoked,
        &consent(
            Action::Rotate,
            &anchor.binding,
            Some(anchor.root),
            anchor.epoch,
            Some(revoked),
            Some(anchor.digest().unwrap()),
        ),
    )
    .await
    .unwrap();
}
pub fn rotation(receipt: &Receipt) -> &Rotation {
    match &receipt.change {
        Change::Rotated(v) => v,
        _ => panic!(),
    }
}
pub fn adoption(rotation: &Rotation) -> Vec<u8> {
    let mut bytes = b"ckmg.rotation.digest.v1\0".to_vec();
    serde_json::to_writer(&mut bytes, rotation).unwrap();
    consent(
        Action::Adopt,
        &rotation.lineage.binding,
        Some(rotation.lineage.root),
        rotation.lineage.epoch,
        Some(rotation.revoked),
        Some(*blake3::hash(&bytes).as_bytes()),
    )
}
