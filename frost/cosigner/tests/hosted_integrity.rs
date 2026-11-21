// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Hosted-key replication integrity: a node never makes hosted material servable on one peer's
//! word.
//!
//! - A node stores a key it does not hold only when two peers return the same material and no
//!   reachable peer returns other material (read-repair, the sweep, a leader adopting a key);
//!   otherwise it answers UNAVAILABLE, never NOT_FOUND.
//! - The sweep never pushes. A push into an id the receiver lacks is accepted only from the caller
//!   holding the receiver's generation fence, and not while another peer holds other material.
//! - A generation that meets a conflict is aborted and rolled back, never outvoted.
//! - Timestamps from a peer may not lie in the future; an RSA key must match its public half.
//! - The degraded 2-of-3 cluster (one node down) keeps serving and heals when the node returns.
//!
//! Three nodes wired in process; each node's mesh and views go through a switch that can make a
//! node unreachable, as a stopped cosigner is over gRPC.

// tonic::Status is large by value (see the crate root); the RPC helpers return it as the service does.
#![allow(clippy::result_large_err)]

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use frost_ed25519::round1::SigningCommitments;
use frost_ed25519::round2::SignatureShare;
use frost_ed25519::Identifier;
use rutli_cosigner::hosted::{HostedKey, HostedSpec};
use rutli_cosigner::keystore::KeyStore;
use rutli_cosigner::node::{Node, Round1Ctx};
use rutli_cosigner::orchestrator::{
    anti_entropy_sweep, generate_hosted_key, repair_hosted_key, Peers, DEFAULT_WRITE_QUORUM,
};
use rutli_cosigner::pb;
use rutli_cosigner::pb::signer_server::Signer;
use rutli_cosigner::peer::{LocalPeer, PeerApi};
use rutli_cosigner::ratelimit::DecryptRateLimiter;
use rutli_cosigner::seal::Sealer;
use rutli_cosigner::service::SignerSvc;
use rutli_cosigner::wrap::Wrapped;
use rutli_cosigner::{DaemonError, Result};
use tonic::{Code, Request};

const N: u16 = 3;
const T: u16 = 2;
const MASTER: &[u8] = b"hosted integrity test cluster master";
const CLUSTER: &str = "integritycluster";
const CEREMONY_ORPHAN_DEFAULT: std::time::Duration = std::time::Duration::from_secs(15 * 60);

/// What a test does to one peer handle's calls, beyond forwarding them.
#[derive(Default)]
struct Hooks {
    /// Run before `fetch_key` answers; `Some(e)` replaces the answer with an error.
    on_fetch: Option<Box<dyn Fn() -> Option<DaemonError> + Send + Sync>>,
    /// Replaces `replicate_key`'s answer.
    on_replicate: Option<Box<dyn Fn() -> Result<Vec<u8>> + Send + Sync>>,
    /// `list_inventory` never answers (a hung peer).
    hang_list: bool,
    /// Run before `replicate_key` is forwarded.
    before_replicate: Option<Box<dyn Fn() + Send + Sync>>,
    /// Extra live ids `list_inventory` reports (made up).
    extra_inventory: Vec<String>,
}

/// A handle on node `inner` that answers like a stopped cosigner while `down` is set, and counts
/// the `fetch_key` calls it sees.
struct Switch {
    inner: LocalPeer,
    down: Arc<AtomicBool>,
    fetches: Arc<AtomicUsize>,
    hooks: Arc<Hooks>,
}

fn down() -> DaemonError {
    DaemonError::Status(tonic::Status::unknown("transport error"))
}

impl Switch {
    fn check(&self) -> Result<()> {
        if self.down.load(Ordering::SeqCst) {
            return Err(down());
        }
        Ok(())
    }
}

#[async_trait]
impl PeerApi for Switch {
    fn identifier(&self) -> Identifier {
        self.inner.identifier()
    }
    fn is_local(&self) -> bool {
        self.inner.is_local()
    }
    async fn sign_round1(&self, k: &str, s: &str, ctx: &Round1Ctx) -> Result<SigningCommitments> {
        self.check()?;
        self.inner.sign_round1(k, s, ctx).await
    }
    async fn sign_round2(
        &self,
        k: &str,
        s: &str,
        m: &[u8],
        c: &BTreeMap<Identifier, SigningCommitments>,
        d: Option<&[u8; 32]>,
    ) -> Result<SignatureShare> {
        self.check()?;
        self.inner.sign_round2(k, s, m, c, d).await
    }
    async fn abort_sign(&self, k: &str, s: &str) -> Result<()> {
        self.check()?;
        self.inner.abort_sign(k, s).await
    }
    async fn ceremony_fence(&self, c: &str, k: &str, kind: &'static str) -> Result<()> {
        self.check()?;
        self.inner.ceremony_fence(c, k, kind).await
    }
    async fn ceremony_release(&self, c: &str, k: &str) -> Result<()> {
        self.check()?;
        self.inner.ceremony_release(c, k).await
    }
    async fn node_info(&self) -> Result<(u16, [u8; 32])> {
        self.check()?;
        self.inner.node_info().await
    }
    async fn hosted_specs(&self) -> Result<Vec<String>> {
        self.check()?;
        self.inner.hosted_specs().await
    }
    async fn replicate_key(&self, c: &str, k: &str, s: &str, p: &[u8], w: &Wrapped) -> Result<Vec<u8>> {
        self.check()?;
        if let Some(f) = &self.hooks.before_replicate {
            f();
        }
        self.check()?;
        if let Some(f) = &self.hooks.on_replicate {
            return f();
        }
        self.inner.replicate_key(c, k, s, p, w).await
    }
    async fn fetch_key(&self, k: &str) -> Result<(String, Vec<u8>, Wrapped)> {
        self.check()?;
        self.fetches.fetch_add(1, Ordering::SeqCst);
        if let Some(f) = &self.hooks.on_fetch {
            if let Some(e) = f() {
                return Err(e);
            }
        }
        self.inner.fetch_key(k).await
    }
    async fn fetch_key_state(&self, k: &str) -> Result<rutli_cosigner::peer::FetchedCopy> {
        self.check()?;
        self.fetches.fetch_add(1, Ordering::SeqCst);
        if let Some(f) = &self.hooks.on_fetch {
            if let Some(e) = f() {
                return Err(e);
            }
        }
        self.inner.fetch_key_state(k).await
    }
    async fn list_keys(&self) -> Result<Vec<(String, String, Vec<u8>)>> {
        self.check()?;
        self.inner.list_keys().await
    }
    async fn list_inventory(&self) -> Result<Vec<pb::KeyManifest>> {
        self.check()?;
        if self.hooks.hang_list {
            tokio::time::sleep(std::time::Duration::from_secs(120)).await;
        }
        let mut inv = self.inner.list_inventory().await?;
        inv.extend(self.hooks.extra_inventory.iter().map(|id| pb::KeyManifest {
            key_id: id.clone(),
            spec: "aes-256-gcm".into(),
            commitment: vec![1; 32],
            ..Default::default()
        }));
        Ok(inv)
    }
    async fn purge_key(&self, c: &str, k: &str) -> Result<bool> {
        self.check()?;
        self.inner.purge_key(c, k).await
    }
}

/// Three nodes with hosted keys. `down[i]` makes node `i` unreachable from every view and mesh;
/// `fetches[i]` counts FetchKey calls node `i` answered.
struct Cluster {
    nodes: Vec<Arc<Node>>,
    down: Vec<Arc<AtomicBool>>,
    fetches: Vec<Arc<AtomicUsize>>,
    _tmp: tempfile::TempDir,
}

impl Cluster {
    fn new() -> Self {
        Self::of(N)
    }

    /// `n` nodes (write quorum 2).
    fn of(n: u16) -> Self {
        Self::build(n, CEREMONY_ORPHAN_DEFAULT, |_, _, _| Hooks::default())
    }

    /// `n` nodes with an orphan timeout for ceremony guards, and the hooks of node `me`'s mesh
    /// handle on node `j` (`mesh_hooks(nodes, me, j)`).
    fn build(n: u16, orphan: std::time::Duration, mesh_hooks: impl Fn(&[Arc<Node>], usize, usize) -> Hooks) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let nodes: Vec<Arc<Node>> = (1..=n)
            .map(|i| {
                let sealer = Arc::new(Sealer::from_master_secret(MASTER, i));
                let ks = KeyStore::open_with_sealer(tmp.path().join(format!("node-{i}")), Some(sealer)).unwrap();
                Arc::new(
                    Node::new_with_ceremony_timeout(Identifier::try_from(i).unwrap(), n, T, ks, orphan)
                        .with_hosted_keys(MASTER, CLUSTER.to_string())
                        .unwrap(),
                )
            })
            .collect();
        let c = Cluster {
            down: (0..n).map(|_| Arc::new(AtomicBool::new(false))).collect(),
            fetches: (0..n).map(|_| Arc::new(AtomicUsize::new(0))).collect(),
            nodes,
            _tmp: tmp,
        };
        // Each node's mesh: the others, through the switches, as the daemon dials them.
        for (me, node) in c.nodes.iter().enumerate() {
            node.set_mesh(c.view_with(me, |j| mesh_hooks(&c.nodes, me, j))).unwrap();
        }
        c
    }

    /// Node `me`'s view: itself in process, every other node as a peer calling on `me`'s behalf.
    fn view(&self, me: usize) -> Peers {
        self.view_with(me, |_| Hooks::default())
    }

    fn view_with(&self, me: usize, hooks: impl Fn(usize) -> Hooks) -> Peers {
        (0..self.nodes.len())
            .map(|j| {
                if j == me {
                    return Arc::new(LocalPeer::new(self.nodes[j].clone())) as Arc<dyn PeerApi>;
                }
                Arc::new(Switch {
                    inner: LocalPeer::new(self.nodes[j].clone()).on_behalf_of(self.nodes[me].clone()),
                    down: self.down[j].clone(),
                    fetches: self.fetches[j].clone(),
                    hooks: Arc::new(hooks(j)),
                }) as Arc<dyn PeerApi>
            })
            .collect()
    }

    /// Node `from` calling node `to`'s Peer API, as over the mesh.
    fn as_peer(&self, from: usize, to: usize) -> LocalPeer {
        LocalPeer::new(self.nodes[to].clone()).on_behalf_of(self.nodes[from].clone())
    }

    fn set_down(&self, i: usize, down: bool) {
        self.down[i].store(down, Ordering::SeqCst);
    }

    fn commitment(&self, i: usize, key_id: &str) -> Option<Vec<u8>> {
        let n = &self.nodes[i];
        n.hosted_load(key_id).ok().map(|k| n.hosted_commitment(&k).unwrap())
    }

    fn signer(&self, i: usize) -> SignerSvc {
        SignerSvc {
            node: self.nodes[i].clone(),
            peers: self.view(i),
            allowed_cns: None,
            operator_cns: None,
            hosted_write_quorum: DEFAULT_WRITE_QUORUM,
            decrypt_limiter: Arc::new(DecryptRateLimiter::new(0)),
            ceremony_test_limiter: Arc::new(DecryptRateLimiter::new(0)),
            sign_guard: None,
            refresh_cns: None,
        }
    }
}

fn aes() -> HostedKey {
    HostedKey::generate(HostedSpec::Aes256Gcm, rutli_cosigner::hosted::now_secs()).unwrap()
}

/// `key` wrapped by node `from` for node `to` under `key_id`: what a peer pushes or serves.
fn wrapped(c: &Cluster, from: usize, to: usize, key_id: &str, key: &HostedKey) -> Wrapped {
    let to_id = rutli_cosigner::hosted::identifier_index(c.nodes[to].identifier).unwrap();
    c.nodes[from].hosted_wrap_for(key_id, key, to_id, &c.nodes[to].dist_public_key().unwrap()).unwrap()
}

fn unconfirmed(r: Result<bool>) {
    assert!(matches!(r, Err(DaemonError::HostedUnconfirmed { .. })), "{r:?}");
}

// ── pull: two peers must agree ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn read_repair_stores_a_key_only_when_two_peers_agree() {
    let c = Cluster::new();
    let id = "rutli-sym-two";
    let key = aes();
    // Nobody holds it: NOT_FOUND (Ok(false)), as before.
    assert!(!repair_hosted_key(&c.nodes[1], &c.view(1), id).await.unwrap());

    // One peer holds it: refused, UNAVAILABLE — one peer's word is not enough.
    c.nodes[0].hosted_store(id, &key).unwrap();
    unconfirmed(repair_hosted_key(&c.nodes[1], &c.view(1), id).await);
    assert!(!c.nodes[1].hosted_exists(id));

    // Two peers hold the same copy: stored.
    c.nodes[2].hosted_store(id, &key).unwrap();
    assert!(repair_hosted_key(&c.nodes[1], &c.view(1), id).await.unwrap());
    assert_eq!(c.commitment(1, id), c.commitment(0, id));
}

/// The read-repair variant of the plant: the first peer to answer used to win. A compromised node
/// that serves other material makes the pull refuse, whoever answers first.
#[tokio::test]
async fn a_peer_serving_other_material_makes_read_repair_refuse_not_store() {
    let c = Cluster::new();
    let id = "rutli-sym-plant-pull";
    c.nodes[0].hosted_store(id, &aes()).unwrap(); // honest
    c.nodes[2].hosted_store(id, &aes()).unwrap(); // node 3, compromised, serves its own material
    unconfirmed(repair_hosted_key(&c.nodes[1], &c.view(1), id).await);
    assert!(!c.nodes[1].hosted_exists(id), "neither copy is stored");

    // With the honest holder down, the liar alone is not enough either.
    c.set_down(0, true);
    unconfirmed(repair_hosted_key(&c.nodes[1], &c.view(1), id).await);
    assert!(!c.nodes[1].hosted_exists(id));
}

/// Every read and encrypt path repairs through the same rule: one holder gives UNAVAILABLE with
/// the `hosted-unconfirmed` trailer (the driver fails over), nothing is served or stored; nobody
/// gives NOT_FOUND (KeyInfo: exists = false); two give the key.
#[tokio::test]
async fn every_signer_read_path_serves_only_confirmed_material() {
    let c = Cluster::new();
    let (rsa, sym) = ("rutli-enc-paths", "rutli-sym-paths");
    let rsa_key = HostedKey::generate(HostedSpec::Rsa2048, rutli_cosigner::hosted::now_secs()).unwrap();
    let sym_key = aes();
    c.nodes[0].hosted_store(rsa, &rsa_key).unwrap();
    c.nodes[0].hosted_store(sym, &sym_key).unwrap();
    let svc = c.signer(1);
    let ct = rsa_key.encrypt_oaep(b"m").unwrap();
    let blob = sym_key.encrypt_symmetric(b"m").unwrap();

    let check = |r: std::result::Result<(), tonic::Status>, what: &str| {
        let e = r.expect_err(what);
        assert_eq!(e.code(), Code::Unavailable, "{what}: {e:?}");
        assert_eq!(e.metadata().get("rutli-error").and_then(|v| v.to_str().ok()), Some("hosted-unconfirmed"), "{what}");
    };
    check(svc.public_key(Request::new(pb::PublicKeyRequest { key_id: rsa.into() })).await.map(|_| ()), "PublicKey");
    check(
        svc.key_info(Request::new(pb::KeyInfoRequest { key_id: rsa.into(), ..Default::default() })).await.map(|_| ()),
        "KeyInfo",
    );
    check(
        svc.decrypt(Request::new(pb::DecryptRequest { key_id: rsa.into(), ciphertext: ct.clone() })).await.map(|_| ()),
        "Decrypt",
    );
    check(
        svc.symmetric_encrypt(Request::new(pb::SymmetricRequest { key_id: sym.into(), data: b"x".to_vec() }))
            .await
            .map(|_| ()),
        "SymmetricEncrypt",
    );
    check(
        svc.symmetric_decrypt(Request::new(pb::SymmetricRequest { key_id: sym.into(), data: blob.clone() }))
            .await
            .map(|_| ()),
        "SymmetricDecrypt",
    );
    assert!(!c.nodes[1].hosted_exists(rsa) && !c.nodes[1].hosted_exists(sym), "nothing unconfirmed is stored");

    // A key nobody holds is still NOT_FOUND / exists = false.
    let info = svc
        .key_info(Request::new(pb::KeyInfoRequest { key_id: "rutli-sym-nobody".into(), ..Default::default() }))
        .await
        .unwrap()
        .into_inner();
    assert!(!info.exists);
    let e = svc.public_key(Request::new(pb::PublicKeyRequest { key_id: "rutli-enc-nobody".into() })).await.unwrap_err();
    assert_eq!(e.code(), Code::NotFound);

    // Confirmed by a second holder: served.
    c.nodes[2].hosted_store(rsa, &rsa_key).unwrap();
    c.nodes[2].hosted_store(sym, &sym_key).unwrap();
    let pk = svc.public_key(Request::new(pb::PublicKeyRequest { key_id: rsa.into() })).await.unwrap().into_inner();
    assert_eq!(pk.public_key_der, rsa_key.public_key_der().unwrap());
    let plain = svc.decrypt(Request::new(pb::DecryptRequest { key_id: rsa.into(), ciphertext: ct })).await.unwrap();
    assert_eq!(plain.into_inner().plaintext, b"m");
    let out = svc.symmetric_decrypt(Request::new(pb::SymmetricRequest { key_id: sym.into(), data: blob })).await.unwrap();
    assert_eq!(out.into_inner().data, b"m");
}

/// Times are not committed to: the latest creation time and the latest undelete time among the
/// agreeing peers are stored (an earlier one would let an older delete intent apply), `None` only
/// when no supporter has one; a supporter whose time lies in the future is no vote at all.
#[tokio::test]
async fn a_pull_takes_the_latest_times_and_refuses_future_ones() {
    let c = Cluster::new();
    let now_ms = rutli_cosigner::intent::now_ms();
    let key = aes();

    // Creation times differ: the later one wins, not one a peer set to 0.
    let id = "rutli-sym-times";
    let mut zero = key.clone();
    zero.created_at = 0;
    c.nodes[0].hosted_store(id, &key).unwrap();
    c.nodes[2].hosted_store(id, &zero).unwrap();
    assert!(repair_hosted_key(&c.nodes[1], &c.view(1), id).await.unwrap());
    assert_eq!(c.nodes[1].hosted_load(id).unwrap().created_at, key.created_at);

    // Undelete times on both sides: the later one.
    let id = "rutli-sym-undeleted-both";
    let (mut a, mut b) = (key.clone(), key.clone());
    a.undeleted_at_ms = Some(now_ms - 5_000);
    b.undeleted_at_ms = Some(now_ms - 1_000);
    c.nodes[0].hosted_store(id, &a).unwrap();
    c.nodes[2].hosted_store(id, &b).unwrap();
    assert!(repair_hosted_key(&c.nodes[1], &c.view(1), id).await.unwrap());
    assert_eq!(c.nodes[1].hosted_load(id).unwrap().undeleted_at_ms, Some(now_ms - 1_000));

    // One side without an undelete time does not erase the other's.
    let id = "rutli-sym-undeleted-one";
    c.nodes[0].hosted_store(id, &a).unwrap();
    c.nodes[2].hosted_store(id, &key).unwrap();
    assert!(repair_hosted_key(&c.nodes[1], &c.view(1), id).await.unwrap());
    assert_eq!(c.nodes[1].hosted_load(id).unwrap().undeleted_at_ms, Some(now_ms - 5_000));

    // A copy carrying a creation time an hour ahead is refused at unwrap: unusable, no confirmation.
    let id = "rutli-sym-future";
    let mut future = key.clone();
    future.created_at = rutli_cosigner::hosted::now_secs() + 3600;
    c.nodes[0].hosted_store(id, &key).unwrap();
    c.nodes[2].hosted_store(id, &future).unwrap();
    unconfirmed(repair_hosted_key(&c.nodes[1], &c.view(1), id).await);
    // And an undelete time in the future, likewise.
    let id = "rutli-sym-future-undelete";
    let mut undeleted = key.clone();
    undeleted.undeleted_at_ms = Some(now_ms + 3_600_000);
    c.nodes[0].hosted_store(id, &key).unwrap();
    c.nodes[2].hosted_store(id, &undeleted).unwrap();
    unconfirmed(repair_hosted_key(&c.nodes[1], &c.view(1), id).await);
}

// ── only an answer counts ───────────────────────────────────────────────────────────────────────

/// A read for a key every holder of which is down answers UNAVAILABLE (the driver fails over), not
/// NOT_FOUND. NOT_FOUND needs `n - write_quorum + 1` nodes that answered "not held": with one of
/// three down, a key nobody holds is still NOT_FOUND.
#[tokio::test]
async fn silent_holders_never_make_a_key_not_found() {
    let c = Cluster::new();
    let id = "rutli-sym-silent-holders";
    let key = aes();
    c.nodes[0].hosted_store(id, &key).unwrap();
    c.nodes[2].hosted_store(id, &key).unwrap();
    c.set_down(0, true);
    c.set_down(2, true);
    unconfirmed(repair_hosted_key(&c.nodes[1], &c.view(1), id).await);
    let e = c.signer(1).public_key(Request::new(pb::PublicKeyRequest { key_id: id.into() })).await.unwrap_err();
    assert_eq!(e.code(), Code::Unavailable);
    // One node down, a key nobody holds: two of three answered "not held" — NOT_FOUND.
    c.set_down(2, false);
    assert!(!repair_hosted_key(&c.nodes[1], &c.view(1), "rutli-sym-nobody").await.unwrap());
}

/// Five nodes: two agree, and a third holder with other material is silent. The pull does not
/// confirm (a silent peer blocks it); once that node answers, the copies disagree.
#[tokio::test]
async fn a_silent_peer_blocks_a_pull_confirmation() {
    let c = Cluster::of(5);
    let id = "rutli-sym-five";
    let key = aes();
    c.nodes[0].hosted_store(id, &key).unwrap();
    c.nodes[1].hosted_store(id, &key).unwrap();
    c.nodes[2].hosted_store(id, &aes()).unwrap();
    c.set_down(2, true);
    unconfirmed(repair_hosted_key(&c.nodes[3], &c.view(3), id).await);
    assert!(!c.nodes[3].hosted_exists(id));
    c.set_down(2, false);
    unconfirmed(repair_hosted_key(&c.nodes[3], &c.view(3), id).await);
    assert!(!c.nodes[3].hosted_exists(id));
    // A key nobody holds needs n - q + 1 = 4 "not held" answers here: with two of five down, UNAVAILABLE.
    c.set_down(0, true);
    c.set_down(1, true);
    unconfirmed(repair_hosted_key(&c.nodes[3], &c.view(3), "rutli-sym-five-nobody").await);
    c.set_down(1, false);
    assert!(!repair_hosted_key(&c.nodes[3], &c.view(3), "rutli-sym-five-nobody").await.unwrap());
}

/// A push is refused while another peer answers with a copy the receiver cannot check (here a
/// creation time in the future): an unknown copy is not agreement.
#[tokio::test]
async fn a_push_is_refused_while_a_peer_holds_a_copy_that_cannot_be_checked() {
    let c = Cluster::new();
    let id = "rutli-sym-unverifiable";
    let mut ahead = aes();
    ahead.created_at = rutli_cosigner::hosted::now_secs() + 3600;
    c.nodes[2].hosted_store(id, &ahead).unwrap();
    let leader = c.as_peer(0, 1);
    leader.ceremony_fence("genkey-u", id, "genkey").await.unwrap();
    let e = leader.replicate_key("genkey-u", id, "aes-256-gcm", &[], &wrapped(&c, 0, 1, id, &aes())).await;
    assert!(matches!(e, Err(DaemonError::HostedUnconfirmed { .. })), "{e:?}");
    assert!(!c.nodes[1].hosted_exists(id));
}

/// A roster entry listed twice is one node: one holder listed twice is not two agreeing peers.
#[tokio::test]
async fn a_duplicated_roster_entry_counts_once() {
    let c = Cluster::new();
    let id = "rutli-sym-dup";
    c.nodes[0].hosted_store(id, &aes()).unwrap();
    let mut view = c.view(1);
    view.push(view[0].clone());
    unconfirmed(repair_hosted_key(&c.nodes[1], &view, id).await);
    assert!(!c.nodes[1].hosted_exists(id));
}

/// The read path is bounded: past the node's fan-out ceiling a lookup for an id this node lacks
/// answers UNAVAILABLE without asking the peers — never NOT_FOUND, so it cannot hide a key — and a
/// key this node holds is served throughout.
#[tokio::test]
async fn read_repair_fan_out_is_bounded_and_never_answers_not_found_when_throttled() {
    let c = Cluster::new();
    let held = "rutli-enc-held";
    let k = HostedKey::generate(HostedSpec::Rsa2048, rutli_cosigner::hosted::now_secs()).unwrap();
    c.nodes[1].hosted_store(held, &k).unwrap();
    let svc = c.signer(1);
    let mut throttled = 0;
    for i in 0..200 {
        let r = svc.public_key(Request::new(pb::PublicKeyRequest { key_id: format!("rutli-enc-madeup-{i}") })).await;
        match r.unwrap_err() {
            e if e.code() == Code::Unavailable => throttled += 1,
            e => assert_eq!(e.code(), Code::NotFound, "{e:?}"),
        }
        assert!(svc.public_key(Request::new(pb::PublicKeyRequest { key_id: held.into() })).await.is_ok());
    }
    assert!(throttled > 0, "the ceiling never applied");
    assert!(c.fetches[0].load(Ordering::SeqCst) < 200, "throttled lookups asked no peer");
}

/// One hung peer does not stall the sweep: it goes on with the peers that answered.
#[tokio::test]
async fn a_hung_peer_does_not_stall_the_sweep() {
    let c = Cluster::new();
    let id = "rutli-sym-hung";
    let key = aes();
    c.nodes[0].hosted_store(id, &key).unwrap();
    c.nodes[2].hosted_store(id, &key).unwrap();
    let view = c.view_with(1, |j| Hooks { hang_list: j == 2, ..Hooks::default() });
    let started = std::time::Instant::now();
    assert_eq!(anti_entropy_sweep(&c.nodes[1], &view).await.unwrap(), 1);
    assert!(started.elapsed() < std::time::Duration::from_secs(30), "{:?}", started.elapsed());
    assert!(c.nodes[1].hosted_exists(id));
}

// ── the sweep: pull only ────────────────────────────────────────────────────────────────────────

/// A planted (or pre-upgrade diverged) replica does not spread: no sweep pushes it, and a node
/// that lacks the id refuses to pull while the copies disagree.
#[tokio::test]
async fn a_poisoned_replica_does_not_spread_through_the_sweep() {
    let c = Cluster::new();
    let id = "rutli-sym-poison";
    c.nodes[0].hosted_store(id, &aes()).unwrap();
    c.nodes[2].hosted_store(id, &aes()).unwrap();
    for (i, node) in c.nodes.iter().enumerate() {
        assert_eq!(anti_entropy_sweep(node, &c.view(i)).await.unwrap(), 0, "node {}", i + 1);
    }
    assert!(!c.nodes[1].hosted_exists(id));
    // Each holder keeps what it had: nothing is merged or replaced automatically.
    assert_ne!(c.commitment(0, id), c.commitment(2, id));
    // Node 2 answers UNAVAILABLE for the id, so the driver goes to a node that holds a copy.
    let e = c.signer(1).symmetric_encrypt(Request::new(pb::SymmetricRequest { key_id: id.into(), data: b"x".to_vec() })).await;
    assert_eq!(e.unwrap_err().code(), Code::Unavailable);
}

/// The sweep pulls each missing id once per pass (one FetchKey per peer), not once per peer that
/// lists it.
#[tokio::test]
async fn the_sweep_pulls_each_missing_key_once() {
    let c = Cluster::new();
    let key = aes();
    c.nodes[0].hosted_store("rutli-sym-once", &key).unwrap();
    c.nodes[2].hosted_store("rutli-sym-once", &key).unwrap();
    assert_eq!(anti_entropy_sweep(&c.nodes[1], &c.view(1)).await.unwrap(), 1);
    assert_eq!(c.fetches[0].load(Ordering::SeqCst), 1);
    assert_eq!(c.fetches[2].load(Ordering::SeqCst), 1);
}

// ── push: the generation fence, and no contradicting peer ───────────────────────────────────────

/// The genkey race: an honest leader fences every node, then generates off-runtime; in that window
/// the compromised node pushes its own material for the id to an honest node. Refused: the honest
/// node's fence belongs to the leader. The generation then completes on every node with one key.
#[tokio::test]
async fn a_push_racing_an_honest_generation_is_refused() {
    let c = Cluster::new();
    let (id, cid) = ("rutli-sym-race", "genkey-honest");
    // Node 1 (honest leader) has fenced node 3.
    c.as_peer(0, 2).ceremony_fence(cid, id, "genkey").await.unwrap();
    // Node 2 (compromised) pushes under the leader's ceremony id, and under its own.
    let planted = aes();
    for ceremony in [cid, "genkey-mine"] {
        let e = c.as_peer(1, 2).replicate_key(ceremony, id, "aes-256-gcm", &[], &wrapped(&c, 1, 2, id, &planted)).await;
        assert!(matches!(e, Err(DaemonError::HostedPushRefused(_))), "{e:?}");
    }
    assert!(!c.nodes[2].hosted_exists(id));
    c.as_peer(0, 2).ceremony_release(cid, id).await.unwrap();

    let (_, created, replicas) = generate_hosted_key(&c.nodes[0], &c.view(0), id, HostedSpec::Aes256Gcm, 2).await.unwrap();
    assert!(created);
    assert_eq!(replicas, 3);
    assert_eq!(c.commitment(2, id), c.commitment(0, id));
    assert_eq!(c.commitment(1, id), c.commitment(0, id));
}

/// A peer that takes the generation fence itself (these nodes run without a signing policy, so a
/// genkey fence needs no client intent here) still cannot plant over material another reachable
/// peer holds.
#[tokio::test]
async fn a_peer_that_fences_a_generation_itself_cannot_plant_over_another_copy() {
    let c = Cluster::new();
    let id = "rutli-sym-self-fence";
    c.nodes[0].hosted_store(id, &aes()).unwrap();
    let evil = c.as_peer(1, 2);
    evil.ceremony_fence("genkey-evil", id, "genkey").await.unwrap();
    let e = evil.replicate_key("genkey-evil", id, "aes-256-gcm", &[], &wrapped(&c, 1, 2, id, &aes())).await;
    assert!(matches!(e, Err(DaemonError::HostedConflict { .. })), "{e:?}");
    assert!(!c.nodes[2].hosted_exists(id));
}

/// On nodes that do not require a generate intent (no signing policy here; with one, only
/// `require_ceremony_intent: false`): for an id nobody holds yet, the node that fenced it can create
/// it on an honest node — and when it keeps a copy itself, it is the second agreeing peer, so the
/// material spreads by pull and a later generation adopts it. With the default switch the fence is
/// refused (tests/generate_intent.rs). Documented in docs/security/threat-model.md.
#[tokio::test]
async fn a_fenced_push_into_an_id_nobody_holds_spreads_when_the_attacker_keeps_a_copy() {
    let c = Cluster::new();
    let id = "rutli-sym-unrequested";
    let planted = aes();
    let evil = c.as_peer(1, 2);
    evil.ceremony_fence("genkey-squat", id, "genkey").await.unwrap();
    evil.replicate_key("genkey-squat", id, "aes-256-gcm", &[], &wrapped(&c, 1, 2, id, &planted)).await.unwrap();
    evil.ceremony_release("genkey-squat", id).await.unwrap();
    assert!(c.nodes[2].hosted_exists(id));

    // With the planted copy alone, an honest generation refuses (UNAVAILABLE) rather than adopt it
    // or mint a second key.
    let e = generate_hosted_key(&c.nodes[0], &c.view(0), id, HostedSpec::Aes256Gcm, 2).await;
    assert!(matches!(e, Err(DaemonError::HostedUnconfirmed { .. })), "{e:?}");
    assert!(!c.nodes[0].hosted_exists(id));

    // The attacker keeps the same material itself: two agreeing peers. The honest node pulls it,
    // and a generation adopts it.
    c.nodes[1].hosted_store(id, &planted).unwrap();
    assert!(repair_hosted_key(&c.nodes[0], &c.view(0), id).await.unwrap());
    assert_eq!(c.nodes[0].hosted_load(id).unwrap().private_der, planted.private_der);
    let (got, created, _) = generate_hosted_key(&c.nodes[0], &c.view(0), id, HostedSpec::Aes256Gcm, 2).await.unwrap();
    assert!(!created);
    assert_eq!(got.private_der, planted.private_der);
}

/// A rollback purge removes only what its own generation created: a key that was there before is
/// refused under the generation's fence, and a fenced node that holds nothing answers "nothing".
#[tokio::test]
async fn a_rollback_purge_never_removes_a_key_that_was_there_before() {
    let c = Cluster::new();
    let id = "rutli-sym-preexisting";
    c.nodes[1].hosted_store(id, &aes()).unwrap();
    let leader = c.as_peer(0, 1);
    leader.ceremony_fence("genkey-p", id, "genkey").await.unwrap();
    assert!(leader.purge_key("genkey-p", id).await.is_err());
    assert!(c.nodes[1].hosted_exists(id));
    let empty = c.as_peer(0, 2);
    empty.ceremony_fence("genkey-p", id, "genkey").await.unwrap();
    assert!(!empty.purge_key("genkey-p", id).await.unwrap());
}

/// The leader writes a new key to its own disk only after the write quorum holds it, so a leader
/// that dies before its first replica leaves no copy anywhere (row 1 of the table in
/// docs/hosted-keys.md, "A leader that dies mid-generation").
#[tokio::test]
async fn the_leader_writes_a_new_key_only_after_the_quorum_holds_it() {
    let c = Cluster::new();
    let id = "rutli-sym-late-write";
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let (leader_node, s2) = (c.nodes[0].clone(), seen.clone());
    let view = c.view_with(0, move |_| {
        let (n, s) = (leader_node.clone(), s2.clone());
        Hooks {
            before_replicate: Some(Box::new(move || s.lock().unwrap().push(n.hosted_exists("rutli-sym-late-write")))),
            ..Hooks::default()
        }
    });
    generate_hosted_key(&c.nodes[0], &view, id, HostedSpec::Aes256Gcm, 2).await.unwrap();
    assert_eq!(*seen.lock().unwrap(), vec![false, false], "no leader copy while replicas are pushed");
    assert!(c.nodes[0].hosted_exists(id));

    // Row 1: every push fails (the leader "dies" before any replica lands). Nothing is on any disk,
    // and a retry mints cleanly.
    let id = "rutli-sym-no-replica";
    let failing = c.view_with(0, |_| Hooks { on_replicate: Some(Box::new(|| Err(down()))), ..Hooks::default() });
    assert!(generate_hosted_key(&c.nodes[0], &failing, id, HostedSpec::Aes256Gcm, 2).await.is_err());
    for (i, node) in c.nodes.iter().enumerate() {
        assert!(!node.hosted_exists(id), "node {}", i + 1);
    }
    let (_, created, replicas) = generate_hosted_key(&c.nodes[2], &c.view(2), id, HostedSpec::Aes256Gcm, 2).await.unwrap();
    assert!(created);
    assert_eq!(replicas, 3);
}

/// A rollback that cannot reach a node leaves that node's copy (an open case, see
/// docs/hosted-keys.md); it is logged and counted, never silent.
#[tokio::test]
async fn an_unreachable_node_keeps_its_copy_after_a_rollback() {
    let c = Cluster::new();
    let id = "rutli-sym-left-behind";
    let down2 = c.down[1].clone();
    let view = c.view_with(0, move |j| {
        if j != 2 {
            return Hooks::default();
        }
        let d = down2.clone();
        Hooks {
            on_replicate: Some(Box::new(move || {
                d.store(true, Ordering::SeqCst); // node 2 drops off after taking its replica
                Err(DaemonError::HostedConflict { key_id: "rutli-sym-left-behind".into(), detail: "x".into() })
            })),
            ..Hooks::default()
        }
    });
    assert!(matches!(
        generate_hosted_key(&c.nodes[0], &view, id, HostedSpec::Aes256Gcm, 2).await,
        Err(DaemonError::HostedConflict { .. })
    ));
    assert!(!c.nodes[0].hosted_exists(id));
    assert!(c.nodes[1].hosted_exists(id), "the purge did not reach node 2");
}

/// Mixed versions, emulated with the calls a 0.4.0 node makes (its RPCs are unchanged): a 0.4.0
/// leader fences and pushes under its ceremony id, which a new node accepts; a 0.4.0 sweep push is
/// refused; a 0.4.0 node that lacks a key pulls it from one new peer with the old `FetchKey`.
#[tokio::test]
async fn mixed_version_sequences() {
    let c = Cluster::new();
    // Node 1 plays a 0.4.0 leader: its own copy first, then fence and push to the new nodes.
    let id = "rutli-sym-old-leader";
    let key = aes();
    c.nodes[0].hosted_store(id, &key).unwrap();
    for j in [1, 2] {
        let to = c.as_peer(0, j);
        to.ceremony_fence("genkey-old", id, "genkey").await.unwrap();
        to.replicate_key("genkey-old", id, "aes-256-gcm", &[], &wrapped(&c, 0, j, id, &key)).await.unwrap();
        to.ceremony_release("genkey-old", id).await.unwrap();
    }
    assert_eq!(c.commitment(2, id), c.commitment(0, id));

    // Its sweep pushes a key node 3 lacks: refused; node 3 pulls it once two nodes hold it.
    let id = "rutli-sym-old-sweep";
    c.nodes[0].hosted_store(id, &key).unwrap();
    let e = c.as_peer(0, 2).replicate_key("repair-1", id, "aes-256-gcm", &[], &wrapped(&c, 0, 2, id, &key)).await;
    assert!(matches!(e, Err(DaemonError::HostedPushRefused(_))), "{e:?}");
    c.nodes[1].hosted_store(id, &key).unwrap();
    assert_eq!(anti_entropy_sweep(&c.nodes[2], &c.view(2)).await.unwrap(), 1);

    // A 0.4.0 node that lacks a key takes it from the first peer that serves it (old FetchKey).
    let id = "rutli-sym-old-pull";
    c.nodes[1].hosted_store(id, &key).unwrap();
    let (spec, _, w) = c.as_peer(0, 1).fetch_key(id).await.unwrap();
    let pulled = c.nodes[0].hosted_unwrap(id, HostedSpec::parse(&spec).unwrap(), &w).unwrap();
    c.nodes[0].hosted_store(id, &pulled).unwrap();
    assert_eq!(c.commitment(0, id), c.commitment(1, id));
}

/// The refusals are counted under their reasons, and a rollback that missed a node is counted.
#[tokio::test]
async fn refusals_and_incomplete_rollbacks_are_counted() {
    let handle = metrics_exporter_prometheus::PrometheusBuilder::new().install_recorder().expect("one recorder per test binary");
    let c = Cluster::new();
    let id = "rutli-sym-counted";
    let _ = c.as_peer(0, 1).replicate_key("repair-x", id, "aes-256-gcm", &[], &wrapped(&c, 0, 1, id, &aes())).await;
    let down2 = c.down[1].clone();
    let view = c.view_with(0, move |j| {
        if j != 2 {
            return Hooks::default();
        }
        let d = down2.clone();
        Hooks {
            on_replicate: Some(Box::new(move || {
                d.store(true, Ordering::SeqCst);
                Err(DaemonError::HostedConflict { key_id: "rutli-sym-counted-2".into(), detail: "x".into() })
            })),
            ..Hooks::default()
        }
    });
    let _ = generate_hosted_key(&c.nodes[0], &view, "rutli-sym-counted-2", HostedSpec::Aes256Gcm, 2).await;
    let out = handle.render();
    let value = |prefix: &str| -> f64 {
        out.lines().find_map(|l| l.strip_prefix(prefix)).and_then(|v| v.trim().parse().ok()).unwrap_or(0.0)
    };
    assert!(value(r#"rutli_hosted_replication_refusals_total{reason="unfenced"} "#) >= 1.0, "{out}");
    assert!(value(r#"rutli_hosted_replication_refusals_total{reason="generate-conflict"} "#) >= 1.0, "{out}");
    assert!(value("rutli_hosted_rollback_incomplete_total ") >= 1.0, "{out}");
}

/// A 0.4.0 node's anti-entropy push (a fresh "repair-…" ceremony id, no fence) is refused; an
/// identical copy is still an idempotent no-op; different material over a held id is a conflict.
#[tokio::test]
async fn unfenced_identical_and_conflicting_pushes() {
    let c = Cluster::new();
    let id = "rutli-sym-push";
    let key = aes();
    let e = c.as_peer(0, 1).replicate_key("repair-0d6b9a3e", id, "aes-256-gcm", &[], &wrapped(&c, 0, 1, id, &key)).await;
    assert!(matches!(e, Err(DaemonError::HostedPushRefused(_))), "{e:?}");
    assert_eq!(tonic::Status::from(e.unwrap_err()).code(), Code::FailedPrecondition);

    c.nodes[1].hosted_store(id, &key).unwrap();
    let same = c.as_peer(0, 1).replicate_key("repair-1", id, "aes-256-gcm", &[], &wrapped(&c, 0, 1, id, &key)).await.unwrap();
    assert_eq!(Some(same), c.commitment(1, id));

    let e = c.as_peer(0, 1).replicate_key("repair-2", id, "aes-256-gcm", &[], &wrapped(&c, 0, 1, id, &aes())).await;
    let e = e.unwrap_err();
    assert!(matches!(e, DaemonError::HostedConflict { .. }), "{e:?}");
    let s = tonic::Status::from(e);
    assert_eq!(s.code(), Code::Aborted);
    assert_eq!(s.metadata().get("rutli-error").and_then(|v| v.to_str().ok()), Some("hosted-conflict"));
}

/// Timestamps in the future are refused on a push too (they would make the key refuse every
/// delete until then), and an RSA key whose public half is another key's is refused at validate.
#[tokio::test]
async fn a_push_with_a_future_time_or_a_mismatched_rsa_key_is_refused() {
    let c = Cluster::new();
    let leader = c.as_peer(0, 1);
    let id = "rutli-sym-future-push";
    let mut key = aes();
    key.created_at = u64::MAX / 2000;
    leader.ceremony_fence("genkey-f", id, "genkey").await.unwrap();
    let e = leader.replicate_key("genkey-f", id, "aes-256-gcm", &[], &wrapped(&c, 0, 1, id, &key)).await.unwrap_err();
    assert!(matches!(e, DaemonError::HostedInvalid(_)), "{e:?}");
    assert_eq!(tonic::Status::from(e).code(), Code::InvalidArgument);
    let mut key = aes();
    key.undeleted_at_ms = Some(rutli_cosigner::intent::now_ms() + 3_600_000);
    assert!(matches!(
        leader.replicate_key("genkey-f", id, "aes-256-gcm", &[], &wrapped(&c, 0, 1, id, &key)).await,
        Err(DaemonError::HostedInvalid(_))
    ));
    assert!(!c.nodes[1].hosted_exists(id));

    let id = "rutli-enc-mismatched";
    let a = HostedKey::generate(HostedSpec::Rsa2048, rutli_cosigner::hosted::now_secs()).unwrap();
    let b = HostedKey::generate(HostedSpec::Rsa2048, rutli_cosigner::hosted::now_secs()).unwrap();
    let mut mixed = a.clone();
    mixed.public_der = b.public_der.clone();
    assert!(mixed.validate().is_err());
    assert!(a.validate().is_ok());
    leader.ceremony_fence("genkey-r", id, "genkey").await.unwrap();
    let e = leader.replicate_key("genkey-r", id, "rsa-2048-oaep-sha256", &[], &wrapped(&c, 0, 1, id, &mixed)).await;
    assert!(e.is_err(), "{e:?}");
    assert!(!c.nodes[1].hosted_exists(id));
}

// ── the leader: a conflict aborts ───────────────────────────────────────────────────────────────

/// The quorum is met by the leader and node 2, and node 3 holds other material (planted right
/// after the leader looked): the generation is aborted and rolled back on every node that took the
/// key in it, instead of being reported created with two replicas. Two shapes: node 3 refuses the
/// leader's push itself, after node 2 stored the key; or node 2 refuses because it sees node 3's
/// copy.
#[tokio::test]
async fn a_conflict_aborts_the_generation_even_with_the_quorum_met() {
    // Node 3 refuses the push (its copy landed after the leader's look).
    let c = Cluster::new();
    let id = "rutli-sym-abort";
    let (node3, planted) = (c.nodes[2].clone(), aes());
    let view = c.view_with(0, move |j| {
        if j != 2 {
            return Hooks::default();
        }
        let (node3, p) = (node3.clone(), planted.clone());
        Hooks {
            on_replicate: Some(Box::new(move || {
                node3.hosted_store("rutli-sym-abort", &p).unwrap();
                Err(DaemonError::HostedConflict {
                    key_id: "rutli-sym-abort".into(),
                    detail: "it already exists here with different material".into(),
                })
            })),
            ..Hooks::default()
        }
    });
    let e = generate_hosted_key(&c.nodes[0], &view, id, HostedSpec::Aes256Gcm, 2).await.unwrap_err();
    assert!(matches!(e, DaemonError::HostedConflict { .. }), "{e:?}");
    assert_eq!(tonic::Status::from(e).code(), Code::Aborted);
    assert!(!c.nodes[0].hosted_exists(id), "the leader's copy is rolled back");
    assert!(!c.nodes[1].hosted_exists(id), "node 2's copy from this generation is rolled back");
    assert!(c.nodes[2].hosted_exists(id), "a copy the generation did not create stays");

    // Node 2 refuses: it asks node 3 before it stores, and node 3 holds other material.
    let c = Cluster::new();
    let id = "rutli-sym-abort-2";
    let (node3, planted) = (c.nodes[2].clone(), aes());
    let view = c.view_with(0, move |j| {
        if j != 2 {
            return Hooks::default();
        }
        let (node3, p) = (node3.clone(), planted.clone());
        Hooks {
            on_fetch: Some(Box::new(move || {
                let _ = node3.hosted_store("rutli-sym-abort-2", &p);
                Some(DaemonError::UnknownKey("rutli-sym-abort-2".into()))
            })),
            ..Hooks::default()
        }
    });
    let e = generate_hosted_key(&c.nodes[0], &view, id, HostedSpec::Aes256Gcm, 2).await.unwrap_err();
    assert!(matches!(e, DaemonError::HostedConflict { .. }), "{e:?}");
    assert!(!c.nodes[0].hosted_exists(id) && !c.nodes[1].hosted_exists(id));
}

/// A 0.4.0 replica's create-once refusal (ALREADY_EXISTS, "different material") and a replica that
/// acknowledges with a commitment to other material both abort the generation.
#[tokio::test]
async fn a_04_conflict_text_and_a_lying_ack_both_abort() {
    let cases: Vec<Box<dyn Fn() -> Result<Vec<u8>> + Send + Sync>> = vec![
        Box::new(|| {
            Err(DaemonError::Status(tonic::Status::already_exists(
                "key rutli-sym-x already exists here with different material — refusing to overwrite already exists — refusing DKG (it would overwrite/destroy the existing key)",
            )))
        }),
        Box::new(|| Ok(vec![0u8; 32])),
    ];
    for (n, case) in cases.into_iter().enumerate() {
        let c = Cluster::new();
        let id = format!("rutli-sym-old-{n}");
        let case = Arc::new(case);
        let view = c.view_with(0, |j| {
            if j != 2 {
                return Hooks::default();
            }
            let case = case.clone();
            Hooks { on_replicate: Some(Box::new(move || (*case)())), ..Hooks::default() }
        });
        let e = generate_hosted_key(&c.nodes[0], &view, &id, HostedSpec::Aes256Gcm, 2).await;
        assert!(matches!(e, Err(DaemonError::HostedConflict { .. })), "case {n}: {e:?}");
        assert!(!c.nodes[0].hosted_exists(&id) && !c.nodes[1].hosted_exists(&id), "case {n}: rolled back");
    }
}

/// A leader that died after replicating to one peer left two copies. A retry through another
/// leader with only one copy reachable refuses (UNAVAILABLE: the driver fails over) rather than
/// mint a second key; with both reachable it adopts the existing key. No fork either way.
#[tokio::test]
async fn a_retry_after_a_leader_died_mid_generation_adopts_or_refuses_never_forks() {
    let c = Cluster::new();
    let (id, cid) = ("rutli-sym-dead-leader", "genkey-dead");
    let key = aes();
    // Node 1 stored the key and pushed it to node 2 under its fence, then died.
    c.nodes[0].hosted_store(id, &key).unwrap();
    let dead = c.as_peer(0, 1);
    dead.ceremony_fence(cid, id, "genkey").await.unwrap();
    dead.replicate_key(cid, id, "aes-256-gcm", &[], &wrapped(&c, 0, 1, id, &key)).await.unwrap();
    // Its fence on node 2 lapses (the orphan timeout); modelled by the release.
    dead.ceremony_release(cid, id).await.unwrap();
    c.set_down(0, true);

    // Retry on node 3 with node 1 down: one copy reachable — refused, nothing minted.
    let e = generate_hosted_key(&c.nodes[2], &c.view(2), id, HostedSpec::Aes256Gcm, 2).await;
    assert!(matches!(e, Err(DaemonError::HostedUnconfirmed { .. })), "{e:?}");
    assert!(!c.nodes[2].hosted_exists(id));
    // The driver fails over to node 2, which holds it: the existing key, replicated to node 3.
    let (got, created, replicas) = generate_hosted_key(&c.nodes[1], &c.view(1), id, HostedSpec::Aes256Gcm, 2).await.unwrap();
    assert!(!created);
    assert_eq!(replicas, 2);
    assert_eq!(got.private_der, key.private_der);
    assert_eq!(c.commitment(2, id), c.commitment(1, id));

    // Node 1 is back; another retry on a node that lacked it would adopt, never mint.
    c.set_down(0, false);
    let id2 = "rutli-sym-dead-leader-2";
    let key2 = aes();
    c.nodes[0].hosted_store(id2, &key2).unwrap();
    c.nodes[1].hosted_store(id2, &key2).unwrap();
    let (got, created, replicas) = generate_hosted_key(&c.nodes[2], &c.view(2), id2, HostedSpec::Aes256Gcm, 2).await.unwrap();
    assert!(!created);
    assert_eq!(replicas, 3);
    assert_eq!(got.private_der, key2.private_der);
}

// ── the degraded 2-of-3 cluster ─────────────────────────────────────────────────────────────────

/// One node down is a normal state. Walked through with node 3 down, then node 1:
/// - GenerateKey on node 1 commits at the write quorum (nodes 1, 2);
/// - node 3 back, node 1 down: node 3's read-repair and sweep see one copy (node 2) — refused,
///   UNAVAILABLE, nothing stored; node 2 keeps serving the key it holds;
/// - node 1 back: node 3's sweep pulls the key (two agree) and the cluster has converged.
#[tokio::test]
async fn a_degraded_cluster_keeps_serving_and_heals_when_the_node_returns() {
    let c = Cluster::new();
    let id = "rutli-sym-degraded";
    c.set_down(2, true);
    let (key, created, replicas) = generate_hosted_key(&c.nodes[0], &c.view(0), id, HostedSpec::Aes256Gcm, 2).await.unwrap();
    assert!(created);
    assert_eq!(replicas, 2);
    let blob = key.encrypt_symmetric(b"degraded").unwrap();

    // Node 3 returns while node 1 goes down.
    c.set_down(2, false);
    c.set_down(0, true);
    unconfirmed(repair_hosted_key(&c.nodes[2], &c.view(2), id).await);
    assert_eq!(anti_entropy_sweep(&c.nodes[2], &c.view(2)).await.unwrap(), 0);
    assert!(!c.nodes[2].hosted_exists(id));
    let e = c.signer(2).symmetric_decrypt(Request::new(pb::SymmetricRequest { key_id: id.into(), data: blob.clone() })).await;
    assert_eq!(e.unwrap_err().code(), Code::Unavailable, "the driver fails over to node 2");
    // Node 2 never loses or stops serving what it holds, and its sweep changes nothing.
    assert_eq!(anti_entropy_sweep(&c.nodes[1], &c.view(1)).await.unwrap(), 0);
    let out = c.signer(1).symmetric_decrypt(Request::new(pb::SymmetricRequest { key_id: id.into(), data: blob.clone() })).await;
    assert_eq!(out.unwrap().into_inner().data, b"degraded");

    // A generation of a new key with only node 2 reachable from node 3 still commits (2 of 3).
    let (_, created, replicas) =
        generate_hosted_key(&c.nodes[2], &c.view(2), "rutli-sym-degraded-2", HostedSpec::Aes256Gcm, 2).await.unwrap();
    assert!(created);
    assert_eq!(replicas, 2);

    // Node 1 back: node 3 pulls the first key, node 1 the second; converged.
    c.set_down(0, false);
    assert_eq!(anti_entropy_sweep(&c.nodes[2], &c.view(2)).await.unwrap(), 1);
    assert_eq!(anti_entropy_sweep(&c.nodes[0], &c.view(0)).await.unwrap(), 1);
    for (i, node) in c.nodes.iter().enumerate() {
        assert_eq!(anti_entropy_sweep(node, &c.view(i)).await.unwrap(), 0);
        assert_eq!(c.commitment(i, id), c.commitment(1, id));
        assert_eq!(c.commitment(i, "rutli-sym-degraded-2"), c.commitment(1, "rutli-sym-degraded-2"));
    }
    let out = c.signer(2).symmetric_decrypt(Request::new(pb::SymmetricRequest { key_id: id.into(), data: blob })).await;
    assert_eq!(out.unwrap().into_inner().data, b"degraded");
}

/// A push from the generation's leader while the receiver cannot reach the third node is
/// accepted: an unreachable peer is not a contradiction (otherwise one node down would stop every
/// generation).
#[tokio::test]
async fn a_fenced_push_is_accepted_with_the_third_node_unreachable() {
    let c = Cluster::new();
    c.nodes[2].hosted_store("rutli-sym-elsewhere", &aes()).unwrap(); // node 3 holds other material...
    c.set_down(2, true); // ...and is down
    let leader = c.as_peer(0, 1);
    let key = aes();
    leader.ceremony_fence("genkey-d", "rutli-sym-elsewhere", "genkey").await.unwrap();
    leader
        .replicate_key("genkey-d", "rutli-sym-elsewhere", "aes-256-gcm", &[], &wrapped(&c, 0, 1, "rutli-sym-elsewhere", &key))
        .await
        .unwrap();
    // When node 3 returns, the sweeps report the conflict and change nothing.
    c.set_down(2, false);
    anti_entropy_sweep(&c.nodes[1], &c.view(1)).await.unwrap();
    assert_ne!(c.commitment(1, "rutli-sym-elsewhere"), c.commitment(2, "rutli-sym-elsewhere"));
}

// ── what the driver will compare after a generation ─────────────────────────────────────────────

/// GenerateKey answers with the leader's commitment; KeyInfo with local_only reports a node's own
/// copy — commitment and derived public key, no read-repair, no replica count.
#[tokio::test]
async fn generate_reports_the_commitment_and_key_info_local_only_does_not_repair() {
    let c = Cluster::new();
    let svc = c.signer(0);
    let reply = svc
        .generate_key(Request::new(pb::GenerateKeyRequest { key_id: "rutli-enc-cmp".into(), spec: "rsa-2048-oaep-sha256".into(), intent: None }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(Some(reply.commitment.clone()), c.commitment(0, "rutli-enc-cmp"));
    for i in (0..c.nodes.len()).rev() {
        let info = c
            .signer(i)
            .key_info(Request::new(pb::KeyInfoRequest { key_id: "rutli-enc-cmp".into(), local_only: true }))
            .await
            .unwrap()
            .into_inner();
        assert!(info.exists);
        assert_eq!(info.commitment, reply.commitment, "node {}", i + 1);
        assert_eq!(info.public_key_der, reply.public_key_der, "node {}", i + 1);
        assert_eq!(info.replicas, 0);
    }

    // A node that lacks a key two peers hold: local_only says so and does not pull it.
    let key = aes();
    c.nodes[0].hosted_store("rutli-sym-cmp", &key).unwrap();
    c.nodes[2].hosted_store("rutli-sym-cmp", &key).unwrap();
    let svc1 = c.signer(1);
    let local = svc1
        .key_info(Request::new(pb::KeyInfoRequest { key_id: "rutli-sym-cmp".into(), local_only: true }))
        .await
        .unwrap()
        .into_inner();
    assert!(!local.exists);
    assert!(!c.nodes[1].hosted_exists("rutli-sym-cmp"));
    let repaired = svc1
        .key_info(Request::new(pb::KeyInfoRequest { key_id: "rutli-sym-cmp".into(), local_only: false }))
        .await
        .unwrap()
        .into_inner();
    assert!(repaired.exists);
    assert!(repaired.public_key_der.is_empty(), "a symmetric key has no public half");
    assert_eq!(Some(repaired.commitment), c.commitment(0, "rutli-sym-cmp"));
}

/// A key held here with a creation time in the future (written before this release) is reported.
#[tokio::test]
async fn a_held_key_with_a_future_time_is_reported() {
    let c = Cluster::new();
    let mut key = aes();
    key.created_at = rutli_cosigner::hosted::now_secs() + 3600;
    c.nodes[0].hosted_store("rutli-sym-ahead", &key).unwrap();
    c.nodes[0].hosted_store("rutli-sym-fine", &aes()).unwrap();
    let found = c.nodes[0].hosted_future_timestamps().unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].0, "rutli-sym-ahead");
}

// ── second review round ─────────────────────────────────────────────────────────────────────────

/// A completed generation cannot be purged by fencing its ceremony id again: a rollback purge only
/// undoes a write made under the same fence instance. Covers a release that arrived, and one that
/// never did (the guard lapsed and was preempted, then the attacker fences the old ceremony id).
#[tokio::test]
async fn a_completed_generation_cannot_be_purged_by_re_fencing_its_ceremony_id() {
    let c = Cluster::build(3, std::time::Duration::ZERO, |_, _, _| Hooks::default());
    let key = aes();
    for (id, released) in [("rutli-sym-refence-a", true), ("rutli-sym-refence-b", false)] {
        let cid = format!("genkey-{id}");
        let leader = c.as_peer(0, 2);
        leader.ceremony_fence(&cid, id, "genkey").await.unwrap();
        leader.replicate_key(&cid, id, "aes-256-gcm", &[], &wrapped(&c, 0, 2, id, &key)).await.unwrap();
        if released {
            leader.ceremony_release(&cid, id).await.unwrap();
        } else {
            // The release never arrives; another generation preempts the lapsed guard and ends.
            let other = c.as_peer(0, 2);
            other.ceremony_fence("genkey-other", id, "genkey").await.unwrap();
            other.ceremony_release("genkey-other", id).await.unwrap();
        }
        let evil = c.as_peer(1, 2);
        evil.ceremony_fence(&cid, id, "genkey").await.unwrap();
        assert!(evil.purge_key(&cid, id).await.is_err(), "{id}");
        assert!(c.nodes[2].hosted_exists(id), "{id}: the key stays");
    }
}

/// Five nodes, write quorum 2: a key acknowledged on nodes 1 and 2; with both down, a retry on
/// node 3 sees two silent holders and refuses (UNAVAILABLE) instead of minting a second key. With
/// one node of five down, a new key still mints (four "not held" answers).
#[tokio::test]
async fn a_mint_needs_enough_not_held_answers() {
    let c = Cluster::of(5);
    let id = "rutli-sym-five-mint";
    let key = aes();
    c.nodes[0].hosted_store(id, &key).unwrap();
    c.nodes[1].hosted_store(id, &key).unwrap();
    c.set_down(0, true);
    c.set_down(1, true);
    let e = generate_hosted_key(&c.nodes[2], &c.view(2), id, HostedSpec::Aes256Gcm, 2).await;
    assert!(matches!(e, Err(DaemonError::HostedUnconfirmed { .. })), "{e:?}");
    for (i, node) in c.nodes.iter().enumerate().skip(2) {
        assert!(!node.hosted_exists(id), "node {}", i + 1);
    }
    c.set_down(1, false);
    let (_, created, _) =
        generate_hosted_key(&c.nodes[2], &c.view(2), "rutli-sym-five-new", HostedSpec::Aes256Gcm, 2).await.unwrap();
    assert!(created);
}

/// An unusable answer blocks NOT_FOUND even when enough peers said "not held".
#[tokio::test]
async fn an_unusable_answer_blocks_not_found() {
    let c = Cluster::new();
    let id = "rutli-sym-unusable-absent";
    let mut ahead = aes();
    ahead.created_at = rutli_cosigner::hosted::now_secs() + 3600;
    c.nodes[0].hosted_store(id, &ahead).unwrap();
    unconfirmed(repair_hosted_key(&c.nodes[1], &c.view(1), id).await);
}

/// EcdhDerive serves only confirmed material, like every other read path.
#[tokio::test]
async fn ecdh_derive_serves_only_confirmed_material() {
    let c = Cluster::new();
    let id = "rutli-enc-ecdh-paths";
    let key = HostedKey::generate(HostedSpec::EcP256, rutli_cosigner::hosted::now_secs()).unwrap();
    let other = HostedKey::generate(HostedSpec::EcP256, rutli_cosigner::hosted::now_secs()).unwrap();
    let spki = other.public_key_der().unwrap();
    let point = spki[spki.len() - 65..].to_vec();
    c.nodes[0].hosted_store(id, &key).unwrap();
    let svc = c.signer(1);
    let ask = || svc.ecdh_derive(Request::new(pb::EcdhDeriveRequest { key_id: id.into(), peer_point: point.clone() }));
    assert_eq!(ask().await.unwrap_err().code(), Code::Unavailable);
    assert!(!c.nodes[1].hosted_exists(id));
    c.nodes[2].hosted_store(id, &key).unwrap();
    let z = ask().await.unwrap().into_inner().shared_secret;
    assert_eq!(z, key.ecdh_p256(&point).unwrap().to_vec());
}

/// One sweep pulls a bounded number of missing ids: a peer listing hundreds of made-up ids costs a
/// bounded number of fan-outs, and a real key two peers list is pulled first.
#[tokio::test]
async fn the_sweep_bounds_its_pulls_and_pulls_real_keys_first() {
    let c = Cluster::new();
    let id = "rutli-sym-zzz-real";
    let key = aes();
    c.nodes[0].hosted_store(id, &key).unwrap();
    c.nodes[2].hosted_store(id, &key).unwrap();
    let made_up: Vec<String> = (0..300).map(|i| format!("rutli-sym-aaa-{i:03}")).collect();
    let view = c.view_with(1, |j| Hooks { extra_inventory: if j == 0 { made_up.clone() } else { Vec::new() }, ..Hooks::default() });
    assert_eq!(anti_entropy_sweep(&c.nodes[1], &view).await.unwrap(), 1);
    assert!(c.nodes[1].hosted_exists(id));
    let asked = c.fetches[2].load(Ordering::SeqCst);
    assert!(asked <= 1 + rutli_cosigner::orchestrator::SWEEP_MAX_PULLS_PER_PEER, "{asked} fan-outs");
}

/// A rollback that arrives while a push of the same generation is still checking its peers ends
/// the fence there: the push does not store (no orphan the rollback missed).
#[tokio::test]
async fn a_rollback_during_a_pushs_peer_check_leaves_no_orphan() {
    let (id, cid) = ("rutli-sym-race-purge", "genkey-race-purge");
    let c = Cluster::build(3, CEREMONY_ORPHAN_DEFAULT, move |nodes, me, j| {
        if me != 1 || j != 2 {
            return Hooks::default();
        }
        // Node 2 asks node 3 during its check: meanwhile the leader's rollback reaches node 2.
        let n2 = nodes[1].clone();
        Hooks {
            on_fetch: Some(Box::new(move || {
                assert!(!n2.hosted_rollback_purge_from(cid, id, Some("cosigner1")).unwrap());
                None
            })),
            ..Hooks::default()
        }
    });
    let leader = c.as_peer(0, 1);
    leader.ceremony_fence(cid, id, "genkey").await.unwrap();
    let e = leader.replicate_key(cid, id, "aes-256-gcm", &[], &wrapped(&c, 0, 1, id, &aes())).await;
    assert!(matches!(e, Err(DaemonError::HostedPushRefused(_))), "{e:?}");
    assert!(!c.nodes[1].hosted_exists(id));
}

/// A live key that arrives at the receiver between its peer check and its store is compared, never
/// overwritten: different material is a conflict.
#[tokio::test]
async fn a_key_arriving_during_a_pushs_peer_check_is_not_overwritten() {
    let (id, cid) = ("rutli-sym-race-live", "genkey-race-live");
    let arrived = aes();
    let a2 = arrived.clone();
    let c = Cluster::build(3, CEREMONY_ORPHAN_DEFAULT, move |nodes, me, j| {
        if me != 1 || j != 2 {
            return Hooks::default();
        }
        let (n2, k) = (nodes[1].clone(), a2.clone());
        Hooks {
            on_fetch: Some(Box::new(move || {
                let _ = n2.hosted_store(id, &k);
                None
            })),
            ..Hooks::default()
        }
    });
    let leader = c.as_peer(0, 1);
    leader.ceremony_fence(cid, id, "genkey").await.unwrap();
    let e = leader.replicate_key(cid, id, "aes-256-gcm", &[], &wrapped(&c, 0, 1, id, &aes())).await;
    assert!(matches!(e, Err(DaemonError::HostedConflict { .. })), "{e:?}");
    assert_eq!(c.nodes[1].hosted_load(id).unwrap().private_der, arrived.private_der);
}


/// Five nodes, four peers each listing a hundred made-up ids: the total bound is hit, and the real
/// key two peers list (sorting last by name) is still pulled, because ids more peers list go first.
#[tokio::test]
async fn the_sweep_pulls_a_key_two_peers_list_before_made_up_ids() {
    let c = Cluster::of(5);
    let id = "rutli-sym-zzz-real-five";
    let key = aes();
    for i in [0, 2, 3, 4] {
        c.nodes[i].hosted_store(id, &key).unwrap();
    }
    let view = c.view_with(1, |j| Hooks {
        extra_inventory: (0..100).map(|i| format!("rutli-sym-aaa-{j}-{i:03}")).collect(),
        ..Hooks::default()
    });
    assert_eq!(anti_entropy_sweep(&c.nodes[1], &view).await.unwrap(), 1);
    assert!(c.nodes[1].hosted_exists(id));
}

/// A peer that fences and pushes made-up ids in a loop is held to the node's fan-out ceiling: past
/// it the push answers "try again" (UNAVAILABLE), never a conflict.
#[tokio::test]
async fn fenced_pushes_are_held_to_the_fan_out_ceiling() {
    let c = Cluster::new();
    let evil = c.as_peer(2, 1);
    let mut throttled = 0;
    for i in 0..200 {
        let id = format!("rutli-sym-flood-{i:03}");
        let cid = format!("genkey-flood-{i:03}");
        evil.ceremony_fence(&cid, &id, "genkey").await.unwrap();
        match evil.replicate_key(&cid, &id, "aes-256-gcm", &[], &wrapped(&c, 2, 1, &id, &aes())).await {
            Ok(_) => {}
            Err(DaemonError::HostedUnconfirmed { .. }) => throttled += 1,
            Err(e) => panic!("{e:?}"),
        }
    }
    assert!(throttled > 0, "the ceiling never applied");
}
