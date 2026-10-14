// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! The split ceremony across a 3-node in-process cluster (LocalPeer), on B1's real Canton 3.6.1
//! namespace export: share-recipient → dealer → import-share on every node → the cluster signs
//! under the original Canton key → refresh → signs again; plus the failure shapes the runbook
//! promises (DKG refused for the imported id, a node down, a half-finished install).

// DaemonError is large by value (see the crate root); the test helpers return it like the crate does.
#![allow(clippy::result_large_err)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use frost_ed25519::keys::dkg::{round1, round2};
use frost_ed25519::round1::SigningCommitments;
use frost_ed25519::round2::SignatureShare;
use frost_ed25519::Identifier;

use rutli_cosigner::keystore::KeyStore;
use rutli_cosigner::node::Node;
use rutli_cosigner::orchestrator::{ceremony_sign_test, run_dkg, run_refresh, sign, Peers};
use rutli_cosigner::peer::{LocalPeer, PeerApi};
use rutli_cosigner::seal::Sealer;
use rutli_cosigner::share_delivery::{self, RecipientRequest, ShareBundle};
use rutli_cosigner::share_import::{import_share, share_recipient, NodeContext};
use rutli_cosigner::verify_key::{check_views, sign_test_plan, NodeView};

#[path = "common/pki.rs"]
mod pki;
use rutli_cosigner::{DaemonError, Result as DaemonResult};

const N: u16 = 3;
const T: u16 = 2;
const KEY: &str = "frost-import-1220cb0e";
const CEREMONY: &str = "b2-cluster-test";
const MASTER: &[u8] = b"split ceremony cluster test master secret";

/// The namespace key of B1's throwaway 3.6.1 node: (seed, raw public key, fingerprint).
fn canton_namespace_key() -> ([u8; 32], [u8; 32], String) {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../canton-key/testdata/vectors");
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("manifest.json")).unwrap()).unwrap();
    let password = manifest["password"].as_str().unwrap();
    let input = std::fs::read(dir.join("namespace.export-pw.bin")).unwrap();
    let key = rutli_canton_key::parse(&input, Some(password.as_bytes())).unwrap();
    let rutli_canton_key::PrivateKeyMaterial::Ed25519 { seed } = &key.material else { panic!() };
    let rutli_canton_key::PublicKey::Ed25519(public) = key.public else { panic!() };
    (**seed, public, key.fingerprint())
}

struct Site {
    data_dir: PathBuf,
    ctx: NodeContext,
    signer: rutli_cosigner::request_auth::NodeSigner,
}

impl Site {
    fn new(root: &Path, identifier: u16) -> Self {
        let data_dir = root.join(format!("node-{identifier}"));
        let ctx = NodeContext {
            data_dir: data_dir.clone(),
            identifier,
            threshold: T,
            max_signers: N,
            roster: (1..=N).collect(),
            cluster_id: pki::shared().cluster_id(),
        };
        let signer = pki::shared().signer(&format!("cosigner{identifier}"));
        Self { data_dir, ctx, signer }
    }

    fn sealer(&self) -> Sealer {
        Sealer::from_master_secret(MASTER, self.ctx.identifier)
    }

    /// The node's key store, as the daemon and the offline CLI both open it.
    fn keystore(&self) -> KeyStore {
        let sealer = Arc::new(self.sealer());
        KeyStore::open_with_sealer(self.data_dir.join("keys"), Some(sealer)).unwrap()
    }

    fn recipient(&self) -> RecipientRequest {
        share_recipient(&self.ctx, &self.keystore(), &self.sealer(), &self.signer, KEY, CEREMONY, false).unwrap()
    }

    fn import(&self, bundle: &ShareBundle, fingerprint: &str) -> DaemonResult<()> {
        import_share(&self.ctx, &self.keystore(), &self.sealer(), bundle, fingerprint, false).map(|_| ())
    }

    fn node(&self) -> Arc<Node> {
        let id = Identifier::try_from(self.ctx.identifier).unwrap();
        Arc::new(Node::new(id, N, T, self.keystore()))
    }
}

/// Steps 1–2 of the runbook: every node publishes a recipient request, the dealer splits and seals.
fn ceremony(root: &Path) -> (Vec<Site>, Vec<ShareBundle>, [u8; 32], String) {
    let (seed, public, fingerprint) = canton_namespace_key();
    let sites: Vec<Site> = (1..=N).map(|i| Site::new(root, i)).collect();
    let requests: Vec<RecipientRequest> = sites.iter().map(Site::recipient).collect();
    let roster: Vec<u16> = requests.iter().map(|r| r.identifier).collect();
    let (shares, pkp) = rutli_frost_core::dealer::split_ed25519_seed(&seed, &roster, T).unwrap();
    let bundles = requests
        .iter()
        .zip(&shares)
        .map(|(r, s)| {
            // What the dealer does first: verify the request to the cluster CA.
            let verified =
                rutli_cosigner::request_auth::verify_request(r, pki::shared().ca_pem.as_bytes()).unwrap();
            let usage = rutli_cosigner::carry::CarriedUsage {
                expected: "namespace".into(),
                recorded: Some(vec!["namespace".into()]),
            };
            share_delivery::seal_share(&verified, s, &pkp, &fingerprint, &usage).unwrap()
        })
        .collect();
    (sites, bundles, public, fingerprint)
}

/// The Signer API of `node`, as the daemon serves it (allowlists off: in-process caller).
fn signer_svc(node: &Arc<Node>, peers: &Peers) -> rutli_cosigner::service::SignerSvc {
    rutli_cosigner::service::SignerSvc {
        node: node.clone(),
        peers: peers.clone(),
        allowed_cns: None,
        operator_cns: None,
        hosted_write_quorum: 2,
        decrypt_limiter: Arc::new(rutli_cosigner::ratelimit::DecryptRateLimiter::new(0)),
        ceremony_test_limiter: Arc::new(rutli_cosigner::service::ceremony_sign_test_limiter(
            rutli_cosigner::config::DEFAULT_CEREMONY_SIGN_TEST_RATE_LIMIT_PER_MIN,
        )),
    }
}

fn local_peers(nodes: &[Arc<Node>]) -> Peers {
    nodes.iter().map(|n| Arc::new(LocalPeer::new(n.clone())) as Arc<dyn PeerApi>).collect()
}

fn verifies(public: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    rutli_cosigner::verify_key::signature_verifies(public, msg, sig)
}

/// `verify-key`, in process: every node's KeyStatus, checked together; then each node leads one
/// signature.
async fn verify_key(nodes: &[Arc<Node>], peers: &Peers, fingerprint: &str, sign_test: bool) -> rutli_cosigner::verify_key::VerifyReport {
    let views: Vec<NodeView> = nodes
        .iter()
        .zip(1u16..)
        .map(|(n, id)| NodeView {
            identifier: id,
            endpoint: format!("local-{id}"),
            status: n.key_status(KEY).map_err(|e| e.to_string()),
        })
        .collect();
    let roster: Vec<u16> = (1..=N).collect();
    let mut report = check_views(KEY, fingerprint, &roster, T, &views);
    if sign_test && report.ok {
        // What `verify-key --sign-test` does over gRPC: every t-subset, leader rotating.
        for (leader, signers) in sign_test_plan(&roster, T) {
            let n = &nodes[usize::from(leader) - 1];
            let result = ceremony_sign_test(n, peers, KEY, &signers)
                .await
                .map(|(m, s)| (m.to_vec(), s.to_vec()))
                .map_err(|e| e.to_string());
            report.record_signature(leader, &signers, result);
        }
    }
    report
}

#[tokio::test]
async fn an_imported_canton_key_signs_verifies_refreshes_and_signs_again() {
    let tmp = tempfile::tempdir().unwrap();
    let (sites, bundles, public, fingerprint) = ceremony(tmp.path());
    for (site, bundle) in sites.iter().zip(&bundles) {
        site.import(bundle, &fingerprint).unwrap();
    }
    let nodes: Vec<Arc<Node>> = sites.iter().map(Site::node).collect();
    let peers = local_peers(&nodes);

    // The cluster's key IS the Canton key: same raw public key, same fingerprint.
    for n in &nodes {
        assert_eq!(n.group_key(KEY).unwrap(), public);
    }
    let msg = rutli_frost_core::dealer::canton_test_message(b"NamespaceDelegation");
    let sig = sign(&nodes[0], &peers, KEY, &msg).await.unwrap();
    assert!(verifies(&public, &msg, &sig), "must verify under the original Canton public key");

    let before = verify_key(&nodes, &peers, &fingerprint, true).await;
    assert!(before.ok, "{:?}", before.problems);
    assert_eq!(before.sign_test.len(), 3);
    assert_eq!((before.origin.as_deref(), before.refresh_count), (Some("dealer-split"), Some(0)));
    assert_eq!(before.pkp_digest.as_deref(), Some(bundles[0].pkp_digest.as_str()));

    // Refresh: same key, new sharing, counted. Every dealt bundle is now worthless.
    assert_eq!(run_refresh(&peers, KEY).await.unwrap(), public);
    let after = verify_key(&nodes, &peers, &fingerprint, true).await;
    assert!(after.ok, "{:?}", after.problems);
    assert_eq!(after.refresh_count, Some(1));
    assert_ne!(after.pkp_digest, before.pkp_digest, "refresh must change the sharing");
    let msg = rutli_frost_core::dealer::canton_test_message(b"after refresh");
    assert!(verifies(&public, &msg, &sign(&nodes[2], &peers, KEY, &msg).await.unwrap()));

    // A copy of a bundle is dead: install deleted the recipient secret. (That a dealt share no
    // longer combines with refreshed ones is pinned in rutli-frost-core's dealer tests.)
    let state_gone = share_delivery::load_recipient(&sites[0].data_dir, &sites[0].sealer(), KEY);
    assert!(state_gone.is_err(), "install deleted the recipient secret: the bundle cannot be opened");

    // A restart (fresh Node over the same store) still signs.
    let nodes: Vec<Arc<Node>> = sites.iter().map(Site::node).collect();
    let peers = local_peers(&nodes);
    let msg = rutli_frost_core::dealer::canton_test_message(b"after restart");
    assert!(verifies(&public, &msg, &sign(&nodes[1], &peers, KEY, &msg).await.unwrap()));
}

#[tokio::test]
async fn dkg_can_never_mint_or_overwrite_the_imported_id() {
    let tmp = tempfile::tempdir().unwrap();
    let (sites, bundles, public, fingerprint) = ceremony(tmp.path());

    // Before install: reserved, on every node.
    let nodes: Vec<Arc<Node>> = sites.iter().map(Site::node).collect();
    let peers = local_peers(&nodes);
    assert!(matches!(run_dkg(&peers, KEY).await, Err(DaemonError::ReservedKeyId(_))));
    for n in &nodes {
        assert!(matches!(n.dkg_part1("d", KEY), Err(DaemonError::ReservedKeyId(_))));
    }

    // After install: still refused, and the key is untouched.
    for (site, bundle) in sites.iter().zip(&bundles) {
        site.import(bundle, &fingerprint).unwrap();
    }
    assert!(run_dkg(&peers, KEY).await.is_err());
    let msg = rutli_frost_core::dealer::canton_test_message(b"still the canton key");
    assert!(verifies(&public, &msg, &sign(&nodes[0], &peers, KEY, &msg).await.unwrap()));
}

/// A cosigner that is down: every call fails as an unreachable peer would.
struct DownPeer(Identifier);

fn down<T>() -> DaemonResult<T> {
    Err(DaemonError::NotServing("cosigner is down".into()))
}

#[async_trait]
impl PeerApi for DownPeer {
    fn identifier(&self) -> Identifier {
        self.0
    }
    async fn sign_round1(&self, _: &str, _: &str) -> DaemonResult<SigningCommitments> {
        down()
    }
    async fn sign_round2(
        &self,
        _: &str,
        _: &str,
        _: &[u8],
        _: &BTreeMap<Identifier, SigningCommitments>,
    ) -> DaemonResult<SignatureShare> {
        down()
    }
    async fn abort_sign(&self, _: &str, _: &str) -> DaemonResult<()> {
        down()
    }
    async fn ceremony_fence(&self, _: &str, _: &str, _: &'static str) -> DaemonResult<()> {
        down()
    }
    async fn ceremony_release(&self, _: &str, _: &str) -> DaemonResult<()> {
        down()
    }
    async fn dkg_part1(&self, _: &str, _: &str) -> DaemonResult<round1::Package> {
        down()
    }
    async fn dkg_part2(
        &self,
        _: &str,
        _: &BTreeMap<Identifier, round1::Package>,
    ) -> DaemonResult<BTreeMap<Identifier, round2::Package>> {
        down()
    }
    async fn dkg_part3(
        &self,
        _: &str,
        _: &BTreeMap<Identifier, round1::Package>,
        _: &BTreeMap<Identifier, round2::Package>,
    ) -> DaemonResult<[u8; 32]> {
        down()
    }
    async fn refresh_part1(&self, _: &str, _: &str) -> DaemonResult<round1::Package> {
        down()
    }
    async fn refresh_part2(
        &self,
        _: &str,
        _: &BTreeMap<Identifier, round1::Package>,
    ) -> DaemonResult<BTreeMap<Identifier, round2::Package>> {
        down()
    }
    async fn refresh_part3(
        &self,
        _: &str,
        _: &BTreeMap<Identifier, round1::Package>,
        _: &BTreeMap<Identifier, round2::Package>,
    ) -> DaemonResult<[u8; 32]> {
        down()
    }
    async fn node_info(&self) -> DaemonResult<(u16, [u8; 32])> {
        down()
    }
    async fn replicate_key(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: &[u8],
        _: &rutli_cosigner::wrap::Wrapped,
    ) -> DaemonResult<Vec<u8>> {
        down()
    }
    async fn fetch_key(&self, _: &str) -> DaemonResult<(String, Vec<u8>, rutli_cosigner::wrap::Wrapped)> {
        down()
    }
    async fn list_keys(&self) -> DaemonResult<Vec<(String, String, Vec<u8>)>> {
        down()
    }
    async fn purge_key(&self, _: &str, _: &str) -> DaemonResult<bool> {
        down()
    }
}

#[tokio::test]
async fn any_two_nodes_sign_with_the_third_down() {
    let tmp = tempfile::tempdir().unwrap();
    let (sites, bundles, public, fingerprint) = ceremony(tmp.path());
    for (site, bundle) in sites.iter().zip(&bundles) {
        site.import(bundle, &fingerprint).unwrap();
    }
    let nodes: Vec<Arc<Node>> = sites.iter().map(Site::node).collect();
    for dead in 0..3 {
        let peers: Peers = nodes
            .iter()
            .enumerate()
            .map(|(i, n)| {
                if i == dead {
                    Arc::new(DownPeer(n.identifier)) as Arc<dyn PeerApi>
                } else {
                    Arc::new(LocalPeer::new(n.clone())) as Arc<dyn PeerApi>
                }
            })
            .collect();
        let leader = &nodes[(dead + 1) % 3];
        let msg = rutli_frost_core::dealer::canton_test_message(format!("down {dead}").as_bytes());
        let sig = sign(leader, &peers, KEY, &msg).await.unwrap();
        assert!(verifies(&public, &msg, &sig), "quorum without node {}", dead + 1);
        // A refresh needs everyone: refused with a node down, nothing changes.
        assert!(run_refresh(&peers, KEY).await.is_err());
    }
    let report = verify_key(&nodes, &local_peers(&nodes), &fingerprint, false).await;
    assert!(report.ok && report.refresh_count == Some(0), "{:?}", report.problems);
}

#[tokio::test]
async fn a_half_finished_install_signs_refuses_refresh_and_changes_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let (sites, bundles, public, fingerprint) = ceremony(tmp.path());
    // Nodes 1 and 2 installed, node 3 not yet.
    sites[0].import(&bundles[0], &fingerprint).unwrap();
    sites[1].import(&bundles[1], &fingerprint).unwrap();
    let share_file = |i: usize| sites[i].data_dir.join("keys").join(format!("{KEY}.json"));
    let before: Vec<Vec<u8>> = (0..2).map(|i| std::fs::read(share_file(i)).unwrap()).collect();

    let nodes: Vec<Arc<Node>> = sites.iter().map(Site::node).collect();
    let peers = local_peers(&nodes);

    // Two installed shares are a quorum: signing works (node 3 answers UnknownKey and is skipped).
    let msg = rutli_frost_core::dealer::canton_test_message(b"two of three installed");
    assert!(verifies(&public, &msg, &sign(&nodes[0], &peers, KEY, &msg).await.unwrap()));
    // But node 3 cannot LEAD a sign for a key it does not hold (NOT_FOUND, on which the driver
    // does not fail over) — which is why the runbook installs on every node before cutover.
    assert!(matches!(sign(&nodes[2], &peers, KEY, &msg).await, Err(DaemonError::UnknownKey(_))));

    // Refresh is all-or-nothing and node 3 has nothing: refused, and no share was rewritten.
    let err = run_refresh(&peers, KEY).await.unwrap_err();
    assert!(matches!(err, DaemonError::UnknownKey(_)), "got {err:?}");
    for (i, bytes) in before.iter().enumerate() {
        assert_eq!(&std::fs::read(share_file(i)).unwrap(), bytes, "node {} unchanged", i + 1);
    }
    assert!(!nodes[2].has_key(KEY));
    // verify-key reports the gap.
    let report = verify_key(&nodes, &peers, &fingerprint, false).await;
    assert!(!report.ok && report.problems.iter().any(|p| p.starts_with("node 3")), "{:?}", report.problems);

    // No ceremony guard was left behind: finishing the install makes everything work, in the
    // live cluster (the daemon caches nothing for a key it did not have).
    sites[2].import(&bundles[2], &fingerprint).unwrap();
    assert_eq!(run_refresh(&peers, KEY).await.unwrap(), public);
    let report = verify_key(&nodes, &peers, &fingerprint, true).await;
    assert!(report.ok, "{:?}", report.problems);
    assert_eq!(report.refresh_count, Some(1));
}

/// Review MEDIUM-1 (PoC `poc_sign_test_never_exercises_node3`): a node whose secret share is
/// broken but whose public view is intact must fail the sign test. With "first t responders"
/// quorums every test signature used nodes {1,2} and Gate B passed.
#[tokio::test]
async fn the_sign_test_catches_a_node_with_a_broken_secret_share() {
    use frost_ed25519::keys::{KeyPackage, SigningShare};
    let tmp = tempfile::tempdir().unwrap();
    let (sites, bundles, public, fingerprint) = ceremony(tmp.path());
    for (site, bundle) in sites.iter().zip(&bundles) {
        site.import(bundle, &fingerprint).unwrap();
    }
    // Corrupt node 3's signing share; everything public stays intact.
    let ks = sites[2].keystore();
    let mut share = ks.load(KEY).unwrap();
    let kp = share.key_package.clone();
    let mut b = [0u8; 32];
    b[0] = 42;
    let bad = SigningShare::deserialize(&b).unwrap();
    share.key_package =
        KeyPackage::new(*kp.identifier(), bad, *kp.verifying_share(), *kp.verifying_key(), *kp.min_signers());
    ks.save(KEY, &share).unwrap();

    let nodes: Vec<Arc<Node>> = sites.iter().map(Site::node).collect();
    let peers = local_peers(&nodes);
    let report = verify_key(&nodes, &peers, &fingerprint, true).await;
    assert!(!report.ok, "Gate B must not pass with node 3's share broken");
    let failed: Vec<_> = report.sign_test.iter().filter(|s| !s.ok).collect();
    assert!(!failed.is_empty(), "{:?}", report.sign_test);

    // And the reason it matters: {2,3} really cannot sign.
    let degraded: Peers = vec![
        Arc::new(DownPeer(Identifier::try_from(1u16).unwrap())) as Arc<dyn PeerApi>,
        Arc::new(LocalPeer::new(nodes[1].clone())),
        Arc::new(LocalPeer::new(nodes[2].clone())),
    ];
    let msg = rutli_frost_core::dealer::canton_test_message(b"node 1 lost");
    let r = sign(&nodes[1], &degraded, KEY, &msg).await;
    assert!(!r.as_ref().map(|s| verifies(&public, &msg, s)).unwrap_or(false));
}

/// Review MEDIUM-2: the sign test signs one fixed, server-computed digest, only for imported keys,
/// with exactly the requested quorum — nothing an operator credential could turn into `Sign`.
#[tokio::test]
async fn the_ceremony_sign_test_signs_only_its_own_digest_with_exactly_the_quorum_asked() {
    let tmp = tempfile::tempdir().unwrap();
    let (sites, bundles, public, fingerprint) = ceremony(tmp.path());
    for (site, bundle) in sites.iter().zip(&bundles) {
        site.import(bundle, &fingerprint).unwrap();
    }
    let nodes: Vec<Arc<Node>> = sites.iter().map(Site::node).collect();
    let peers = local_peers(&nodes);

    let (msg, sig) = ceremony_sign_test(&nodes[0], &peers, KEY, &[2, 3]).await.unwrap();
    assert_eq!(msg, rutli_cosigner::verify_key::verify_message(CEREMONY, KEY));
    assert!(verifies(&public, &msg, &sig));

    // Wrong quorum sizes, duplicates and strangers are refused, not "fixed up".
    for bad in [&[1u16][..], &[1, 2, 3], &[2, 2], &[1, 4]] {
        assert!(ceremony_sign_test(&nodes[0], &peers, KEY, bad).await.is_err(), "{bad:?}");
    }
    // No substitution: a requested signer that is down fails the test.
    let degraded: Peers = vec![
        Arc::new(LocalPeer::new(nodes[0].clone())) as Arc<dyn PeerApi>,
        Arc::new(LocalPeer::new(nodes[1].clone())),
        Arc::new(DownPeer(nodes[2].identifier)),
    ];
    assert!(ceremony_sign_test(&nodes[0], &degraded, KEY, &[1, 3]).await.is_err());

    // A DKG key has no ceremony digest: refused.
    run_dkg(&peers, "namespace-dkg").await.unwrap();
    let err = ceremony_sign_test(&nodes[0], &peers, "namespace-dkg", &[1, 2]).await.unwrap_err();
    assert!(matches!(err, DaemonError::Ceremony(_)), "{err:?}");
}

/// Review NEW-3 (PoC `poc2_operator_sign_test_leaves_unpruned_markers`): every CeremonySignTest
/// burns one fsynced, never-pruned nonce marker on each signer. The operator role must not be able
/// to loop it without bound — the Signer API rate-limits it per key (RESOURCE_EXHAUSTED).
#[tokio::test]
async fn the_operator_cannot_loop_the_sign_test_into_unbounded_nonce_markers() {
    use rutli_cosigner::pb::signer_server::Signer;
    let tmp = tempfile::tempdir().unwrap();
    let (sites, bundles, _public, fingerprint) = ceremony(tmp.path());
    for (site, bundle) in sites.iter().zip(&bundles) {
        site.import(bundle, &fingerprint).unwrap();
    }
    let nodes: Vec<Arc<Node>> = sites.iter().map(Site::node).collect();
    let peers = local_peers(&nodes);
    let svc = signer_svc(&nodes[0], &peers);

    let mut refused = 0;
    for _ in 0..200 {
        let req = tonic::Request::new(rutli_cosigner::pb::CeremonySignTestRequest {
            key_id: KEY.into(),
            signers: vec![1, 2],
        });
        match svc.ceremony_sign_test(req).await {
            Ok(_) => {}
            Err(s) if s.code() == tonic::Code::ResourceExhausted => refused += 1,
            Err(s) => panic!("unexpected {s:?}"),
        }
    }
    let dir = sites[0].data_dir.join("keys").join(format!("{KEY}.nonces"));
    let markers = std::fs::read_dir(&dir).unwrap().count();
    assert!(refused > 0, "200 back-to-back sign tests must hit the rate limit");
    assert!(markers <= 20, "node 1 holds {markers} nonce markers after 200 operator calls");
}
