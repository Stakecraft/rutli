// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Readiness must follow the key store (2026-10-07 DevNet incident): a cosigner whose `/data/keys`
//! became unreadable kept answering Health ok and kept being chosen as leader while every Sign
//! failed. Covers `Signer.Health` and the `rutli-cosigner health` container probe.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;

use frost_ed25519::Identifier;
use rutli_cosigner::keystore::KeyStore;
use rutli_cosigner::node::Node;
use rutli_cosigner::orchestrator::{run_dkg, run_refresh, sign, Peers};
use rutli_cosigner::pb::signer_server::Signer;
use rutli_cosigner::pb::{
    DecryptRequest, DkgRequest, GroupKeyRequest, HealthRequest, KeyInfoRequest, SignRequest,
};
use rutli_cosigner::peer::{LocalPeer, PeerApi};
use rutli_cosigner::ratelimit::DecryptRateLimiter;
use rutli_cosigner::service::SignerSvc;
use tonic::Request;

fn chmod(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// chmod 000 `dir`; false (permissions restored) when the process reads it anyway — root, where
/// permission bits are not enforced and these tests prove nothing.
fn lock_out(dir: &Path) -> bool {
    chmod(dir, 0o000);
    if std::fs::read_dir(dir).is_ok() {
        chmod(dir, 0o700);
        eprintln!("permission bits not enforced (running as root?) — skipping");
        return false;
    }
    true
}

async fn health(svc: &SignerSvc) -> (bool, String) {
    let r = Signer::health(svc, Request::new(HealthRequest {})).await.unwrap().into_inner();
    (r.ok, r.detail)
}

#[tokio::test]
async fn unreadable_keys_dir_makes_health_not_serving() {
    let tmp = tempfile::tempdir().unwrap();
    let keys = tmp.path().join("keys");
    let ks = KeyStore::open(&keys).unwrap();
    // Zero freshness: Health caches its verdict for a few seconds in production; here every call
    // must probe, or the lock-out below would be answered from the pre-lock cache.
    let node = Arc::new(
        Node::new(Identifier::try_from(1).unwrap(), 1, 1, ks)
            .with_keystore_probe_freshness(std::time::Duration::ZERO),
    );
    let peers: Peers = vec![Arc::new(LocalPeer::new(node.clone())) as Arc<dyn PeerApi>];
    let svc = SignerSvc {
        node,
        peers,
        allowed_cns: None,
        operator_cns: None,
        hosted_write_quorum: 1,
        decrypt_limiter: Arc::new(DecryptRateLimiter::new(0)),
        ceremony_test_limiter: Arc::new(DecryptRateLimiter::new(0)),
    };
    std::fs::write(keys.join("some-key.json"), b"{}").unwrap();

    assert_eq!(health(&svc).await, (true, "serving".to_string()));

    if !lock_out(&keys) {
        return;
    }
    let locked = health(&svc).await;
    // While the verdict is down, the node declines to LEAD: UNAVAILABLE at the RPC entry (which
    // every driver version fails over on), not an INTERNAL from deep inside a session or ceremony.
    let led_sign = Signer::sign(
        &svc,
        Request::new(SignRequest { key_id: "some-key".into(), message: canton_digest() }),
    )
    .await;
    let led_dkg = Signer::dkg(&svc, Request::new(DkgRequest { key_id: "new-key".into() })).await;
    // Every other store-touching RPC answers the same way — above all never NOT_FOUND / "does not
    // exist" for a key the node merely cannot read (Canton would believe it gone).
    let group_key =
        Signer::group_key(&svc, Request::new(GroupKeyRequest { key_id: "some-key".into() })).await;
    let key_info =
        Signer::key_info(&svc, Request::new(KeyInfoRequest { key_id: "some-key".into() })).await;
    let decrypt = Signer::decrypt(
        &svc,
        Request::new(DecryptRequest { key_id: "some-key".into(), ciphertext: vec![0; 256] }),
    )
    .await;
    chmod(&keys, 0o700); // restore BEFORE asserting, or a failure leaves an undeletable tempdir
    let (ok, detail) = locked;
    assert!(!ok, "a node that cannot read its key store must not report healthy");
    assert!(detail.contains("NOT_SERVING"), "{detail}");
    assert!(detail.contains(&keys.display().to_string()), "detail must name the path: {detail}");
    for (what, r) in [
        ("Sign", led_sign.map(|_| ())),
        ("Dkg", led_dkg.map(|_| ())),
        ("GroupKey", group_key.map(|_| ())),
        ("KeyInfo", key_info.map(|_| ())),
        ("Decrypt", decrypt.map(|_| ())),
    ] {
        let status = r.expect_err(&format!("{what} must be refused while the key store is down"));
        assert_eq!(status.code(), tonic::Code::Unavailable, "{what}: {status:?}");
        assert!(status.message().contains("readiness probe"), "{what}: {status:?}");
    }

    assert_eq!(health(&svc).await, (true, "serving".to_string()), "must recover on its own");
}

fn canton_digest() -> Vec<u8> {
    let mut m = vec![0x12u8, 0x20];
    m.extend([7u8; 32]);
    m
}

/// The incident's second half. A broken node that has signed since startup holds its share in
/// memory, so it can still answer round 1 — and only fails at round 2, which must write a nonce
/// marker. Peers are tried in identifier order, so it lands in EVERY leader's quorum and sinks
/// every signature: failing over between leaders alone does not restore signing. It must refuse
/// round 1 instead, so leaders skip it. Covers both shapes: an unreadable store (refused by the
/// fail-closed nonce lookup, immediately) and a read-only one (refused once the readiness probe
/// has seen it).
#[tokio::test]
async fn healthy_leaders_sign_around_a_peer_whose_key_store_broke() {
    let tmp = tempfile::tempdir().unwrap();
    let nodes: Vec<Arc<Node>> = (1..=3u16)
        .map(|i| {
            let ks = KeyStore::open(tmp.path().join(format!("node-{i}"))).unwrap();
            Arc::new(Node::new(Identifier::try_from(i).unwrap(), 3, 2, ks))
        })
        .collect();
    let peers: Peers =
        nodes.iter().map(|n| Arc::new(LocalPeer::new(n.clone())) as Arc<dyn PeerApi>).collect();
    run_dkg(&peers, "k").await.unwrap();
    let msg = canton_digest();
    sign(&nodes[0], &peers, "k", &msg).await.unwrap(); // node 1 now has its share cached
    let keys1 = tmp.path().join("node-1");

    // Unreadable (the incident: Permission denied).
    if !lock_out(&keys1) {
        return;
    }
    let mut results = Vec::new();
    for leader in &nodes {
        results.push(sign(leader, &peers, "k", &msg).await);
    }
    chmod(&keys1, 0o700);
    for (i, r) in results.iter().enumerate() {
        // Including node 1 itself as leader: it skips itself and aggregates the other two shares.
        assert!(r.is_ok(), "leader {} must sign around the broken peer: {r:?}", i + 1);
    }

    // Read-only (a remount — the whole tree, nonce-marker dir included): reads still work, so only
    // the probe verdict keeps node 1 out.
    let nonces1 = keys1.join("k.nonces");
    chmod(&nonces1, 0o500);
    chmod(&keys1, 0o500);
    let verdict = nodes[0].check_keystore();
    let led_by_2 = sign(&nodes[1], &peers, "k", &msg).await;
    chmod(&keys1, 0o700);
    chmod(&nonces1, 0o700);
    assert!(verdict.is_err(), "a read-only key store must fail the probe");
    assert!(led_by_2.is_ok(), "a read-only peer must be skipped, not sink the quorum: {led_by_2:?}");

    // Recovery: once the probe passes again, node 1 is back in quorums.
    nodes[0].check_keystore().unwrap();
    sign(&nodes[1], &peers, "k", &msg).await.unwrap();
}

/// A participant whose store went read-only can still `exists()`/`load()` its share, so a refresh
/// would fail only at its final save — after the nodes before it had persisted theirs: a
/// half-applied refresh, and no signing for that key until repaired. The fence must refuse it, so
/// the whole ceremony rolls back before any crypto and leaves no guard behind.
#[tokio::test]
async fn a_sick_participant_refuses_the_ceremony_fence_so_a_refresh_never_half_applies() {
    let tmp = tempfile::tempdir().unwrap();
    let nodes: Vec<Arc<Node>> = (1..=3u16)
        .map(|i| {
            let ks = KeyStore::open(tmp.path().join(format!("node-{i}"))).unwrap();
            Arc::new(Node::new(Identifier::try_from(i).unwrap(), 3, 2, ks))
        })
        .collect();
    let peers: Peers =
        nodes.iter().map(|n| Arc::new(LocalPeer::new(n.clone())) as Arc<dyn PeerApi>).collect();
    run_dkg(&peers, "k").await.unwrap();
    let share = |i: u16| std::fs::read(tmp.path().join(format!("node-{i}")).join("k.json")).unwrap();
    let before: Vec<Vec<u8>> = (1..=3).map(share).collect();

    // The LAST node in fence order goes read-only, so the fence has to roll back nodes 1 and 2.
    let keys3 = tmp.path().join("node-3");
    chmod(&keys3, 0o500);
    if nodes[2].check_keystore().is_ok() {
        chmod(&keys3, 0o700);
        eprintln!("permission bits not enforced (running as root?) — skipping");
        return;
    }
    let refreshed = run_refresh(&peers, "k").await;
    chmod(&keys3, 0o700);

    let err = refreshed.expect_err("a refresh with a read-only participant must be refused");
    assert!(err.to_string().contains("readiness probe"), "refused at the fence, not later: {err}");
    let after: Vec<Vec<u8>> = (1..=3).map(share).collect();
    assert_eq!(before, after, "no node may persist a refreshed share when one participant cannot");

    // No fence left anywhere: once node 3 recovers, a cluster-wide refresh (which needs every
    // node's guard) goes through, and the cluster still signs.
    nodes[2].check_keystore().unwrap();
    run_refresh(&peers, "k").await.expect("the refused refresh must not leave a guard behind");
    sign(&nodes[0], &peers, "k", &canton_digest()).await.unwrap();
}

#[test]
fn health_subcommand_reports_ready_only_with_a_readable_store_and_a_listener() {
    let tmp = tempfile::tempdir().unwrap();
    let keys = tmp.path().join("keys");
    std::fs::create_dir_all(&keys).unwrap();
    std::fs::write(keys.join("some-key.json"), b"{}").unwrap();

    // Stand-in for the gRPC server. The config listens on 0.0.0.0, as the deployed configs do, so
    // this also covers dialling loopback instead of the unspecified address.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let cfg = tmp.path().join("cosigner1.json");
    std::fs::write(
        &cfg,
        serde_json::json!({
            "identifier": 1,
            "listen": format!("0.0.0.0:{port}"),
            "threshold": 1,
            "data_dir": tmp.path(),
            "peers": [{ "identifier": 1, "endpoint": format!("http://127.0.0.1:{port}") }],
        })
        .to_string(),
    )
    .unwrap();

    let probe = || {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_rutli-cosigner"))
            .args(["--config", cfg.to_str().unwrap(), "health"])
            .env_remove("RUTLI_COSIGNER_CONFIG")
            .output()
            .unwrap();
        (out.status.code(), String::from_utf8_lossy(&out.stdout).trim().to_string())
    };

    assert_eq!(probe(), (Some(0), "ready".to_string()));

    if lock_out(&keys) {
        let locked = probe();
        chmod(&keys, 0o700);
        assert_eq!(locked.0, Some(1), "unreadable key store must fail the probe: {}", locked.1);
        assert!(locked.1.contains("unreadable"), "{}", locked.1);
        assert_eq!(probe(), (Some(0), "ready".to_string()));
    }

    drop(listener);
    let down = probe();
    assert_eq!(down.0, Some(1), "no listener must fail the probe: {}", down.1);
    assert!(down.1.contains("not accepting connections"), "{}", down.1);
}
