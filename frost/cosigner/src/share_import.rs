// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! The cosigner side of the split ceremony: `share-recipient`, `import-share`, `abort-import`.
//!
//! All three are **offline CLI operations, never RPCs**, for the same reason `export-key` is
//! (see [`crate::export`]): installing key material must need host access *and* the node's seal
//! secret, and must add no network attack surface. They may run against a stopped node or inside
//! the live pod (`kubectl exec`): installation is a no-clobber [`KeyStore::create`], and the daemon
//! caches nothing for a key id it does not have, so it simply finds the share on first use.
//!
//! [`import_share`] runs its checks in a fixed order and installs only if every one passes; with
//! `dry_run` it stops right before writing, so an operator can rehearse all three nodes first.

use std::path::{Path, PathBuf};

use frost_ed25519 as frost;
use frost::keys::KeyPackage;
use frost::Identifier;
use serde::Serialize;

use crate::config::Config;
use crate::keystore::{KeyOrigin, KeyStore, Record, Share, ORIGIN_DEALER_SPLIT};
use crate::seal::Sealer;
use crate::share_delivery::{
    self, RecipientRequest, ShareBundle, BUNDLE_KIND, BUNDLE_VERSION, RECIPIENT_KIND,
    RECIPIENT_VERSION, SHARE_SPEC, SHARE_WRAP_VERSION,
};
use crate::{DaemonError, Result};

/// What this node's configuration says about itself, as the ceremony needs it.
#[derive(Debug, Clone)]
pub struct NodeContext {
    pub data_dir: PathBuf,
    pub identifier: u16,
    pub threshold: u16,
    pub max_signers: u16,
    /// Every configured identifier, sorted.
    pub roster: Vec<u16>,
    pub cluster_id: String,
}

impl NodeContext {
    pub fn from_config(cfg: &Config) -> Result<Self> {
        let mut roster: Vec<u16> = cfg.peers.iter().map(|p| p.identifier).collect();
        roster.sort_unstable();
        Ok(Self {
            data_dir: cfg.data_dir.clone(),
            identifier: cfg.identifier,
            threshold: cfg.threshold,
            max_signers: cfg.max_signers(),
            roster,
            cluster_id: cfg.cluster_id()?,
        })
    }

    pub fn keys_dir(&self) -> PathBuf {
        self.data_dir.join("keys")
    }

    fn me(&self) -> Result<Identifier> {
        Identifier::try_from(self.identifier).map_err(DaemonError::Frost)
    }
}

/// `share-recipient`: mint this node's recipient keypair for `key_id` in ceremony `ceremony_id`
/// and return the public request for the dealer, signed with this node's mTLS identity (`signer`,
/// see [`crate::request_auth`]). Refuses an id that is not an import id, a key that already exists
/// here, and a pending recipient unless `replace`.
pub fn share_recipient(
    ctx: &NodeContext,
    keystore: &KeyStore,
    sealer: &Sealer,
    signer: &crate::request_auth::NodeSigner,
    key_id: &str,
    ceremony_id: &str,
    replace: bool,
) -> Result<RecipientRequest> {
    check_import_id(key_id)?;
    share_delivery::validate_ceremony_id(ceremony_id)?;
    if key_present(keystore, key_id)? {
        return Err(DaemonError::KeyExists(key_id.to_string()));
    }
    let template = RecipientRequest {
        v: RECIPIENT_VERSION,
        kind: RECIPIENT_KIND.into(),
        ceremony_id: ceremony_id.into(),
        key_id: key_id.into(),
        cluster_id: ctx.cluster_id.clone(),
        identifier: ctx.identifier,
        threshold: ctx.threshold,
        max_signers: ctx.max_signers,
        roster: ctx.roster.clone(),
        recipient_pub: String::new(),
        signature_alg: String::new(),
        signer_chain: Vec::new(),
        signature: String::new(),
    };
    share_delivery::create_recipient(&ctx.data_dir, sealer, signer, template, replace)
}

/// `recipient-sas`: the Gate 0 line for this node's pending recipient, `SAS node <i> <sas>
/// ceremony <id> key <key_id>`, computed from the request stored in the sealed recipient file —
/// the request this node actually signed, whatever file reached the dealer. Read-only; needs the
/// seal secret (the file is sealed), which the pod has.
pub fn recipient_sas(data_dir: &Path, sealer: &Sealer, key_id: &str) -> Result<String> {
    check_import_id(key_id)?;
    let state = share_delivery::load_recipient(data_dir, sealer, key_id)?;
    let r = &state.request;
    Ok(format!(
        "SAS node {} {} ceremony {} key {}",
        r.identifier,
        crate::request_auth::sas(r),
        r.ceremony_id,
        r.key_id
    ))
}

/// What `import-share` did (or, for a dry run, would do). Public values only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImportReport {
    pub key_id: String,
    pub ceremony_id: String,
    pub identifier: u16,
    pub canton_fingerprint: String,
    pub group_verifying_key: String,
    /// This node's verifying share (hex), as in the public key package.
    pub own_verifying_share: String,
    pub pkp_digest: String,
    pub threshold: u16,
    pub max_signers: u16,
    /// `dry-run` (checked, nothing written), `installed`, or `already-installed` (an identical
    /// re-import: same ceremony, same package; nothing changed).
    pub outcome: &'static str,
}

/// `import-share`: verify `bundle` against this node, the pending recipient and the operator's
/// expected Canton fingerprint, then install it with a no-clobber create and delete the recipient
/// secret. Checks, in order:
///
/// 1. format: bundle kind, version, spec, envelope version;
/// 2. `recipient` is this node's identifier;
/// 3. `cluster_id` is this node's (derived from its CA certificate);
/// 4. if the key is already installed: an identical re-import (same ceremony, same package digest,
///    never refreshed) is a no-op success, anything else is `KeyExists`;
/// 5. `key_id` and `ceremony_id` match the pending recipient file;
/// 6. threshold, cluster size and the package's identifiers match this node's configuration;
/// 7. the group key's Canton fingerprint is `expect_fingerprint`;
/// 8. the envelope opens with the pending recipient secret (AAD binds every field above);
/// 9. the share is addressed to this node and passes VSS against its commitment
///    (`KeyPackage::try_from`), whose constant term is the group key, with `min_signers == t`;
/// 10. this node's verifying share is the package's entry for it;
/// 11. the package is a consistent t-of-n sharing (`check_public_key_package`).
///
/// Then (not for a dry run): create the share file, delete the recipient secret.
pub fn import_share(
    ctx: &NodeContext,
    keystore: &KeyStore,
    sealer: &Sealer,
    bundle: &ShareBundle,
    expect_fingerprint: &str,
    dry_run: bool,
) -> Result<ImportReport> {
    // 1. Format.
    if bundle.kind != BUNDLE_KIND
        || bundle.v != BUNDLE_VERSION
        || bundle.spec != SHARE_SPEC
        || bundle.wrapped.version != SHARE_WRAP_VERSION
    {
        return Err(ceremony(format!(
            "not a v{BUNDLE_VERSION} {BUNDLE_KIND} bundle (kind {:?}, v {}, spec {:?}, envelope v{})",
            bundle.kind, bundle.v, bundle.spec, bundle.wrapped.version
        )));
    }
    // 2–3. This node, this cluster.
    if bundle.recipient != ctx.identifier {
        return Err(ceremony(format!(
            "this bundle is for node {}, this is node {} — use share-{}-node{}.json",
            bundle.recipient, ctx.identifier, bundle.key_id, ctx.identifier
        )));
    }
    if bundle.cluster_id != ctx.cluster_id {
        return Err(ceremony(format!(
            "this bundle is for cluster {}, this node is in cluster {}",
            bundle.cluster_id, ctx.cluster_id
        )));
    }
    check_import_id(&bundle.key_id)?;

    // 4. Already installed?
    if key_present(keystore, &bundle.key_id)? {
        return already_installed(ctx, keystore, bundle, expect_fingerprint, dry_run);
    }

    // 5. The pending recipient for this key and ceremony.
    let state = share_delivery::load_recipient(&ctx.data_dir, sealer, &bundle.key_id)?;
    if state.request.ceremony_id != bundle.ceremony_id {
        return Err(ceremony(format!(
            "this bundle is from ceremony {}, the pending recipient here is for ceremony {}",
            bundle.ceremony_id, state.request.ceremony_id
        )));
    }

    // 6. Threshold, size, roster — against the configuration, not just the bundle's own claims.
    if bundle.threshold != ctx.threshold || bundle.max_signers != ctx.max_signers {
        return Err(ceremony(format!(
            "bundle is {}-of-{}, this node is configured {}-of-{}",
            bundle.threshold, bundle.max_signers, ctx.threshold, ctx.max_signers
        )));
    }
    let roster: std::collections::BTreeSet<Identifier> = ctx
        .roster
        .iter()
        .map(|&i| Identifier::try_from(i).map_err(DaemonError::Frost))
        .collect::<Result<_>>()?;
    let pkp = &bundle.public_key_package;
    if pkp.verifying_shares().keys().copied().collect::<std::collections::BTreeSet<_>>() != roster {
        return Err(ceremony(format!(
            "the public key package is not for this cluster's roster {:?}",
            ctx.roster
        )));
    }

    // 7. The key the operator expects.
    let group = bundle.group_key()?;
    let fingerprint = share_delivery::ed25519_fingerprint(&group);
    if fingerprint != expect_fingerprint || bundle.canton_fingerprint != expect_fingerprint {
        return Err(ceremony(format!(
            "the bundle's group key has Canton fingerprint {fingerprint}, expected \
             {expect_fingerprint} — refusing to install a different key"
        )));
    }

    // 8. Open (re-checks every public field against the pending request, then the AEAD).
    let share = bundle.open(&state)?;

    // 9. Addressed to us, VSS-valid, commitment constant term = group key, t = threshold.
    if *share.identifier() != ctx.me()? {
        return Err(ceremony("the sealed share is not for this node".into()));
    }
    let key_package = KeyPackage::try_from(share).map_err(|_| {
        ceremony("the share fails VSS verification against its commitment".into())
    })?;
    if key_package.verifying_key() != pkp.verifying_key()
        || key_package.verifying_key().serialize()?.as_slice() != group.as_slice()
    {
        return Err(ceremony("the share's commitment is for a different group key".into()));
    }
    if *key_package.min_signers() != ctx.threshold {
        return Err(ceremony(format!(
            "the share's commitment has threshold {}, this node is configured {}",
            key_package.min_signers(),
            ctx.threshold
        )));
    }
    // 10. Our verifying share is the package's.
    if pkp.verifying_shares().get(key_package.identifier()) != Some(key_package.verifying_share()) {
        return Err(ceremony(
            "this node's verifying share differs from the public key package's entry".into(),
        ));
    }
    // 11. The whole package is consistent.
    rutli_frost_core::dealer::check_public_key_package(pkp, ctx.threshold)?;

    let report = ImportReport {
        key_id: bundle.key_id.clone(),
        ceremony_id: bundle.ceremony_id.clone(),
        identifier: ctx.identifier,
        canton_fingerprint: fingerprint.clone(),
        group_verifying_key: hex::encode(group),
        own_verifying_share: hex::encode(key_package.verifying_share().serialize()?),
        pkp_digest: bundle.pkp_digest.clone(),
        threshold: ctx.threshold,
        max_signers: ctx.max_signers,
        outcome: if dry_run { "dry-run" } else { "installed" },
    };
    if dry_run {
        return Ok(report);
    }

    let share = Share {
        key_package,
        public_key_package: pkp.clone(),
        origin: Some(KeyOrigin {
            kind: ORIGIN_DEALER_SPLIT.into(),
            ceremony_id: bundle.ceremony_id.clone(),
            canton_fingerprint: fingerprint,
            installed_at: crate::hosted::now_secs(),
            refresh_count: 0,
        }),
    };
    keystore.create(&bundle.key_id, &share)?;
    // Installed: the bundle must now be dead. If this fails the share is still installed — say so;
    // `abort-import` without the delete flag removes the recipient file and keeps the share.
    share_delivery::delete_recipient(&ctx.data_dir, &bundle.key_id).map_err(|e| {
        ceremony(format!(
            "the share IS installed, but deleting the recipient secret failed ({e}) — run \
             `abort-import --key-id {} --ceremony-id {}` to remove it",
            bundle.key_id, bundle.ceremony_id
        ))
    })?;
    Ok(report)
}

/// Step 4: the key file exists. Identical re-import = success, anything else = `KeyExists`.
fn already_installed(
    ctx: &NodeContext,
    keystore: &KeyStore,
    bundle: &ShareBundle,
    expect_fingerprint: &str,
    dry_run: bool,
) -> Result<ImportReport> {
    let exists = || DaemonError::KeyExists(bundle.key_id.clone());
    let Record::Frost(share) = keystore.load_record(&bundle.key_id)? else { return Err(exists()) };
    let Some(origin) = &share.origin else { return Err(exists()) };
    let digest = hex::encode(rutli_frost_core::dealer::pkp_digest(&share.public_key_package)?);
    let group = rutli_frost_core::dkg::group_verifying_key_bytes(&share.public_key_package)?;
    let identical = origin.kind == ORIGIN_DEALER_SPLIT
        && origin.ceremony_id == bundle.ceremony_id
        && origin.refresh_count == 0
        && digest == bundle.pkp_digest
        && *share.key_package.identifier() == ctx.me()?;
    if !identical {
        return Err(exists());
    }
    // "Identical" must also mean "the key the operator expects": never report success for an
    // installed key the operator did not name.
    if origin.canton_fingerprint != expect_fingerprint
        || share_delivery::ed25519_fingerprint(&group) != expect_fingerprint
    {
        return Err(ceremony(format!(
            "{} is installed here with fingerprint {}, not the expected {expect_fingerprint}",
            bundle.key_id, origin.canton_fingerprint
        )));
    }
    // A crash between the create and the recipient deletion leaves the bundle openable; finish
    // the job now.
    if !dry_run {
        share_delivery::delete_recipient(&ctx.data_dir, &bundle.key_id)?;
    }
    Ok(ImportReport {
        key_id: bundle.key_id.clone(),
        ceremony_id: origin.ceremony_id.clone(),
        identifier: ctx.identifier,
        canton_fingerprint: origin.canton_fingerprint.clone(),
        group_verifying_key: hex::encode(group),
        own_verifying_share: hex::encode(share.key_package.verifying_share().serialize()?),
        pkp_digest: digest,
        threshold: *share.key_package.min_signers(),
        max_signers: share.public_key_package.verifying_shares().len() as u16,
        outcome: "already-installed",
    })
}

/// What `abort-import` did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AbortReport {
    pub key_id: String,
    pub ceremony_id: String,
    pub recipient_deleted: bool,
    /// `absent`, `deleted`, or `kept` (present, and `--yes-delete-installed-share` not given).
    pub installed_share: &'static str,
}

/// `abort-import`: back out of ceremony `ceremony_id` for `key_id` on this node. Always deletes the
/// pending recipient secret (if it belongs to this ceremony). Deletes an installed share only if it
/// came from this very ceremony, was never refreshed, and `delete_installed` is set — so this can
/// never destroy a DKG key, another ceremony's key, or a key that has been refreshed (and may
/// already be the only live copy of an identity). There is deliberately no generic key-destroy.
pub fn abort_import(
    ctx: &NodeContext,
    keystore: &KeyStore,
    sealer: &Sealer,
    key_id: &str,
    ceremony_id: &str,
    delete_installed: bool,
) -> Result<AbortReport> {
    check_import_id(key_id)?;
    share_delivery::validate_ceremony_id(ceremony_id)?;

    // Decide everything before deleting anything.
    let installed = if key_present(keystore, key_id)? {
        let Record::Frost(share) = keystore.load_record(key_id)? else {
            return Err(ceremony(format!("{key_id} is a hosted key, not an imported share")));
        };
        match &share.origin {
            Some(o) if o.kind == ORIGIN_DEALER_SPLIT && o.ceremony_id == ceremony_id => {
                if o.refresh_count > 0 {
                    return Err(ceremony(format!(
                        "{key_id} has been refreshed {} time(s) since install — it is a live key \
                         now, abort-import will not delete it",
                        o.refresh_count
                    )));
                }
                true
            }
            Some(o) => {
                return Err(ceremony(format!(
                    "{key_id} was installed by ceremony {}, not {ceremony_id} — refusing",
                    o.ceremony_id
                )))
            }
            None => {
                return Err(ceremony(format!(
                    "{key_id} is a DKG key, not an imported share — abort-import never touches it"
                )))
            }
        }
    } else {
        false
    };

    let path = share_delivery::recipient_path(&ctx.data_dir, key_id)?;
    let recipient_deleted = if path.try_exists()? {
        // Must be this ceremony's. An unreadable file (wrong seal secret) is refused, not guessed.
        let state = share_delivery::load_recipient(&ctx.data_dir, sealer, key_id)?;
        if state.request.ceremony_id != ceremony_id {
            return Err(ceremony(format!(
                "the pending recipient for {key_id} belongs to ceremony {}, not {ceremony_id}",
                state.request.ceremony_id
            )));
        }
        share_delivery::delete_recipient(&ctx.data_dir, key_id)?
    } else {
        false
    };

    let installed_share = match (installed, delete_installed) {
        (false, _) => "absent",
        (true, false) => "kept",
        (true, true) => {
            keystore.delete(key_id)?;
            "deleted"
        }
    };
    Ok(AbortReport {
        key_id: key_id.into(),
        ceremony_id: ceremony_id.into(),
        recipient_deleted,
        installed_share,
    })
}

/// Read a share bundle file.
pub fn read_bundle(path: &Path) -> Result<ShareBundle> {
    serde_json::from_slice(&std::fs::read(path)?).map_err(|e| {
        ceremony(format!("{} is not a share bundle: {e}", path.display()))
    })
}

fn check_import_id(key_id: &str) -> Result<()> {
    if share_delivery::is_import_key_id(key_id) {
        Ok(())
    } else {
        Err(ceremony(format!(
            "{key_id:?} is not an import key id — imported keys are named \
             <prefix>frost-import-<name> (e.g. frost-import-<first 8 hex of the fingerprint>)"
        )))
    }
}

/// Whether a key file exists. Unlike [`KeyStore::exists`] an IO error is an error, never "absent".
fn key_present(keystore: &KeyStore, key_id: &str) -> Result<bool> {
    match keystore.load_record(key_id) {
        Ok(_) => Ok(true),
        Err(DaemonError::UnknownKey(_)) => Ok(false),
        Err(e) => Err(e),
    }
}

fn ceremony(msg: String) -> DaemonError {
    DaemonError::Ceremony(msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use frost::keys::PublicKeyPackage;

    const KEY: &str = "frost-import-test";
    const CEREMONY: &str = "c-1";
    const SEED: [u8; 32] = [3u8; 32];

    struct TestNode {
        _tmp: tempfile::TempDir,
        ctx: NodeContext,
        sealer: Sealer,
        signer: crate::request_auth::NodeSigner,
        keystore: KeyStore,
    }

    impl TestNode {
        fn new(identifier: u16) -> Self {
            let tmp = tempfile::tempdir().unwrap();
            let ctx = NodeContext {
                data_dir: tmp.path().to_path_buf(),
                identifier,
                threshold: 2,
                max_signers: 3,
                roster: vec![1, 2, 3],
                cluster_id: crate::test_pki::shared().cluster_id(),
            };
            let sealer = Sealer::from_master_secret(b"share import test master", identifier);
            let keystore = KeyStore::open_with_sealer(
                ctx.keys_dir(),
                Some(std::sync::Arc::new(Sealer::from_master_secret(
                    b"share import test master",
                    identifier,
                ))),
            )
            .unwrap();
            let signer = crate::test_pki::shared().signer(&format!("cosigner{identifier}"));
            Self { _tmp: tmp, ctx, sealer, signer, keystore }
        }

        fn recipient(&self) -> RecipientRequest {
            share_recipient(&self.ctx, &self.keystore, &self.sealer, &self.signer, KEY, CEREMONY, false).unwrap()
        }

        fn import(&self, b: &ShareBundle, dry_run: bool) -> Result<ImportReport> {
            import_share(&self.ctx, &self.keystore, &self.sealer, b, &fingerprint(), dry_run)
        }
    }

    fn fingerprint() -> String {
        share_delivery::ed25519_fingerprint(&rutli_frost_core::dealer::public_key_from_seed(&SEED))
    }

    fn deal(requests: &[RecipientRequest]) -> (Vec<ShareBundle>, PublicKeyPackage) {
        let ids: Vec<u16> = requests.iter().map(|r| r.identifier).collect();
        let (shares, pkp) = rutli_frost_core::dealer::split_ed25519_seed(&SEED, &ids, 2).unwrap();
        let bundles = requests
            .iter()
            .zip(&shares)
            .map(|(r, s)| {
                let ca = crate::test_pki::shared().ca_pem.as_bytes();
                let verified = crate::request_auth::verify_request(r, ca).unwrap();
                share_delivery::seal_share(&verified, s, &pkp, &fingerprint()).unwrap()
            })
            .collect();
        (bundles, pkp)
    }

    fn three() -> (Vec<TestNode>, Vec<ShareBundle>) {
        let nodes: Vec<TestNode> = (1..=3).map(TestNode::new).collect();
        let requests: Vec<RecipientRequest> = nodes.iter().map(|n| n.recipient()).collect();
        let (bundles, _) = deal(&requests);
        (nodes, bundles)
    }

    fn assert_ceremony_err(r: Result<ImportReport>, needle: &str) {
        match r {
            Err(e) => assert!(e.to_string().contains(needle), "expected {needle:?} in: {e}"),
            Ok(rep) => panic!("expected an error containing {needle:?}, got {rep:?}"),
        }
    }

    #[test]
    fn dry_run_checks_everything_and_writes_nothing_then_install_kills_the_bundle() {
        let (nodes, bundles) = three();
        let n = &nodes[0];
        let dry = n.import(&bundles[0], true).unwrap();
        assert_eq!(dry.outcome, "dry-run");
        assert!(!n.keystore.exists(KEY));
        assert!(share_delivery::recipient_path(&n.ctx.data_dir, KEY).unwrap().exists());

        let done = n.import(&bundles[0], false).unwrap();
        assert_eq!(done.outcome, "installed");
        assert_eq!(done.canton_fingerprint, fingerprint());
        assert_eq!(done.pkp_digest, bundles[0].pkp_digest);
        let installed = n.keystore.load(KEY).unwrap();
        let origin = installed.origin.unwrap();
        assert_eq!((origin.ceremony_id.as_str(), origin.refresh_count), (CEREMONY, 0));
        assert!(!share_delivery::recipient_path(&n.ctx.data_dir, KEY).unwrap().exists());

        // Identical re-import: no-op success (the bundle can no longer be opened, and need not be).
        assert_eq!(n.import(&bundles[0], false).unwrap().outcome, "already-installed");
    }

    /// Review NEW-2: a witness can re-derive the SAS from the node's own sealed state, in a session
    /// of their own, any time before install.
    #[test]
    fn recipient_sas_is_read_back_from_the_sealed_state_until_install() {
        let n = TestNode::new(2);
        let request = n.recipient();
        let line = recipient_sas(&n.ctx.data_dir, &n.sealer, KEY).unwrap();
        assert!(line.starts_with(&format!("SAS node 2 {} ", crate::request_auth::sas(&request))), "{line}");
        assert!(line.contains(CEREMONY));
        // Not with another node's seal key, not for a non-import id.
        let other = Sealer::from_master_secret(b"share import test master", 3);
        assert!(recipient_sas(&n.ctx.data_dir, &other, KEY).is_err());
        assert!(recipient_sas(&n.ctx.data_dir, &n.sealer, "frost-namespace").is_err());
    }

    /// Review LOW-1: a crash between the create and the recipient deletion must not leave the
    /// bundle openable for good, and "identical" must include the expected fingerprint.
    #[test]
    fn a_re_import_finishes_an_interrupted_install_and_checks_the_fingerprint() {
        let (nodes, bundles) = three();
        let n = &nodes[0];
        let recipient = share_delivery::recipient_path(&n.ctx.data_dir, KEY).unwrap();
        let saved = std::fs::read(&recipient).unwrap();
        n.import(&bundles[0], false).unwrap();
        // The crash: share created, recipient file never deleted.
        std::fs::write(&recipient, &saved).unwrap();
        assert!(share_delivery::load_recipient(&n.ctx.data_dir, &n.sealer, KEY).is_ok());

        // Re-run with the wrong expectation: refused, nothing touched.
        let wrong = format!("1220{}", "ab".repeat(32));
        let r = import_share(&n.ctx, &n.keystore, &n.sealer, &bundles[0], &wrong, false);
        assert_ceremony_err(r, "not the expected");
        assert!(recipient.exists());
        // A dry run reports, deletes nothing.
        assert_eq!(n.import(&bundles[0], true).unwrap().outcome, "already-installed");
        assert!(recipient.exists());
        // The real re-run finishes the install: the recipient secret is gone.
        assert_eq!(n.import(&bundles[0], false).unwrap().outcome, "already-installed");
        assert!(!recipient.exists());
    }

    #[test]
    fn every_node_installs_and_the_installed_shares_reconstruct_the_canton_key() {
        let (nodes, bundles) = three();
        let mut kps = Vec::new();
        for (n, b) in nodes.iter().zip(&bundles) {
            n.import(b, false).unwrap();
            kps.push(n.keystore.load(KEY).unwrap());
        }
        let quorum: Vec<KeyPackage> = kps[1..].iter().map(|s| s.key_package.clone()).collect();
        let key = frost::keys::reconstruct(&quorum).unwrap();
        assert_eq!(
            frost::VerifyingKey::from(&key).serialize().unwrap(),
            rutli_frost_core::dealer::public_key_from_seed(&SEED).to_vec()
        );
    }

    #[test]
    fn import_refuses_the_wrong_node_cluster_ceremony_fingerprint_and_config() {
        let (nodes, bundles) = three();
        let n = &nodes[0];
        assert_ceremony_err(n.import(&bundles[1], false), "for node 2");

        let mut b = bundles[0].clone();
        b.cluster_id = "other".into();
        assert_ceremony_err(n.import(&b, false), "cluster");

        let mut b = bundles[0].clone();
        b.ceremony_id = "c-2".into();
        assert_ceremony_err(n.import(&b, false), "ceremony");

        // Operator expects a different key.
        let other_fp = format!("1220{}", "ab".repeat(32));
        let r = import_share(&n.ctx, &n.keystore, &n.sealer, &bundles[0], &other_fp, false);
        assert_ceremony_err(r, "expected");

        // This node's config changed between share-recipient and import.
        let mut ctx = n.ctx.clone();
        ctx.threshold = 3;
        let r = import_share(&ctx, &n.keystore, &n.sealer, &bundles[0], &fingerprint(), false);
        assert_ceremony_err(r, "configured");

        let mut b = bundles[0].clone();
        b.v = 2;
        assert_ceremony_err(n.import(&b, false), "bundle");

        // Nothing was installed by any of that, and the real bundle still installs.
        assert!(!n.keystore.exists(KEY));
        n.import(&bundles[0], false).unwrap();
    }

    #[test]
    fn import_needs_a_pending_recipient_and_refuses_a_key_that_exists_differently() {
        let (nodes, bundles) = three();
        let n = &nodes[0];
        share_delivery::delete_recipient(&n.ctx.data_dir, KEY).unwrap();
        assert_ceremony_err(n.import(&bundles[0], false), "no pending recipient");

        // A different key already sits under the id (another ceremony's): KeyExists, untouched.
        let n = &nodes[1];
        n.import(&bundles[1], false).unwrap();
        let mut from_another = bundles[1].clone();
        from_another.ceremony_id = "c-other".into();
        assert!(matches!(n.import(&from_another, false), Err(DaemonError::KeyExists(_))));
        let mut other_package = bundles[1].clone();
        other_package.pkp_digest = hex::encode([0u8; 32]);
        assert!(matches!(n.import(&other_package, false), Err(DaemonError::KeyExists(_))));
    }

    #[test]
    fn share_recipient_refuses_non_import_ids_existing_keys_and_needs_replace() {
        let n = TestNode::new(1);
        let r = share_recipient(&n.ctx, &n.keystore, &n.sealer, &n.signer, "frost-namespace", CEREMONY, false);
        assert!(r.is_err());
        n.recipient();
        assert!(share_recipient(&n.ctx, &n.keystore, &n.sealer, &n.signer, KEY, CEREMONY, false).is_err());
        share_recipient(&n.ctx, &n.keystore, &n.sealer, &n.signer, KEY, CEREMONY, true).unwrap();

        let (nodes, bundles) = three();
        nodes[2].import(&bundles[2], false).unwrap();
        let again = share_recipient(&nodes[2].ctx, &nodes[2].keystore, &nodes[2].sealer, &nodes[2].signer, KEY, "c-9", true);
        assert!(matches!(again, Err(DaemonError::KeyExists(_))));
    }

    #[test]
    fn abort_import_only_ever_deletes_this_ceremonys_unrefreshed_share_and_only_when_told() {
        let (nodes, bundles) = three();

        // Before install: abort removes the recipient, nothing else.
        let n = &nodes[0];
        let rep = abort_import(&n.ctx, &n.keystore, &n.sealer, KEY, CEREMONY, false).unwrap();
        assert!(rep.recipient_deleted);
        assert_eq!(rep.installed_share, "absent");
        assert_ceremony_err(n.import(&bundles[0], false), "no pending recipient");

        // Wrong ceremony id: refused, recipient kept.
        let n = &nodes[1];
        assert!(abort_import(&n.ctx, &n.keystore, &n.sealer, KEY, "c-other", true).is_err());
        assert!(share_delivery::recipient_path(&n.ctx.data_dir, KEY).unwrap().exists());

        // Installed, no flag: kept. With the flag: deleted.
        n.import(&bundles[1], false).unwrap();
        let rep = abort_import(&n.ctx, &n.keystore, &n.sealer, KEY, CEREMONY, false).unwrap();
        assert_eq!(rep.installed_share, "kept");
        assert!(n.keystore.exists(KEY));
        assert!(abort_import(&n.ctx, &n.keystore, &n.sealer, KEY, "c-other", true).is_err());
        let rep = abort_import(&n.ctx, &n.keystore, &n.sealer, KEY, CEREMONY, true).unwrap();
        assert_eq!(rep.installed_share, "deleted");
        assert!(!n.keystore.exists(KEY));

        // Refreshed: never deleted.
        let n = &nodes[2];
        n.import(&bundles[2], false).unwrap();
        let mut share = n.keystore.load(KEY).unwrap();
        share.origin.as_mut().unwrap().refresh_count = 1;
        n.keystore.save(KEY, &share).unwrap();
        let err = abort_import(&n.ctx, &n.keystore, &n.sealer, KEY, CEREMONY, true).unwrap_err();
        assert!(err.to_string().contains("refreshed"), "{err}");
        assert!(n.keystore.exists(KEY));

        // A DKG key (no origin) under an import-shaped id: never.
        let mut dkg_like = n.keystore.load(KEY).unwrap();
        dkg_like.origin = None;
        n.keystore.save(KEY, &dkg_like).unwrap();
        assert!(abort_import(&n.ctx, &n.keystore, &n.sealer, KEY, CEREMONY, true).is_err());
        assert!(n.keystore.exists(KEY));

        // And never anything that is not an import id.
        assert!(abort_import(&n.ctx, &n.keystore, &n.sealer, "frost-namespace", CEREMONY, true).is_err());
    }
}
