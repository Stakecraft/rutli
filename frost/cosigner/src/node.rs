// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Per-node state and the typed peer operations. The gRPC [`crate::service`] layer and the
//! in-process [`crate::peer::LocalPeer`] both drive these methods; the wire (de)serialization lives
//! only at those edges, so this module stays type-safe.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use frost_ed25519 as frost;
use frost::keys::dkg::{round1, round2};
use frost::round1::SigningCommitments;
use frost::round2::SignatureShare;
use frost::Identifier;

use rutli_frost_core::dkg::{group_verifying_key_bytes, DkgParticipant};
use rutli_frost_core::nonce_store::NonceStore;
use rutli_frost_core::refresh::RefreshParticipant;
use rutli_frost_core::session::{aggregate, Cosigner};

use crate::keystore::{KeyStore, Share};
use crate::{DaemonError, Result};

struct DkgState {
    key_id: String,
    participant: DkgParticipant,
}

struct RefreshState {
    key_id: String,
    participant: RefreshParticipant,
}

/// A per-key ceremony guard: only one DKG/refresh may be in progress for a given key at a time.
/// Owner is the ceremony id; a guard whose ceremony crashed mid-flight is preempted after the
/// orphan timeout (an in-progress ceremony releases its guard at part3 / on clean failure, so this
/// only ever applies to a leader that died between part1 and part3).
struct CeremonyGuard {
    owner: String,
    kind: &'static str,
    started: Instant,
}

/// How long an orphaned ceremony guard blocks a new ceremony for the same key. Longer than any
/// realistic DKG/refresh round-trip; shorter than a human's patience for a crashed ceremony.
const CEREMONY_ORPHAN_TIMEOUT: Duration = Duration::from_secs(15 * 60);

pub struct Node {
    pub identifier: Identifier,
    pub max_signers: u16,
    pub min_signers: u16,
    keystore: KeyStore,
    /// Key-store readiness verdict (see [`crate::health`]), shared with Health and the monitor.
    keystore_health: Arc<crate::health::KeystoreHealth>,
    cosigners: Mutex<std::collections::HashMap<String, Arc<Cosigner>>>,
    dkg_sessions: Mutex<std::collections::HashMap<String, DkgState>>,
    refresh_sessions: Mutex<std::collections::HashMap<String, RefreshState>>,
    // key_id -> the ceremony currently allowed to (re)write that key's share.
    ceremonies: Mutex<std::collections::HashMap<String, CeremonyGuard>>,
    ceremony_orphan_timeout: Duration,
    /// Set when hosted (non-FROST) keys are enabled: this node's derived wrapping key plus the
    /// cluster identity envelopes are bound to. `None` disables every hosted-key operation.
    hosted: Option<HostedCtx>,
}

/// Node index whose distribution public key keys [`Node::hosted_commitment`].
///
/// A commitment is compared across nodes (replication acks, anti-entropy), so it must be the same
/// on every node: it is keyed off one fixed, cluster-wide value, not off the computing node's own
/// distribution key. It is 0 because that is the value every node effectively used before the
/// identifier-index fix (0.3.2), when each node's index read as 0 — keeping it makes commitments
/// from a 0.3.1 node and a fixed node agree during a rolling upgrade.
const COMMITMENT_KEY_INDEX: u16 = 0;

struct HostedCtx {
    dist_key: crate::wrap::DistKey,
    /// Public half of the cluster-wide commitment key (see [`COMMITMENT_KEY_INDEX`]).
    commitment_key: [u8; 32],
    cluster_id: String,
    /// Needed to derive a *peer's* distribution public key when serving FetchKey. Under today's
    /// shared master secret every node can already derive every peer's key; with per-node secrets
    /// this becomes a pinned config value instead.
    master: zeroize::Zeroizing<Vec<u8>>,
}

impl Node {
    pub fn new(identifier: Identifier, max_signers: u16, min_signers: u16, keystore: KeyStore) -> Self {
        Self::new_with_ceremony_timeout(
            identifier,
            max_signers,
            min_signers,
            keystore,
            CEREMONY_ORPHAN_TIMEOUT,
        )
    }

    /// Same as [`Node::new`] but with a custom orphan-guard timeout (tests use a tiny value to
    /// exercise preemption without waiting the production 15 minutes).
    pub fn new_with_ceremony_timeout(
        identifier: Identifier,
        max_signers: u16,
        min_signers: u16,
        keystore: KeyStore,
        ceremony_orphan_timeout: Duration,
    ) -> Self {
        let mut keystore_health = crate::health::KeystoreHealth::new(keystore.dir());
        keystore_health.set_io_hook(keystore.io_hook());
        let keystore_health = Arc::new(keystore_health);
        Self {
            identifier,
            max_signers,
            min_signers,
            keystore,
            keystore_health,
            cosigners: Mutex::new(Default::default()),
            dkg_sessions: Mutex::new(Default::default()),
            refresh_sessions: Mutex::new(Default::default()),
            ceremonies: Mutex::new(Default::default()),
            ceremony_orphan_timeout,
            hosted: None,
        }
    }

    /// Reserve `key_id` for ceremony `owner`. Fails if a *different*, non-orphaned ceremony holds it
    /// — this is what serializes concurrent DKG/refresh and prevents split-brain shares. When it
    /// preempts an *orphaned* guard (a leader that died mid-ceremony, past the timeout), it also
    /// drops that old ceremony's leftover session state so its stale part2/part3 cannot proceed.
    fn acquire_ceremony(&self, key_id: &str, owner: &str, kind: &'static str) -> Result<()> {
        let preempted: Option<String> = {
            let mut guards = self.ceremonies.lock().expect("ceremonies lock");
            let preempted = match guards.get(key_id) {
                Some(cur) if cur.owner != owner => {
                    if cur.started.elapsed() < self.ceremony_orphan_timeout {
                        return Err(DaemonError::CeremonyInProgress {
                            key_id: key_id.to_string(),
                            kind: cur.kind,
                            other: cur.owner.clone(),
                        });
                    }
                    Some(cur.owner.clone()) // orphan — preempt it
                }
                _ => None,
            };
            guards.insert(
                key_id.to_string(),
                CeremonyGuard { owner: owner.to_string(), kind, started: Instant::now() },
            );
            preempted
        }; // ceremonies lock released before touching the session maps (avoid nested locks)
        if let Some(stale) = preempted {
            self.dkg_sessions.lock().expect("dkg lock").remove(&stale);
            self.refresh_sessions.lock().expect("refresh lock").remove(&stale);
        }
        Ok(())
    }

    /// Release the guard for `key_id` iff `owner` still holds it.
    fn release_ceremony(&self, key_id: &str, owner: &str) {
        let mut guards = self.ceremonies.lock().expect("ceremonies lock");
        if guards.get(key_id).map(|c| c.owner == owner).unwrap_or(false) {
            guards.remove(key_id);
        }
    }

    /// Assert ceremony `owner` still holds the guard for `key_id`. A ceremony that was preempted
    /// (its guard taken by a newer one after the orphan timeout) must NOT persist — this is the
    /// load-bearing safety check against a stale leader clobbering/splitting shares on refresh.
    fn assert_owns(&self, key_id: &str, owner: &str) -> Result<()> {
        let guards = self.ceremonies.lock().expect("ceremonies lock");
        match guards.get(key_id) {
            Some(g) if g.owner == owner => Ok(()),
            _ => Err(DaemonError::CeremonySuperseded {
                key_id: key_id.to_string(),
                owner: owner.to_string(),
            }),
        }
    }

    /// Whether a DKG/refresh ceremony currently holds `key_id` (used to fence signing).
    fn ceremony_active(&self, key_id: &str) -> Option<&'static str> {
        self.ceremonies.lock().expect("ceremonies lock").get(key_id).map(|g| g.kind)
    }

    /// Cluster-wide fence step: take the per-key guard *before* DKG/refresh crypto so every peer
    /// refuses new signs while the ceremony is in flight. Refuses if this node still holds
    /// in-flight sign nonces for the key (reverse fence — drain first).
    pub fn ceremony_fence(&self, ceremony_id: &str, key_id: &str, kind: &'static str) -> Result<()> {
        // A DKG/refresh participant persists a share at the very end. On a read-only remount
        // `exists()`/`load()` still work, so without this the ceremony would fail only at this
        // node's final save — after the nodes before it had already persisted theirs: a half-applied
        // refresh, and no signing for that key until repaired. Refusing the fence makes `fence_all`
        // roll back before any crypto. Hosted-key fences (genkey/delkey) are not gated: those writes
        // tolerate a missing replica (write quorum / anti-entropy).
        if matches!(kind, "dkg" | "refresh") {
            self.refuse_if_keystore_down()?;
        }
        // Ids reserved for imported keys are never minted by DKG — refused at the fence, so not
        // even a guard is taken for one.
        if kind == "dkg" && crate::share_delivery::is_reserved_for_import(key_id) {
            return Err(DaemonError::ReservedKeyId(key_id.to_string()));
        }
        let pending = self.pending_sign_count(key_id);
        if pending > 0 {
            return Err(DaemonError::SignInProgress {
                key_id: key_id.to_string(),
                kind,
                pending,
            });
        }
        self.acquire_ceremony(key_id, ceremony_id, kind)
    }

    /// Roll back a fence taken by [`ceremony_fence`] (partial cluster fence / aborted ceremony).
    pub fn ceremony_release(&self, ceremony_id: &str, key_id: &str) {
        self.release_ceremony(key_id, ceremony_id);
    }

    /// Load (and cache) this node's cosigner state for `key_id`.
    fn cosigner(&self, key_id: &str) -> Result<Arc<Cosigner>> {
        {
            let map = self.cosigners.lock().expect("cosigners lock");
            if let Some(c) = map.get(key_id) {
                return Ok(c.clone());
            }
        }
        let share = self.keystore.load(key_id)?;
        let nonce_store = NonceStore::open(self.keystore.nonce_dir(key_id))?;
        let cosigner = Arc::new(Cosigner::new(
            share.key_package,
            share.public_key_package,
            nonce_store,
        ));
        self.cosigners
            .lock()
            .expect("cosigners lock")
            .insert(key_id.to_string(), cosigner.clone());
        Ok(cosigner)
    }

    pub fn has_key(&self, key_id: &str) -> bool {
        self.keystore.exists(key_id)
    }

    /// Run the key-store readiness probe now and publish the verdict (gauge + transition log),
    /// bypassing the Health cache. Blocking filesystem IO; the daemon itself goes through
    /// [`crate::health::probe`].
    pub fn check_keystore(&self) -> Result<()> {
        self.keystore_health.check()
    }

    /// This node's key-store readiness state, for Health and the monitor loop.
    pub fn keystore_health(&self) -> &Arc<crate::health::KeystoreHealth> {
        &self.keystore_health
    }

    /// Serve Health's key-store verdict from cache for `fresh` instead of
    /// [`crate::health::FRESH`]. Tests pass zero so every Health call probes.
    pub fn with_keystore_probe_freshness(mut self, fresh: Duration) -> Self {
        self.keystore_health_mut().set_freshness(fresh);
        self
    }

    /// Publish a hung readiness probe as unresponsive after `after` instead of
    /// [`crate::health::UNRESPONSIVE_AFTER`] (it still takes at least one
    /// [`crate::health::PROBE_TIMEOUT`] to notice). Tests use it to skip the grace.
    pub fn with_keystore_unresponsive_after(mut self, after: Duration) -> Self {
        self.keystore_health_mut().set_unresponsive_after(after);
        self
    }

    fn keystore_health_mut(&mut self) -> &mut crate::health::KeystoreHealth {
        Arc::get_mut(&mut self.keystore_health)
            .expect("configure the key-store probe before the node is shared")
    }

    /// Run `op` against this node on tokio's blocking pool and await it.
    ///
    /// For every node operation an RPC handler (or the in-process [`crate::peer::LocalPeer`])
    /// reaches that may touch the key store: share and hosted-key reads and writes, nonce-marker
    /// lookups and creates. On a hung volume — a dead NFS/CSI mount, a snapshot hook's fsfreeze —
    /// that call parks its thread for as long as the kernel says. On an async worker that would
    /// stall every task the worker serves, and with the shipped 500m CPU limit the cgroup-aware
    /// runtime has exactly one worker: Health, `/metrics` and every peer RPC would freeze together,
    /// before the readiness verdict could turn later calls away. Parked here, it costs one blocking
    /// thread and nothing else.
    ///
    /// `op` runs to completion even if the caller stops waiting (a client deadline, a dropped
    /// request), so a sign round is never cut in half: round 2 still burns its nonce marker before
    /// computing the share, all inside `op`.
    pub async fn blocking<T, F>(self: &Arc<Self>, op: F) -> Result<T>
    where
        F: FnOnce(&Node) -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let node = Arc::clone(self);
        match tokio::task::spawn_blocking(move || op(&node)).await {
            Ok(result) => result,
            // A panic stays a panic, exactly as if `op` had run inline.
            Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
            Err(e) => Err(DaemonError::Io(std::io::Error::other(format!(
                "key-store operation did not run: {e}"
            )))),
        }
    }

    /// `Err(NotServing)` — gRPC UNAVAILABLE — while this node's key store fails its readiness probe
    /// ([`crate::health`]). Checked at the entry of every store-touching Signer RPC (Sign, Dkg,
    /// Refresh, GroupKey and the hosted-key operations), so a sick node declines to LEAD before
    /// starting anything (the driver fails over on UNAVAILABLE — every driver version, not only one
    /// that also fails over on INTERNAL — and no half-run ceremony is left behind); at the DKG/refresh
    /// ceremony fence, so it declines to take part in one; and in [`Node::sign_round1`], so it
    /// declines to JOIN another leader's quorum.
    pub fn refuse_if_keystore_down(&self) -> Result<()> {
        if self.keystore_health.is_down() {
            return Err(DaemonError::NotServing(format!(
                "key store {} failed its readiness probe — not leading or joining an operation it \
                 cannot finish",
                self.keystore.dir().display()
            )));
        }
        Ok(())
    }

    pub fn group_key(&self, key_id: &str) -> Result<[u8; 32]> {
        Ok(group_verifying_key_bytes(self.cosigner(key_id)?.public_key_package())?)
    }

    /// This node's view of FROST key `key_id`, public values only, read from the key file (not the
    /// signing cache) so it shows what is persisted, provenance included. For `verify-key`.
    pub fn key_status(&self, key_id: &str) -> Result<crate::pb::KeyStatusReply> {
        let share = self.keystore.load(key_id)?;
        let kp = &share.key_package;
        let pkp = &share.public_key_package;
        let mut reply = crate::pb::KeyStatusReply {
            identifier: kp.identifier().serialize(),
            group_verifying_key: group_verifying_key_bytes(pkp)?.to_vec(),
            own_verifying_share: kp.verifying_share().serialize()?,
            pkp_digest: rutli_frost_core::dealer::pkp_digest(pkp)?.to_vec(),
            threshold: u32::from(*kp.min_signers()),
            public_key_package: serde_json::to_vec(pkp)?,
            origin: "dkg".into(),
            ..Default::default()
        };
        if let Some(o) = &share.origin {
            reply.origin = o.kind.clone();
            reply.ceremony_id = o.ceremony_id.clone();
            reply.canton_fingerprint = o.canton_fingerprint.clone();
            reply.installed_at = o.installed_at;
            reply.refresh_count = o.refresh_count;
        }
        Ok(reply)
    }

    /// The split-ceremony test digest for `key_id`, computed from the key's recorded provenance —
    /// never from caller input — or `Ceremony` if the key was not installed by the split ceremony.
    pub fn ceremony_test_message(&self, key_id: &str) -> Result<[u8; 34]> {
        let share = self.keystore.load(key_id)?;
        match &share.origin {
            Some(o) if o.kind == crate::keystore::ORIGIN_DEALER_SPLIT => {
                Ok(crate::verify_key::verify_message(&o.ceremony_id, key_id))
            }
            _ => Err(DaemonError::Ceremony(format!(
                "{key_id} has no split-ceremony provenance — the ceremony sign test only signs \
                 for imported keys"
            ))),
        }
    }

    pub fn threshold_for(&self, key_id: &str) -> Result<u16> {
        Ok(self.cosigner(key_id)?.min_signers())
    }

    // -- signing peer ops --

    pub fn sign_round1(&self, key_id: &str, session_id: &str) -> Result<SigningCommitments> {
        // Fence signing against a DKG/refresh in progress for this key: refresh rewrites the share
        // and evicts the cached cosigner, so a NEW sign must not start mid-ceremony. (An already
        // in-flight sign that passed round1 will fail cleanly at round2 if the share was refreshed
        // out from under it — the nonces are gone with the old cosigner.)
        if let Some(kind) = self.ceremony_active(key_id) {
            return Err(DaemonError::CeremonyInProgress {
                key_id: key_id.to_string(),
                kind,
                other: "in progress".to_string(),
            });
        }
        // Nor may a node whose key store failed its readiness probe ([`crate::health`]) volunteer
        // for a quorum. Round 1 can still succeed from the cached share, but round 2 must write a
        // nonce marker and would fail — sinking the signature for whichever healthy leader picked
        // this node, which with identifier-ordered peers is every leader (2026-10-07 incident).
        // Refusing here makes leaders skip it and sign with the rest.
        self.refuse_if_keystore_down()?;
        let result = self.cosigner(key_id)?.round1(session_id);
        self.update_pending_gauge();
        Ok(result?)
    }

    pub fn sign_round2(
        &self,
        key_id: &str,
        session_id: &str,
        message: &[u8],
        commitments: &BTreeMap<Identifier, SigningCommitments>,
    ) -> Result<SignatureShare> {
        // Defense in depth: the leader already rejects non-Canton payloads in `orchestrator::sign`,
        // but THIS is the function the mesh Peer RPC reaches directly. A caller that got onto the
        // Peer API could otherwise collect `threshold` shares over an arbitrary message and
        // aggregate a namespace signature offline, bypassing the leader entirely. The digest guard
        // belongs on both paths; the peer allowlist is the other half of that fix.
        if message.len() != crate::orchestrator::CANTON_DIGEST_LEN {
            return Err(DaemonError::InvalidMessageLength {
                got: message.len(),
                expected: crate::orchestrator::CANTON_DIGEST_LEN,
            });
        }
        let result = self.cosigner(key_id)?.round2(session_id, message, commitments);
        self.update_pending_gauge();
        Ok(result?)
    }

    /// Best-effort abort of an in-flight sign session: free the round-1 nonces held for
    /// `session_id` instead of letting them linger until the pending-TTL sweep. No-op if this node
    /// never held nonces for it (cosigner not cached, or round2 already burned the session).
    pub fn abort_sign(&self, key_id: &str, session_id: &str) {
        let cached = self.cosigners.lock().expect("cosigners lock").get(key_id).cloned();
        if let Some(c) = cached {
            c.abort(session_id);
        }
        self.update_pending_gauge();
    }

    /// In-flight (round-1, not yet round-2) sign sessions currently held for `key_id`; 0 if the
    /// cosigner isn't cached. For observability and abort/TTL tests.
    pub fn pending_sign_count(&self, key_id: &str) -> usize {
        self.cosigners
            .lock()
            .expect("cosigners lock")
            .get(key_id)
            .map(|c| c.pending_count())
            .unwrap_or(0)
    }

    /// Drop in-flight sign sessions past their TTL on every cached key (see
    /// [`crate::health::spawn_monitor`]), and refresh the pending gauge.
    pub fn prune_expired_sign_sessions(&self) {
        let pruned: usize = self
            .cosigners
            .lock()
            .expect("cosigners lock")
            .values()
            .map(|c| c.prune_expired())
            .sum();
        if pruned > 0 {
            tracing::debug!(pruned, "dropped expired in-flight sign sessions");
        }
        self.update_pending_gauge();
    }

    /// In-flight sign sessions across all cached keys on this node.
    pub fn pending_sign_total(&self) -> usize {
        self.cosigners.lock().expect("cosigners lock").values().map(|c| c.pending_count()).sum()
    }

    /// Keep the pending-sessions gauge in step after any round1/round2/abort. No-op without an
    /// installed metrics recorder (tests, metrics disabled).
    fn update_pending_gauge(&self) {
        metrics::gauge!(crate::metrics::PENDING_SIGN_SESSIONS).set(self.pending_sign_total() as f64);
    }

    /// Leader-side aggregation using this node's copy of the group public key.
    pub fn aggregate(
        &self,
        key_id: &str,
        message: &[u8],
        commitments: &BTreeMap<Identifier, SigningCommitments>,
        shares: &BTreeMap<Identifier, SignatureShare>,
    ) -> Result<[u8; 64]> {
        Ok(aggregate(message, commitments, shares, self.cosigner(key_id)?.public_key_package())?)
    }

    // -- DKG peer ops --

    pub fn dkg_part1(&self, dkg_id: &str, key_id: &str) -> Result<round1::Package> {
        // `…frost-import-…` ids belong to the split ceremony. Refusing them here, on every node and
        // whether or not the import has happened yet, means a DKG can never mint a key under an id
        // an operator is about to install (and a half-installed import is never "completed" by one).
        if crate::share_delivery::is_reserved_for_import(key_id) {
            return Err(DaemonError::ReservedKeyId(key_id.to_string()));
        }
        // DKG must never clobber a provisioned key — the namespace key is non-rotatable, so an
        // accidental re-DKG (failover retry, ops mistake) would destroy the node's identity.
        if self.keystore.exists(key_id) {
            return Err(DaemonError::KeyExists(key_id.to_string()));
        }
        // Serialize against any other DKG/refresh for this key (prevents split-brain shares).
        self.acquire_ceremony(key_id, dkg_id, "dkg")?;
        let mut participant = DkgParticipant::new(self.identifier, self.max_signers, self.min_signers);
        match participant.part1() {
            Ok(package) => {
                self.dkg_sessions
                    .lock()
                    .expect("dkg lock")
                    .insert(dkg_id.to_string(), DkgState { key_id: key_id.to_string(), participant });
                Ok(package)
            }
            Err(e) => {
                self.release_ceremony(key_id, dkg_id);
                Err(e.into())
            }
        }
    }

    pub fn dkg_part2(
        &self,
        dkg_id: &str,
        round1_map: &BTreeMap<Identifier, round1::Package>,
    ) -> Result<BTreeMap<Identifier, round2::Package>> {
        let key_id = self.dkg_key_id(dkg_id)?;
        self.assert_owns(&key_id, dkg_id)?; // refuse if a newer ceremony superseded this one
        let mut sessions = self.dkg_sessions.lock().expect("dkg lock");
        let result = {
            let state = sessions.get_mut(dkg_id).ok_or_else(|| DaemonError::UnknownDkg(dkg_id.into()))?;
            let others = without_self(round1_map, self.identifier);
            state.participant.part2(&others)
        };
        match result {
            Ok(packages) => Ok(packages),
            Err(e) => {
                sessions.remove(dkg_id); // prune the failed ceremony's session (no leak)
                drop(sessions);
                self.release_ceremony(&key_id, dkg_id);
                Err(e.into())
            }
        }
    }

    pub fn dkg_part3(
        &self,
        dkg_id: &str,
        round1_map: &BTreeMap<Identifier, round1::Package>,
        round2_for_me: &BTreeMap<Identifier, round2::Package>,
    ) -> Result<[u8; 32]> {
        let mut state = {
            let mut sessions = self.dkg_sessions.lock().expect("dkg lock");
            sessions.remove(dkg_id).ok_or_else(|| DaemonError::UnknownDkg(dkg_id.into()))?
        };
        // Ownership is the load-bearing guard: a ceremony preempted after the orphan timeout must
        // NOT persist, or a stale leader could clobber/split shares (esp. on refresh).
        let outcome = self
            .assert_owns(&state.key_id, dkg_id)
            .and_then(|_| self.finish_dkg(&mut state, round1_map, round2_for_me));
        self.release_ceremony(&state.key_id, dkg_id); // no-op if we no longer own it
        outcome
    }

    fn dkg_key_id(&self, dkg_id: &str) -> Result<String> {
        self.dkg_sessions
            .lock()
            .expect("dkg lock")
            .get(dkg_id)
            .map(|s| s.key_id.clone())
            .ok_or_else(|| DaemonError::UnknownDkg(dkg_id.into()))
    }

    fn finish_dkg(
        &self,
        state: &mut DkgState,
        round1_map: &BTreeMap<Identifier, round1::Package>,
        round2_for_me: &BTreeMap<Identifier, round2::Package>,
    ) -> Result<[u8; 32]> {
        // Re-check under the ceremony guard: refuse if the key was provisioned meanwhile.
        if self.keystore.exists(&state.key_id) {
            return Err(DaemonError::KeyExists(state.key_id.clone()));
        }
        let others = without_self(round1_map, self.identifier);
        let (key_package, public_key_package) = state.participant.part3(&others, round2_for_me)?;

        let share =
            Share { key_package, public_key_package: public_key_package.clone(), origin: None };
        // create, not save: fails if the file appeared since the check above (an import-share run
        // in the pod, a racing ceremony) instead of overwriting it.
        self.keystore.create(&state.key_id, &share)?;
        // Drop any cached cosigner so it is reloaded fresh from the saved share.
        self.cosigners.lock().expect("cosigners lock").remove(&state.key_id);
        Ok(group_verifying_key_bytes(&public_key_package)?)
    }

    // -- proactive refresh peer ops (same three-part shape as DKG) --

    pub fn refresh_part1(&self, refresh_id: &str, key_id: &str) -> Result<round1::Package> {
        if !self.keystore.exists(key_id) {
            return Err(DaemonError::UnknownKey(key_id.to_string()));
        }
        // Reverse fence + acquire (idempotent if the orchestrator already fenced with this id).
        let pending = self.pending_sign_count(key_id);
        if pending > 0 {
            return Err(DaemonError::SignInProgress {
                key_id: key_id.to_string(),
                kind: "refresh",
                pending,
            });
        }
        // Serialize against any other DKG/refresh for this key (prevents split-brain shares).
        self.acquire_ceremony(key_id, refresh_id, "refresh")?;
        let mut participant = RefreshParticipant::new(self.identifier, self.max_signers, self.min_signers);
        match participant.part1() {
            Ok(package) => {
                self.refresh_sessions
                    .lock()
                    .expect("refresh lock")
                    .insert(refresh_id.to_string(), RefreshState { key_id: key_id.to_string(), participant });
                Ok(package)
            }
            Err(e) => {
                self.release_ceremony(key_id, refresh_id);
                Err(e.into())
            }
        }
    }

    pub fn refresh_part2(
        &self,
        refresh_id: &str,
        round1_map: &BTreeMap<Identifier, round1::Package>,
    ) -> Result<BTreeMap<Identifier, round2::Package>> {
        let key_id = self.refresh_key_id(refresh_id)?;
        self.assert_owns(&key_id, refresh_id)?;
        let mut sessions = self.refresh_sessions.lock().expect("refresh lock");
        let result = {
            let state =
                sessions.get_mut(refresh_id).ok_or_else(|| DaemonError::UnknownDkg(refresh_id.into()))?;
            let others = without_self(round1_map, self.identifier);
            state.participant.part2(&others)
        };
        match result {
            Ok(packages) => Ok(packages),
            Err(e) => {
                sessions.remove(refresh_id);
                drop(sessions);
                self.release_ceremony(&key_id, refresh_id);
                Err(e.into())
            }
        }
    }

    pub fn refresh_part3(
        &self,
        refresh_id: &str,
        round1_map: &BTreeMap<Identifier, round1::Package>,
        round2_for_me: &BTreeMap<Identifier, round2::Package>,
    ) -> Result<[u8; 32]> {
        let mut state = {
            let mut sessions = self.refresh_sessions.lock().expect("refresh lock");
            sessions.remove(refresh_id).ok_or_else(|| DaemonError::UnknownDkg(refresh_id.into()))?
        };
        // The load-bearing check for refresh: a superseded refresh must not rewrite shares.
        let outcome = self
            .assert_owns(&state.key_id, refresh_id)
            .and_then(|_| self.finish_refresh(&mut state, round1_map, round2_for_me));
        self.release_ceremony(&state.key_id, refresh_id);
        outcome
    }

    fn refresh_key_id(&self, refresh_id: &str) -> Result<String> {
        self.refresh_sessions
            .lock()
            .expect("refresh lock")
            .get(refresh_id)
            .map(|s| s.key_id.clone())
            .ok_or_else(|| DaemonError::UnknownDkg(refresh_id.into()))
    }

    fn finish_refresh(
        &self,
        state: &mut RefreshState,
        round1_map: &BTreeMap<Identifier, round1::Package>,
        round2_for_me: &BTreeMap<Identifier, round2::Package>,
    ) -> Result<[u8; 32]> {
        let old = self.keystore.load(&state.key_id)?;
        let old_group = group_verifying_key_bytes(&old.public_key_package)?;
        // A dealt key's provenance survives the refresh, which is counted: after the first one, the
        // dealer's copies of the shares no longer combine with the live ones.
        let origin = old.origin.clone().map(|mut o| {
            o.refresh_count += 1;
            o
        });
        let others = without_self(round1_map, self.identifier);
        let (key_package, public_key_package) = state.participant.part3(
            &others,
            round2_for_me,
            old.public_key_package,
            old.key_package,
        )?;

        let new_group = group_verifying_key_bytes(&public_key_package)?;
        if new_group != old_group {
            // Never persist a share whose group key drifted — that would change the node identity.
            return Err(DaemonError::Disagreement(format!(
                "refresh changed the group key for {} — aborting",
                state.key_id
            )));
        }

        let share = Share { key_package, public_key_package, origin };
        self.keystore.save(&state.key_id, &share)?;
        self.cosigners.lock().expect("cosigners lock").remove(&state.key_id);
        Ok(new_group)
    }
}

/// Hosted keys may never live under an id reserved for the split ceremony (`…frost-import-…`).
pub(crate) fn refuse_reserved_for_hosted(key_id: &str) -> Result<()> {
    if crate::share_delivery::is_reserved_for_import(key_id) {
        return Err(DaemonError::ReservedKeyId(key_id.to_string()));
    }
    Ok(())
}

fn without_self(
    map: &BTreeMap<Identifier, round1::Package>,
    me: Identifier,
) -> BTreeMap<Identifier, round1::Package> {
    map.iter().filter(|(&id, _)| id != me).map(|(&id, p)| (id, p.clone())).collect()
}

// ── cluster-hosted (non-FROST) keys ────────────────────────────────────────────────────────────

impl Node {
    /// Enable hosted keys on this node: derive its wrapping key from the cluster master secret and
    /// bind envelopes to `cluster_id`. Without this, every hosted-key op returns an error.
    pub fn with_hosted_keys(mut self, master_secret: &[u8], cluster_id: String) -> Result<Self> {
        let id = crate::hosted::identifier_index(self.identifier)?;
        self.hosted = Some(HostedCtx {
            dist_key: crate::wrap::DistKey::derive(master_secret, id),
            commitment_key: crate::wrap::DistKey::derive(master_secret, COMMITMENT_KEY_INDEX)
                .public_bytes(),
            cluster_id,
            master: zeroize::Zeroizing::new(master_secret.to_vec()),
        });
        Ok(self)
    }

    pub fn hosted_enabled(&self) -> bool {
        self.hosted.is_some()
    }

    fn hosted_ctx(&self) -> Result<&HostedCtx> {
        self.hosted.as_ref().ok_or_else(|| {
            DaemonError::Config(
                "cluster-hosted keys are not enabled on this node (set hosted_keys.enabled and \
                 configure share_seal — hosted keys are never stored unsealed)"
                    .into(),
            )
        })
    }

    /// This node's X25519 distribution public key, for peers wrapping material to it.
    pub fn dist_public_key(&self) -> Result<[u8; 32]> {
        Ok(self.hosted_ctx()?.dist_key.public_bytes())
    }

    pub fn cluster_id(&self) -> Result<&str> {
        Ok(&self.hosted_ctx()?.cluster_id)
    }

    /// The distribution public key of peer `node_identifier`, for wrapping material to it.
    pub fn dist_public_key_for(&self, node_identifier: u16) -> Result<[u8; 32]> {
        let ctx = self.hosted_ctx()?;
        Ok(crate::wrap::DistKey::derive(&ctx.master, node_identifier).public_bytes())
    }

    /// The existing hosted key for `key_id`, if this node already has one.
    ///
    /// Split out from generation so the caller can do the (CPU-heavy) keygen off the async runtime
    /// while keeping the idempotency check here: a retried request must return the existing key
    /// rather than silently minting a second one under the same name.
    pub fn hosted_existing(
        &self,
        key_id: &str,
        spec: crate::hosted::HostedSpec,
    ) -> Result<Option<crate::hosted::HostedKey>> {
        self.hosted_ctx()?;
        if !self.keystore.exists(key_id) {
            return Ok(None);
        }
        let existing = self.keystore.load_hosted(key_id)?;
        if existing.spec != spec {
            return Err(DaemonError::KeyExists(format!(
                "{key_id} already exists with spec {} (requested {})",
                existing.spec.as_str(),
                spec.as_str()
            )));
        }
        Ok(Some(existing))
    }

    /// Generate a hosted key locally. Does **not** replicate — the orchestrator drives that.
    /// Idempotent: an existing key with the same id is returned untouched, so a retried request
    /// (driver failover, client retry) never silently mints a second key under the same name.
    ///
    /// Blocking: RSA keygen is hundreds of milliseconds of CPU. Async callers should use
    /// [`Node::hosted_existing`] plus a `spawn_blocking` keygen instead (see
    /// `orchestrator::generate_hosted_key`); this stays for the sync/offline paths.
    pub fn hosted_generate(
        &self,
        key_id: &str,
        spec: crate::hosted::HostedSpec,
    ) -> Result<(crate::hosted::HostedKey, bool)> {
        self.hosted_ctx()?;
        refuse_reserved_for_hosted(key_id)?;
        if self.keystore.exists(key_id) {
            let existing = self.keystore.load_hosted(key_id)?;
            if existing.spec != spec {
                return Err(DaemonError::KeyExists(format!(
                    "{key_id} already exists with spec {} (requested {})",
                    existing.spec.as_str(),
                    spec.as_str()
                )));
            }
            return Ok((existing, false));
        }
        let key = crate::hosted::HostedKey::generate(spec, crate::hosted::now_secs())?;
        // create, not save: whatever appeared under the id meanwhile is never replaced.
        self.keystore.create_hosted(key_id, &key)?;
        Ok((key, true))
    }

    /// Store a hosted key received from a peer (already unwrapped and verified).
    pub fn hosted_store(&self, key_id: &str, key: &crate::hosted::HostedKey) -> Result<()> {
        self.hosted_ctx()?;
        // A peer may never push a hosted key under an id reserved for the split ceremony: it would
        // squat on an import, or (with a rename-based write) replace an installed share.
        refuse_reserved_for_hosted(key_id)?;
        // Create-once-immutable: a key id maps to one key forever. Canton rotates by minting a new
        // id plus a topology transaction, so a differing replica is a genuine conflict — never a
        // merge. Overwriting here could silently destroy the material peers already committed to.
        let identical_or_conflict = |node: &Node| -> Result<()> {
            let existing = node.keystore.load_hosted(key_id)?;
            if node.hosted_commitment(&existing)? != node.hosted_commitment(key)? {
                return Err(DaemonError::KeyExists(format!(
                    "{key_id} already exists here with different material — refusing to overwrite"
                )));
            }
            Ok(()) // identical replica: idempotent no-op
        };
        if self.keystore.exists(key_id) {
            return identical_or_conflict(self);
        }
        // create, not save: a file that appeared since the check (a racing push, a FROST share) is
        // never renamed over; it is compared like any existing one.
        match self.keystore.create_hosted(key_id, key) {
            Err(DaemonError::KeyExists(_)) => identical_or_conflict(self),
            other => other,
        }
    }

    pub fn hosted_load(&self, key_id: &str) -> Result<crate::hosted::HostedKey> {
        self.hosted_ctx()?;
        self.keystore.load_hosted(key_id)
    }

    pub fn hosted_exists(&self, key_id: &str) -> bool {
        self.keystore.exists(key_id) && self.keystore.load_hosted(key_id).is_ok()
    }

    pub fn hosted_list(&self) -> Result<Vec<String>> {
        self.hosted_ctx()?;
        self.keystore.list_hosted()
    }

    pub fn hosted_delete(&self, key_id: &str) -> Result<bool> {
        self.hosted_ctx()?;
        if !self.keystore.exists(key_id) {
            return Ok(false);
        }
        // Refuse to route a FROST share through the hosted delete path: namespace keys are
        // non-rotatable and deleting one destroys the node's identity.
        self.keystore.load_hosted(key_id)?;
        self.keystore.delete(key_id)?;
        Ok(true)
    }

    /// Keyed digest of a key's material: lets two nodes agree they hold the *same* key without
    /// revealing anything about it. Keyed by the cluster master (via the dist key), so a
    /// commitment is meaningless off-cluster.
    pub fn hosted_commitment(&self, key: &crate::hosted::HostedKey) -> Result<Vec<u8>> {
        let ctx = self.hosted_ctx()?;
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"rutli-keycommit-v1");
        h.update(ctx.commitment_key); // cluster-scoped, not a bare hash of the key
        h.update(key.spec.as_str().as_bytes());
        h.update(key.private_der.as_bytes());
        Ok(h.finalize().to_vec())
    }

    /// Wrap a hosted key for `recipient` (its identifier + distribution public key).
    pub fn hosted_wrap_for(
        &self,
        key_id: &str,
        key: &crate::hosted::HostedKey,
        recipient: u16,
        recipient_pub: &[u8; 32],
    ) -> Result<crate::wrap::Wrapped> {
        let ctx = self.hosted_ctx()?;
        let material = serde_json::to_vec(key)?;
        crate::wrap::wrap_for(
            recipient,
            recipient_pub,
            &material,
            &ctx.cluster_id,
            key_id,
            key.spec.as_str(),
        )
    }

    /// Unwrap an envelope addressed to this node and parse the key.
    pub fn hosted_unwrap(
        &self,
        key_id: &str,
        spec: crate::hosted::HostedSpec,
        w: &crate::wrap::Wrapped,
    ) -> Result<crate::hosted::HostedKey> {
        let ctx = self.hosted_ctx()?;
        let plain = ctx.dist_key.unwrap_key(w, &ctx.cluster_id, key_id, spec.as_str())?;
        let key: crate::hosted::HostedKey = serde_json::from_slice(&plain)?;
        if key.spec != spec {
            return Err(DaemonError::Config(
                "wrapped key spec does not match the declared spec".into(),
            ));
        }
        Ok(key)
    }

    // -- crypto operations served to the driver --

    pub fn hosted_decrypt(&self, key_id: &str, ciphertext: &[u8]) -> Result<Vec<u8>> {
        Ok(self.hosted_load(key_id)?.decrypt_oaep(ciphertext)?.to_vec())
    }

    pub fn hosted_encrypt_symmetric(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>> {
        self.hosted_load(key_id)?.encrypt_symmetric(data)
    }

    pub fn hosted_decrypt_symmetric(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>> {
        Ok(self.hosted_load(key_id)?.decrypt_symmetric(data)?.to_vec())
    }
}
