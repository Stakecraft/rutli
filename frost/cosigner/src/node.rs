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

use crate::ceremony_record::{CeremonyRecord, CeremonyRecords, Decision, RecordState, StatusInfo};
use crate::keystore::{KeyStore, Share};
use crate::{DaemonError, Result};

/// The all-node ceremonies that write FROST shares, both two-phase (see [`crate::ceremony_record`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CeremonyKind {
    Dkg,
    Refresh,
}

impl CeremonyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            CeremonyKind::Dkg => "dkg",
            CeremonyKind::Refresh => "refresh",
        }
    }

    pub fn parse(kind: &str) -> Result<Self> {
        match kind {
            "dkg" => Ok(CeremonyKind::Dkg),
            "refresh" => Ok(CeremonyKind::Refresh),
            other => Err(DaemonError::Config(format!(
                "ceremony kind must be \"dkg\" or \"refresh\", got {other:?}"
            ))),
        }
    }
}

enum Participant {
    Dkg(DkgParticipant),
    Refresh(RefreshParticipant),
}

/// One ceremony this node takes part in, between part 1 and its vote. Memory only: a restart
/// drops it, and the node then votes no ([`Node::ceremony_status`]).
struct Session {
    key_id: String,
    kind: CeremonyKind,
    /// `None` while part 3 runs: the session is finishing and is no longer abortable.
    participant: Option<Participant>,
    started: Instant,
}

/// Ceremony sessions and votes under one lock, so "no session and no record" is decided
/// atomically with writing the no-vote that answer implies.
#[derive(Default)]
struct CeremonyBook {
    sessions: std::collections::HashMap<String, Session>,
    records: BTreeMap<String, CeremonyRecord>,
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

/// The epoch a DKG commits its key at; each committed refresh adds one.
pub const FIRST_EPOCH: u64 = 1;

pub struct Node {
    pub identifier: Identifier,
    pub max_signers: u16,
    pub min_signers: u16,
    keystore: KeyStore,
    /// Key-store readiness verdict (see [`crate::health`]), shared with Health and the monitor.
    keystore_health: Arc<crate::health::KeystoreHealth>,
    cosigners: Mutex<std::collections::HashMap<String, Arc<Cosigner>>>,
    // key_id -> the ceremony currently allowed to (re)write that key's share.
    ceremonies: Mutex<std::collections::HashMap<String, CeremonyGuard>>,
    ceremony_orphan_timeout: Duration,
    /// This node's durable ceremony votes (see [`crate::ceremony_record`]), cached in `book` and
    /// written through to `keys/.ceremonies/`. One lock: every vote change is serialized.
    record_store: CeremonyRecords,
    book: Mutex<CeremonyBook>,
    /// The other cosigners, as this node dials them (per-peer TLS names). Set once by the daemon
    /// after building the roster; the ceremony resolver talks to peers directly through it, never
    /// through the leader.
    mesh: std::sync::OnceLock<Vec<Arc<dyn crate::peer::PeerApi>>>,
    /// Set when hosted (non-FROST) keys are enabled: this node's derived wrapping key plus the
    /// cluster identity envelopes are bound to. `None` disables every hosted-key operation.
    hosted: Option<HostedCtx>,
}

/// What a node needs to take part in hosted-key replication, built from its seal keys and config
/// by [`crate::seal::SealKeys::hosted_keyring`].
pub struct HostedKeyring {
    /// This node's distribution keypair (it unwraps envelopes addressed to it).
    pub dist_key: crate::wrap::DistKey,
    /// The cluster-wide key [`Node::hosted_commitment`] is keyed by (see
    /// [`crate::wrap::COMMITMENT_KEY_INDEX`]); the same on every node.
    pub commitment_key: [u8; 32],
    /// The distribution public key of every roster node, this one included, by identifier:
    /// pinned in config on a seal bundle, derived from the master on the legacy path. A node is
    /// never wrapped material under any other key.
    pub peer_dist_keys: BTreeMap<u16, [u8; 32]>,
}

struct HostedCtx {
    dist_key: crate::wrap::DistKey,
    /// Public, cluster-wide commitment key (see [`HostedKeyring::commitment_key`]).
    commitment_key: [u8; 32],
    cluster_id: String,
    /// Every roster node's distribution public key, for wrapping material to it (FetchKey,
    /// replication). Holding the master is no longer needed: a peer's key is looked up, not derived.
    peer_dist_keys: BTreeMap<u16, [u8; 32]>,
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
        let record_store = CeremonyRecords::open(keystore.ceremony_dir());
        let records = match record_store.load_all() {
            Ok(list) => list.into_iter().map(|r| (r.ceremony_id.clone(), r)).collect(),
            Err(e) => {
                // Unreadable record directory: start with no cached votes and say so. A ceremony this
                // node voted in will read as unknown to peers — they wait, they never commit on it.
                tracing::error!(error = %e, "cannot read this node's ceremony records");
                BTreeMap::new()
            }
        };
        let node = Self {
            identifier,
            max_signers,
            min_signers,
            keystore,
            keystore_health,
            cosigners: Mutex::new(Default::default()),
            ceremonies: Mutex::new(Default::default()),
            ceremony_orphan_timeout,
            record_store,
            book: Mutex::new(CeremonyBook { sessions: Default::default(), records }),
            mesh: std::sync::OnceLock::new(),
            hosted: None,
        };
        if let Err(e) = node.recover_ceremonies() {
            tracing::error!(error = %e, "ceremony recovery at startup failed");
        }
        node
    }

    /// Startup repair of the two-phase ceremony state, for what a crash can leave behind:
    ///
    /// * a staged share with no STAGED record (crashed between writing the share and the vote, or
    ///   an aborted ceremony whose share delete did not finish): deleted — nobody can commit a
    ///   ceremony this node never voted yes on;
    /// * a STAGED record whose staged share is gone: if the live share is exactly the staged
    ///   outcome the node crashed between promoting it and recording COMMITTED, so the record is
    ///   completed; anything else is reported and left STAGED for an operator.
    pub fn recover_ceremonies(&self) -> Result<()> {
        let mut book = self.book.lock().expect("ceremony lock");
        let records = &mut book.records;
        for (key_id, ceremony_id) in self.keystore.list_staged()? {
            let voted_yes = records
                .get(&ceremony_id)
                .is_some_and(|r| r.state == RecordState::Staged && r.key_id == key_id);
            if !voted_yes {
                self.keystore.discard_staged(&key_id, &ceremony_id)?;
                tracing::warn!(
                    key_id = %key_id,
                    ceremony_id = %ceremony_id,
                    "removed a staged share without a staged vote (interrupted or aborted ceremony)"
                );
            }
        }
        let pending: Vec<CeremonyRecord> =
            records.values().filter(|r| r.state == RecordState::Staged).cloned().collect();
        for rec in pending {
            if self.keystore.has_staged(&rec.key_id, &rec.ceremony_id)? {
                continue;
            }
            let promoted = match self.keystore.load(&rec.key_id) {
                Ok(share) => {
                    share.epoch == rec.new_epoch
                        && hex::encode(share.pkp_digest()?) == rec.new_pkp_digest
                }
                Err(_) => false,
            };
            if promoted {
                let done = CeremonyRecord {
                    state: RecordState::Committed,
                    updated_ms: crate::ceremony_record::now_ms(),
                    ..rec.clone()
                };
                self.record_store.write(Some(&rec), &done)?;
                records.insert(done.ceremony_id.clone(), done);
                tracing::info!(
                    key_id = %rec.key_id,
                    ceremony_id = %rec.ceremony_id,
                    epoch = rec.new_epoch,
                    "completed a ceremony commit interrupted after the share was promoted"
                );
            } else {
                tracing::error!(
                    key_id = %rec.key_id,
                    ceremony_id = %rec.ceremony_id,
                    "STAGED ceremony record whose staged share is missing and whose live share is \
                     not the staged outcome — this node cannot commit it; an operator must resolve \
                     it (docs/ceremonies.md)"
                );
            }
        }
        Ok(())
    }

    /// This node's record for `ceremony_id`, if it has voted in it.
    pub fn ceremony_record(&self, ceremony_id: &str) -> Option<CeremonyRecord> {
        self.book.lock().expect("ceremony lock").records.get(ceremony_id).cloned()
    }

    /// Every ceremony record this node holds.
    pub fn all_records(&self) -> Vec<CeremonyRecord> {
        self.book.lock().expect("ceremony lock").records.values().cloned().collect()
    }

    /// Staged share files on disk, as `(key_id, ceremony_id)`.
    pub fn staged_share_files(&self) -> Result<Vec<(String, String)>> {
        self.keystore.list_staged()
    }

    /// This node's key-store directory (`data_dir/keys`).
    pub fn key_store_dir(&self) -> &std::path::Path {
        self.keystore.dir()
    }

    /// Every ceremony this node has voted yes on and not yet resolved.
    pub fn staged_records(&self) -> Vec<CeremonyRecord> {
        self.book
            .lock()
            .expect("ceremony lock")
            .records
            .values()
            .filter(|r| r.state == RecordState::Staged)
            .cloned()
            .collect()
    }

    /// This node's view of key `key_id` for ceremony decisions: its committed share's epoch, PKP
    /// digest and group key (public values only), and whether a ceremony for it is staged here.
    /// Absent key: `present = false`. A hosted key under the id: `present`, origin "hosted".
    pub fn key_epoch(&self, key_id: &str) -> Result<crate::pb::KeyEpochReply> {
        let mut reply = crate::pb::KeyEpochReply::default();
        match self.keystore.load_record(key_id) {
            Ok(crate::keystore::Record::Frost(share)) => {
                reply.present = true;
                reply.epoch = share.epoch;
                reply.pkp_digest = share.pkp_digest()?.to_vec();
                reply.group_verifying_key = group_verifying_key_bytes(&share.public_key_package)?.to_vec();
                reply.origin = share.origin.as_ref().map(|o| o.kind.clone()).unwrap_or_else(|| "dkg".into());
            }
            Ok(crate::keystore::Record::Hosted(_)) => {
                reply.present = true;
                reply.origin = "hosted".into();
            }
            Err(DaemonError::UnknownKey(_)) => {}
            Err(e) => return Err(e),
        }
        if let Some(r) = self.staged_records().into_iter().find(|r| r.key_id == key_id) {
            reply.staged = true;
            reply.staged_ceremony_id = r.ceremony_id;
            reply.staged_new_epoch = r.new_epoch;
            reply.staged_new_pkp_digest = hex::decode(&r.new_pkp_digest).unwrap_or_default();
        }
        Ok(reply)
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
            // Its session is dropped; this node's vote on it is no (recorded the first time anyone
            // asks — see `ceremony_status`).
            self.book.lock().expect("ceremony lock").sessions.remove(&stale);
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
            epoch: share.epoch,
            ..Default::default()
        };
        if let Some(o) = &share.origin {
            reply.origin = o.kind.clone();
            reply.ceremony_id = o.ceremony_id.clone();
            reply.canton_fingerprint = o.canton_fingerprint.clone();
            reply.installed_at = o.installed_at;
            reply.refresh_count = o.refresh_count;
            if let Some(u) = &o.carried_usage {
                reply.carried_for = u.expected.clone();
                reply.recorded_usage = match &u.recorded {
                    Some(list) => list.join(","),
                    None => "unknown".into(),
                };
            }
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

    // -- two-phase DKG / refresh (see crate::ceremony_record for the state machine) --

    /// Attach the mesh: every roster peer as this node dials it. Self entries are dropped (a node
    /// never asks itself over the mesh). Set once.
    pub fn set_mesh(&self, peers: Vec<Arc<dyn crate::peer::PeerApi>>) -> Result<()> {
        let me = self.identifier;
        let others: Vec<_> = peers.into_iter().filter(|p| p.identifier() != me).collect();
        self.mesh
            .set(others)
            .map_err(|_| DaemonError::Config("the node's mesh is already set".into()))
    }

    pub fn has_mesh(&self) -> bool {
        self.mesh.get().is_some()
    }

    /// The mesh peer with configured identifier `id`, if this node has one.
    pub fn mesh_peer(&self, id: u16) -> Option<Arc<dyn crate::peer::PeerApi>> {
        let want = Identifier::try_from(id).ok()?;
        self.mesh.get()?.iter().find(|p| p.identifier() == want).cloned()
    }

    /// This node's configured identifier as a number.
    pub fn index(&self) -> Result<u16> {
        crate::hosted::identifier_index(self.identifier)
    }

    /// The fence for a DKG or refresh: [`Node::ceremony_fence`] plus the two-phase rules. Refuses
    /// while a ceremony for `key_id` is staged here (it must resolve first), a DKG over an
    /// existing key, and a refresh whose leader saw a different sharing than this node holds
    /// (`expect` = the leader's (epoch, PKP digest)) — a refresh must start from one sharing on
    /// every node, or it would fold fresh zero-shares into mixed epochs (H1).
    pub fn ceremony_begin(
        &self,
        ceremony_id: &str,
        key_id: &str,
        kind: CeremonyKind,
        expect: Option<(u64, [u8; 32])>,
    ) -> Result<()> {
        crate::keystore::validate_ceremony_id(ceremony_id)?;
        self.refuse_if_staged(key_id)?;
        match kind {
            CeremonyKind::Dkg => {
                if self.keystore.exists(key_id) {
                    return Err(DaemonError::KeyExists(key_id.to_string()));
                }
            }
            CeremonyKind::Refresh => {
                let share = self.keystore.load(key_id)?;
                if let Some((epoch, digest)) = expect {
                    let mine = share.pkp_digest()?;
                    if share.epoch != epoch || mine != digest {
                        return Err(DaemonError::CeremonyRefused(format!(
                            "refresh of {key_id}: this node holds epoch {} (pkp {}…) but the leader \
                             expects epoch {epoch} (pkp {}…) — the nodes are not on one sharing",
                            share.epoch,
                            &hex::encode(mine)[..12],
                            &hex::encode(digest)[..12]
                        )));
                    }
                }
            }
        }
        self.ceremony_fence(ceremony_id, key_id, kind.as_str())
    }

    fn refuse_if_staged(&self, key_id: &str) -> Result<()> {
        let book = self.book.lock().expect("ceremony lock");
        if let Some(r) =
            book.records.values().find(|r| r.state == RecordState::Staged && r.key_id == key_id)
        {
            return Err(DaemonError::CeremonyRefused(format!(
                "ceremony {} for {key_id} is staged on this node and not yet resolved — its \
                 resolver must commit or abort it first",
                r.ceremony_id
            )));
        }
        Ok(())
    }

    /// Part 1 of either ceremony: take the guard, start the session, return the round-1 package.
    fn start_session(&self, ceremony_id: &str, key_id: &str, kind: CeremonyKind) -> Result<round1::Package> {
        crate::keystore::validate_ceremony_id(ceremony_id)?;
        self.refuse_if_staged(key_id)?;
        self.acquire_ceremony(key_id, ceremony_id, kind.as_str())?;
        let mut participant = match kind {
            CeremonyKind::Dkg => {
                Participant::Dkg(DkgParticipant::new(self.identifier, self.max_signers, self.min_signers))
            }
            CeremonyKind::Refresh => Participant::Refresh(RefreshParticipant::new(
                self.identifier,
                self.max_signers,
                self.min_signers,
            )),
        };
        let package = match &mut participant {
            Participant::Dkg(p) => p.part1(),
            Participant::Refresh(p) => p.part1(),
        };
        let package = match package {
            Ok(p) => p,
            Err(e) => {
                self.release_ceremony(key_id, ceremony_id);
                return Err(e.into());
            }
        };
        let mut book = self.book.lock().expect("ceremony lock");
        // A ceremony id is used once per node: a node that already voted on it (or answered for
        // it as unknown, which is a no-vote) never starts it again.
        if book.records.contains_key(ceremony_id) || book.sessions.contains_key(ceremony_id) {
            drop(book);
            self.release_ceremony(key_id, ceremony_id);
            return Err(DaemonError::CeremonyRefused(format!(
                "ceremony id {ceremony_id} was already used on this node"
            )));
        }
        book.sessions.insert(
            ceremony_id.to_string(),
            Session { key_id: key_id.to_string(), kind, participant: Some(participant), started: Instant::now() },
        );
        Ok(package)
    }

    /// The key id of live session `ceremony_id` of `kind`.
    fn session_key(&self, ceremony_id: &str, kind: CeremonyKind) -> Result<String> {
        let book = self.book.lock().expect("ceremony lock");
        match book.sessions.get(ceremony_id) {
            Some(s) if s.kind == kind => Ok(s.key_id.clone()),
            _ => Err(DaemonError::UnknownDkg(ceremony_id.into())),
        }
    }

    /// Record a no-vote for `ceremony_id` unless this node already recorded a vote. Caller holds
    /// the ceremony lock.
    fn record_abort_locked(&self, book: &mut CeremonyBook, ceremony_id: &str, reason: &str) -> Result<()> {
        if book.records.contains_key(ceremony_id) {
            return Ok(());
        }
        let rec = CeremonyRecord::aborted(ceremony_id, reason);
        self.record_store.write(None, &rec)?;
        book.records.insert(ceremony_id.to_string(), rec);
        Ok(())
    }

    /// Drop a failed session and vote no on it. Best effort on the vote: a peer asking later gets
    /// the same answer from [`Node::ceremony_status`].
    fn fail_session(&self, ceremony_id: &str, key_id: &str, reason: &str) {
        {
            let mut book = self.book.lock().expect("ceremony lock");
            book.sessions.remove(ceremony_id);
            if let Err(e) = self.record_abort_locked(&mut book, ceremony_id, reason) {
                tracing::warn!(ceremony_id, error = %e, "could not record an aborted ceremony");
            }
        }
        self.release_ceremony(key_id, ceremony_id);
    }

    /// Run part 2 of either ceremony against the session's participant.
    fn session_part2(
        &self,
        ceremony_id: &str,
        kind: CeremonyKind,
        round1_map: &BTreeMap<Identifier, round1::Package>,
    ) -> Result<BTreeMap<Identifier, round2::Package>> {
        let key_id = self.session_key(ceremony_id, kind)?;
        self.assert_owns(&key_id, ceremony_id)?; // refuse if a newer ceremony superseded this one
        let others = without_self(round1_map, self.identifier);
        let result = {
            let mut book = self.book.lock().expect("ceremony lock");
            let session =
                book.sessions.get_mut(ceremony_id).ok_or_else(|| DaemonError::UnknownDkg(ceremony_id.into()))?;
            match session.participant.as_mut() {
                Some(Participant::Dkg(p)) => p.part2(&others).map_err(DaemonError::from),
                Some(Participant::Refresh(p)) => p.part2(&others).map_err(DaemonError::from),
                None => Err(DaemonError::CeremonyRefused(format!("ceremony {ceremony_id} is finishing"))),
            }
        };
        if let Err(e) = &result {
            self.fail_session(ceremony_id, &key_id, &format!("part 2 failed: {e}"));
        }
        result
    }

    /// Part 3 of either ceremony: compute the new share (`finish`), then vote yes durably — the
    /// staged share first, fsynced, then the STAGED record. Any failure votes no instead. The
    /// guard is released either way; the share only goes live on commit ([`Node::apply_resolution`]).
    fn finish_session(
        &self,
        ceremony_id: &str,
        kind: CeremonyKind,
        roster: Vec<u16>,
        round1_digest: Option<[u8; 32]>,
        finish: impl FnOnce(&str, Participant) -> Result<(Share, Option<KeyVersion>)>,
    ) -> Result<StagedOutcome> {
        let (key_id, participant) = {
            let mut book = self.book.lock().expect("ceremony lock");
            let session = match book.sessions.get_mut(ceremony_id) {
                Some(s) if s.kind == kind => s,
                _ => return Err(DaemonError::UnknownDkg(ceremony_id.into())),
            };
            let participant = session.participant.take().ok_or_else(|| {
                DaemonError::CeremonyRefused(format!("ceremony {ceremony_id} is already finishing"))
            })?;
            (session.key_id.clone(), participant)
        };
        // Ownership is the load-bearing guard: a ceremony preempted after the orphan timeout must
        // NOT stage, or a stale leader could split shares.
        let staged = self
            .assert_owns(&key_id, ceremony_id)
            .and_then(|_| finish(&key_id, participant))
            .and_then(|(share, old)| self.stage_vote(ceremony_id, kind, &key_id, roster, round1_digest, share, old));
        if let Err(e) = &staged {
            // No STAGED record exists, so the staged share (if written) is nobody's yes-vote.
            let _ = self.keystore.discard_staged(&key_id, ceremony_id);
            self.fail_session(ceremony_id, &key_id, &format!("part 3 failed: {e}"));
        } else {
            self.release_ceremony(&key_id, ceremony_id);
        }
        staged
    }

    #[allow(clippy::too_many_arguments)]
    fn stage_vote(
        &self,
        ceremony_id: &str,
        kind: CeremonyKind,
        key_id: &str,
        roster: Vec<u16>,
        round1_digest: Option<[u8; 32]>,
        share: Share,
        old: Option<(u64, [u8; 32])>,
    ) -> Result<StagedOutcome> {
        let outcome = StagedOutcome {
            new_epoch: share.epoch,
            new_pkp_digest: share.pkp_digest()?,
            group_key: group_verifying_key_bytes(&share.public_key_package)?,
        };
        self.keystore.stage(key_id, ceremony_id, &share)?;
        let now = crate::ceremony_record::now_ms();
        let rec = CeremonyRecord {
            ceremony_id: ceremony_id.to_string(),
            state: RecordState::Staged,
            key_id: key_id.to_string(),
            kind: kind.as_str().to_string(),
            roster,
            old_epoch: old.map(|o| o.0).unwrap_or(0),
            old_pkp_digest: old.map(|o| hex::encode(o.1)).unwrap_or_default(),
            new_epoch: outcome.new_epoch,
            new_pkp_digest: hex::encode(outcome.new_pkp_digest),
            group_key: hex::encode(outcome.group_key),
            round1_digest: round1_digest.map(hex::encode).unwrap_or_default(),
            reason: String::new(),
            peers_settled: false,
            created_ms: now,
            updated_ms: now,
        };
        let mut book = self.book.lock().expect("ceremony lock");
        // `write` refuses if a vote already exists (a no-vote recorded meanwhile stays a no-vote).
        self.record_store.write(book.records.get(ceremony_id), &rec)?;
        book.records.insert(ceremony_id.to_string(), rec);
        book.sessions.remove(ceremony_id);
        tracing::info!(
            ceremony_id,
            key_id,
            kind = kind.as_str(),
            epoch = outcome.new_epoch,
            "ceremony staged (yes-vote recorded); committing once every node confirms"
        );
        Ok(outcome)
    }

    /// DKG part 3's computation: the new share at [`FIRST_EPOCH`].
    fn dkg_share(
        &self,
        key_id: &str,
        participant: Participant,
        round1_map: &BTreeMap<Identifier, round1::Package>,
        round2_for_me: &BTreeMap<Identifier, round2::Package>,
    ) -> Result<(Share, Option<KeyVersion>)> {
        let Participant::Dkg(mut p) = participant else {
            return Err(DaemonError::CeremonyRefused("not a DKG session".into()));
        };
        // Re-check under the ceremony guard: refuse if the key was provisioned meanwhile.
        if self.keystore.exists(key_id) {
            return Err(DaemonError::KeyExists(key_id.to_string()));
        }
        let others = without_self(round1_map, self.identifier);
        let (key_package, public_key_package) = p.part3(&others, round2_for_me)?;
        let share = Share {
            key_package,
            public_key_package,
            origin: None,
            epoch: FIRST_EPOCH,
            key_id: key_id.to_string(),
        };
        Ok((share, None))
    }

    /// Refresh part 3's computation: the old share with the zero-sharing folded in, at the old
    /// epoch + 1, and the (epoch, PKP digest) it replaces.
    fn refresh_share(
        &self,
        key_id: &str,
        participant: Participant,
        round1_map: &BTreeMap<Identifier, round1::Package>,
        round2_for_me: &BTreeMap<Identifier, round2::Package>,
    ) -> Result<(Share, Option<KeyVersion>)> {
        let Participant::Refresh(mut p) = participant else {
            return Err(DaemonError::CeremonyRefused("not a refresh session".into()));
        };
        let old = self.keystore.load(key_id)?;
        let old_group = group_verifying_key_bytes(&old.public_key_package)?;
        let old_version = (old.epoch, old.pkp_digest()?);
        // A dealt key's provenance survives the refresh, which is counted: after the first one, the
        // dealer's copies of the shares no longer combine with the live ones.
        let origin = old.origin.clone().map(|mut o| {
            o.refresh_count += 1;
            o
        });
        let others = without_self(round1_map, self.identifier);
        let (key_package, public_key_package) =
            p.part3(&others, round2_for_me, old.public_key_package, old.key_package)?;
        if group_verifying_key_bytes(&public_key_package)? != old_group {
            // Never stage a share whose group key drifted — that would change the node identity.
            return Err(DaemonError::Disagreement(format!(
                "refresh changed the group key for {key_id} — aborting"
            )));
        }
        let share = Share {
            key_package,
            public_key_package,
            origin,
            epoch: old_version.0 + 1,
            key_id: key_id.to_string(),
        };
        Ok((share, Some(old_version)))
    }

    /// What this node can say about `ceremony_id` (`Peer.CeremonyStatus`): its recorded vote, or
    /// IN_PROGRESS while the session lives. With neither, it durably votes no **before** answering
    /// ABORTED — so the answer can never change later — and the same for a session orphaned past
    /// the orphan timeout (its leader is gone; part 3 will never come).
    pub fn ceremony_status(&self, ceremony_id: &str) -> Result<StatusInfo> {
        crate::keystore::validate_ceremony_id(ceremony_id)?;
        let mut release = None;
        let info = {
            let mut book = self.book.lock().expect("ceremony lock");
            if let Some(r) = book.records.get(ceremony_id) {
                return Ok(StatusInfo::from_record(r));
            }
            match book.sessions.get(ceremony_id) {
                Some(s) if s.participant.is_none() || s.started.elapsed() < self.ceremony_orphan_timeout => {
                    return Ok(StatusInfo::in_progress());
                }
                Some(_) => {
                    let s = book.sessions.remove(ceremony_id).expect("present");
                    release = Some(s.key_id);
                    self.record_abort_locked(&mut book, ceremony_id, "orphaned: no part 3 within the orphan timeout")?;
                }
                None => self.record_abort_locked(
                    &mut book,
                    ceremony_id,
                    "unknown here: no session and no record when a peer asked",
                )?,
            }
            StatusInfo::from_record(book.records.get(ceremony_id).expect("just recorded"))
        };
        if let Some(key_id) = release {
            self.release_ceremony(&key_id, ceremony_id);
        }
        Ok(info)
    }

    /// The leader gives up on `ceremony_id` (`Peer.CeremonyAbort`). Only a session still in memory
    /// is dropped (with a durable no-vote); a recorded vote is never changed by the leader's word —
    /// a STAGED node aborts only on evidence from its peers ([`crate::ceremony::resolve`]).
    pub fn ceremony_abort(&self, ceremony_id: &str) -> Result<StatusInfo> {
        crate::keystore::validate_ceremony_id(ceremony_id)?;
        let mut release = None;
        let info = {
            let mut book = self.book.lock().expect("ceremony lock");
            if let Some(r) = book.records.get(ceremony_id) {
                return Ok(StatusInfo::from_record(r));
            }
            if let Some(s) = book.sessions.get(ceremony_id) {
                if s.participant.is_none() {
                    return Ok(StatusInfo::in_progress()); // part 3 running; it will vote
                }
                release = book.sessions.remove(ceremony_id).map(|s| s.key_id);
            }
            self.record_abort_locked(&mut book, ceremony_id, "aborted by the ceremony leader")?;
            StatusInfo::from_record(book.records.get(ceremony_id).expect("just recorded"))
        };
        if let Some(key_id) = release {
            self.release_ceremony(&key_id, ceremony_id);
        }
        Ok(info)
    }

    /// Apply the resolver's verdict to a STAGED ceremony: commit (promote the staged share, then
    /// record COMMITTED) or abort (delete it, then record ABORTED). A record that is not STAGED is
    /// returned unchanged — resolution is idempotent and a terminal vote never changes.
    pub fn apply_resolution(&self, ceremony_id: &str, decision: &Decision) -> Result<StatusInfo> {
        let mut book = self.book.lock().expect("ceremony lock");
        let rec = book
            .records
            .get(ceremony_id)
            .cloned()
            .ok_or_else(|| DaemonError::UnknownDkg(ceremony_id.into()))?;
        if rec.state != RecordState::Staged {
            return Ok(StatusInfo::from_record(&rec));
        }
        let (state, reason) = match decision {
            Decision::Wait(_) => return Ok(StatusInfo::from_record(&rec)),
            Decision::Commit => {
                self.commit_staged(&rec)?;
                (RecordState::Committed, String::new())
            }
            Decision::Abort(why) => {
                self.keystore.discard_staged(&rec.key_id, ceremony_id)?;
                (RecordState::Aborted, why.clone())
            }
        };
        let done = CeremonyRecord {
            state,
            reason,
            updated_ms: crate::ceremony_record::now_ms(),
            ..rec.clone()
        };
        self.record_store.write(Some(&rec), &done)?;
        book.records.insert(ceremony_id.to_string(), done.clone());
        drop(book);
        if state == RecordState::Committed {
            // The next sign loads the committed share.
            self.cosigners.lock().expect("cosigners lock").remove(&rec.key_id);
            tracing::info!(ceremony_id, key_id = %rec.key_id, epoch = rec.new_epoch, "ceremony committed");
        } else {
            tracing::warn!(ceremony_id, key_id = %rec.key_id, reason = %done.reason, "ceremony aborted");
        }
        metrics::counter!(crate::metrics::CEREMONY_RESOLUTIONS, "result" => state.as_str()).increment(1);
        Ok(StatusInfo::from_record(&done))
    }

    /// Make a STAGED ceremony's share live. DKG: create-once (a different key appearing under the
    /// id refuses the commit). Refresh: replace the live share only if it is still exactly the one
    /// the refresh started from. A share already promoted by an interrupted commit counts as done.
    fn commit_staged(&self, rec: &CeremonyRecord) -> Result<()> {
        let is_outcome = |s: &Share| -> Result<bool> {
            Ok(s.epoch == rec.new_epoch && hex::encode(s.pkp_digest()?) == rec.new_pkp_digest)
        };
        if !self.keystore.has_staged(&rec.key_id, &rec.ceremony_id)? {
            return match self.keystore.load(&rec.key_id) {
                Ok(live) if is_outcome(&live)? => Ok(()),
                _ => Err(DaemonError::Disagreement(format!(
                    "ceremony {}: the staged share for {} is missing — cannot commit",
                    rec.ceremony_id, rec.key_id
                ))),
            };
        }
        match CeremonyKind::parse(&rec.kind)? {
            CeremonyKind::Dkg => match self.keystore.promote_staged(&rec.key_id, &rec.ceremony_id, false)? {
                crate::keystore::Promotion::Promoted => Ok(()),
                crate::keystore::Promotion::TargetExists => {
                    if is_outcome(&self.keystore.load(&rec.key_id)?)? {
                        self.keystore.discard_staged(&rec.key_id, &rec.ceremony_id)
                    } else {
                        Err(DaemonError::Disagreement(format!(
                            "ceremony {}: a different key appeared under {} — refusing to commit \
                             over it",
                            rec.ceremony_id, rec.key_id
                        )))
                    }
                }
            },
            CeremonyKind::Refresh => {
                let live = self.keystore.load(&rec.key_id)?;
                if is_outcome(&live)? {
                    return self.keystore.discard_staged(&rec.key_id, &rec.ceremony_id);
                }
                if live.epoch != rec.old_epoch || hex::encode(live.pkp_digest()?) != rec.old_pkp_digest {
                    return Err(DaemonError::Disagreement(format!(
                        "ceremony {}: the live share of {} (epoch {}) is not the one this refresh \
                         started from (epoch {}) — refusing to replace it",
                        rec.ceremony_id, rec.key_id, live.epoch, rec.old_epoch
                    )));
                }
                self.keystore.promote_staged(&rec.key_id, &rec.ceremony_id, true)?;
                Ok(())
            }
        }
    }

    /// Whether this node has a staged or committed ceremony record for `key_id`.
    pub fn has_ceremony_for(&self, key_id: &str) -> bool {
        self.book
            .lock()
            .expect("ceremony lock")
            .records
            .values()
            .any(|r| r.key_id == key_id && r.state != RecordState::Aborted)
    }

    /// Delete this node's file for `key_id` and its (empty) nonce directory — the last step of
    /// [`crate::ceremony::discard_partial_key`], which checks everything else first. Refuses if
    /// any signing session was ever burned for the key here.
    pub fn discard_local_key(&self, key_id: &str) -> Result<()> {
        let nonces = self.keystore.nonce_dir(key_id);
        if nonces.try_exists()? && std::fs::read_dir(&nonces)?.next().is_some() {
            return Err(DaemonError::CeremonyRefused(format!(
                "{key_id} has signed on this node (nonce markers in {}) — refusing to discard it",
                nonces.display()
            )));
        }
        self.keystore.delete(key_id)?;
        if nonces.try_exists()? {
            std::fs::remove_dir(&nonces)?;
        }
        self.cosigners.lock().expect("cosigners lock").remove(key_id);
        tracing::warn!(key_id, "discarded this node's file for a legacy partial DKG key");
        Ok(())
    }

    /// Terminal records not yet known to be settled on every peer.
    pub fn unsettled_records(&self) -> Vec<CeremonyRecord> {
        self.book
            .lock()
            .expect("ceremony lock")
            .records
            .values()
            .filter(|r| r.is_terminal() && !r.peers_settled && !r.roster.is_empty())
            .cloned()
            .collect()
    }

    /// Note that every peer has resolved `ceremony_id` too.
    pub fn mark_settled(&self, ceremony_id: &str) -> Result<()> {
        let mut book = self.book.lock().expect("ceremony lock");
        let Some(rec) = book.records.get(ceremony_id).cloned() else { return Ok(()) };
        if !rec.is_terminal() || rec.peers_settled {
            return Ok(());
        }
        let done = CeremonyRecord { peers_settled: true, updated_ms: crate::ceremony_record::now_ms(), ..rec.clone() };
        self.record_store.write(Some(&rec), &done)?;
        book.records.insert(ceremony_id.to_string(), done);
        Ok(())
    }

    /// Delete terminal records older than `older_than` that nobody can still ask about: settled
    /// ones, and no-votes that never named a roster (unknown ids). Returns how many.
    pub fn gc_records(&self, older_than: Duration) -> Result<usize> {
        let cutoff = crate::ceremony_record::now_ms().saturating_sub(older_than.as_millis() as u64);
        let mut book = self.book.lock().expect("ceremony lock");
        let old: Vec<String> = book
            .records
            .values()
            .filter(|r| r.is_terminal() && (r.peers_settled || r.roster.is_empty()) && r.updated_ms < cutoff)
            .map(|r| r.ceremony_id.clone())
            .collect();
        for id in &old {
            self.record_store.remove(id)?;
            book.records.remove(id);
        }
        Ok(old.len())
    }

    // -- relay transport (pre-C1 wire shape; replaced by direct delivery) --

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
        self.start_session(dkg_id, key_id, CeremonyKind::Dkg)
    }

    pub fn dkg_part2(
        &self,
        dkg_id: &str,
        round1_map: &BTreeMap<Identifier, round1::Package>,
    ) -> Result<BTreeMap<Identifier, round2::Package>> {
        self.session_part2(dkg_id, CeremonyKind::Dkg, round1_map)
    }

    /// Stage this node's new share and vote yes. Returns the group key; the share is not live
    /// until the ceremony commits.
    pub fn dkg_part3(
        &self,
        dkg_id: &str,
        round1_map: &BTreeMap<Identifier, round1::Package>,
        round2_for_me: &BTreeMap<Identifier, round2::Package>,
    ) -> Result<StagedOutcome> {
        let roster = roster_of(round1_map)?;
        self.finish_session(dkg_id, CeremonyKind::Dkg, roster, None, |key_id, participant| {
            self.dkg_share(key_id, participant, round1_map, round2_for_me)
        })
    }

    pub fn refresh_part1(&self, refresh_id: &str, key_id: &str) -> Result<round1::Package> {
        if !self.keystore.exists(key_id) {
            return Err(DaemonError::UnknownKey(key_id.to_string()));
        }
        // Reverse fence (idempotent if the orchestrator already fenced with this id).
        let pending = self.pending_sign_count(key_id);
        if pending > 0 {
            return Err(DaemonError::SignInProgress {
                key_id: key_id.to_string(),
                kind: "refresh",
                pending,
            });
        }
        self.start_session(refresh_id, key_id, CeremonyKind::Refresh)
    }

    pub fn refresh_part2(
        &self,
        refresh_id: &str,
        round1_map: &BTreeMap<Identifier, round1::Package>,
    ) -> Result<BTreeMap<Identifier, round2::Package>> {
        self.session_part2(refresh_id, CeremonyKind::Refresh, round1_map)
    }

    pub fn refresh_part3(
        &self,
        refresh_id: &str,
        round1_map: &BTreeMap<Identifier, round1::Package>,
        round2_for_me: &BTreeMap<Identifier, round2::Package>,
    ) -> Result<StagedOutcome> {
        let roster = roster_of(round1_map)?;
        self.finish_session(refresh_id, CeremonyKind::Refresh, roster, None, |key_id, participant| {
            self.refresh_share(key_id, participant, round1_map, round2_for_me)
        })
    }
}

/// A sharing of a key as nodes compare it: (epoch, PKP digest).
pub type KeyVersion = (u64, [u8; 32]);

/// What a node staged in part 3: the outcome every node must agree on before anyone commits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StagedOutcome {
    pub new_epoch: u64,
    pub new_pkp_digest: [u8; 32],
    pub group_key: [u8; 32],
}

/// The configured identifiers of a round-1 map's participants, ascending.
fn roster_of(round1_map: &BTreeMap<Identifier, round1::Package>) -> Result<Vec<u16>> {
    let mut roster =
        round1_map.keys().map(|&id| crate::hosted::identifier_index(id)).collect::<Result<Vec<_>>>()?;
    roster.sort_unstable();
    Ok(roster)
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
    /// Enable hosted keys from a legacy shared master: every key derived as before, for a roster of
    /// identifiers `1..=max_signers`. The daemon builds its keyring from config instead
    /// ([`crate::seal::SealKeys::hosted_keyring`]); this stays for tests and tools.
    pub fn with_hosted_keys(self, master_secret: &[u8], cluster_id: String) -> Result<Self> {
        let id = crate::hosted::identifier_index(self.identifier)?;
        let keyring = HostedKeyring {
            dist_key: crate::wrap::DistKey::derive(master_secret, id),
            commitment_key: crate::wrap::legacy_commitment_key(master_secret),
            peer_dist_keys: (1..=self.max_signers)
                .map(|j| (j, crate::wrap::DistKey::derive(master_secret, j).public_bytes()))
                .collect(),
        };
        self.with_hosted_keyring(keyring, cluster_id)
    }

    /// Enable hosted keys with an explicit keyring and bind envelopes to `cluster_id`. Without
    /// this, every hosted-key op returns an error. Refuses a keyring whose own key is for another
    /// node, or which pins a different key for this node than the one it holds.
    pub fn with_hosted_keyring(mut self, keyring: HostedKeyring, cluster_id: String) -> Result<Self> {
        let id = crate::hosted::identifier_index(self.identifier)?;
        if keyring.dist_key.identifier() != id {
            return Err(DaemonError::Config(format!(
                "hosted-key distribution key is for node {}, but this node is {id}",
                keyring.dist_key.identifier()
            )));
        }
        if keyring.peer_dist_keys.get(&id) != Some(&keyring.dist_key.public_bytes()) {
            return Err(DaemonError::Config(format!(
                "the pinned distribution key for this node ({id}) is missing or does not match its \
                 seal keys"
            )));
        }
        self.hosted = Some(HostedCtx {
            dist_key: keyring.dist_key,
            commitment_key: keyring.commitment_key,
            cluster_id,
            peer_dist_keys: keyring.peer_dist_keys,
        });
        Ok(self)
    }

    pub fn hosted_enabled(&self) -> bool {
        self.hosted.is_some()
    }

    /// The hosted-key specs this node can store and serve: every spec this build knows, or none
    /// with hosted keys off. Reported in `Capabilities` (to the driver) and `NodeInfo` (to peers).
    pub fn hosted_specs(&self) -> Vec<String> {
        if self.hosted_enabled() {
            crate::hosted::HostedSpec::ALL.iter().map(|s| s.as_str().to_string()).collect()
        } else {
            Vec::new()
        }
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

    /// The pinned distribution public key of roster node `node_identifier`, for wrapping material
    /// to it. A node outside the roster has none, so nothing is ever wrapped to it.
    pub fn dist_public_key_for(&self, node_identifier: u16) -> Result<[u8; 32]> {
        let ctx = self.hosted_ctx()?;
        ctx.peer_dist_keys.get(&node_identifier).copied().ok_or_else(|| {
            DaemonError::Config(format!(
                "node {node_identifier} is not in this node's roster — no distribution key for it"
            ))
        })
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

    /// This node's own copy of hosted key `key_id`, public half only, for `verify-hosted`. Reads
    /// the key file and nothing else: no read-repair, so an absent key reads `present: false` — and
    /// so does a FROST share under the id, so that the reply never tells which ids hold shares. The
    /// public key is the one the private key derives ([`crate::hosted::HostedKey::derived_public_key_der`]);
    /// a key file whose stored public half disagrees is an error, never `present`.
    pub fn hosted_key_status(&self, key_id: &str) -> Result<crate::pb::HostedKeyStatusReply> {
        self.hosted_ctx()?;
        refuse_reserved_for_hosted(key_id)?;
        let identifier = u32::from(crate::hosted::identifier_index(self.identifier)?);
        let absent = crate::pb::HostedKeyStatusReply { identifier, present: false, ..Default::default() };
        match self.keystore.load_record(key_id) {
            Ok(crate::keystore::Record::Hosted(key)) => Ok(crate::pb::HostedKeyStatusReply {
                identifier,
                present: true,
                spec: key.spec.as_str().to_string(),
                public_key_der: if key.spec.is_asymmetric() { key.derived_public_key_der()? } else { Vec::new() },
                created_at: key.created_at,
            }),
            Ok(crate::keystore::Record::Frost(_)) | Err(DaemonError::UnknownKey(_)) => Ok(absent),
            Err(e) => Err(e),
        }
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
    /// revealing anything about it. Keyed by the cluster-wide commitment key, so a commitment is
    /// not a bare hash of the key.
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
        // The key in the clear, briefly: wiped on drop.
        let material = zeroize::Zeroizing::new(serde_json::to_vec(key)?);
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
        // A peer's material must be self-consistent before it is stored: an EC key whose public
        // half is not its own would have this node serve a public key it cannot decrypt for.
        key.validate()?;
        Ok(key)
    }

    // -- crypto operations served to the driver --

    pub fn hosted_decrypt(&self, key_id: &str, ciphertext: &[u8]) -> Result<Vec<u8>> {
        Ok(self.hosted_load(key_id)?.decrypt_oaep(ciphertext)?.to_vec())
    }

    /// The static ECDH for an `ec-p256-ecies` key: `Z = x(d·V)`. Refuses ids reserved for the
    /// split ceremony and every other spec (an RSA, AES or FROST key is never an ECDH oracle).
    /// See [`crate::hosted::HostedKey::ecdh_p256`] for the peer-point rules.
    pub fn hosted_ecdh(
        &self,
        key_id: &str,
        peer_point: &[u8],
    ) -> Result<zeroize::Zeroizing<[u8; crate::hosted::P256_SHARED_SECRET_LEN]>> {
        refuse_reserved_for_hosted(key_id)?;
        self.hosted_load(key_id)?.ecdh_p256(peer_point)
    }

    pub fn hosted_encrypt_symmetric(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>> {
        self.hosted_load(key_id)?.encrypt_symmetric(data)
    }

    pub fn hosted_decrypt_symmetric(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>> {
        Ok(self.hosted_load(key_id)?.decrypt_symmetric(data)?.to_vec())
    }
}
