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
use rutli_frost_core::session::{aggregate, Cosigner, SessionBinding};

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
    /// Configured identifiers of every participant (checked against this node's own roster).
    roster: Vec<u16>,
    /// Refresh: the sharing this node held at part 1, which the new one must replace.
    old: Option<KeyVersion>,
    /// This node's own round-1 package (canonical bytes), to check the leader's map against.
    own_round1: Vec<u8>,
    /// Set by part 2: the round-1 map this node used and its digest.
    part2: Option<Part2State>,
    /// Round-2 packages delivered to this node directly by their senders, by sender, with the
    /// round-1 digest each sender computed.
    inbox: BTreeMap<u16, ([u8; 32], round2::Package)>,
}

struct Part2State {
    digest: [u8; 32],
    round1_map: BTreeMap<Identifier, round1::Package>,
}

/// Ceremony sessions and votes under one lock, so "no session and no record" is decided
/// atomically with writing the no-vote that answer implies.
#[derive(Default)]
struct CeremonyBook {
    sessions: std::collections::HashMap<String, Session>,
    records: BTreeMap<String, CeremonyRecord>,
}

/// A per-key ceremony guard: only one DKG/refresh (or hosted-key genkey/delkey) may be in progress
/// for a given key at a time. Owner is the ceremony id. A guard whose ceremony stalled is preempted
/// by the next ceremony once it is orphaned ([`Node::guard_orphaned`]): a DKG/refresh fence never
/// followed by part 1 after [`CEREMONY_FENCE_TIMEOUT`], anything else after the orphan timeout (an
/// in-progress ceremony releases its guard at part 3 / on clean failure, so that only ever applies
/// to a leader that died between part 1 and part 3).
///
/// The guard serializes ceremonies; it does **not** fence signing (see [`Node::sign_round1`]).
struct CeremonyGuard {
    owner: String,
    kind: &'static str,
    /// When the owner first took the guard. Never moved by the same owner taking it again (its own
    /// part 1, or a repeated fence), so no ceremony id can keep a guard alive by re-fencing.
    started: Instant,
    /// The owner has a ceremony session on this node (part 1 ran), not just a fence.
    session: bool,
}

/// How long an orphaned ceremony guard blocks a new ceremony for the same key. Longer than any
/// realistic DKG/refresh round-trip; shorter than a human's patience for a crashed ceremony.
const CEREMONY_ORPHAN_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// How long a DKG/refresh fence that was never followed by part 1 blocks a new ceremony for the
/// same key. An honest leader sends part 1 right after fencing every node (milliseconds); a fence
/// left behind by a leader that died in between, or by a peer fencing on its own, must not hold
/// off the refresh CronJob's quick retries for the full orphan timeout. Hosted-key fences
/// (genkey/delkey) never have a session and keep the orphan timeout: they are held across a whole
/// generation or delete.
pub const CEREMONY_FENCE_TIMEOUT: Duration = Duration::from_secs(60);

/// How often a running node prunes expired nonce markers (and once at startup).
pub const NONCE_PRUNE_INTERVAL: Duration = Duration::from_secs(10 * 60);
/// Most markers one prune pass removes, so a pass over a huge backlog stays short; a pass that hits
/// it is followed by another a few seconds later.
pub const NONCE_PRUNE_BUDGET: usize = 10_000;

/// The epoch a DKG commits its key at; each committed refresh adds one.
pub const FIRST_EPOCH: u64 = 1;

/// Most no-votes this node keeps for ceremony ids a peer asked about but this node never had a
/// session or record for, per asking peer (certificate CN) and in total (audit F2). Beyond either
/// cap such a question is answered with a refusal — not evidence of anything to the asker, which
/// keeps waiting — instead of a durable record, so one compromised peer cannot fill the key volume
/// with records (each is a file and two fsyncs) and stop the node.
pub const MAX_UNKNOWN_NO_VOTES_PER_ASKER: usize = 256;
pub const MAX_UNKNOWN_NO_VOTES: usize = 1024;

/// Most sign sessions (between round 1 and round 2) held in memory per key. Real signs hold a
/// session for milliseconds; a peer opening round 1 after round 1 (without an intent, while
/// `require_intent` is off, nothing else limits it) is refused here instead of growing memory
/// until the pending-session TTL.
pub const MAX_PENDING_SIGN_SESSIONS_PER_KEY: usize = 1024;

/// Most ceremony sessions (between part 1 and the vote) held in memory at once. A part 1 beyond
/// it first drops sessions orphaned past the orphan timeout, then is refused.
pub const MAX_CEREMONY_SESSIONS: usize = 64;

/// How long an abort that contradicts a peer's yes-vote waits before the votes are gathered again
/// (audit F3; see [`crate::ceremony_record::mixed_evidence`]).
pub const MIXED_EVIDENCE_REGATHER: Duration = Duration::from_secs(2);

pub struct Node {
    pub identifier: Identifier,
    pub max_signers: u16,
    pub min_signers: u16,
    keystore: KeyStore,
    /// Key-store readiness verdict (see [`crate::health`]), shared with Health and the monitor.
    keystore_health: Arc<crate::health::KeystoreHealth>,
    /// Loaded signing state per key: the share's cosigner and the sharing it belongs to.
    cosigners: Mutex<std::collections::HashMap<String, CachedKey>>,
    /// Keys whose share this node's epoch check found stale ([`crate::epoch_check`]): round 1 and
    /// leading are refused for them until a check finds the share current again.
    stale: Mutex<std::collections::HashMap<String, StaleMark>>,
    /// `signing_policy.require_epoch_match`: refuse round 1 from a leader that names no sharing.
    require_epoch_match: bool,
    /// The signing policy and sign journal (audit C2). `None` (tests, offline tools): no policy,
    /// no journal — the daemon always sets one.
    sign_guard: Option<Arc<crate::sign_policy::SignGuard>>,
    // key_id -> the ceremony currently allowed to (re)write that key's share.
    ceremonies: Mutex<std::collections::HashMap<String, CeremonyGuard>>,
    ceremony_orphan_timeout: Duration,
    /// See [`CEREMONY_FENCE_TIMEOUT`].
    ceremony_fence_timeout: Duration,
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
    /// Hosted keys this node created under a genkey ceremony (key id -> ceremony id): the only keys
    /// a PurgeKey without a delete intent may remove — the rollback of a generation that missed its
    /// write quorum, while that generation still holds the fence (audit M2).
    hosted_created_in: Mutex<std::collections::HashMap<String, String>>,
    /// `hosted_keys.delete_grace_secs`: how long a tombstone retains the deleted key's material.
    delete_grace: Duration,
    /// Caps on no-votes for unknown ceremony ids: (per asker, total). See
    /// [`MAX_UNKNOWN_NO_VOTES_PER_ASKER`].
    unknown_no_vote_caps: (usize, usize),
    /// See [`MIXED_EVIDENCE_REGATHER`].
    regather_delay: Duration,
    #[cfg(test)]
    hooks: TestHooks,
}

#[cfg(test)]
type OnceHook = Box<dyn FnOnce(&Node) + Send>;
#[cfg(test)]
type SessionHook = Arc<dyn Fn(&str, &str) + Send + Sync>;

/// Fault and pause seams for this crate's unit tests, absent from every other build (the same
/// approach as the sign journal's injected faults).
#[cfg(test)]
#[derive(Default)]
struct TestHooks {
    /// Run once by part 1 right after it took the ceremony guard, before it builds the session.
    after_part1_acquire: Mutex<Option<OnceHook>>,
    /// Run by sign round 2, with the key id and session id, right after it took its handle on the
    /// cached cosigner and before using it (a refresh commit may evict that cosigner meanwhile).
    after_round2_cosigner: Mutex<Option<SessionHook>>,
}

/// What a node holds under a hosted key id.
pub enum HostedState {
    Absent,
    Live(Box<crate::hosted::HostedKey>),
    Tombstone(Box<crate::hosted::Tombstone>),
    /// A FROST share — never a hosted key, never tombstoned.
    Frost,
}

/// What applying a tombstone did on this node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TombstoneOutcome {
    /// This node held the key live: it is now a tombstone (material retained for the grace period).
    Converted,
    /// This node did not hold the key: the tombstone is recorded, so the key can never arrive.
    Recorded,
    /// Already tombstoned here (or the intent was cleared by break-glass): nothing changed.
    Already,
}

/// What a peer's tombstone manifest says about the deleted key, recorded with the tombstone on a
/// node that never held it.
#[derive(Clone, Debug, Default)]
pub struct DeletedKeyInfo {
    pub spec: String,
    pub created_at: u64,
    pub commitment: Vec<u8>,
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
        let (records, records_loaded) = match record_store.load_all() {
            Ok(list) => (list.into_iter().map(|r| (r.ceremony_id.clone(), r)).collect(), true),
            Err(e) => {
                // Unreadable record directory: start with no cached votes and say so. A ceremony this
                // node voted in will read as unknown to peers — they wait, they never commit on it.
                tracing::error!(error = %e, "cannot read this node's ceremony records");
                (BTreeMap::new(), false)
            }
        };
        let node = Self {
            identifier,
            max_signers,
            min_signers,
            keystore,
            keystore_health,
            cosigners: Mutex::new(Default::default()),
            stale: Mutex::new(Default::default()),
            require_epoch_match: false,
            sign_guard: None,
            ceremonies: Mutex::new(Default::default()),
            ceremony_orphan_timeout,
            ceremony_fence_timeout: CEREMONY_FENCE_TIMEOUT,
            record_store,
            book: Mutex::new(CeremonyBook { sessions: Default::default(), records }),
            mesh: std::sync::OnceLock::new(),
            hosted: None,
            hosted_created_in: Mutex::new(Default::default()),
            delete_grace: Duration::from_secs(crate::config::DEFAULT_DELETE_GRACE_SECS),
            unknown_no_vote_caps: (MAX_UNKNOWN_NO_VOTES_PER_ASKER, MAX_UNKNOWN_NO_VOTES),
            regather_delay: MIXED_EVIDENCE_REGATHER,
            #[cfg(test)]
            hooks: TestHooks::default(),
        };
        if !records_loaded {
            // Without the votes the repair cannot tell an orphaned staged share from one this node
            // voted yes on (audit F4): leave everything as it is until a start that reads them.
            tracing::error!("ceremony startup repair skipped: the ceremony records could not be read");
        } else if let Err(e) = node.recover_ceremonies() {
            tracing::error!(error = %e, "ceremony recovery at startup failed");
        }
        node
    }

    /// Override the caps on no-votes for unknown ceremony ids (per asker, total). Tests.
    pub fn with_unknown_no_vote_caps(mut self, per_asker: usize, total: usize) -> Self {
        self.unknown_no_vote_caps = (per_asker, total);
        self
    }

    /// Override [`CEREMONY_FENCE_TIMEOUT`]. Tests.
    pub fn with_ceremony_fence_timeout(mut self, timeout: Duration) -> Self {
        self.ceremony_fence_timeout = timeout;
        self
    }

    /// Override [`MIXED_EVIDENCE_REGATHER`]. Tests.
    pub fn with_regather_delay(mut self, delay: Duration) -> Self {
        self.regather_delay = delay;
        self
    }

    pub fn regather_delay(&self) -> Duration {
        self.regather_delay
    }

    /// Startup repair of the two-phase ceremony state, for what a crash can leave behind:
    ///
    /// * a staged share with no record **file** for its ceremony (crashed between writing the
    ///   share and the vote), or whose record is a terminal vote without a quarantine (an aborted
    ///   ceremony whose share delete did not finish, or a commit's leftover): deleted — nobody can
    ///   commit a ceremony this node never voted yes on. A record file that exists but does not
    ///   parse keeps its share (audit F4: that unreadable vote may be a yes), as does a STAGED vote
    ///   or a quarantined abort (audit F3);
    /// * a STAGED record whose staged share is gone: if the live share is exactly the staged
    ///   outcome the node crashed between promoting it and recording COMMITTED, so the record is
    ///   completed; anything else is reported and left STAGED for an operator.
    pub fn recover_ceremonies(&self) -> Result<()> {
        let mut book = self.book()?;
        let records = &mut book.records;
        for (key_id, ceremony_id) in self.keystore.list_staged()? {
            let discard = match records.get(&ceremony_id) {
                Some(r) => r.key_id != key_id || (r.state != RecordState::Staged && !r.quarantined),
                // No parsed record: discard only if there is no record file at all.
                None => !self.record_store.file_exists(&ceremony_id)?,
            };
            if discard {
                self.keystore.discard_staged(&key_id, &ceremony_id)?;
                tracing::warn!(
                    key_id = %key_id,
                    ceremony_id = %ceremony_id,
                    "removed a staged share without a staged vote (interrupted or aborted ceremony)"
                );
            } else if !records.contains_key(&ceremony_id) {
                tracing::error!(
                    key_id = %key_id,
                    ceremony_id = %ceremony_id,
                    "staged share kept: its ceremony record exists but cannot be read — an operator \
                     must inspect it (docs/ceremonies.md)"
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
    /// `None` also when the ceremony state cannot be read (see [`Node::book`]); callers then go
    /// through a path that reports the error.
    pub fn ceremony_record(&self, ceremony_id: &str) -> Option<CeremonyRecord> {
        self.book().ok()?.records.get(ceremony_id).cloned()
    }

    /// Every ceremony record this node holds.
    pub fn all_records(&self) -> Vec<CeremonyRecord> {
        self.book().map(|b| b.records.values().cloned().collect()).unwrap_or_default()
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
    /// Empty when the ceremony state cannot be read (see [`Node::book`]): the resolver skips a
    /// pass, and every operation that must not miss a staged ceremony reads it through
    /// [`Node::book`] itself and fails instead.
    pub fn staged_records(&self) -> Vec<CeremonyRecord> {
        self.staged_records_checked().unwrap_or_default()
    }

    fn staged_records_checked(&self) -> Result<Vec<CeremonyRecord>> {
        Ok(self.book()?.records.values().filter(|r| r.state == RecordState::Staged).cloned().collect())
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
            Ok(crate::keystore::Record::Hosted(_)) | Ok(crate::keystore::Record::Tombstone(_)) => {
                reply.present = true;
                reply.origin = "hosted".into();
            }
            Err(DaemonError::UnknownKey(_)) => {}
            Err(e) => return Err(e),
        }
        if let Some(mark) = self.stale_mark(key_id) {
            reply.stale = true;
            reply.stale_reason = mark.reason;
        }
        if let Some(r) = self.staged_records_checked()?.into_iter().find(|r| r.key_id == key_id) {
            reply.staged = true;
            reply.staged_ceremony_id = r.ceremony_id;
            reply.staged_new_epoch = r.new_epoch;
            reply.staged_new_pkp_digest = hex::decode(&r.new_pkp_digest).unwrap_or_default();
        }
        Ok(reply)
    }

    /// Reserve `key_id` for ceremony `owner`, as a fence (no session: part 1 marks that itself,
    /// atomically with creating the session — see [`Node::mark_session`]). Fails if a *different*,
    /// non-orphaned ceremony holds it — this is what serializes concurrent DKG/refresh and prevents
    /// split-brain shares. When it preempts an *orphaned* guard ([`Node::guard_orphaned`]), it also
    /// drops that old ceremony's leftover session state so its stale part 2/part 3 cannot proceed.
    ///
    /// The same owner taking the guard again keeps it as it is — in particular its `started`, so a
    /// fence repeated under one ceremony id never extends it (before 0.4.0-rc.4 it reset the timer,
    /// and a fence re-sent under the same id held the key forever).
    ///
    /// Returns whether this call created the guard (`false`: `owner` already held it), so a caller
    /// that fails afterwards can put things back exactly as they were.
    fn acquire_ceremony(&self, key_id: &str, owner: &str, kind: &'static str) -> Result<bool> {
        let preempted: Option<String> = {
            let mut guards = self.guards();
            let preempted = match guards.get_mut(key_id) {
                Some(cur) if cur.owner == owner => {
                    if cur.kind != kind {
                        return Err(DaemonError::CeremonyRefused(format!(
                            "ceremony {owner} holds {key_id} as a {} ceremony, not a {kind} one",
                            cur.kind
                        )));
                    }
                    return Ok(false);
                }
                Some(cur) => {
                    if !self.guard_orphaned(cur) {
                        return Err(DaemonError::CeremonyInProgress {
                            key_id: key_id.to_string(),
                            kind: cur.kind,
                            other: cur.owner.clone(),
                        });
                    }
                    Some(cur.owner.clone()) // orphan — preempt it
                }
                None => None,
            };
            guards.insert(
                key_id.to_string(),
                CeremonyGuard { owner: owner.to_string(), kind, started: Instant::now(), session: false },
            );
            preempted
        }; // ceremonies lock released before touching the session maps (avoid nested locks)
        if let Some(stale) = preempted {
            // Its session is dropped; this node's vote on it is no (recorded the first time anyone
            // asks — see `ceremony_status`).
            self.book()?.sessions.remove(&stale);
        }
        Ok(true)
    }

    /// Mark `owner`'s guard on `key_id` as backed by a ceremony session. Part 1 calls it with the
    /// book locked, immediately before inserting the session, so a guard says `session` exactly
    /// when a session exists: a guard marked earlier and left behind by a part 1 that failed before
    /// the insert would be judged by the orphan timeout instead of [`CEREMONY_FENCE_TIMEOUT`], and
    /// block DKG/refresh (and hosted-key writes) for the key for 15 minutes instead of one.
    ///
    /// Lock order: the book, then the guards. Nothing takes the book while holding the guards
    /// (every guard critical section is a single map operation), so this cannot deadlock.
    fn mark_session(&self, key_id: &str, owner: &str) -> Result<()> {
        match self.guards().get_mut(key_id) {
            Some(g) if g.owner == owner => {
                g.session = true;
                Ok(())
            }
            // Preempted since part 1 took it (only possible for a fence already past its timeout).
            _ => Err(DaemonError::CeremonySuperseded { key_id: key_id.to_string(), owner: owner.to_string() }),
        }
    }

    /// After the book dropped every in-memory session (poison recovery, [`Node::book`]): turn
    /// every DKG/refresh guard marked as having a session back into a fence, so it is judged by
    /// [`CEREMONY_FENCE_TIMEOUT`] (measured, as always, from its first acquisition) rather than the
    /// 15-minute orphan timeout. Caller holds the book lock (order: book, then guards).
    ///
    /// Unmarked rather than released, for the same reason a failed part 1 keeps its leader's fence
    /// ([`Node::start_session`]): the guard is that ceremony's reservation of the key, and while
    /// its leader is alive the leader ends it — its part 2/part 3 here find no session (and
    /// `assert_owns` still guards staging), it aborts, and its abort releases every fence. Until
    /// then the guard keeps serializing ceremonies on this node like the leader's fences on the
    /// others. A dead leader blocks the key for at most the fence timeout from when the guard was
    /// taken, which is usually already past. Without this a session-less guard kept the 15-minute
    /// orphan timeout.
    ///
    /// Hosted-key (genkey/delkey) guards are left as they are: they never have a session, and
    /// keep the orphan timeout by design.
    fn unmark_ceremony_guards(&self) {
        for g in self.guards().values_mut() {
            if g.session && matches!(g.kind, "dkg" | "refresh") {
                g.session = false;
            }
        }
    }

    /// Whether `guard` is orphaned, i.e. the next ceremony for its key may preempt it: a DKG/refresh
    /// fence with no session after [`CEREMONY_FENCE_TIMEOUT`], any other guard after the orphan
    /// timeout. Both measured from the owner's first acquisition.
    fn guard_orphaned(&self, guard: &CeremonyGuard) -> bool {
        let timeout = if !guard.session && matches!(guard.kind, "dkg" | "refresh") {
            self.ceremony_fence_timeout
        } else {
            self.ceremony_orphan_timeout
        };
        guard.started.elapsed() >= timeout
    }

    /// Release the guard for `key_id` iff `owner` still holds it.
    fn release_ceremony(&self, key_id: &str, owner: &str) {
        let mut guards = self.guards();
        if guards.get(key_id).map(|c| c.owner == owner).unwrap_or(false) {
            guards.remove(key_id);
        }
    }

    /// Assert ceremony `owner` still holds the guard for `key_id`. A ceremony that was preempted
    /// (its guard taken by a newer one after it was orphaned) must NOT persist — this is the
    /// load-bearing safety check against a stale leader clobbering/splitting shares on refresh.
    fn assert_owns(&self, key_id: &str, owner: &str) -> Result<()> {
        let guards = self.guards();
        match guards.get(key_id) {
            Some(g) if g.owner == owner => Ok(()),
            _ => Err(DaemonError::CeremonySuperseded {
                key_id: key_id.to_string(),
                owner: owner.to_string(),
            }),
        }
    }

    /// Cluster-wide fence step: take the per-key guard *before* DKG/refresh crypto (or a hosted-key
    /// write), so no other ceremony for the key can start on any node while this one is in flight.
    ///
    /// It does not wait for, or refuse over, in-flight signs: up to 0.4.0-rc.3 a DKG/refresh fence
    /// was refused while this node held sign nonces for the key (the "reverse fence"), a leftover
    /// of ceremony protocol 1, where part 3 overwrote the live share. Under protocol 2 part 3 only
    /// stages; see [`Node::sign_round1`] for why signing and ceremonies may overlap.
    pub fn ceremony_fence(&self, ceremony_id: &str, key_id: &str, kind: &'static str) -> Result<()> {
        self.fence_created(ceremony_id, key_id, kind).map(|_| ())
    }

    /// [`Node::ceremony_fence`], returning whether this call created the guard (`false`: this
    /// ceremony id already held it).
    fn fence_created(&self, ceremony_id: &str, key_id: &str, kind: &'static str) -> Result<bool> {
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
        // A hosted-key fence never covers a FROST share: it would serialize that key's DKG/refresh
        // behind a hosted-key operation that can never apply to it.
        if matches!(kind, "genkey" | "delkey") {
            if let Ok(crate::keystore::Record::Frost(_)) = self.keystore.load_record(key_id) {
                return Err(DaemonError::CeremonyRefused(format!(
                    "{key_id} is a FROST share here — a hosted-key {kind} never fences it"
                )));
            }
        }
        self.acquire_ceremony(key_id, ceremony_id, kind)
    }

    /// Roll back a fence taken by [`ceremony_fence`] (partial cluster fence / aborted ceremony).
    pub fn ceremony_release(&self, ceremony_id: &str, key_id: &str) {
        self.release_ceremony(key_id, ceremony_id);
        // Past its fence a generation can no longer be rolled back.
        let mut created = crate::sync::recover(&self.hosted_created_in, "hosted_created_in");
        if created.get(key_id).is_some_and(|c| c == ceremony_id) {
            created.remove(key_id);
        }
    }

    // -- locks (audit L3: a panicking request must not take the node down; see crate::sync) --

    /// The loaded-key cache. On poison it is **emptied**: it is only a cache of what is on disk,
    /// reloaded on the next use; dropping an entry drops that cosigner's in-flight nonces (those
    /// sessions fail at round 2 and the leader retries) and never a burned-session marker. A cosigner
    /// still referenced by an in-flight call keeps working on its own; a second instance for the
    /// same key shares the on-disk markers, so a session still yields at most one share.
    fn cache(&self) -> std::sync::MutexGuard<'_, std::collections::HashMap<String, CachedKey>> {
        crate::sync::recover_reset(&self.cosigners, "key_cache", |m| m.clear())
    }

    /// The per-key ceremony guards, **kept** as they are on poison: each critical section is one
    /// map lookup/insert/remove, so the map is consistent. A guard a panicking ceremony left behind
    /// fails closed: other ceremonies for that key are refused until the ceremony releases it or it
    /// is orphaned and preempted — the same as a leader that crashed mid-ceremony. Signing never
    /// consults the guards.
    ///
    /// Lock order: may be taken while holding the book ([`Node::mark_session`]); the book is never
    /// taken while holding this.
    fn guards(&self) -> std::sync::MutexGuard<'_, std::collections::HashMap<String, CeremonyGuard>> {
        crate::sync::recover(&self.ceremonies, "ceremony_guards")
    }

    /// The stale marks, **kept** on poison: every change is one insert or remove, so a mark is
    /// either set or not; keeping them fails closed, and the next epoch check recomputes every one.
    fn stale_marks(&self) -> std::sync::MutexGuard<'_, std::collections::HashMap<String, StaleMark>> {
        crate::sync::recover(&self.stale, "stale_marks")
    }

    /// The ceremony book (sessions and the cache of durable votes). A holder may have panicked
    /// between writing a vote to disk and caching it, so on poison the book is **rebuilt** the way a
    /// restart would: votes reloaded from `keys/.ceremonies/`, in-memory sessions dropped (this node
    /// then votes no on them, as after a restart). If the votes cannot be reloaded the operation
    /// fails (closed) and the lock stays poisoned, so the next caller tries again; signing does not
    /// use the book and is unaffected. The DKG/refresh guards of the dropped sessions go back to
    /// fence-only ([`Node::unmark_ceremony_guards`]).
    fn book(&self) -> Result<std::sync::MutexGuard<'_, CeremonyBook>> {
        match self.book.lock() {
            Ok(book) => Ok(book),
            Err(poisoned) => {
                let records = self.record_store.load_all().map_err(|e| {
                    tracing::error!(error = %e, "the ceremony lock was poisoned and the votes cannot be reloaded");
                    e
                })?;
                let mut book = poisoned.into_inner();
                book.records = records.into_iter().map(|r| (r.ceremony_id.clone(), r)).collect();
                book.sessions.clear();
                // Still under the book lock (book -> guards), so no part 1 can mark a guard for a
                // new session between the clear and the unmark.
                self.unmark_ceremony_guards();
                crate::sync::note("ceremony_book", "reloaded");
                self.book.clear_poison();
                Ok(book)
            }
        }
    }

    /// Load (and cache) this node's cosigner state for `key_id`.
    fn cosigner(&self, key_id: &str) -> Result<Arc<Cosigner>> {
        Ok(self.cached(key_id)?.cosigner)
    }

    /// Load (and cache) this node's signing state for `key_id`, with the sharing it belongs to.
    fn cached(&self, key_id: &str) -> Result<CachedKey> {
        {
            let map = self.cache();
            if let Some(c) = map.get(key_id) {
                return Ok(c.clone());
            }
        }
        let share = self.keystore.load(key_id)?;
        let view = (share.epoch, share.pkp_digest()?);
        let nonce_store = NonceStore::open(self.keystore.nonce_dir(key_id))?;
        let cached = CachedKey {
            cosigner: Arc::new(Cosigner::new(share.key_package, share.public_key_package, nonce_store)),
            view,
        };
        self.cache()
            .insert(key_id.to_string(), cached.clone());
        Ok(cached)
    }

    /// Apply `signing_policy.require_epoch_match` (see [`crate::config::SigningPolicyConfig`]).
    pub fn with_require_epoch_match(mut self, require: bool) -> Self {
        self.require_epoch_match = require;
        self
    }

    /// Apply the signing policy and sign journal (audit C2) to every signature this node takes
    /// part in.
    pub fn with_sign_guard(mut self, guard: Arc<crate::sign_policy::SignGuard>) -> Self {
        self.sign_guard = Some(guard);
        self
    }

    pub fn sign_guard(&self) -> Option<&Arc<crate::sign_policy::SignGuard>> {
        self.sign_guard.as_ref()
    }

    /// What a leader needs to sign with `key_id`: threshold, its own sharing, its stale mark.
    pub fn signing_view(&self, key_id: &str) -> Result<SigningView> {
        let c = self.cached(key_id)?;
        Ok(SigningView { threshold: c.cosigner.min_signers(), view: c.view, stale: self.stale_mark(key_id) })
    }

    /// This node's stale mark for `key_id`, if its epoch check found the share stale.
    pub fn stale_mark(&self, key_id: &str) -> Option<StaleMark> {
        self.stale_marks().get(key_id).cloned()
    }

    /// Record the epoch check's verdict for `key_id`: `Some` marks the share stale (round 1 and
    /// leading refused), `None` clears a mark. Keeps `rutli_stale_share{key}` in step.
    pub fn set_stale(&self, key_id: &str, mark: Option<StaleMark>) {
        let mut stale = self.stale_marks();
        let changed = match &mark {
            Some(m) => stale.insert(key_id.to_string(), m.clone()).as_ref() != Some(m),
            None => stale.remove(key_id).is_some(),
        };
        drop(stale);
        metrics::gauge!(crate::metrics::STALE_SHARE, "key" => key_id.to_string())
            .set(if mark.is_some() { 1.0 } else { 0.0 });
        match (&mark, changed) {
            (Some(m), true) => tracing::error!(
                key_id,
                own_epoch = m.own_epoch,
                newer_epoch = m.newer_epoch,
                reason = %m.reason,
                "this node's share is STALE — refusing to sign or lead for the key until it is \
                 current (restore a current backup or re-enrol the node; docs/ceremonies.md)"
            ),
            (None, true) => tracing::info!(key_id, "share no longer stale"),
            _ => {}
        }
    }

    /// The newest epoch a COMMITTED ceremony record of this node says `key_id` reached, if any.
    /// A live share older than that was rolled back under the node (a restore from an old backup).
    pub fn committed_epoch(&self, key_id: &str) -> Option<u64> {
        self.book()
            .ok()?
            .records
            .values()
            .filter(|r| r.key_id == key_id && r.state == RecordState::Committed)
            .map(|r| r.new_epoch)
            .max()
    }

    /// One nonce-marker prune pass over every key's store (audit L4): remove burned-session
    /// markers older than `retention`, at most `budget` in total. Returns the totals; publishes
    /// `rutli_nonce_markers_pruned_total` and `rutli_nonce_markers`. Skipped (an error) while the
    /// key store fails its readiness probe. See
    /// [`rutli_frost_core::nonce_store::NonceStore::prune_older_than`] for why pruning past
    /// [`rutli_frost_core::session::MARKER_RETENTION`] cannot enable nonce reuse.
    pub fn prune_nonce_markers(&self, retention: Duration, budget: usize) -> Result<rutli_frost_core::nonce_store::PruneReport> {
        self.refuse_if_keystore_down()?;
        let mut total = rutli_frost_core::nonce_store::PruneReport::default();
        for entry in std::fs::read_dir(self.keystore.dir())? {
            let entry = entry?;
            let name = entry.file_name();
            if !name.to_string_lossy().ends_with(".nonces") || !entry.file_type()?.is_dir() {
                continue;
            }
            let r = NonceStore::open(entry.path())?.prune_older_than(retention, budget - total.removed)?;
            total.removed += r.removed;
            total.kept += r.kept;
            total.truncated |= r.truncated;
        }
        metrics::counter!(crate::metrics::NONCE_MARKERS_PRUNED).increment(total.removed as u64);
        metrics::gauge!(crate::metrics::NONCE_MARKERS).set(total.kept as f64);
        if total.removed > 0 {
            tracing::info!(removed = total.removed, kept = total.kept, "pruned expired nonce markers");
        }
        Ok(total)
    }

    /// The background nonce-marker pruner: a pass now (startup), then every
    /// [`NONCE_PRUNE_INTERVAL`] — sooner while a pass hits [`NONCE_PRUNE_BUDGET`]. Each pass runs on
    /// the blocking pool, and the next one starts only after it returns, so a hung volume parks one
    /// thread, never a pile of them.
    pub fn spawn_nonce_pruner(node: Arc<Node>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                let pass = node
                    .blocking(|n| n.prune_nonce_markers(rutli_frost_core::session::MARKER_RETENTION, NONCE_PRUNE_BUDGET))
                    .await;
                let wait = match pass {
                    Ok(r) if r.truncated => Duration::from_secs(5),
                    Ok(_) => NONCE_PRUNE_INTERVAL,
                    Err(e) => {
                        tracing::warn!(error = %e, "nonce-marker prune pass skipped");
                        NONCE_PRUNE_INTERVAL
                    }
                };
                tokio::time::sleep(wait).await;
            }
        })
    }

    /// Every FROST key id this node holds a share for.
    pub fn frost_key_ids(&self) -> Result<Vec<String>> {
        self.keystore.list_frost()
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
            stale: self.stale_mark(key_id).is_some(),
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

    pub fn sign_round1(&self, key_id: &str, session_id: &str, ctx: &Round1Ctx) -> Result<SigningCommitments> {
        // No ceremony fence here. Up to 0.4.0-rc.3 any DKG/refresh guard on the key refused round 1;
        // since a guard could be held by a fence alone, a peer (or a leader dying between fence and
        // part 1) could stop this key's signing on this node until a restart. Signing and a
        // ceremony may overlap safely under ceremony protocol 2:
        //  * fence, parts 1–3 never touch the live share or the cached cosigner: part 3 reads the
        //    live share and writes only a *staged* share plus its STAGED vote (`stage_vote`);
        //  * the live share changes only at commit (`commit_staged`), which runs after part 3 has
        //    already released the guard — so signing across a commit was always possible, and is
        //    handled: commit evicts the cached cosigner, round 1 is checked against the leader's
        //    sharing (`check_epoch`), and a sign whose round 1 ran before the commit either
        //    completes on the old sharing (every member's round 2 already held the evicted
        //    `Cosigner`; the group key is unchanged) or fails cleanly at round 2 on a member whose
        //    round 2 started after the commit (the fresh `Cosigner` has no session for it), and the
        //    next sign runs on the new sharing (see `sign_across_commit_tests`);
        //  * nonces are never reused: round-1 nonces live only in the `Cosigner` that made them and
        //    are dropped with it, and every session burns a durable marker shared by any instance;
        //  * DKG has no live key to sign with.
        // Hosted keys never sign through here, and a hosted-key fence never covers a FROST share.
        //
        // A node whose key store failed its readiness probe ([`crate::health`]) may not volunteer
        // for a quorum. Round 1 can still succeed from the cached share, but round 2 must write a
        // nonce marker and would fail — sinking the signature for whichever healthy leader picked
        // this node, which with identifier-ordered peers is every leader (2026-10-07 incident).
        // Refusing here makes leaders skip it and sign with the rest.
        self.refuse_if_keystore_down()?;
        let cached = self.cached(key_id)?;
        if cached.cosigner.pending_count() >= MAX_PENDING_SIGN_SESSIONS_PER_KEY {
            self.prune_expired_sign_sessions();
            let pending = cached.cosigner.pending_count();
            if pending >= MAX_PENDING_SIGN_SESSIONS_PER_KEY {
                tracing::warn!(key_id, pending, "refusing sign round 1: too many sessions waiting for round 2");
                return Err(DaemonError::NotServing(format!(
                    "{pending} sign sessions for {key_id} are waiting for round 2 on this node — refusing more"
                )));
            }
        }
        self.check_epoch(key_id, &cached, ctx)?;
        let mut binding = ctx.binding(key_id)?;
        // The signing policy (audit C2), before any nonce exists: what authorizes this session.
        let auth = match &self.sign_guard {
            Some(g) => Some(g.authorize_round1(key_id, ctx, || self.ceremony_test_message(key_id))?),
            None => None,
        };
        if let Some(crate::sign_policy::SessionAuth::Intent(v)) = &auth {
            binding = binding.with_message(&v.message);
        }
        let result = cached.cosigner.round1(session_id, binding);
        if let (Ok(_), Some(g), Some(auth)) = (&result, &self.sign_guard, auth) {
            g.remember(key_id, session_id, auth);
        }
        self.update_pending_gauge();
        Ok(result?)
    }

    /// Round 1's epoch rules (audit H1/M1): never sign from a stale share, and never from another
    /// sharing than the leader's — shares of different sharings never combine, so a mixed quorum
    /// can only fail, and an old sharing must not be revived.
    fn check_epoch(&self, key_id: &str, cached: &CachedKey, ctx: &Round1Ctx) -> Result<()> {
        if let Some(mark) = self.stale_mark(key_id) {
            return Err(DaemonError::StaleShare {
                key_id: key_id.to_string(),
                peer: cached.view,
                reason: mark.reason,
            });
        }
        match ctx.leader_view {
            Some(leader) if leader != cached.view => {
                metrics::counter!(crate::metrics::EPOCH_MISMATCH).increment(1);
                let err = DaemonError::EpochMismatch { key_id: key_id.to_string(), peer: cached.view, leader };
                tracing::error!(key_id, error = %err, "sign round 1 refused: the leader signs with another sharing");
                Err(err)
            }
            Some(_) => Ok(()),
            None if self.require_epoch_match => Err(DaemonError::CeremonyRefused(format!(
                "sign round 1 for {key_id}: the leader did not say which sharing (epoch) it signs \
                 with, and signing_policy.require_epoch_match is set — upgrade that cosigner"
            ))),
            None => {
                metrics::counter!(crate::metrics::EPOCH_CHECK_SKIPPED).increment(1);
                tracing::warn!(
                    key_id,
                    "sign round 1 from a leader that sends no sharing (an older release): epoch check \
                     skipped — expected only during a rolling upgrade"
                );
                Ok(())
            }
        }
    }

    pub fn sign_round2(
        &self,
        key_id: &str,
        session_id: &str,
        message: &[u8],
        commitments: &BTreeMap<Identifier, SigningCommitments>,
    ) -> Result<SignatureShare> {
        self.sign_round2_with(key_id, session_id, message, commitments, None)
    }

    /// Sign round 2, presenting the digest of the signing intent round 1 carried (`None`: round 1
    /// had none). With a signing policy: the policy's round-2 checks, then the core binding
    /// checks, then — before the nonce marker burns — the rate-limit charge and the durable
    /// journal entry ([`crate::sign_policy::SignGuard`]); a refusal at any step releases nothing
    /// and drops the session's nonces.
    pub fn sign_round2_with(
        &self,
        key_id: &str,
        session_id: &str,
        message: &[u8],
        commitments: &BTreeMap<Identifier, SigningCommitments>,
        intent_digest: Option<[u8; 32]>,
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
        let cosigner = self.cosigner(key_id)?;
        #[cfg(test)]
        {
            let hook = crate::sync::recover(&self.hooks.after_round2_cosigner, "test_hook").clone();
            if let Some(hook) = hook {
                hook(key_id, session_id);
            }
        }
        let result = match &self.sign_guard {
            None => cosigner.round2(session_id, key_id, message, commitments, intent_digest.as_ref()).map_err(DaemonError::from),
            Some(g) => {
                let auth = match g.take(key_id, session_id) {
                    Some(a) => a,
                    None if g.require_intent() => {
                        cosigner.abort(session_id);
                        self.update_pending_gauge();
                        return Err(crate::intent::refused(
                            "missing",
                            format!("sign round 2 for session {session_id}: no round-1 authorization on this node"),
                        ));
                    }
                    None => crate::sign_policy::SessionAuth::NoIntent,
                };
                match g.check_round2(&auth, message, intent_digest.as_ref()) {
                    Err(e) => {
                        cosigner.abort(session_id);
                        Err(e)
                    }
                    Ok(()) => cosigner.round2_guarded(
                        session_id,
                        key_id,
                        message,
                        commitments,
                        intent_digest.as_ref(),
                        || g.journal_release(key_id, session_id, &auth, message),
                    ),
                }
            }
        };
        self.update_pending_gauge();
        result
    }

    /// Best-effort abort of an in-flight sign session: free the round-1 nonces held for
    /// `session_id` instead of letting them linger until the pending-TTL sweep. No-op if this node
    /// never held nonces for it (cosigner not cached, or round2 already burned the session).
    pub fn abort_sign(&self, key_id: &str, session_id: &str) {
        if let Some(g) = &self.sign_guard {
            g.forget(key_id, session_id);
        }
        let cached = self.cache().get(key_id).cloned();
        if let Some(c) = cached {
            c.cosigner.abort(session_id);
        }
        self.update_pending_gauge();
    }

    /// In-flight (round-1, not yet round-2) sign sessions currently held for `key_id`; 0 if the
    /// cosigner isn't cached. For observability and abort/TTL tests.
    pub fn pending_sign_count(&self, key_id: &str) -> usize {
        let cached = self.cache().get(key_id).map(|c| c.cosigner.clone());
        cached.map(|c| c.pending_count()).unwrap_or(0)
    }

    /// Every cached cosigner, taken out of the cache lock so a cosigner's own session lock is
    /// never acquired while the cache lock is held (audit L3: no nested locking).
    fn cached_cosigners(&self) -> Vec<Arc<Cosigner>> {
        self.cache().values().map(|c| c.cosigner.clone()).collect()
    }

    /// Drop in-flight sign sessions past their TTL on every cached key (see
    /// [`crate::health::spawn_monitor`]), and refresh the pending gauge.
    pub fn prune_expired_sign_sessions(&self) {
        let pruned: usize = self.cached_cosigners().iter().map(|c| c.prune_expired()).sum();
        if pruned > 0 {
            tracing::debug!(pruned, "dropped expired in-flight sign sessions");
        }
        // frost/core cannot log or export metrics; publish its session-map recoveries here.
        static SEEN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let recovered = rutli_frost_core::session::lock_poison_recoveries();
        let before = SEEN.swap(recovered, std::sync::atomic::Ordering::Relaxed);
        if recovered > before {
            metrics::counter!(crate::metrics::LOCK_POISON_RECOVERIES, "lock" => "sign_sessions")
                .increment(recovered - before);
            tracing::error!(
                recoveries = recovered - before,
                "recovered a signing session map poisoned by a panicking request — its in-flight \
                 sessions were dropped and the node keeps serving; the panic is a bug to report"
            );
        }
        self.update_pending_gauge();
    }

    /// In-flight sign sessions across all cached keys on this node.
    pub fn pending_sign_total(&self) -> usize {
        self.cached_cosigners().iter().map(|c| c.pending_count()).sum()
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

    /// Configured identifiers of this node's mesh peers (empty before the mesh is attached).
    pub fn mesh_ids(&self) -> Vec<u16> {
        self.mesh
            .get()
            .map(|m| m.iter().filter_map(|p| crate::hosted::identifier_index(p.identifier()).ok()).collect())
            .unwrap_or_default()
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
    /// a ceremony id this node already voted on (part 1 would refuse it anyway — refusing at the
    /// fence means a used id never even takes the guard), while a ceremony for `key_id` is staged
    /// here (it must resolve first), a DKG over an existing key, and a refresh whose leader saw a
    /// different sharing than this node holds (`expect` = the leader's (epoch, PKP digest)) — a
    /// refresh must start from one sharing on every node, or it would fold fresh zero-shares into
    /// mixed epochs (H1).
    ///
    /// First of all, before any of that and before the guard: the client's ceremony intent
    /// ([`Node::authorize_ceremony`]) — so a peer that leads a ceremony no authorized client asked
    /// for takes no guard and opens no session here.
    pub fn ceremony_begin(
        &self,
        ceremony_id: &str,
        key_id: &str,
        kind: CeremonyKind,
        expect: Option<(u64, [u8; 32])>,
        intent: Option<&crate::pb::SignedIntent>,
    ) -> Result<()> {
        // Pure checks first: a malformed or oversized id never reaches a refusal message or a log.
        crate::keystore::validate_ceremony_id(ceremony_id)?;
        crate::keystore::validate_key_id(key_id)?;
        if let Some(v) = self.authorize_ceremony(kind, key_id, ceremony_id, intent)? {
            tracing::info!(
                ceremony_id,
                key_id,
                requested_by = %v.signer_cn,
                role = ?v.role,
                "{} fence: ceremony intent verified",
                kind.as_str()
            );
        }
        if self.book()?.records.contains_key(ceremony_id) {
            return Err(DaemonError::CeremonyRefused(format!(
                "ceremony id {ceremony_id} was already used on this node"
            )));
        }
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
        // One fence per ceremony per node: a second fence under an id that already holds the guard
        // here is a second leader for the same ceremony — under ceremony intents, two leaders
        // presenting one client intent. Refused, never joined: two leaders must never drive one
        // ceremony id. (A re-fence never extended a guard either; now it is refused outright.)
        if !self.fence_created(ceremony_id, key_id, kind.as_str())? {
            return Err(DaemonError::CeremonyRefused(format!(
                "ceremony {ceremony_id} already holds the guard for {key_id} on this node — a second \
                 fence under one ceremony id (a second leader for one client intent) is refused"
            )));
        }
        Ok(())
    }

    /// The client authorization of a DKG/refresh this node is asked to fence or start (refresh-fence
    /// remediation, layer L2): the ceremony intent verified by this node itself — signer role and
    /// pin, cluster, kind, key, validity, and `ceremony_id` == the id it names — or, without one,
    /// refused when `signing_policy.require_ceremony_intent` is on (else accepted and counted).
    /// `Ok(None)`: no intent (accepted), or no signing policy at all (plaintext dev, test rigs).
    fn authorize_ceremony(
        &self,
        kind: CeremonyKind,
        key_id: &str,
        ceremony_id: &str,
        intent: Option<&crate::pb::SignedIntent>,
    ) -> Result<Option<crate::intent::VerifiedCeremony>> {
        match &self.sign_guard {
            Some(g) => g.authorize_ceremony(kind, key_id, ceremony_id, intent),
            None => Ok(None),
        }
    }

    fn refuse_if_staged(&self, key_id: &str) -> Result<()> {
        let book = self.book()?;
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
    ///
    /// The guard is all or nothing. On success it is held and marked as having a session — marked
    /// under the book lock, immediately before the session is inserted ([`Node::mark_session`]).
    /// On any failure after it was taken, it is left exactly as this call found it:
    ///  * **Created by this call** (this node was never fenced for the ceremony, or its fence was
    ///    released or preempted meanwhile): released. Nothing else owns it — no leader fenced this
    ///    node under this id — so leaving it would only block the key's next ceremony until the
    ///    fence timeout, for a part 1 that never happened.
    ///  * **Already held by this ceremony** (its leader's fence, [`Node::ceremony_begin`]): kept,
    ///    still fence-only. The fence is the leader's cluster-wide reservation, and its lifetime is
    ///    the leader's to end: the leader's abort path releases every fence (`release_all`), and a
    ///    leader that died is covered by [`CEREMONY_FENCE_TIMEOUT`] — which applies precisely because
    ///    the guard was never marked. Dropping it here would unfence this one node while the leader
    ///    still counts it as fenced, and its retained cost is bounded by that short timeout.
    ///    A repeated part 1 also lands here: the live session keeps its guard (already marked).
    fn start_session(
        &self,
        ceremony_id: &str,
        key_id: &str,
        kind: CeremonyKind,
        roster: Vec<u16>,
        old: Option<KeyVersion>,
    ) -> Result<round1::Package> {
        crate::keystore::validate_ceremony_id(ceremony_id)?;
        self.refuse_if_staged(key_id)?;
        let created = self.acquire_ceremony(key_id, ceremony_id, kind.as_str())?;
        let result = self.open_session(ceremony_id, key_id, kind, roster, old);
        if result.is_err() && created {
            self.release_ceremony(key_id, ceremony_id);
        }
        result
    }

    /// The body of [`Node::start_session`] once the guard is held (fence-only): build the
    /// participant and its round-1 package, then — under one book lock — check the ceremony id,
    /// mark the guard and insert the session. Leaves the guard for its caller to restore on error.
    fn open_session(
        &self,
        ceremony_id: &str,
        key_id: &str,
        kind: CeremonyKind,
        roster: Vec<u16>,
        old: Option<KeyVersion>,
    ) -> Result<round1::Package> {
        #[cfg(test)]
        if let Some(hook) = crate::sync::recover(&self.hooks.after_part1_acquire, "test_hook").take() {
            hook(self);
        }
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
        }?;
        let own_round1 = package.serialize()?;
        let mut book = self.book()?;
        // A ceremony id is used once per node: a node that already voted on it (or answered for
        // it as unknown, which is a no-vote) never starts it again.
        if book.sessions.contains_key(ceremony_id) {
            // A repeated part 1: the live session keeps its guard and its package.
            return Err(DaemonError::CeremonyRefused(format!(
                "ceremony {ceremony_id} is already in progress on this node"
            )));
        }
        if book.records.contains_key(ceremony_id) {
            return Err(DaemonError::CeremonyRefused(format!(
                "ceremony id {ceremony_id} was already used on this node"
            )));
        }
        if book.sessions.len() >= MAX_CEREMONY_SESSIONS {
            let orphans = self.drop_orphaned_sessions_locked(&mut book);
            let full = book.sessions.len() >= MAX_CEREMONY_SESSIONS;
            drop(book);
            for (k, c) in orphans {
                self.release_ceremony(&k, &c);
            }
            if full {
                return Err(DaemonError::NotServing(format!(
                    "{MAX_CEREMONY_SESSIONS} ceremony sessions are already in progress on this node — retry later"
                )));
            }
            book = self.book()?;
            if book.sessions.contains_key(ceremony_id) || book.records.contains_key(ceremony_id) {
                return Err(DaemonError::CeremonyRefused(format!(
                    "ceremony id {ceremony_id} was already used on this node"
                )));
            }
        }
        // From here on nothing can fail between marking the guard and inserting the session, and
        // both happen under this book lock.
        self.mark_session(key_id, ceremony_id)?;
        book.sessions.insert(
            ceremony_id.to_string(),
            Session {
                key_id: key_id.to_string(),
                kind,
                participant: Some(participant),
                started: Instant::now(),
                roster,
                old,
                own_round1,
                part2: None,
                inbox: BTreeMap::new(),
            },
        );
        Ok(package)
    }

    /// The roster a leader names must be exactly this node's: itself plus its mesh peers (every
    /// identifier `1..=n` when no mesh is attached). A ceremony over any other set of nodes —
    /// fewer (so the leader could stand in for a missing one), more, or other ones — is refused.
    fn check_roster(&self, roster: &[u16]) -> Result<()> {
        let mut expected = self.own_roster()?;
        expected.dedup();
        if roster != expected.as_slice() || roster.len() != usize::from(self.max_signers) {
            return Err(DaemonError::CeremonyRefused(format!(
                "the ceremony roster {roster:?} is not this node's roster {expected:?}"
            )));
        }
        Ok(())
    }

    /// Part 1 (ceremony protocol 2): check the client's ceremony intent again (part 1 is
    /// stateless; the id binding ties it to the fence's guard), check the leader's roster, take the
    /// guard, start the session, return this node's round-1 package (public; the leader broadcasts
    /// the full map in part 2).
    pub fn ceremony_part1(
        &self,
        ceremony_id: &str,
        key_id: &str,
        kind: CeremonyKind,
        roster: &[u16],
        intent: Option<&crate::pb::SignedIntent>,
    ) -> Result<round1::Package> {
        crate::keystore::validate_ceremony_id(ceremony_id)?;
        crate::keystore::validate_key_id(key_id)?;
        self.authorize_ceremony(kind, key_id, ceremony_id, intent)?;
        let old = match kind {
            CeremonyKind::Dkg => {
                // `…frost-import-…` ids belong to the split ceremony. Refusing them here, on every
                // node and whether or not the import has happened yet, means a DKG can never mint a
                // key under an id an operator is about to install.
                if crate::share_delivery::is_reserved_for_import(key_id) {
                    return Err(DaemonError::ReservedKeyId(key_id.to_string()));
                }
                // DKG must never clobber a provisioned key — the namespace key is non-rotatable.
                if self.keystore.exists(key_id) {
                    return Err(DaemonError::KeyExists(key_id.to_string()));
                }
                None
            }
            CeremonyKind::Refresh => {
                if !self.keystore.exists(key_id) {
                    return Err(DaemonError::UnknownKey(key_id.to_string()));
                }
                // No reverse fence over in-flight signs: see `ceremony_fence`.
                let share = self.keystore.load(key_id)?;
                Some((share.epoch, share.pkp_digest()?))
            }
        };
        self.check_roster(roster)?;
        self.start_session(ceremony_id, key_id, kind, roster.to_vec(), old)
    }

    /// Part 2: check the leader's round-1 map — exactly the roster, and this node's own package
    /// unchanged — compute its digest (C1 echo: every delivery carries it, so a leader that shows
    /// nodes different maps makes every honest node abort) and this node's round-2 packages.
    ///
    /// The packages go to [`crate::ceremony::part2_and_deliver`], which sends each straight to its
    /// recipient over the mesh. Crate-private on purpose: no peer API ever returns them.
    pub(crate) fn ceremony_part2_compute(
        &self,
        ceremony_id: &str,
        round1_map: &BTreeMap<Identifier, round1::Package>,
    ) -> Result<([u8; 32], BTreeMap<u16, round2::Package>)> {
        let (key_id, kind, roster, old, own) = {
            let book = self.book()?;
            let s = book.sessions.get(ceremony_id).ok_or_else(|| DaemonError::UnknownDkg(ceremony_id.into()))?;
            if s.part2.is_some() {
                return Err(DaemonError::CeremonyRefused(format!("ceremony {ceremony_id}: part 2 already ran")));
            }
            (s.key_id.clone(), s.kind, s.roster.clone(), s.old, s.own_round1.clone())
        };
        self.assert_owns(&key_id, ceremony_id)?; // refuse if a newer ceremony superseded this one
        let result = (|| -> Result<([u8; 32], BTreeMap<u16, round2::Package>)> {
            let mut ids =
                round1_map.keys().map(|&id| crate::hosted::identifier_index(id)).collect::<Result<Vec<_>>>()?;
            ids.sort_unstable();
            if ids != roster {
                return Err(DaemonError::CeremonyRefused(format!(
                    "the round-1 map covers nodes {ids:?}, but the ceremony roster is {roster:?}"
                )));
            }
            let mine = round1_map
                .get(&self.identifier)
                .ok_or_else(|| DaemonError::CeremonyRefused("the round-1 map lacks this node".into()))?;
            if mine.serialize()? != own {
                return Err(DaemonError::Disagreement(
                    "the leader's round-1 map carries a different package for this node — \
                     equivocation; aborting"
                        .into(),
                ));
            }
            let ctx = crate::ceremony::DigestContext {
                ceremony_id,
                key_id: &key_id,
                kind,
                max_signers: self.max_signers,
                min_signers: self.min_signers,
                old,
            };
            let digest = crate::ceremony::round1_digest(&ctx, round1_map)?;
            let others = without_self(round1_map, self.identifier);
            let packages = {
                let mut book = self.book()?;
                let s = book
                    .sessions
                    .get_mut(ceremony_id)
                    .ok_or_else(|| DaemonError::UnknownDkg(ceremony_id.into()))?;
                let packages = match s.participant.as_mut() {
                    Some(Participant::Dkg(p)) => p.part2(&others)?,
                    Some(Participant::Refresh(p)) => p.part2(&others)?,
                    None => {
                        return Err(DaemonError::CeremonyRefused(format!("ceremony {ceremony_id} is finishing")))
                    }
                };
                s.part2 = Some(Part2State { digest, round1_map: round1_map.clone() });
                packages
            };
            let mut by_index = BTreeMap::new();
            for (id, pkg) in packages {
                by_index.insert(crate::hosted::identifier_index(id)?, pkg);
            }
            Ok((digest, by_index))
        })();
        if let Err(e) = &result {
            self.fail_session(ceremony_id, &key_id, &format!("part 2 failed: {e}"));
        }
        result
    }

    /// A round-2 package for this node, delivered directly by its sender. `from` is the sender as
    /// the transport authenticated it (the caller's certificate CN, mapped exactly to a roster
    /// identifier) — never a value the sender merely claims. The package must be addressed to this
    /// node and the sender be in the roster; one package per sender — a second, different one is
    /// equivocation and aborts the session. Deliveries may arrive before this node's own part 2.
    pub fn ceremony_deliver(
        &self,
        ceremony_id: &str,
        from: u16,
        to: u16,
        digest: [u8; 32],
        package: round2::Package,
    ) -> Result<()> {
        let me = self.index()?;
        if to != me {
            return Err(DaemonError::CeremonyRefused(format!(
                "a round-2 package for node {to} was delivered to node {me}"
            )));
        }
        if from == me {
            return Err(DaemonError::CeremonyRefused("a node never delivers to itself".into()));
        }
        let mut book = self.book()?;
        let s = book.sessions.get_mut(ceremony_id).ok_or_else(|| DaemonError::UnknownDkg(ceremony_id.into()))?;
        if !s.roster.contains(&from) {
            return Err(DaemonError::CeremonyRefused(format!(
                "node {from} is not in the roster of ceremony {ceremony_id}"
            )));
        }
        if s.participant.is_none() {
            return Err(DaemonError::CeremonyRefused(format!("ceremony {ceremony_id} is finishing")));
        }
        match s.inbox.get(&from) {
            Some((d, p)) if *d == digest && p.serialize()? == package.serialize()? => Ok(()), // a retry
            Some(_) => {
                let key_id = s.key_id.clone();
                drop(book);
                let why = format!("node {from} delivered two different round-2 packages — equivocation");
                self.fail_session(ceremony_id, &key_id, &why);
                Err(DaemonError::Disagreement(why))
            }
            None => {
                s.inbox.insert(from, (digest, package));
                Ok(())
            }
        }
    }

    /// Part 3: require a round-2 package from every other roster node, each computed over the
    /// same round-1 map as this node's (equal digests) and the leader's digest equal too; then
    /// stage the new share and vote yes ([`Node::finish_session`]). Any mismatch votes no.
    pub fn ceremony_part3(&self, ceremony_id: &str, leader_digest: &[u8; 32]) -> Result<StagedOutcome> {
        let (key_id, kind, roster, old, digest, round1_map, inbox) = {
            let book = self.book()?;
            let s = book.sessions.get(ceremony_id).ok_or_else(|| DaemonError::UnknownDkg(ceremony_id.into()))?;
            let p2 = s
                .part2
                .as_ref()
                .ok_or_else(|| DaemonError::CeremonyRefused(format!("ceremony {ceremony_id}: part 3 before part 2")))?;
            (s.key_id.clone(), s.kind, s.roster.clone(), s.old, p2.digest, p2.round1_map.clone(), s.inbox.clone())
        };
        let me = self.index()?;
        let checked = (|| -> Result<BTreeMap<Identifier, round2::Package>> {
            if digest != *leader_digest {
                return Err(DaemonError::Disagreement(
                    "the leader's round-1 digest differs from this node's — equivocation; aborting".into(),
                ));
            }
            let mut for_me = BTreeMap::new();
            for &id in roster.iter().filter(|&&id| id != me) {
                let (d, pkg) = inbox.get(&id).ok_or_else(|| {
                    DaemonError::CeremonyRefused(format!("no round-2 package was delivered by node {id}"))
                })?;
                if *d != digest {
                    return Err(DaemonError::Disagreement(format!(
                        "node {id} computed a different round-1 digest — the nodes were shown \
                         different round-1 maps (leader equivocation); aborting"
                    )));
                }
                for_me.insert(Identifier::try_from(id)?, pkg.clone());
            }
            Ok(for_me)
        })();
        let for_me = match checked {
            Ok(m) => m,
            Err(e) => {
                self.fail_session(ceremony_id, &key_id, &format!("part 3 refused: {e}"));
                return Err(e);
            }
        };
        self.finish_session(ceremony_id, kind, roster, Some(digest), |key_id, participant| match kind {
            CeremonyKind::Dkg => self.dkg_share(key_id, participant, &round1_map, &for_me),
            CeremonyKind::Refresh => {
                let (share, was) = self.refresh_share(key_id, participant, &round1_map, &for_me)?;
                if was != old {
                    return Err(DaemonError::Disagreement(format!(
                        "the share of {key_id} changed during the refresh — aborting"
                    )));
                }
                Ok((share, was))
            }
        })
    }

    /// Record a no-vote for `ceremony_id` unless this node already recorded a vote. Caller holds
    /// the ceremony lock.
    ///
    /// Bounded like the no-votes for unknown ids ([`Node::record_unknown_locked`]): at most
    /// [`MAX_UNKNOWN_NO_VOTES`] roster-less no-votes for failed or orphaned sessions are kept (a
    /// peer can open sessions for made-up key ids and let them orphan). Beyond it the session is
    /// dropped without a record and nothing is answered — the same safe refusal.
    fn record_abort_locked(&self, book: &mut CeremonyBook, ceremony_id: &str, reason: &str) -> Result<()> {
        if book.records.contains_key(ceremony_id) {
            return Ok(());
        }
        let cap = self.unknown_no_vote_caps.1;
        let held = book
            .records
            .values()
            .filter(|r| r.state == RecordState::Aborted && r.roster.is_empty() && r.unknown_asked_by.is_none())
            .count();
        if held >= cap {
            metrics::counter!(crate::metrics::CEREMONY_UNKNOWN_REFUSED).increment(1);
            return Err(DaemonError::RateLimited(format!(
                "ceremony {ceremony_id}: this node already holds {held} no-votes for failed or orphaned \
                 sessions (cap {cap}) — not recording another (this is no vote)"
            )));
        }
        let rec = CeremonyRecord::aborted(ceremony_id, reason);
        self.record_store.write(None, &rec)?;
        book.records.insert(ceremony_id.to_string(), rec);
        Ok(())
    }

    /// Drop a failed session and vote no on it. Best effort on the vote: a peer asking later gets
    /// the same answer from [`Node::ceremony_status`].
    fn fail_session(&self, ceremony_id: &str, key_id: &str, reason: &str) {
        match self.book() {
            Ok(mut book) => {
                book.sessions.remove(ceremony_id);
                if let Err(e) = self.record_abort_locked(&mut book, ceremony_id, reason) {
                    tracing::warn!(ceremony_id, error = %e, "could not record an aborted ceremony");
                }
            }
            Err(e) => tracing::warn!(ceremony_id, error = %e, "could not record an aborted ceremony"),
        }
        self.release_ceremony(key_id, ceremony_id);
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
            let mut book = self.book()?;
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
            quarantined: false,
            split_detected_ms: 0,
            unknown_asked_by: None,
            recovered: false,
        };
        let mut book = self.book()?;
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

    /// Drop the sessions orphaned past the orphan timeout (their leader is gone; part 3 will never
    /// come), each with a no-vote (best effort). Returns `(key_id, ceremony_id)` of each, whose
    /// guards the caller releases after dropping the book lock.
    fn drop_orphaned_sessions_locked(&self, book: &mut CeremonyBook) -> Vec<(String, String)> {
        let orphaned: Vec<String> = book
            .sessions
            .iter()
            .filter(|(_, s)| s.participant.is_some() && s.started.elapsed() >= self.ceremony_orphan_timeout)
            .map(|(id, _)| id.clone())
            .collect();
        let mut out = Vec::new();
        for id in orphaned {
            if let Some(s) = book.sessions.remove(&id) {
                if let Err(e) = self.record_abort_locked(book, &id, "orphaned: no part 3 within the orphan timeout") {
                    tracing::warn!(ceremony_id = %id, error = %e, "could not record an orphaned ceremony's no-vote");
                }
                out.push((s.key_id, id));
            }
        }
        out
    }

    /// Record a no-vote for `ceremony_id`, which this node has no session or record for, because
    /// `asker` asked about it (audit F2). Caller holds the ceremony lock.
    ///
    /// Bounded: at most [`MAX_UNKNOWN_NO_VOTES_PER_ASKER`] such records per asking peer and
    /// [`MAX_UNKNOWN_NO_VOTES`] in total (until the 30-day garbage collection removes them).
    /// Beyond either cap this refuses (RESOURCE_EXHAUSTED) instead of answering.
    ///
    /// **Why the refusal keeps the two-phase commit safe.** The invariant is: this node answers
    /// ABORTED only from a durable record, and once it has, never starts (and so never stages or
    /// commits) that ceremony id. A refusal writes nothing and answers nothing: the asker gets
    /// [`crate::ceremony_record::PeerReport::Unknown`], which is not evidence — its resolver waits,
    /// it neither commits (that needs this node's yes-vote) nor aborts on it. And since no no-vote
    /// was given, this node may still take part in that id later without contradicting anything it
    /// said. The cost is liveness only, and only once a peer has spent its quota: a STAGED peer
    /// asking about a ceremony this node really lost waits (or uses `ceremony resolve
    /// --assume-lost`) instead of aborting, while signing continues on the old share.
    fn record_unknown_locked(&self, book: &mut CeremonyBook, ceremony_id: &str, asker: Option<&str>) -> Result<()> {
        let asker = asker.unwrap_or("");
        let (per_asker, total) = self.unknown_no_vote_caps;
        let mut mine = 0usize;
        let mut all = 0usize;
        for r in book.records.values() {
            if let Some(by) = &r.unknown_asked_by {
                all += 1;
                if by == asker {
                    mine += 1;
                }
            }
        }
        if mine >= per_asker || all >= total {
            metrics::counter!(crate::metrics::CEREMONY_UNKNOWN_REFUSED).increment(1);
            tracing::warn!(
                ceremony_id,
                asker,
                from_asker = mine,
                total = all,
                "refusing to record another no-vote for an unknown ceremony id (cap reached) — the asker \
                 waits; a peer asking about many unknown ceremonies is misbehaving"
            );
            return Err(DaemonError::RateLimited(format!(
                "ceremony {ceremony_id} is unknown here and this node already holds {mine} no-vote(s) for \
                 unknown ceremonies asked by {asker:?} ({all} in total; caps {per_asker}/{total}) — \
                 not answering (this is no vote)"
            )));
        }
        let mut rec = CeremonyRecord::aborted(ceremony_id, "unknown here: no session and no record when a peer asked");
        rec.unknown_asked_by = Some(asker.to_string());
        self.record_store.write(None, &rec)?;
        book.records.insert(ceremony_id.to_string(), rec);
        metrics::gauge!(crate::metrics::CEREMONY_UNKNOWN_NO_VOTES).set((all + 1) as f64);
        Ok(())
    }

    /// What this node can say about `ceremony_id` (`Peer.CeremonyStatus`): its recorded vote, or
    /// IN_PROGRESS while the session lives. With neither, it durably votes no **before** answering
    /// ABORTED — so the answer can never change later — and the same for a session orphaned past
    /// the orphan timeout (its leader is gone; part 3 will never come). An in-process caller; a
    /// peer's question goes through [`Node::ceremony_status_from`].
    pub fn ceremony_status(&self, ceremony_id: &str) -> Result<StatusInfo> {
        self.ceremony_status_from(ceremony_id, None)
    }

    /// [`Node::ceremony_status`] asked by the peer whose certificate CN is `asker`: a no-vote for
    /// an unknown id is bounded per asker ([`Node::record_unknown_locked`]).
    pub fn ceremony_status_from(&self, ceremony_id: &str, asker: Option<&str>) -> Result<StatusInfo> {
        crate::keystore::validate_ceremony_id(ceremony_id)?;
        let mut release = None;
        let info = {
            let mut book = self.book()?;
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
                    self.record_abort_locked(&mut book, ceremony_id, "orphaned: no part 3 within the orphan timeout")
                }
                None => self.record_unknown_locked(&mut book, ceremony_id, asker),
            }
            .map(|()| StatusInfo::from_record(book.records.get(ceremony_id).expect("just recorded")))
        };
        // The orphaned session is gone either way, so its guard goes too — even when its no-vote
        // could not be recorded (a cap).
        if let Some(key_id) = release {
            self.release_ceremony(&key_id, ceremony_id);
        }
        info
    }

    /// The leader gives up on `ceremony_id` (`Peer.CeremonyAbort`). Only a session still in memory
    /// is dropped (with a durable no-vote); a recorded vote is never changed by the leader's word —
    /// a STAGED node aborts only on evidence from its peers ([`crate::ceremony::resolve`]).
    pub fn ceremony_abort(&self, ceremony_id: &str) -> Result<StatusInfo> {
        self.ceremony_abort_from(ceremony_id, None)
    }

    /// [`Node::ceremony_abort`] from the peer whose certificate CN is `asker`.
    pub fn ceremony_abort_from(&self, ceremony_id: &str, asker: Option<&str>) -> Result<StatusInfo> {
        crate::keystore::validate_ceremony_id(ceremony_id)?;
        let mut release = None;
        let info = {
            let mut book = self.book()?;
            if let Some(r) = book.records.get(ceremony_id) {
                return Ok(StatusInfo::from_record(r));
            }
            if let Some(s) = book.sessions.get(ceremony_id) {
                if s.participant.is_none() {
                    return Ok(StatusInfo::in_progress()); // part 3 running; it will vote
                }
                release = book.sessions.remove(ceremony_id).map(|s| s.key_id);
                self.record_abort_locked(&mut book, ceremony_id, "aborted by the ceremony leader")
            } else {
                self.record_unknown_locked(&mut book, ceremony_id, asker)
            }
            .map(|()| StatusInfo::from_record(book.records.get(ceremony_id).expect("just recorded")))
        };
        if let Some(key_id) = release {
            self.release_ceremony(&key_id, ceremony_id);
        }
        info
    }

    /// Apply the resolver's verdict to a STAGED ceremony: commit (promote the staged share, then
    /// record COMMITTED) or abort (delete it, then record ABORTED). A record that is not STAGED is
    /// returned unchanged — resolution is idempotent and a terminal vote never changes.
    pub fn apply_resolution(&self, ceremony_id: &str, decision: &Decision) -> Result<StatusInfo> {
        self.apply_resolution_with(ceremony_id, decision, false, false)
    }

    /// [`Node::apply_resolution`]; an abort with `quarantine` keeps the staged share (audit F3),
    /// and `split` flags the ceremony as resolved differently elsewhere (a peer COMMITTED it).
    pub fn apply_resolution_with(&self, ceremony_id: &str, decision: &Decision, quarantine: bool, split: bool) -> Result<StatusInfo> {
        let mut book = self.book()?;
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
                if !quarantine {
                    self.keystore.discard_staged(&rec.key_id, ceremony_id)?;
                }
                (RecordState::Aborted, why.clone())
            }
        };
        let now = crate::ceremony_record::now_ms();
        let aborted = state == RecordState::Aborted;
        let done = CeremonyRecord {
            state,
            reason,
            updated_ms: now,
            quarantined: aborted && quarantine,
            split_detected_ms: if aborted && split { now } else { 0 },
            ..rec.clone()
        };
        self.record_store.write(Some(&rec), &done)?;
        book.records.insert(ceremony_id.to_string(), done.clone());
        drop(book);
        if state == RecordState::Committed {
            // The next sign loads the committed share, which is newer than anything a stale mark
            // was measured against.
            self.cache().remove(&rec.key_id);
            if self.stale_mark(&rec.key_id).is_some() {
                self.set_stale(&rec.key_id, None);
            }
            tracing::info!(ceremony_id, key_id = %rec.key_id, epoch = rec.new_epoch, "ceremony committed");
        } else if split {
            tracing::error!(
                ceremony_id,
                key_id = %rec.key_id,
                reason = %done.reason,
                "ceremony aborted here while a peer reports it COMMITTED — a cosigner equivocated; the \
                 staged share is quarantined: see `rutli-cosigner ceremony recover-commit` (docs/ceremonies.md)"
            );
        } else {
            tracing::warn!(ceremony_id, key_id = %rec.key_id, reason = %done.reason, quarantined = quarantine, "ceremony aborted");
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
    /// `true` (fail closed: the caller refuses to discard) when the ceremony state cannot be read.
    pub fn has_ceremony_for(&self, key_id: &str) -> bool {
        self.book()
            .map(|b| b.records.values().any(|r| r.key_id == key_id && r.state != RecordState::Aborted))
            .unwrap_or(true)
    }

    /// Delete this node's file for `key_id` and its (empty) nonce directory — the last step of
    /// [`crate::ceremony::discard_partial_key`], which checks everything else first. Refuses if
    /// any signing session was ever burned for the key here: a marker, or the sentinel marker
    /// pruning leaves behind ([`rutli_frost_core::nonce_store::PRUNED_SENTINEL`]).
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
        self.cache().remove(key_id);
        tracing::warn!(key_id, "discarded this node's file for a legacy partial DKG key");
        Ok(())
    }

    /// Terminal records not yet known to be settled on every peer.
    pub fn unsettled_records(&self) -> Vec<CeremonyRecord> {
        self.book()
            .map(|b| {
                b.records
                    .values()
                    .filter(|r| r.is_terminal() && !r.peers_settled && !r.roster.is_empty())
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Note that every peer has resolved `ceremony_id` too.
    pub fn mark_settled(&self, ceremony_id: &str) -> Result<()> {
        let mut book = self.book()?;
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
        let mut book = self.book()?;
        let old: Vec<String> = book
            .records
            .values()
            .filter(|r| r.is_terminal() && !r.quarantined && (r.peers_settled || r.roster.is_empty()) && r.updated_ms < cutoff)
            .map(|r| r.ceremony_id.clone())
            .collect();
        for id in &old {
            self.record_store.remove(id)?;
            book.records.remove(id);
        }
        Ok(old.len())
    }

    /// ABORTED records whose staged share is quarantined (audit F3).
    pub fn quarantined_records(&self) -> Vec<CeremonyRecord> {
        self.book()
            .map(|b| b.records.values().filter(|r| r.quarantined).cloned().collect())
            .unwrap_or_default()
    }

    /// Flag a quarantined ceremony as split (a peer reports it COMMITTED with this node's outcome).
    /// Returns whether it was newly flagged.
    pub fn flag_split(&self, ceremony_id: &str) -> Result<bool> {
        let mut book = self.book()?;
        let Some(rec) = book.records.get(ceremony_id).cloned() else { return Ok(false) };
        if !rec.quarantined || rec.split_detected_ms != 0 {
            return Ok(false);
        }
        let now = crate::ceremony_record::now_ms();
        let done = CeremonyRecord { split_detected_ms: now, updated_ms: now, ..rec.clone() };
        self.record_store.write(Some(&rec), &done)?;
        book.records.insert(ceremony_id.to_string(), done);
        Ok(true)
    }

    /// Delete a quarantined staged share and clear the quarantine (no node can commit the
    /// ceremony any more, its retention passed, or the operator dropped it).
    pub fn drop_quarantine(&self, ceremony_id: &str) -> Result<()> {
        let mut book = self.book()?;
        let Some(rec) = book.records.get(ceremony_id).cloned() else {
            return Err(DaemonError::UnknownDkg(ceremony_id.into()));
        };
        if !rec.quarantined {
            return Ok(());
        }
        self.keystore.discard_staged(&rec.key_id, ceremony_id)?;
        let done = CeremonyRecord { quarantined: false, updated_ms: crate::ceremony_record::now_ms(), ..rec.clone() };
        self.record_store.write(Some(&rec), &done)?;
        book.records.insert(ceremony_id.to_string(), done);
        tracing::info!(ceremony_id, key_id = %rec.key_id, "dropped a quarantined staged share");
        Ok(())
    }

    /// Drop quarantines older than `older_than` that no split was detected for. Returns how many.
    pub fn gc_quarantine(&self, older_than: Duration) -> Result<usize> {
        let cutoff = crate::ceremony_record::now_ms().saturating_sub(older_than.as_millis() as u64);
        let old: Vec<String> = self
            .quarantined_records()
            .into_iter()
            .filter(|r| r.split_detected_ms == 0 && r.updated_ms < cutoff)
            .map(|r| r.ceremony_id)
            .collect();
        for id in &old {
            self.drop_quarantine(id)?;
        }
        Ok(old.len())
    }

    /// Ceremonies this node aborted while a peer reports them COMMITTED, quarantine still held:
    /// `rutli_ceremonies_split`.
    pub fn split_count(&self) -> usize {
        self.quarantined_records().iter().filter(|r| r.split_detected_ms != 0).count()
    }

    /// The last step of [`crate::ceremony::recover_commit`] (which checks the peers first): make
    /// the quarantined share of an ABORTED ceremony live and record COMMITTED (`recovered`).
    pub fn apply_recovery(&self, ceremony_id: &str) -> Result<StatusInfo> {
        let mut book = self.book()?;
        let rec = book
            .records
            .get(ceremony_id)
            .cloned()
            .ok_or_else(|| DaemonError::UnknownDkg(ceremony_id.into()))?;
        if rec.state != RecordState::Aborted || !rec.quarantined {
            return Err(DaemonError::CeremonyRefused(format!(
                "ceremony {ceremony_id} is {} here{} — only a quarantined abort can be recovered",
                rec.state.as_str(),
                if rec.state == RecordState::Aborted { " without a quarantined share" } else { "" }
            )));
        }
        if !self.keystore.has_staged(&rec.key_id, ceremony_id)? {
            return Err(DaemonError::CeremonyRefused(format!(
                "ceremony {ceremony_id}: the quarantined share of {} is missing",
                rec.key_id
            )));
        }
        self.commit_staged(&rec)?;
        let now = crate::ceremony_record::now_ms();
        let done = CeremonyRecord {
            state: RecordState::Committed,
            quarantined: false,
            recovered: true,
            reason: format!("recovered by the operator after: {}", rec.reason),
            updated_ms: now,
            ..rec.clone()
        };
        self.record_store.write_recovery(&rec, &done)?;
        book.records.insert(ceremony_id.to_string(), done.clone());
        drop(book);
        self.cache().remove(&rec.key_id);
        if self.stale_mark(&rec.key_id).is_some() {
            self.set_stale(&rec.key_id, None);
        }
        metrics::counter!(crate::metrics::CEREMONY_RESOLUTIONS, "result" => "recovered").increment(1);
        tracing::warn!(ceremony_id, key_id = %rec.key_id, epoch = rec.new_epoch, "quarantined ceremony share recovered and committed by the operator");
        Ok(StatusInfo::from_record(&done))
    }

    /// [`Node::ceremony_part1`] for a DKG over this node's own roster (every identifier `1..=n`, or
    /// itself plus its mesh). Convenience for tools and tests.
    pub fn dkg_part1(&self, dkg_id: &str, key_id: &str) -> Result<round1::Package> {
        self.ceremony_part1(dkg_id, key_id, CeremonyKind::Dkg, &self.own_roster()?, None)
    }

    /// [`Node::ceremony_part1`] for a refresh over this node's own roster.
    pub fn refresh_part1(&self, refresh_id: &str, key_id: &str) -> Result<round1::Package> {
        self.ceremony_part1(refresh_id, key_id, CeremonyKind::Refresh, &self.own_roster()?, None)
    }

    fn own_roster(&self) -> Result<Vec<u16>> {
        let me = self.index()?;
        let mut roster: Vec<u16> = match self.mesh.get() {
            Some(mesh) => mesh.iter().map(|p| crate::hosted::identifier_index(p.identifier())).collect::<Result<_>>()?,
            None => (1..=self.max_signers).filter(|&i| i != me).collect(),
        };
        roster.push(me);
        roster.sort_unstable();
        Ok(roster)
    }
}

/// A sharing of a key as nodes compare it: (epoch, PKP digest).
pub type KeyVersion = crate::error::KeyVersion;

/// A key's loaded signing state: its [`Cosigner`] and the sharing (epoch, PKP digest) of the share
/// it was built from — what sign round 1 compares against the leader's.
#[derive(Clone)]
struct CachedKey {
    cosigner: Arc<Cosigner>,
    view: KeyVersion,
}

/// What a leader declares in sign round 1 (`SignRound1Request` beyond key and session).
#[derive(Clone, Debug, Default)]
pub struct Round1Ctx {
    /// The sharing the leader signs with. `None`: a leader from before epochs, which sends none.
    pub leader_view: Option<KeyVersion>,
    /// The message the session will sign; round 2 must sign exactly it. `None`: not declared.
    pub message: Option<Vec<u8>>,
    /// The attempt's signer set (configured identifiers); round 2's commitment map must be exactly
    /// these. `None`: not declared.
    pub signers: Option<Vec<u16>>,
    /// The client's signing intent (audit C2), forwarded unchanged; the session is bound to its
    /// digest, and a node with a signing policy verifies it.
    pub intent: Option<crate::pb::SignedIntent>,
    /// A split-ceremony sign test (`purpose = "sign-test"`): no intent, the node's own test digest.
    pub sign_test: bool,
}

impl Round1Ctx {
    /// The session binding this context declares for `key_id` (see
    /// [`rutli_frost_core::session::SessionBinding`]). Intents (audit C2) plug in here.
    fn binding(&self, key_id: &str) -> Result<SessionBinding> {
        let mut b = SessionBinding::new(key_id);
        if let Some(m) = &self.message {
            if m.len() != crate::orchestrator::CANTON_DIGEST_LEN {
                return Err(DaemonError::InvalidMessageLength {
                    got: m.len(),
                    expected: crate::orchestrator::CANTON_DIGEST_LEN,
                });
            }
            b = b.with_message(m);
        }
        if let Some(ids) = &self.signers {
            let set: std::collections::BTreeSet<Identifier> =
                ids.iter().map(|&i| Identifier::try_from(i)).collect::<std::result::Result<_, _>>()?;
            if set.len() != ids.len() {
                return Err(DaemonError::Core(rutli_frost_core::CoreError::InvalidBinding(format!(
                    "the declared signer set {ids:?} repeats a cosigner"
                ))));
            }
            b = b.with_signers(set);
        }
        if let Some(intent) = &self.intent {
            b = b.with_intent_digest(crate::intent::intent_digest(intent));
        }
        Ok(b)
    }
}

/// Why this node treats its share of a key as stale ([`crate::epoch_check`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StaleMark {
    /// The epoch of this node's share when it was found stale.
    pub own_epoch: u64,
    /// The newer committed epoch that makes it stale.
    pub newer_epoch: u64,
    pub reason: String,
}

/// What a leader needs to sign with key K: the threshold, its own sharing, and whether it is stale.
#[derive(Clone, Debug)]
pub struct SigningView {
    pub threshold: u16,
    pub view: KeyVersion,
    pub stale: Option<StaleMark>,
}

/// What a node staged in part 3: the outcome every node must agree on before anyone commits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StagedOutcome {
    pub new_epoch: u64,
    pub new_pkp_digest: [u8; 32],
    pub group_key: [u8; 32],
}

/// Hosted keys may never live under an id reserved for the split ceremony (`…frost-import-…`).
/// The refusal for a write under a tombstoned id: ALREADY_EXISTS, naming the break-glass.
pub(crate) fn tombstoned(key_id: &str) -> DaemonError {
    DaemonError::KeyExists(format!(
        "{key_id} is tombstoned (deleted): hosted key ids are never reused — undelete it \
         (rutli-cosigner hosted-undelete, within the grace period), or clear the tombstone on EVERY \
         node (rutli-cosigner hosted-clear-tombstone) before generating it again"
    ))
}

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
        let existing = match self.hosted_state(key_id)? {
            HostedState::Tombstone(_) => return Err(tombstoned(key_id)),
            _ => self.keystore.load_hosted(key_id)?,
        };
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
            if let HostedState::Tombstone(_) = self.hosted_state(key_id)? {
                return Err(tombstoned(key_id));
            }
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
        self.hosted_store_for(key_id, key, None)
    }

    /// [`Node::hosted_store`], noting the genkey ceremony that created it here (`created_by`), so
    /// that generation — and only it, while it holds its fence — may roll it back.
    pub fn hosted_store_for(&self, key_id: &str, key: &crate::hosted::HostedKey, created_by: Option<&str>) -> Result<()> {
        self.hosted_ctx()?;
        // A peer may never push a hosted key under an id reserved for the split ceremony: it would
        // squat on an import, or (with a rename-based write) replace an installed share.
        refuse_reserved_for_hosted(key_id)?;
        // Create-once-immutable: a key id maps to one key forever. Canton rotates by minting a new
        // id plus a topology transaction, so a differing replica is a genuine conflict — never a
        // merge. Overwriting here could silently destroy the material peers already committed to.
        // A tombstoned id stays deleted: nothing ever overwrites a tombstone (audit M2).
        let identical_or_conflict = |node: &Node| -> Result<()> {
            let existing = match node.hosted_state(key_id)? {
                HostedState::Tombstone(_) => return Err(tombstoned(key_id)),
                HostedState::Live(k) => k,
                HostedState::Frost => {
                    return Err(DaemonError::KeyExists(format!("{key_id} is a FROST share here")))
                }
                HostedState::Absent => return Err(DaemonError::UnknownKey(key_id.to_string())),
            };
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
        // create, not save: a file that appeared since the check (a racing push, a FROST share, a
        // tombstone) is never renamed over; it is compared like any existing one.
        match self.keystore.create_hosted(key_id, key) {
            Err(DaemonError::KeyExists(_)) => identical_or_conflict(self),
            Ok(()) => {
                if let Some(c) = created_by {
                    crate::sync::recover(&self.hosted_created_in, "hosted_created_in")
                        .insert(key_id.to_string(), c.to_string());
                }
                Ok(())
            }
            other => other,
        }
    }

    /// What this node holds under `key_id`.
    pub fn hosted_state(&self, key_id: &str) -> Result<HostedState> {
        Ok(match self.keystore.load_record(key_id) {
            Ok(crate::keystore::Record::Hosted(k)) => HostedState::Live(k),
            Ok(crate::keystore::Record::Tombstone(t)) => HostedState::Tombstone(t),
            Ok(crate::keystore::Record::Frost(_)) => HostedState::Frost,
            Err(DaemonError::UnknownKey(_)) => HostedState::Absent,
            Err(e) => return Err(e),
        })
    }

    /// Whether `key_id` is tombstoned on this node.
    pub fn hosted_tombstoned(&self, key_id: &str) -> Result<bool> {
        Ok(self.keystore.exists(key_id) && matches!(self.hosted_state(key_id)?, HostedState::Tombstone(_)))
    }

    /// How long a tombstone keeps the deleted key's material (`hosted_keys.delete_grace_secs`).
    pub fn with_delete_grace(mut self, grace: Duration) -> Self {
        self.delete_grace = grace;
        self
    }

    /// Delete hosted key `key_id` on this node by the client's delete intent (audit M2): verify it
    /// here — whoever forwarded it — and replace the key with a tombstone that retains its material
    /// for the grace period; on a node that lacks the key, record the tombstone so the key can never
    /// arrive. `expiry`: [`crate::intent::Expiry::Enforce`] for a live delete (DeleteKey, PurgeKey),
    /// `Propagated` for a tombstone a peer propagates. A tombstone never applies to a copy created or
    /// undeleted after its intent was issued.
    pub fn hosted_apply_tombstone(
        &self,
        key_id: &str,
        intent: &crate::pb::SignedIntent,
        expiry: crate::intent::Expiry,
        known: Option<&DeletedKeyInfo>,
    ) -> Result<TombstoneOutcome> {
        use prost::Message;
        self.hosted_ctx()?;
        refuse_reserved_for_hosted(key_id)?;
        let verifier = self.sign_guard.as_ref().map(|g| g.verifier().clone()).ok_or_else(|| {
            crate::intent::refused_delete(
                "disabled",
                "this node verifies no delete intents (no signing policy / TLS) — hosted-key deletes are disabled".into(),
            )
        })?;
        let now = crate::intent::now_ms();
        let v = verifier.verify_delete(intent, key_id, now, expiry)?;
        if self.keystore.is_cleared(key_id, &v.digest)? {
            return Ok(TombstoneOutcome::Already);
        }
        let grace_ms = u64::try_from(self.delete_grace.as_millis()).unwrap_or(u64::MAX);
        // A propagated tombstone keeps the original deletion time (checked against its intent's
        // validity by every node it reaches next — audit F7); the grace period runs from now.
        let deleted_at_ms = match expiry {
            crate::intent::Expiry::Propagated { deleted_at_ms } => deleted_at_ms,
            crate::intent::Expiry::Enforce => now,
        };
        let tombstone = |info: DeletedKeyInfo, retained: Option<crate::hosted::HostedKey>| crate::hosted::Tombstone {
            key_id: key_id.to_string(),
            spec: info.spec,
            created_at: info.created_at,
            commitment: hex::encode(info.commitment),
            deleted_at_ms,
            purge_after_ms: now.saturating_add(grace_ms),
            delete_intent: hex::encode(intent.encode_to_vec()),
            retained: if grace_ms == 0 { None } else { retained },
        };
        for _ in 0..3 {
            match self.hosted_state(key_id)? {
                HostedState::Tombstone(_) => return Ok(TombstoneOutcome::Already),
                HostedState::Frost => {
                    return Err(DaemonError::Config(format!(
                        "{key_id} is a FROST share — a delete intent never touches one"
                    )))
                }
                HostedState::Live(k) => {
                    if v.issued_at_ms.saturating_add(verifier.skew_ms()) < k.live_since_ms() {
                        return Err(crate::intent::refused_delete(
                            "stale",
                            format!(
                                "the delete intent for {key_id} was issued before this copy was created or \
                                 undeleted — not applied to it"
                            ),
                        ));
                    }
                    let info = DeletedKeyInfo {
                        spec: k.spec.as_str().to_string(),
                        created_at: k.created_at,
                        commitment: self.hosted_commitment(&k)?,
                    };
                    self.keystore.save_tombstone(key_id, &tombstone(info, Some(*k)))?;
                    metrics::counter!(crate::metrics::HOSTED_TOMBSTONES_WRITTEN, "how" => "converted").increment(1);
                    tracing::warn!(key_id, signer = %v.signer_cn, "hosted key deleted: replaced by a tombstone");
                    return Ok(TombstoneOutcome::Converted);
                }
                HostedState::Absent => {
                    match self.keystore.create_tombstone(key_id, &tombstone(known.cloned().unwrap_or_default(), None)) {
                        Ok(()) => {
                            metrics::counter!(crate::metrics::HOSTED_TOMBSTONES_WRITTEN, "how" => "recorded").increment(1);
                            tracing::info!(key_id, signer = %v.signer_cn, "tombstone recorded for a hosted key this node does not hold");
                            return Ok(TombstoneOutcome::Recorded);
                        }
                        // Something arrived meanwhile (a racing push): read it again and decide.
                        Err(DaemonError::KeyExists(_)) => continue,
                        Err(e) => return Err(e),
                    }
                }
            }
        }
        Err(DaemonError::Config(format!("{key_id}: the key file kept changing while it was being tombstoned")))
    }

    /// PurgeKey without a delete intent: the rollback of a key this node created in genkey
    /// ceremony `ceremony_id`, which still holds this node's fence for the key — a generation that
    /// missed its write quorum. Anything else is refused: no peer and no leader can physically
    /// remove a key otherwise (audit M2).
    pub fn hosted_rollback_purge(&self, ceremony_id: &str, key_id: &str) -> Result<bool> {
        self.hosted_ctx()?;
        let fenced = self.guards().get(key_id).is_some_and(|g| g.owner == ceremony_id && g.kind == "genkey");
        let created_here = crate::sync::recover(&self.hosted_created_in, "hosted_created_in")
            .get(key_id)
            .is_some_and(|c| c == ceremony_id);
        if !(fenced && created_here) {
            return Err(crate::intent::refused_delete(
                "rollback",
                format!(
                    "PurgeKey for {key_id} carries no delete intent, and it is not the rollback of a key this \
                     node created in the same, still-fenced generation — refused"
                ),
            ));
        }
        match self.hosted_state(key_id)? {
            HostedState::Live(_) => {
                self.keystore.delete(key_id)?;
                crate::sync::recover(&self.hosted_created_in, "hosted_created_in").remove(key_id);
                Ok(true)
            }
            HostedState::Absent => Ok(false),
            _ => Err(DaemonError::Config(format!("{key_id} is no longer the key this generation created"))),
        }
    }

    /// This node's hosted-key inventory as `ListKeys` reports it: every live key and every
    /// tombstone (with its delete intent, for the receiving node to verify).
    pub fn hosted_manifest(&self) -> Result<Vec<crate::pb::KeyManifest>> {
        let mut keys = Vec::new();
        for key_id in self.hosted_list()? {
            let key = self.hosted_load(&key_id)?;
            keys.push(crate::pb::KeyManifest {
                key_id,
                spec: key.spec.as_str().to_string(),
                created_at: key.created_at,
                commitment: self.hosted_commitment(&key)?,
                ..Default::default()
            });
        }
        for t in self.hosted_tombstones()? {
            use prost::Message;
            keys.push(crate::pb::KeyManifest {
                commitment: hex::decode(&t.commitment).unwrap_or_default(),
                delete_intent: t.intent()?.encode_to_vec(),
                tombstone: true,
                deleted_at_ms: t.deleted_at_ms,
                spec: t.spec,
                created_at: t.created_at,
                key_id: t.key_id,
            });
        }
        Ok(keys)
    }

    /// Every tombstone on this node.
    pub fn hosted_tombstones(&self) -> Result<Vec<crate::hosted::Tombstone>> {
        self.hosted_ctx()?;
        self.keystore.list_tombstones()
    }

    /// Drop the retained material of every tombstone past its grace period. Returns how many.
    pub fn hosted_purge_expired(&self, now_ms: u64) -> Result<usize> {
        self.hosted_ctx()?;
        let mut n = 0;
        for mut t in self.keystore.list_tombstones()? {
            if t.retained.is_some() && now_ms > t.purge_after_ms {
                t.retained = None;
                self.keystore.save_tombstone(&t.key_id.clone(), &t)?;
                tracing::info!(key_id = %t.key_id, "grace period over: a deleted key's retained material dropped");
                n += 1;
            }
        }
        Ok(n)
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
            Ok(crate::keystore::Record::Frost(_))
            | Ok(crate::keystore::Record::Tombstone(_))
            | Err(DaemonError::UnknownKey(_)) => Ok(absent),
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

#[cfg(test)]
mod poison_tests {
    use super::*;
    use crate::peer::{LocalPeer, PeerApi};

    /// Audit L3: a request that panics while holding one of the node's locks must not break the
    /// node's other work — every lock recovers (see the accessors above for how).
    #[tokio::test]
    async fn a_panicking_holder_of_any_node_lock_does_not_break_later_calls() {
        let tmp = tempfile::tempdir().unwrap();
        let nodes: Vec<Arc<Node>> = (1..=3u16)
            .map(|i| {
                let ks = KeyStore::open(tmp.path().join(format!("n{i}"))).unwrap();
                Arc::new(Node::new(Identifier::try_from(i).unwrap(), 3, 2, ks))
            })
            .collect();
        crate::peer::wire_local_mesh(&nodes).unwrap();
        let peers: Vec<Arc<dyn PeerApi>> =
            nodes.iter().map(|n| Arc::new(LocalPeer::new(n.clone())) as Arc<dyn PeerApi>).collect();
        let group = crate::orchestrator::run_dkg(&peers, "k").await.unwrap();
        let n = &nodes[0];
        let records_before = n.all_records().len();
        assert!(records_before > 0);
        n.sign_round1("k", "in-flight", &Round1Ctx::default()).unwrap();

        crate::sync::poison(&n.cosigners);
        crate::sync::poison(&n.ceremonies);
        crate::sync::poison(&n.stale);
        crate::sync::poison(&n.book);

        // Signing, led by the node and with it as a member, works.
        let msg = rutli_frost_core::dealer::canton_test_message(b"after a panic");
        let sig = crate::orchestrator::sign(n, &peers, "k", &msg).await.unwrap();
        assert!(crate::verify_key::signature_verifies(&group, &msg, &sig));
        // The key cache was emptied (its in-flight nonces with it), not trusted.
        assert_eq!(n.pending_sign_count("k"), 0);
        // Ceremony state was rebuilt from disk: the votes are all there, and new ones record.
        assert_eq!(n.all_records().len(), records_before);
        assert_eq!(n.ceremony_status("never-seen").unwrap().phase, crate::ceremony_record::Phase::Aborted);
        assert_eq!(n.all_records().len(), records_before + 1);
        assert!(n.key_epoch("k").unwrap().present);
        assert!(n.stale_mark("k").is_none());
        assert!(!n.cosigners.is_poisoned());
        assert!(!n.stale.is_poisoned() && !n.book.is_poisoned());
        // A refresh (fence, guards, book, staged votes) runs end to end afterwards. Signing never
        // touches the ceremony guards, so this is what recovers that lock.
        assert_eq!(crate::orchestrator::run_refresh(&peers, "k").await.unwrap(), group);
        assert!(!n.ceremonies.is_poisoned());
    }
}

#[cfg(test)]
mod guard_tests {
    use super::*;
    use std::path::{Path, PathBuf};

    /// Make the book's next lock fail the way a real fault does: poisoned, with its votes
    /// unreadable (the record directory replaced by a file), so the rebuild in [`Node::book`] fails.
    fn break_book(node: &Node) -> PathBuf {
        let dir = node.keystore.ceremony_dir();
        let aside = dir.with_extension("aside");
        if dir.exists() {
            std::fs::rename(&dir, &aside).unwrap();
        }
        std::fs::write(&dir, b"not a directory").unwrap();
        crate::sync::poison(&node.book);
        dir
    }

    fn mend_book(dir: &Path) {
        std::fs::remove_file(dir).unwrap();
        let aside = dir.with_extension("aside");
        if aside.exists() {
            std::fs::rename(&aside, dir).unwrap();
        }
    }

    fn guard(node: &Node, key_id: &str) -> Option<(String, bool)> {
        node.guards().get(key_id).map(|g| (g.owner.clone(), g.session))
    }

    fn node(tmp: &tempfile::TempDir, fence_timeout: Duration) -> Node {
        let ks = KeyStore::open(tmp.path().join("n1")).unwrap();
        Node::new(Identifier::try_from(1).unwrap(), 3, 2, ks).with_ceremony_fence_timeout(fence_timeout)
    }

    /// A part 1 that fails between taking the guard and creating its session (here: the book
    /// cannot be locked) must not leave the guard marked as having a session. Before 0.4.0-rc.4 it
    /// did, and the leader's fence was then judged by the 15-minute orphan timeout instead of the
    /// fence timeout, blocking the key's DKG/refresh (and hosted-key writes) for 15 minutes. The
    /// leader's fence stays a fence: it still serializes, and it expires after the fence timeout.
    #[test]
    fn a_part1_failing_before_its_session_exists_leaves_the_leaders_fence_fence_only() {
        let tmp = tempfile::tempdir().unwrap();
        let fence_timeout = Duration::from_secs(2); // outlasts a loaded CI runner between steps
        let n = node(&tmp, fence_timeout);
        n.ceremony_fence("dkg-a", "k", "dkg").unwrap();
        let broken: Arc<Mutex<Option<PathBuf>>> = Arc::default();
        let b = broken.clone();
        *n.hooks.after_part1_acquire.lock().unwrap() =
            Some(Box::new(move |node: &Node| *b.lock().unwrap() = Some(break_book(node))));

        assert!(n.ceremony_part1("dkg-a", "k", CeremonyKind::Dkg, &[1, 2, 3], None).is_err());
        mend_book(broken.lock().unwrap().as_ref().expect("the hook ran"));

        assert_eq!(guard(&n, "k"), Some(("dkg-a".to_string(), false)), "kept, and fence-only");
        assert!(n.book().unwrap().sessions.is_empty());
        // Still the leader's fence: another ceremony is refused within the fence timeout...
        let refused = n.ceremony_fence("dkg-b", "k", "dkg");
        assert!(matches!(refused, Err(DaemonError::CeremonyInProgress { .. })), "{refused:?}");
        // ...and preempts it after the fence timeout, not the 15-minute orphan timeout.
        std::thread::sleep(fence_timeout + Duration::from_millis(250));
        n.ceremony_fence("dkg-b", "k", "dkg").unwrap();
        assert_eq!(guard(&n, "k"), Some(("dkg-b".to_string(), false)));
    }

    /// The same failure on a part 1 that took the guard itself (no fence for its ceremony on this
    /// node) releases it: nothing else owns it. A part 1 that succeeds holds the guard marked.
    #[test]
    fn a_part1_failing_before_its_session_exists_releases_a_guard_it_created() {
        let tmp = tempfile::tempdir().unwrap();
        let n = node(&tmp, CEREMONY_FENCE_TIMEOUT);
        let broken: Arc<Mutex<Option<PathBuf>>> = Arc::default();
        let b = broken.clone();
        *n.hooks.after_part1_acquire.lock().unwrap() =
            Some(Box::new(move |node: &Node| *b.lock().unwrap() = Some(break_book(node))));

        assert!(n.ceremony_part1("dkg-a", "k", CeremonyKind::Dkg, &[1, 2, 3], None).is_err());
        mend_book(broken.lock().unwrap().as_ref().expect("the hook ran"));
        assert_eq!(guard(&n, "k"), None, "released");

        // The key is free at once, and a part 1 that succeeds marks the guard with its session.
        n.ceremony_part1("dkg-b", "k", CeremonyKind::Dkg, &[1, 2, 3], None).unwrap();
        assert_eq!(guard(&n, "k"), Some(("dkg-b".to_string(), true)));
        assert!(n.book().unwrap().sessions.contains_key("dkg-b"));
    }

    /// Poison recovery drops every in-memory ceremony session; the DKG/refresh guards those
    /// sessions had marked go back to fence-only, so a dead leader's ceremony blocks the key for the
    /// fence timeout, not 15 minutes. Hosted-key guards are not touched.
    #[test]
    fn book_poison_recovery_turns_the_dropped_sessions_guards_back_into_fences() {
        let tmp = tempfile::tempdir().unwrap();
        let fence_timeout = Duration::from_secs(2); // outlasts a loaded CI runner between steps
        let n = node(&tmp, fence_timeout);
        n.ceremony_fence("dkg-a", "k", "dkg").unwrap();
        n.ceremony_part1("dkg-a", "k", CeremonyKind::Dkg, &[1, 2, 3], None).unwrap();
        assert_eq!(guard(&n, "k"), Some(("dkg-a".to_string(), true)));
        // A hosted-key guard, marked by hand to show recovery leaves its kind alone (hosted guards
        // never carry a session in practice).
        n.guards().insert(
            "h".to_string(),
            CeremonyGuard { owner: "genkey-a".into(), kind: "genkey", started: Instant::now(), session: true },
        );

        crate::sync::poison(&n.book);
        assert!(n.book().unwrap().sessions.is_empty(), "recovered: sessions dropped");

        assert_eq!(guard(&n, "k"), Some(("dkg-a".to_string(), false)), "back to a fence");
        assert_eq!(guard(&n, "h"), Some(("genkey-a".to_string(), true)), "hosted guard untouched");
        // The dropped ceremony cannot go on here.
        assert!(n.ceremony_part3("dkg-a", &[0u8; 32]).is_err());
        // Still a fence within its timeout; preemptible after it, not after 15 minutes.
        let refused = n.ceremony_fence("dkg-b", "k", "dkg");
        assert!(matches!(refused, Err(DaemonError::CeremonyInProgress { .. })), "{refused:?}");
        std::thread::sleep(fence_timeout + Duration::from_millis(250));
        n.ceremony_fence("dkg-b", "k", "dkg").unwrap();
        assert_eq!(guard(&n, "k"), Some(("dkg-b".to_string(), false)));
    }
}

/// A sign whose round 2 already holds the old cosigner when a refresh commit evicts it (the commit
/// evicts the cache entry, not the `Arc` an in-flight call cloned). Made deterministic by pausing
/// round 2 right after that clone until the refresh has committed on every node.
#[cfg(test)]
mod sign_across_commit_tests {
    use super::*;
    use crate::orchestrator::{run_dkg, run_refresh, sign};
    use crate::peer::{LocalPeer, PeerApi};
    use rutli_frost_core::nonce_store::NonceStore;
    use std::sync::Condvar;

    const KEY: &str = "k";

    fn cluster(tmp: &tempfile::TempDir) -> (Vec<Arc<Node>>, Vec<Arc<dyn PeerApi>>) {
        let nodes: Vec<Arc<Node>> = (1..=3u16)
            .map(|i| {
                let ks = KeyStore::open(tmp.path().join(format!("n{i}"))).unwrap();
                Arc::new(Node::new(Identifier::try_from(i).unwrap(), 3, 2, ks))
            })
            .collect();
        crate::peer::wire_local_mesh(&nodes).unwrap();
        let peers = nodes.iter().map(|n| Arc::new(LocalPeer::new(n.clone())) as Arc<dyn PeerApi>).collect();
        (nodes, peers)
    }

    /// Round 2 calls that reach the hook park here until the gate opens.
    #[derive(Default)]
    struct Gate {
        state: Mutex<(Vec<String>, bool)>, // (sessions parked so far, open)
        cv: Condvar,
    }

    impl Gate {
        fn park(&self, session_id: &str) {
            let mut s = self.state.lock().unwrap();
            s.0.push(session_id.to_string());
            self.cv.notify_all();
            let (_s, timeout) =
                self.cv.wait_timeout_while(s, Duration::from_secs(30), |s| !s.1).unwrap();
            assert!(!timeout.timed_out(), "the gate was never opened");
        }

        async fn parked(&self, n: usize) -> Vec<String> {
            let deadline = Instant::now() + Duration::from_secs(30);
            loop {
                let parked = self.state.lock().unwrap().0.clone();
                if parked.len() >= n {
                    return parked;
                }
                assert!(Instant::now() < deadline, "only {} round 2 call(s) parked, expected {n}", parked.len());
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }

        fn open(&self) {
            self.state.lock().unwrap().1 = true;
            self.cv.notify_all();
        }
    }

    /// Park round 2 on `node` for `session` (any session: `None`) once it holds its cosigner.
    fn pause_round2(node: &Node, gate: &Arc<Gate>, session: Option<&'static str>) {
        let gate = gate.clone();
        *node.hooks.after_round2_cosigner.lock().unwrap() = Some(Arc::new(move |_key: &str, s: &str| {
            if session.is_none_or(|want| want == s) {
                gate.park(s);
            }
        }));
    }

    fn assert_burned_once(node: &Node, session: &str) {
        let store = NonceStore::open(node.keystore.nonce_dir(KEY)).unwrap();
        assert!(store.is_consumed(session).unwrap(), "node {:?} burned {session}", node.identifier);
        assert!(
            matches!(store.consume(session), Err(rutli_frost_core::CoreError::NonceReuse(_))),
            "a second burn of {session} is refused"
        );
    }

    /// Every member of an in-flight quorum cloned the old cosigner before the commit: each releases
    /// its share from the old sharing, the shares aggregate (with the leader's new public key
    /// package — a refresh keeps the group key) into a signature valid under the unchanged group
    /// key, and each member's nonce marker is burned exactly once: the session can get no further
    /// share from the new cosigner or any other instance.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_all_old_round2_in_flight_across_a_refresh_commit_completes_without_nonce_reuse() {
        let tmp = tempfile::tempdir().unwrap();
        let (nodes, peers) = cluster(&tmp);
        let group = run_dkg(&peers, KEY).await.unwrap();
        let msg = rutli_frost_core::dealer::canton_test_message(b"round 2 spans a commit");
        let session = "in-flight";
        let old_view = nodes[0].signing_view(KEY).unwrap().view;
        let ctx = Round1Ctx { leader_view: Some(old_view), ..Default::default() };
        let mut commitments = BTreeMap::new();
        for n in &nodes[..2] {
            commitments.insert(n.identifier, n.sign_round1(KEY, session, &ctx).unwrap());
        }

        let gate = Arc::new(Gate::default());
        let members: Vec<_> = nodes[..2]
            .iter()
            .map(|n| {
                pause_round2(n, &gate, Some(session));
                let (n, commitments) = (n.clone(), commitments.clone());
                std::thread::spawn(move || n.sign_round2(KEY, session, &msg, &commitments))
            })
            .collect();
        gate.parked(2).await;

        // The refresh commits on every node, evicting the cosigners both round 2 calls hold.
        assert_eq!(run_refresh(&peers, KEY).await.unwrap(), group);
        for n in &nodes {
            let v = n.signing_view(KEY).unwrap().view;
            assert_eq!(v.0, old_view.0 + 1);
            assert_ne!(v.1, old_view.1, "a new sharing");
            assert_eq!(n.pending_sign_count(KEY), 0, "the new cosigner holds no old nonces");
        }

        gate.open();
        let mut shares = BTreeMap::new();
        for (n, h) in nodes[..2].iter().zip(members) {
            shares.insert(n.identifier, h.join().unwrap().expect("the old cosigner signs its own session"));
        }
        let sig = nodes[0].aggregate(KEY, &msg, &commitments, &shares).unwrap();
        assert!(crate::verify_key::signature_verifies(&group, &msg, &sig));

        let new_ctx = Round1Ctx { leader_view: Some(nodes[0].signing_view(KEY).unwrap().view), ..Default::default() };
        for n in &nodes[..2] {
            assert_burned_once(n, session);
            assert!(n.sign_round2(KEY, session, &msg, &commitments).is_err(), "no second share");
            assert!(n.sign_round1(KEY, session, &new_ctx).is_err(), "no fresh nonces for a burned session");
            assert_eq!(n.pending_sign_count(KEY), 0);
        }
    }

    /// The leader's own round 2 cloned the old cosigner before the commit; the next member's
    /// round 2 starts after it, on the new cosigner, which has no session for it. The attempt fails
    /// cleanly: no signature, only the old member's marker burned (once), nothing left pending.
    ///
    /// The leader does retry in the same call, with a fresh session on another subset, but that
    /// round 1 is refused by the epoch check — the leader's view of the sharing predates the
    /// commit — so the call gives up (`ThresholdNotMet`: one member excluded at round 2, the other
    /// at the retry's round 1). The next sign, with fresh sessions on the new sharing, succeeds.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_mixed_round2_across_a_refresh_commit_fails_cleanly_and_a_fresh_sign_succeeds() {
        let tmp = tempfile::tempdir().unwrap();
        let (nodes, peers) = cluster(&tmp);
        let group = run_dkg(&peers, KEY).await.unwrap();
        let msg = rutli_frost_core::dealer::canton_test_message(b"mixed across a commit");

        let gate = Arc::new(Gate::default());
        pause_round2(&nodes[0], &gate, None);
        let leading = {
            let (leader, peers) = (nodes[0].clone(), peers.clone());
            tokio::spawn(async move { sign(&leader, &peers, KEY, &msg).await })
        };
        let session = gate.parked(1).await.remove(0);
        assert_eq!(run_refresh(&peers, KEY).await.unwrap(), group);
        *nodes[0].hooks.after_round2_cosigner.lock().unwrap() = None;
        gate.open();

        let err = leading.await.unwrap().unwrap_err();
        assert!(matches!(err, DaemonError::ThresholdNotMet { needed: 2, got: 1 }), "{err:?}");
        // Node 1 (the leader) released its old share; node 2's round 2 found no session on its new
        // cosigner and burned nothing; its old nonces went with the evicted cosigner.
        assert_burned_once(&nodes[0], &session);
        let store = NonceStore::open(nodes[1].keystore.nonce_dir(KEY)).unwrap();
        assert!(!store.is_consumed(&session).unwrap());
        for n in &nodes {
            assert_eq!(n.pending_sign_count(KEY), 0);
        }

        let sig = sign(&nodes[0], &peers, KEY, &msg).await.unwrap();
        assert!(crate::verify_key::signature_verifies(&group, &msg, &sig));
    }
}
