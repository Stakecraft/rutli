// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

use thiserror::Error;

#[derive(Debug, Error)]
pub enum DaemonError {
    #[error(transparent)]
    Core(#[from] rutli_frost_core::CoreError),

    #[error("frost: {0}")]
    Frost(#[from] frost_ed25519::Error),

    #[error("serde: {0}")]
    Serde(#[from] serde_json::Error),

    /// Deliberately opaque: a decryption failure must not say *why* (bad padding vs bad key vs
    /// wrong length). A distinguishable failure is a padding oracle.
    #[error("decryption failed")]
    DecryptFailed,

    #[error("{0}")]
    RateLimited(String),

    /// An `EcdhDerive` peer point that is not a 65-byte uncompressed SEC1 point on P-256. Saying
    /// why is safe here, unlike [`DaemonError::DecryptFailed`]: whether a point is well-formed and
    /// on the curve is public information, computed without the key.
    #[error("invalid peer point: {0}")]
    InvalidPoint(String),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// The key-store readiness probe failed ([`crate::keystore::KeyStore::check_readable`]): the
    /// volume under `data_dir/keys` cannot be listed, opened, read or written. A node in this state
    /// fails every Sign/Dkg it touches, so `Signer.Health` reports NOT_SERVING on it.
    #[error("keystore {} {what}: {source}", .path.display())]
    KeystoreUnavailable {
        path: std::path::PathBuf,
        /// "unreadable" | "not writable" | "unresponsive".
        what: &'static str,
        source: std::io::Error,
    },

    #[error("rpc transport: {0}")]
    Transport(#[from] tonic::transport::Error),

    #[error("rpc status: {0}")]
    Status(#[from] tonic::Status),

    /// This node's key store failed its last readiness probe, so it refuses to join a signing
    /// quorum it could not finish. Leaders skip it like an unreachable peer.
    #[error("not serving: {0}")]
    NotServing(String),

    /// This node's key store is down ([`crate::health`]): its readiness probe failed, or round-2
    /// store work met a definite I/O error. UNAVAILABLE with the `rutli-error: keystore-down`
    /// trailer, so a leader can tell it from a peer it cannot reach (and route around it at once).
    #[error("not serving: {0}")]
    KeystoreDown(String),

    /// A peer call did not complete within its deadline (`peer` = the peer's roster number, `call`
    /// = which call, `after` = the deadline). The leader's own clock, around the whole call: queue,
    /// connect and RPC ([`crate::peer::CallClass`]). Counts as unreachable for hosted writes.
    #[error("cosigner {peer} did not answer {call} within {after:?}")]
    PeerDeadline { peer: u16, call: &'static str, after: std::time::Duration },

    /// Fewer than `needed` cosigners (this one included) can be reached, so a signature cannot be
    /// formed here. UNAVAILABLE with the `rutli-error: no-quorum` trailer: another leader may see
    /// more of the cluster. `missing` names the peers this leader cannot reach; the Signer API
    /// passes it only to an authenticated client.
    #[error("no quorum: {visible} of the {needed} cosigners needed are reachable from this node (missing: {missing:?})")]
    NoQuorum { needed: usize, visible: usize, missing: Vec<u16> },

    /// This leader is overloaded (its own sign round missed its deadline, or too many signatures are
    /// in flight here): UNAVAILABLE with the `rutli-error: overloaded` trailer, before any member
    /// is excluded, so the client moves to another leader.
    #[error("overloaded: {0}")]
    Overloaded(String),

    /// The client's deadline (`grpc-timeout`) leaves less time than one signature needs.
    /// DEADLINE_EXCEEDED; no round was started.
    #[error("the client's deadline leaves {left:?}, less than the {needed:?} a signature needs — no round started")]
    ClientDeadline { left: std::time::Duration, needed: std::time::Duration },

    #[error("unknown key id: {0}")]
    UnknownKey(String),

    #[error("unknown dkg session: {0}")]
    UnknownDkg(String),

    #[error("key {0} already exists — refusing DKG (it would overwrite/destroy the existing key)")]
    KeyExists(String),

    #[error("a {kind} ceremony (id {other}) is already in progress for key {key_id}")]
    CeremonyInProgress { key_id: String, kind: &'static str, other: String },

    #[error("ceremony {owner} for key {key_id} was superseded by a newer ceremony — refusing to persist")]
    CeremonySuperseded { key_id: String, owner: String },

    #[error(
        "invalid sign message length: got {got} bytes, expected {expected} \
         (Canton's multihash-prefixed SHA-256 digest — see docs/wire-contract.md)"
    )]
    InvalidMessageLength { got: usize, expected: usize },

    #[error("could not reach signing threshold: needed {needed}, got {got}")]
    ThresholdNotMet { needed: usize, got: usize },

    #[error("configuration: {0}")]
    Config(String),

    /// A key file this node refuses to load (audit M4): a v2 header naming another cluster, node,
    /// key id or record kind, a DEK this node does not hold, a v1 file while `keyfile.accept_v1` is
    /// off, a plaintext file under sealing, or a plaintext that disagrees with its header or name.
    #[error("key file refused: {0}")]
    KeyFile(String),

    #[error("cluster disagreement: {0}")]
    Disagreement(String),

    /// A DKG/refresh refused before or during the ceremony for a reason the operator must fix
    /// (mixed epochs, a staged ceremony not yet resolved, a mixed-version cluster, a legacy partial
    /// key). FAILED_PRECONDITION: retrying elsewhere does not help.
    #[error("ceremony refused: {0}")]
    CeremonyRefused(String),

    /// A split-ceremony step (share-recipient, import-share, abort-import, verify-key) refused.
    /// Never carries key material.
    #[error("split ceremony: {0}")]
    Ceremony(String),

    /// Sign round 1: the leader signs with another sharing of `key_id` than the one this node
    /// committed (`peer` = the refusing node's own (epoch, PKP digest)). Shares of different
    /// sharings never combine, and a node never signs from a mismatched epoch (audit H1/M1).
    /// FAILED_PRECONDITION with the `rutli-error: epoch-mismatch` trailer (see
    /// [`DaemonError::from_peer_status`]), so a leader can tell it from any other refusal and learn
    /// the peer's sharing.
    #[error(
        "epoch mismatch for {key_id}: this node holds epoch {} (pkp {}…) but the leader signs with \
         epoch {} (pkp {}…) — refusing to sign from a different sharing",
        .peer.0, short(&.peer.1), .leader.0, short(&.leader.1)
    )]
    EpochMismatch { key_id: String, peer: KeyVersion, leader: KeyVersion },

    /// This node's epoch check found its share of `key_id` stale (`peer` = its own (epoch, PKP
    /// digest)), so it refuses to sign or lead for the key. FAILED_PRECONDITION with the
    /// `rutli-error: stale-share` trailer.
    #[error("stale share for {key_id} (this node holds epoch {}): {reason}", .peer.0)]
    StaleShare { key_id: String, peer: KeyVersion, reason: String },

    /// The signing policy refused this signature at this node (audit C2): no intent where one is
    /// required, an invalid or expired intent, a signer the ACL or a pin excludes, missing
    /// approvals, a refresher or other role calling outside its rights. PERMISSION_DENIED with the
    /// `rutli-error: policy-refused` trailer; non-retryable for the driver.
    #[error("{0}")]
    PolicyRefused(String),

    /// A refresh this node refuses to take part in because it took part in a refresh of the same
    /// key less than `signing_policy.refresh_min_interval_secs` ago. FAILED_PRECONDITION with the
    /// `rutli-error: refresh-too-soon` trailer, so a leader passes a peer's refusal on as this
    /// error; counted in `rutli_refresh_interval_refusals_total`.
    #[error("{0}")]
    RefreshTooSoon(String),

    /// This node's sign journal for a key cannot be read or appended to; it refuses to release a
    /// share it cannot journal.
    #[error("sign journal: {0}")]
    Journal(String),

    /// The key id is reserved for the split ceremony (`…frost-import-…`): DKG may never mint it.
    #[error(
        "key id {0} is reserved for imported keys (contains \"frost-import-\") — DKG refuses it; \
         install it with the split ceremony (docs/split-ceremony.md)"
    )]
    ReservedKeyId(String),

    /// A hosted key may only be created under an id the driver routes to hosted keys: its first
    /// routing tag must be `rutli-` ([`crate::node::refuse_unless_hosted_id`]). A `<prefix>frost-…`
    /// id belongs to a FROST key, and a hosted key under it would make that key's DKG fail.
    #[error(
        "key id {0} is not a hosted-key id: a hosted key is created only under <frost.key-prefix>rutli-<name> \
         (the first of \"frost-\" / \"rutli-\" in the id must be \"rutli-\"); FROST ids are never hosted"
    )]
    NotHostedKeyId(String),

    /// Two nodes hold different material under one hosted key id, or a push would make it so.
    /// ABORTED with the `rutli-error: hosted-conflict` trailer: a generation that meets one is
    /// rolled back, and retrying elsewhere does not help — an operator must look.
    #[error("hosted key conflict for {key_id}: {detail}")]
    HostedConflict { key_id: String, detail: String },

    /// This node does not hold the hosted key and could not confirm a copy: fewer than two peers
    /// returned the same material, or peers returned different material. UNAVAILABLE with the
    /// `rutli-error: hosted-unconfirmed` trailer, never NOT_FOUND, so the driver fails over to a
    /// node that holds the key.
    #[error("hosted key {key_id} is not confirmed on this node: {detail}")]
    HostedUnconfirmed { key_id: String, detail: String },

    /// A peer's push this node refuses: the id is absent here and the caller does not hold this
    /// node's generation fence for it under that ceremony id. FAILED_PRECONDITION.
    #[error("hosted key push refused: {0}")]
    HostedPushRefused(String),

    /// Hosted material from a peer whose timestamps lie in the future beyond the clock skew.
    /// INVALID_ARGUMENT.
    #[error("hosted key refused: {0}")]
    HostedInvalid(String),
}

/// A sharing of a FROST key as nodes compare it: (epoch, PKP digest). Same as
/// [`crate::node::KeyVersion`].
pub type KeyVersion = (u64, [u8; 32]);

fn short(digest: &[u8; 32]) -> String {
    hex::encode(&digest[..6])
}

/// Trailer naming a machine-readable refusal reason on an RPC error (`epoch-mismatch`,
/// `stale-share`, with the refusing node's own sharing in [`EPOCH_TRAILER`] and
/// [`PKP_DIGEST_TRAILER`]; `policy-refused`; `hosted-conflict`, `hosted-unconfirmed`).
pub const ERROR_TRAILER: &str = "rutli-error";
pub const EPOCH_TRAILER: &str = "rutli-epoch";
pub const PKP_DIGEST_TRAILER: &str = "rutli-pkp-digest";
const EPOCH_MISMATCH: &str = "epoch-mismatch";
const STALE_SHARE: &str = "stale-share";
const POLICY_REFUSED: &str = "policy-refused";
/// [`ERROR_TRAILER`] value of a sign round 1 refused by a cap on waiting sessions: the member has
/// no room for this caller's sessions, which a leader does not treat as that member failing.
pub const SESSIONS_FULL: &str = "sessions-full";
const REFRESH_TOO_SOON: &str = "refresh-too-soon";
const HOSTED_CONFLICT: &str = "hosted-conflict";
const HOSTED_UNCONFIRMED: &str = "hosted-unconfirmed";
/// [`ERROR_TRAILER`] value of a refusal because the answering node's key store is down
/// ([`DaemonError::KeystoreDown`]).
pub const KEYSTORE_DOWN: &str = "keystore-down";
/// [`ERROR_TRAILER`] value of a Sign refused because too few cosigners are reachable
/// ([`DaemonError::NoQuorum`]).
pub const NO_QUORUM: &str = "no-quorum";
/// [`ERROR_TRAILER`] value of a Sign refused by an overloaded leader ([`DaemonError::Overloaded`]).
pub const OVERLOADED: &str = "overloaded";

fn with_reason(code: tonic::Code, message: String, reason: &'static str) -> tonic::Status {
    let mut md = tonic::metadata::MetadataMap::new();
    md.insert(ERROR_TRAILER, tonic::metadata::MetadataValue::from_static(reason));
    tonic::Status::with_metadata(code, message, md)
}

fn with_view(code: tonic::Code, message: String, reason: &'static str, view: &KeyVersion) -> tonic::Status {
    let mut md = tonic::metadata::MetadataMap::new();
    md.insert(ERROR_TRAILER, tonic::metadata::MetadataValue::from_static(reason));
    // Decimal digits and lowercase hex are always valid ASCII metadata values.
    if let Ok(v) = view.0.to_string().parse() {
        md.insert(EPOCH_TRAILER, v);
    }
    if let Ok(v) = hex::encode(view.1).parse() {
        md.insert(PKP_DIGEST_TRAILER, v);
    }
    tonic::Status::with_metadata(code, message, md)
}

impl DaemonError {
    /// The typed error behind a peer's sign refusal: [`DaemonError::EpochMismatch`] or
    /// [`DaemonError::StaleShare`] when the status carries the [`ERROR_TRAILER`] (with the peer's
    /// own sharing), [`DaemonError::PolicyRefused`] for a signing-policy refusal,
    /// [`DaemonError::RateLimited`] for RESOURCE_EXHAUSTED, else the plain status. `leader` is the
    /// sharing the caller sent.
    pub fn from_peer_status(status: tonic::Status, key_id: &str, leader: Option<KeyVersion>) -> Self {
        let md = status.metadata();
        let reason = md.get(ERROR_TRAILER).and_then(|v| v.to_str().ok()).map(str::to_owned);
        let view = || -> Option<KeyVersion> {
            let epoch = md.get(EPOCH_TRAILER)?.to_str().ok()?.parse().ok()?;
            let digest = hex::decode(md.get(PKP_DIGEST_TRAILER)?.to_str().ok()?).ok()?;
            Some((epoch, digest.try_into().ok()?))
        };
        match (reason.as_deref(), view()) {
            (Some(EPOCH_MISMATCH), Some(peer)) => DaemonError::EpochMismatch {
                key_id: key_id.to_owned(),
                peer,
                leader: leader.unwrap_or_default(),
            },
            (Some(STALE_SHARE), Some(peer)) => DaemonError::StaleShare {
                key_id: key_id.to_owned(),
                peer,
                reason: status.message().to_owned(),
            },
            (Some(POLICY_REFUSED), _) => DaemonError::PolicyRefused(status.message().to_owned()),
            (Some(REFRESH_TOO_SOON), _) => DaemonError::RefreshTooSoon(status.message().to_owned()),
            (Some(HOSTED_CONFLICT), _) => DaemonError::HostedConflict {
                key_id: key_id.to_owned(),
                detail: status.message().to_owned(),
            },
            (Some(HOSTED_UNCONFIRMED), _) => DaemonError::HostedUnconfirmed {
                key_id: key_id.to_owned(),
                detail: status.message().to_owned(),
            },
            (Some(KEYSTORE_DOWN), _) => DaemonError::KeystoreDown(status.message().to_owned()),
            _ if status.code() == tonic::Code::ResourceExhausted => {
                DaemonError::RateLimited(status.message().to_owned())
            }
            _ => DaemonError::Status(status),
        }
    }
}

/// A peer's refusal of a ceremony fence: [`DaemonError::RefreshTooSoon`] when the status carries
/// that trailer, else the plain status (as before).
pub fn from_fence_status(status: tonic::Status) -> DaemonError {
    let too_soon = status.metadata().get(ERROR_TRAILER).and_then(|v| v.to_str().ok()) == Some(REFRESH_TOO_SOON);
    if too_soon {
        DaemonError::RefreshTooSoon(status.message().to_owned())
    } else {
        DaemonError::Status(status)
    }
}

impl From<DaemonError> for tonic::Status {
    fn from(e: DaemonError) -> Self {
        match e {
            DaemonError::EpochMismatch { peer, .. } => {
                with_view(tonic::Code::FailedPrecondition, e.to_string(), EPOCH_MISMATCH, &peer)
            }
            DaemonError::StaleShare { peer, .. } => {
                with_view(tonic::Code::FailedPrecondition, e.to_string(), STALE_SHARE, &peer)
            }
            DaemonError::PolicyRefused(_) => {
                let mut md = tonic::metadata::MetadataMap::new();
                md.insert(ERROR_TRAILER, tonic::metadata::MetadataValue::from_static(POLICY_REFUSED));
                tonic::Status::with_metadata(tonic::Code::PermissionDenied, e.to_string(), md)
            }
            DaemonError::RefreshTooSoon(_) => {
                let mut md = tonic::metadata::MetadataMap::new();
                md.insert(ERROR_TRAILER, tonic::metadata::MetadataValue::from_static(REFRESH_TOO_SOON));
                tonic::Status::with_metadata(tonic::Code::FailedPrecondition, e.to_string(), md)
            }
            DaemonError::HostedConflict { .. } => with_reason(tonic::Code::Aborted, e.to_string(), HOSTED_CONFLICT),
            DaemonError::HostedUnconfirmed { .. } => {
                with_reason(tonic::Code::Unavailable, e.to_string(), HOSTED_UNCONFIRMED)
            }
            DaemonError::HostedPushRefused(_) => tonic::Status::failed_precondition(e.to_string()),
            DaemonError::HostedInvalid(_) => tonic::Status::invalid_argument(e.to_string()),
            DaemonError::Journal(_) => tonic::Status::unavailable(e.to_string()),
            DaemonError::KeystoreDown(_) => with_reason(tonic::Code::Unavailable, e.to_string(), KEYSTORE_DOWN),
            DaemonError::NoQuorum { .. } => with_reason(tonic::Code::Unavailable, e.to_string(), NO_QUORUM),
            DaemonError::Overloaded(_) => with_reason(tonic::Code::Unavailable, e.to_string(), OVERLOADED),
            // A peer that did not answer in time: as good as unreachable, and retryable elsewhere.
            DaemonError::PeerDeadline { .. } => tonic::Status::unavailable(e.to_string()),
            DaemonError::ClientDeadline { .. } => tonic::Status::deadline_exceeded(e.to_string()),
            DaemonError::UnknownKey(_) | DaemonError::UnknownDkg(_) => {
                tonic::Status::not_found(e.to_string())
            }
            DaemonError::ThresholdNotMet { .. } | DaemonError::NotServing(_) => {
                tonic::Status::unavailable(e.to_string())
            }
            DaemonError::Config(_) | DaemonError::Ceremony(_) | DaemonError::CeremonyRefused(_) => {
                tonic::Status::failed_precondition(e.to_string())
            }
            // A round 2 that does not match its session's round-1 binding, or a binding round 1
            // cannot honour: the caller's request is wrong, retrying it elsewhere does not help.
            DaemonError::Core(
                rutli_frost_core::CoreError::BindingMismatch { .. } | rutli_frost_core::CoreError::InvalidBinding(_),
            ) => tonic::Status::failed_precondition(e.to_string()),
            // aborted: this node holds no round-1 nonces for the session any more (it restarted,
            // a ceremony commit replaced the share, the session outlived its TTL). The node and the
            // key are fine and the request was not wrong: a new session will do.
            DaemonError::Core(rutli_frost_core::CoreError::UnknownSession(_)) => tonic::Status::aborted(e.to_string()),
            // permission_denied: the session is live and belongs to the caller that opened it; this
            // caller may not use it up or drop it.
            DaemonError::Core(rutli_frost_core::CoreError::NotSessionOwner { .. }) => {
                tonic::Status::permission_denied(e.to_string())
            }
            // unavailable, as a full key always was: the leader signs with other members, and if it
            // cannot, the driver fails over to another leader, which has its own room here.
            DaemonError::Core(rutli_frost_core::CoreError::SessionsFull { .. }) => {
                let mut md = tonic::metadata::MetadataMap::new();
                md.insert(ERROR_TRAILER, tonic::metadata::MetadataValue::from_static(SESSIONS_FULL));
                tonic::Status::with_metadata(tonic::Code::Unavailable, e.to_string(), md)
            }
            // ALREADY_EXISTS, like a DKG over an existing key: the id is taken — by the import
            // mechanism, whether or not the share has been installed yet.
            DaemonError::ReservedKeyId(_) => tonic::Status::already_exists(e.to_string()),
            // invalid_argument, and nothing more: same code and message for every cause.
            DaemonError::DecryptFailed => tonic::Status::invalid_argument(e.to_string()),
            // Retryable: a legitimate caller should back off and try again, not treat the key as
            // broken. The driver must NOT fail over to another cosigner on this — every node
            // enforces the same limit, so retrying elsewhere would just spread the load an
            // attacker is generating.
            DaemonError::RateLimited(_) => tonic::Status::resource_exhausted(e.to_string()),
            DaemonError::KeyExists(_) => tonic::Status::already_exists(e.to_string()),
            // aborted: a concurrent ceremony is holding the key; the caller may retry later.
            DaemonError::CeremonyInProgress { .. } => tonic::Status::aborted(e.to_string()),
            DaemonError::CeremonySuperseded { .. } => tonic::Status::aborted(e.to_string()),
            DaemonError::InvalidMessageLength { .. }
            | DaemonError::InvalidPoint(_)
            | DaemonError::NotHostedKeyId(_) => {
                tonic::Status::invalid_argument(e.to_string())
            }
            _ => tonic::Status::internal(e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A peer's refusal survives the wire: the leader gets the typed error back, with the peer's
    /// own sharing, from nothing but the gRPC status.
    #[test]
    fn epoch_refusals_round_trip_through_a_grpc_status() {
        let (peer, leader) = ((3, [7u8; 32]), (4, [9u8; 32]));
        let status = tonic::Status::from(DaemonError::EpochMismatch { key_id: "k".into(), peer, leader });
        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
        match DaemonError::from_peer_status(status, "k", Some(leader)) {
            DaemonError::EpochMismatch { key_id, peer: p, leader: l } => {
                assert_eq!((key_id.as_str(), p, l), ("k", peer, leader));
            }
            other => panic!("got {other:?}"),
        }

        let status = tonic::Status::from(DaemonError::StaleShare {
            key_id: "k".into(),
            peer,
            reason: "peer 2 holds epoch 4".into(),
        });
        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
        assert!(matches!(
            DaemonError::from_peer_status(status, "k", Some(leader)),
            DaemonError::StaleShare { peer: p, .. } if p == peer
        ));

        // A round 2 for a session this node no longer holds: ABORTED, not INTERNAL.
        let lost = DaemonError::Core(rutli_frost_core::CoreError::UnknownSession("sign-1".into()));
        assert_eq!(tonic::Status::from(lost).code(), tonic::Code::Aborted);

        // Another caller's session: PERMISSION_DENIED, not ABORTED like an unknown one. A cap on
        // waiting sessions: UNAVAILABLE, whichever cap.
        let foreign = DaemonError::Core(rutli_frost_core::CoreError::NotSessionOwner {
            session: "sign-1".into(),
            owner: "peer 'cosigner2'".into(),
            caller: "peer 'cosigner3'".into(),
        });
        assert_eq!(tonic::Status::from(foreign).code(), tonic::Code::PermissionDenied);
        for cap_kind in [
            rutli_frost_core::session::PendingCap::Key,
            rutli_frost_core::session::PendingCap::Opener,
            rutli_frost_core::session::PendingCap::Request,
        ] {
            let full = DaemonError::Core(rutli_frost_core::CoreError::SessionsFull { cap_kind, open: 1, cap: 1 });
            let status = tonic::Status::from(full);
            assert_eq!(status.code(), tonic::Code::Unavailable);
            assert_eq!(status.metadata().get(ERROR_TRAILER).unwrap(), SESSIONS_FULL);
        }
        // A refresh refused for coming too soon keeps its kind across the mesh.
        let status = tonic::Status::from(DaemonError::RefreshTooSoon("refresh of k refused".into()));
        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
        assert!(matches!(from_fence_status(status.clone()), DaemonError::RefreshTooSoon(m) if m == "refresh of k refused"));
        assert!(matches!(DaemonError::from_peer_status(status, "k", None), DaemonError::RefreshTooSoon(_)));
        assert!(matches!(from_fence_status(tonic::Status::failed_precondition("x")), DaemonError::Status(_)));
        // A hosted-key conflict and an unconfirmed copy keep their meaning across the mesh.
        let conflict = tonic::Status::from(DaemonError::HostedConflict { key_id: "k".into(), detail: "x".into() });
        assert_eq!(conflict.code(), tonic::Code::Aborted);
        assert!(matches!(DaemonError::from_peer_status(conflict, "k", None), DaemonError::HostedConflict { .. }));
        let unconfirmed =
            tonic::Status::from(DaemonError::HostedUnconfirmed { key_id: "k".into(), detail: "x".into() });
        assert_eq!(unconfirmed.code(), tonic::Code::Unavailable);
        assert!(matches!(
            DaemonError::from_peer_status(unconfirmed, "k", None),
            DaemonError::HostedUnconfirmed { .. }
        ));

        // A key store that is down keeps its meaning across the mesh; so do the leader's refusals.
        let down = tonic::Status::from(DaemonError::KeystoreDown("key store /data/keys failed its readiness probe".into()));
        assert_eq!(down.code(), tonic::Code::Unavailable);
        assert_eq!(down.metadata().get(ERROR_TRAILER).unwrap(), KEYSTORE_DOWN);
        assert!(down.message().contains("readiness probe"), "{down:?}");
        assert!(matches!(DaemonError::from_peer_status(down, "k", None), DaemonError::KeystoreDown(_)));
        let nq = tonic::Status::from(DaemonError::NoQuorum { needed: 2, visible: 1, missing: vec![2, 3] });
        assert_eq!((nq.code(), nq.metadata().get(ERROR_TRAILER).unwrap().to_str().unwrap()), (tonic::Code::Unavailable, NO_QUORUM));
        let ov = tonic::Status::from(DaemonError::Overloaded("x".into()));
        assert_eq!((ov.code(), ov.metadata().get(ERROR_TRAILER).unwrap().to_str().unwrap()), (tonic::Code::Unavailable, OVERLOADED));
        let late = DaemonError::PeerDeadline { peer: 2, call: "sign_round1", after: std::time::Duration::from_secs(2) };
        assert_eq!(tonic::Status::from(late).code(), tonic::Code::Unavailable);

        // Any other refusal stays a plain status (an older peer, another reason).
        let plain = tonic::Status::failed_precondition("something else");
        assert!(matches!(DaemonError::from_peer_status(plain, "k", None), DaemonError::Status(_)));
    }
}
