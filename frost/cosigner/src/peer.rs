// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! The peer abstraction the orchestrator drives. A peer is either this node itself
//! ([`LocalPeer`], a direct in-process call) or a remote cosigner ([`GrpcPeer`], over gRPC). The
//! orchestrator is written against [`PeerApi`] and does not care which — which also makes it
//! testable with local peers only, no servers.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use frost_ed25519 as frost;
use frost::keys::dkg::{round1, round2};
use frost::round1::SigningCommitments;
use frost::round2::SignatureShare;
use frost::Identifier;

use crate::ceremony_record::{Outcome, Phase, StatusInfo};
use crate::node::{CeremonyKind, Node, Round1Ctx, StagedOutcome};
use crate::pb::peer_client::PeerClient;
use crate::pb;
use crate::Result;

// async_trait rewrites every method to return a `#[must_use]` boxed future while our `Result` is
// already `#[must_use]`, which trips clippy 1.99's `double_must_use` inside the macro expansion.
#[allow(clippy::double_must_use)]
#[async_trait]
pub trait PeerApi: Send + Sync {
    fn identifier(&self) -> Identifier;
    /// Whether this handle is the calling node itself, in process (a [`LocalPeer`] that acts for
    /// no other node). A leader fences its own node first ([`crate::orchestrator`]).
    fn is_local(&self) -> bool {
        false
    }
    /// This leader's view of the peer's liveness ([`crate::liveness`]); `None` (this node, or a
    /// peer that keeps none) reads as always up.
    fn health(&self) -> Option<&Arc<crate::liveness::PeerHealth>> {
        None
    }
    /// Whether the peer counts as reachable for the leader's quorum check: anything not known
    /// unreachable is. A peer known unreachable is asked once more (a probe no older than `fresh`
    /// is reused, one in flight is joined), waiting at most `wait`.
    async fn reachable_within(&self, _fresh: std::time::Duration, _wait: std::time::Duration) -> bool {
        true
    }
    /// [`PeerApi::sign_round1`] within `deadline` (the leader's clock, around the whole call): past
    /// it, [`crate::DaemonError::PeerDeadline`].
    async fn sign_round1_within(
        &self,
        key_id: &str,
        session_id: &str,
        ctx: &Round1Ctx,
        deadline: std::time::Duration,
    ) -> Result<SigningCommitments> {
        within(self.identifier(), CallClass::Round1, deadline, self.sign_round1(key_id, session_id, ctx)).await
    }
    /// [`PeerApi::sign_round2`] within `deadline`, as [`PeerApi::sign_round1_within`].
    async fn sign_round2_within(
        &self,
        key_id: &str,
        session_id: &str,
        message: &[u8],
        commitments: &BTreeMap<Identifier, SigningCommitments>,
        intent_digest: Option<&[u8; 32]>,
        deadline: std::time::Duration,
    ) -> Result<SignatureShare> {
        within(
            self.identifier(),
            CallClass::Round2,
            deadline,
            self.sign_round2(key_id, session_id, message, commitments, intent_digest),
        )
        .await
    }
    /// [`PeerApi::abort_sign`] within `deadline`.
    async fn abort_sign_within(&self, key_id: &str, session_id: &str, deadline: std::time::Duration) -> Result<()> {
        within(self.identifier(), CallClass::Abort, deadline, self.abort_sign(key_id, session_id)).await
    }
    /// Sign round 1. `ctx` is what the leader declares for the session (its sharing of the key);
    /// a refusal because of it is [`crate::DaemonError::EpochMismatch`] or
    /// [`crate::DaemonError::StaleShare`] over every transport.
    async fn sign_round1(&self, key_id: &str, session_id: &str, ctx: &Round1Ctx) -> Result<SigningCommitments>;
    /// Sign round 2. `intent_digest`: SHA-256 of the signing intent round 1 carried (`None` if it
    /// carried none); the peer refuses one that differs from what it bound.
    async fn sign_round2(
        &self,
        key_id: &str,
        session_id: &str,
        message: &[u8],
        commitments: &BTreeMap<Identifier, SigningCommitments>,
        intent_digest: Option<&[u8; 32]>,
    ) -> Result<SignatureShare>;
    /// Best-effort: drop an in-flight sign session so its nonces are freed now, not at TTL.
    async fn abort_sign(&self, key_id: &str, session_id: &str) -> Result<()>;
    /// Take the per-key ceremony guard before DKG/refresh crypto (cluster-wide sign fence).
    async fn ceremony_fence(&self, ceremony_id: &str, key_id: &str, kind: &'static str) -> Result<()>;
    /// Release a fence taken by [`ceremony_fence`].
    async fn ceremony_release(&self, ceremony_id: &str, key_id: &str) -> Result<()>;
    // -- hosted-key replication --

    /// This peer's identifier and X25519 distribution public key, so material can be wrapped to it.
    async fn node_info(&self) -> Result<(u16, [u8; 32])>;
    /// The hosted-key specs this peer can store and serve (`NodeInfo.hosted_key_specs`). An older
    /// cosigner reports none. The default — "cannot tell" — is what a peer that does not implement
    /// it gets, and makes the leader refuse any spec that needs every node's support.
    async fn hosted_specs(&self) -> Result<Vec<String>> {
        Err(crate::DaemonError::Config("this peer does not report its hosted-key specs".into()))
    }
    /// Push a wrapped hosted key to this peer. Returns the peer's commitment to the material.
    async fn replicate_key(
        &self,
        ceremony_id: &str,
        key_id: &str,
        spec: &str,
        public_key_der: &[u8],
        wrapped: &crate::wrap::Wrapped,
    ) -> Result<Vec<u8>>;
    /// Pull a hosted key from this peer, wrapped to the caller.
    async fn fetch_key(&self, key_id: &str) -> Result<(String, Vec<u8>, crate::wrap::Wrapped)>;
    /// [`PeerApi::fetch_key`], telling a tombstone apart from "not held": what a node asks before
    /// it stores a key it lacks. The default — a peer that cannot say — reports what `fetch_key`
    /// reports, a tombstone included as NOT_FOUND.
    async fn fetch_key_state(&self, key_id: &str) -> Result<FetchedCopy> {
        let (spec, _public_key_der, wrapped) = self.fetch_key(key_id).await?;
        Ok(FetchedCopy::Key { spec, wrapped })
    }
    /// This peer's live hosted keys: (key_id, spec, commitment). Tombstones excluded.
    async fn list_keys(&self) -> Result<Vec<(String, String, Vec<u8>)>>;
    /// This peer's full inventory for anti-entropy: live keys and tombstones (audit M2). The
    /// default — a peer that cannot report tombstones — lists its live keys only.
    async fn list_inventory(&self) -> Result<Vec<pb::KeyManifest>> {
        Ok(self
            .list_keys()
            .await?
            .into_iter()
            .map(|(key_id, spec, commitment)| pb::KeyManifest { key_id, spec, commitment, ..Default::default() })
            .collect())
    }
    /// Roll back a key this peer created in genkey ceremony `ceremony_id` (a generation below its
    /// write quorum, still fenced). Anything else is refused by the peer.
    async fn purge_key(&self, ceremony_id: &str, key_id: &str) -> Result<bool>;
    /// Delete a hosted key on this peer by a client's delete intent, which the peer verifies itself
    /// and records as a tombstone. `true`: it held the key live.
    async fn delete_key(&self, _ceremony_id: &str, _key_id: &str, _intent: &pb::SignedIntent) -> Result<bool> {
        Err(unsupported("hosted-key tombstones"))
    }

    // -- two-phase ceremonies --

    /// This peer's committed epoch / PKP digest for `key_id` and whether a ceremony for it is
    /// staged there (`Peer.KeyEpoch`). The default — a peer that cannot say — makes every ceremony
    /// that needs the answer refuse.
    async fn key_epoch(&self, _key_id: &str) -> Result<pb::KeyEpochReply> {
        Err(crate::DaemonError::Config("this peer does not report key epochs".into()))
    }
    /// The DKG/refresh fence ([`Node::ceremony_begin`]): the per-key guard plus the two-phase
    /// rules; `expect` is the leader's view of the sharing a refresh starts from; `intent` the
    /// client's ceremony intent, forwarded unchanged (every node verifies it itself).
    async fn ceremony_begin(
        &self,
        _ceremony_id: &str,
        _key_id: &str,
        _kind: CeremonyKind,
        _expect: Option<(u64, [u8; 32])>,
        _intent: Option<&pb::SignedIntent>,
    ) -> Result<()> {
        Err(unsupported("two-phase ceremonies"))
    }
    /// Ask this peer to resolve a ceremony it staged now (`Peer.CeremonyCommit`): it confirms with
    /// every roster node directly and commits or aborts on its own evidence, never on the
    /// caller's word. Returns where the ceremony stands there afterwards.
    async fn ceremony_commit(&self, _ceremony_id: &str) -> Result<StatusInfo> {
        Err(unsupported("two-phase ceremonies"))
    }
    /// This peer's vote on a ceremony (`Peer.CeremonyStatus`).
    async fn ceremony_status(&self, _ceremony_id: &str) -> Result<StatusInfo> {
        Err(unsupported("two-phase ceremonies"))
    }
    /// Drop this peer's in-memory session for a ceremony (`Peer.CeremonyAbort`). A recorded vote is
    /// returned unchanged.
    async fn ceremony_abort(&self, _ceremony_id: &str) -> Result<StatusInfo> {
        Err(unsupported("two-phase ceremonies"))
    }
    /// The DKG/refresh wire protocol this peer speaks (`NodeInfo.ceremony_protocol`; 0 from a
    /// cosigner that predates it). A leader refuses a ceremony unless every node reports at least
    /// [`crate::ceremony::CEREMONY_PROTOCOL`].
    async fn ceremony_protocol(&self) -> Result<u32> {
        Err(unsupported("ceremony protocol negotiation"))
    }
    /// Part 1 ([`Node::ceremony_part1`]): this peer's round-1 package (public). `intent` as on
    /// [`PeerApi::ceremony_begin`], verified again by the peer.
    async fn ceremony_part1(
        &self,
        _ceremony_id: &str,
        _key_id: &str,
        _kind: CeremonyKind,
        _roster: &[u16],
        _intent: Option<&pb::SignedIntent>,
    ) -> Result<round1::Package> {
        Err(unsupported("ceremony protocol 2"))
    }
    /// Part 2: the peer checks the round-1 map, computes its round-2 packages and delivers each
    /// directly to its recipient ([`crate::ceremony::part2_and_deliver`]). Returns only its
    /// round-1 digest and whom it delivered to — by construction, no method of this trait ever
    /// returns a round-2 package to the caller (audit C1).
    async fn ceremony_part2(
        &self,
        _ceremony_id: &str,
        _round1_map: &BTreeMap<Identifier, round1::Package>,
    ) -> Result<crate::ceremony::Part2Outcome> {
        Err(unsupported("ceremony protocol 2"))
    }
    /// Deliver this caller's round-2 package for this peer (`to`). The peer takes the sender from
    /// the caller's authenticated identity and refuses a `from` that differs.
    async fn ceremony_deliver(
        &self,
        _ceremony_id: &str,
        _from: u16,
        _to: u16,
        _round1_digest: &[u8; 32],
        _package: &round2::Package,
    ) -> Result<()> {
        Err(unsupported("ceremony protocol 2"))
    }
    /// Part 3 ([`Node::ceremony_part3`]): stage and vote, given the leader's round-1 digest.
    async fn ceremony_part3(&self, _ceremony_id: &str, _round1_digest: &[u8; 32]) -> Result<StagedOutcome> {
        Err(unsupported("ceremony protocol 2"))
    }
}

/// What a peer answers for a hosted key id ([`PeerApi::fetch_key_state`]); NOT_FOUND is an error.
pub enum FetchedCopy {
    /// Its live copy, wrapped to the caller.
    Key { spec: String, wrapped: crate::wrap::Wrapped },
    /// Its tombstone, with the delete intent for the caller to verify.
    Tombstone(Box<pb::KeyManifest>),
}

fn unsupported(what: &str) -> crate::DaemonError {
    crate::DaemonError::CeremonyRefused(format!("this peer does not support {what}"))
}

/// This node, called in-process.
///
/// Every call that may touch the key store runs through [`Node::blocking`], exactly as the same call
/// does when it arrives over gRPC: the leader's own share of a sign round or ceremony must not park
/// an async worker on a stalled volume any more than a peer's may.
pub struct LocalPeer {
    node: Arc<Node>,
    /// Who `fetch_key` wraps to. `None` = this node itself (the leader reading its own store).
    /// Set, it models another cosigner calling this node over gRPC, where the reply is wrapped to
    /// the authenticated caller — see [`LocalPeer::on_behalf_of`].
    caller: Option<Arc<Node>>,
}

impl LocalPeer {
    pub fn new(node: Arc<Node>) -> Self {
        Self { node, caller: None }
    }

    /// This node as seen by `caller` over the mesh: `fetch_key` wraps to `caller`, exactly as
    /// `Peer.FetchKey` does for the certificate-identified caller. In-process clusters (tests) hand
    /// one node a `LocalPeer` of another; without this the envelope would be addressed to the
    /// serving node and the caller could not open it.
    pub fn on_behalf_of(mut self, caller: Arc<Node>) -> Self {
        self.caller = Some(caller);
        self
    }

    /// Who asks, as the serving node would see the caller's certificate CN (`cosigner<N>`), for a
    /// handle acting on behalf of another node; `None` for an in-process leader handle. It is also
    /// who leads a ceremony this handle fences or runs, exactly as over gRPC.
    fn asker(&self) -> Option<String> {
        self.caller.as_ref().and_then(|c| c.index().ok()).map(|i| format!("cosigner{i}"))
    }

    /// Who opens and owns the sign sessions this handle starts: the in-process leader
    /// ([`crate::node::SessionOwner::Local`], which no remote caller can be), or the node it acts
    /// for, by the CN the serving node would see over gRPC.
    fn session_owner(&self) -> crate::node::SessionOwner {
        match self.asker() {
            Some(cn) => crate::node::SessionOwner::Peer(cn),
            None => crate::node::SessionOwner::Local,
        }
    }
}

/// Wire an in-process cluster's mesh: each node reaches every other through a [`LocalPeer`]
/// acting on its behalf — what the daemon does with gRPC peers. Nodes that already have a mesh are
/// left alone. Tests and tools only.
pub fn wire_local_mesh(nodes: &[Arc<Node>]) -> Result<()> {
    for me in nodes.iter().filter(|n| !n.has_mesh()) {
        let mesh: Vec<Arc<dyn PeerApi>> = nodes
            .iter()
            .filter(|n| !Arc::ptr_eq(n, me))
            .map(|n| Arc::new(LocalPeer::new(n.clone()).on_behalf_of(me.clone())) as Arc<dyn PeerApi>)
            .collect();
        me.set_mesh(mesh)?;
    }
    Ok(())
}

#[async_trait]
impl PeerApi for LocalPeer {
    fn identifier(&self) -> Identifier {
        self.node.identifier
    }
    fn is_local(&self) -> bool {
        self.caller.is_none()
    }
    async fn sign_round1(&self, key_id: &str, session_id: &str, ctx: &Round1Ctx) -> Result<SigningCommitments> {
        let (key_id, session_id, ctx) = (key_id.to_owned(), session_id.to_owned(), ctx.clone());
        let owner = self.session_owner();
        self.node
            .sign_op(crate::liveness::Round::One, move |n| n.sign_round1_as(&key_id, &session_id, &ctx, &owner))
            .await
    }
    async fn sign_round2(
        &self,
        key_id: &str,
        session_id: &str,
        message: &[u8],
        commitments: &BTreeMap<Identifier, SigningCommitments>,
        intent_digest: Option<&[u8; 32]>,
    ) -> Result<SignatureShare> {
        let (key_id, session_id) = (key_id.to_owned(), session_id.to_owned());
        let (message, commitments, digest) = (message.to_vec(), commitments.clone(), intent_digest.copied());
        let owner = self.session_owner();
        self.node
            .sign_op(crate::liveness::Round::Two, move |n| {
                n.sign_round2_as(&key_id, &session_id, &message, &commitments, digest, &owner)
            })
            .await
    }
    async fn abort_sign(&self, key_id: &str, session_id: &str) -> Result<()> {
        self.node.abort_sign_as(key_id, session_id, &self.session_owner())
    }
    async fn ceremony_fence(&self, ceremony_id: &str, key_id: &str, kind: &'static str) -> Result<()> {
        self.node.ceremony_fence_from(ceremony_id, key_id, kind, self.asker().as_deref())
    }
    async fn ceremony_release(&self, ceremony_id: &str, key_id: &str) -> Result<()> {
        self.node.ceremony_release_from(ceremony_id, key_id, self.asker().as_deref());
        Ok(())
    }
    async fn node_info(&self) -> Result<(u16, [u8; 32])> {
        Ok((crate::hosted::identifier_index(self.node.identifier)?, self.node.dist_public_key()?))
    }

    async fn hosted_specs(&self) -> Result<Vec<String>> {
        Ok(self.node.hosted_specs())
    }

    async fn replicate_key(
        &self,
        ceremony_id: &str,
        key_id: &str,
        spec: &str,
        _public_key_der: &[u8],
        wrapped: &crate::wrap::Wrapped,
    ) -> Result<Vec<u8>> {
        // The same rules as `Peer.ReplicateKey`: the caller is the node this handle acts for.
        let sender = self.caller.as_ref().and_then(|c| c.index().ok());
        crate::orchestrator::accept_replica(
            &self.node,
            ceremony_id,
            key_id,
            spec,
            wrapped,
            self.asker().as_deref(),
            sender,
        )
        .await
    }

    async fn fetch_key(&self, key_id: &str) -> Result<(String, Vec<u8>, crate::wrap::Wrapped)> {
        // In-process the recipient is this same node, unless `on_behalf_of` named another caller.
        let key_id = key_id.to_owned();
        let caller = self.caller.clone();
        self.node
            .blocking(move |n| {
                let key = n.hosted_load(&key_id)?;
                let recipient = caller.as_deref().unwrap_or(n);
                let (id, pk) = (
                    crate::hosted::identifier_index(recipient.identifier)?,
                    recipient.dist_public_key()?,
                );
                let w = n.hosted_wrap_for(&key_id, &key, id, &pk)?;
                let pub_der = if key.spec.is_asymmetric() { key.public_key_der()? } else { Vec::new() };
                Ok((key.spec.as_str().to_string(), pub_der, w))
            })
            .await
    }

    async fn fetch_key_state(&self, key_id: &str) -> Result<FetchedCopy> {
        let id = key_id.to_owned();
        if let Some(t) = self.node.blocking(move |n| n.hosted_tombstone_manifest(&id)).await? {
            return Ok(FetchedCopy::Tombstone(Box::new(t)));
        }
        let (spec, _public_key_der, wrapped) = self.fetch_key(key_id).await?;
        Ok(FetchedCopy::Key { spec, wrapped })
    }

    async fn list_keys(&self) -> Result<Vec<(String, String, Vec<u8>)>> {
        self.node
            .blocking(|n| {
                let mut out = Vec::new();
                for key_id in n.hosted_list()? {
                    let key = n.hosted_load(&key_id)?;
                    let commitment = n.hosted_commitment(&key)?;
                    out.push((key_id, key.spec.as_str().to_string(), commitment));
                }
                Ok(out)
            })
            .await
    }

    async fn list_inventory(&self) -> Result<Vec<pb::KeyManifest>> {
        self.node.blocking(|n| n.hosted_manifest()).await
    }

    async fn purge_key(&self, ceremony_id: &str, key_id: &str) -> Result<bool> {
        let (ceremony_id, key_id) = (ceremony_id.to_owned(), key_id.to_owned());
        let leader = self.asker();
        self.node.blocking(move |n| n.hosted_rollback_purge_from(&ceremony_id, &key_id, leader.as_deref())).await
    }

    async fn delete_key(&self, _ceremony_id: &str, key_id: &str, intent: &pb::SignedIntent) -> Result<bool> {
        let (key_id, intent) = (key_id.to_owned(), intent.clone());
        self.node
            .blocking(move |n| {
                n.hosted_apply_tombstone(&key_id, &intent, crate::intent::Expiry::Enforce, None)
                    .map(|o| o == crate::node::TombstoneOutcome::Converted)
            })
            .await
    }

    async fn key_epoch(&self, key_id: &str) -> Result<pb::KeyEpochReply> {
        let key_id = key_id.to_owned();
        self.node.blocking(move |n| n.key_epoch(&key_id)).await
    }

    async fn ceremony_begin(
        &self,
        ceremony_id: &str,
        key_id: &str,
        kind: CeremonyKind,
        expect: Option<(u64, [u8; 32])>,
        intent: Option<&pb::SignedIntent>,
    ) -> Result<()> {
        let (ceremony_id, key_id, intent) = (ceremony_id.to_owned(), key_id.to_owned(), intent.cloned());
        let leader = self.asker();
        self.node
            .blocking(move |n| {
                n.ceremony_begin_from(&ceremony_id, &key_id, kind, expect, intent.as_ref(), leader.as_deref())
            })
            .await
    }

    async fn ceremony_commit(&self, ceremony_id: &str) -> Result<StatusInfo> {
        crate::ceremony::resolve_from(&self.node, ceremony_id, self.asker()).await
    }

    async fn ceremony_status(&self, ceremony_id: &str) -> Result<StatusInfo> {
        let ceremony_id = ceremony_id.to_owned();
        let asker = self.asker();
        self.node.blocking(move |n| n.ceremony_status_from(&ceremony_id, asker.as_deref())).await
    }

    async fn ceremony_abort(&self, ceremony_id: &str) -> Result<StatusInfo> {
        let ceremony_id = ceremony_id.to_owned();
        let asker = self.asker();
        self.node.blocking(move |n| n.ceremony_abort_from(&ceremony_id, asker.as_deref())).await
    }

    async fn ceremony_protocol(&self) -> Result<u32> {
        Ok(crate::ceremony::CEREMONY_PROTOCOL)
    }

    async fn ceremony_part1(
        &self,
        ceremony_id: &str,
        key_id: &str,
        kind: CeremonyKind,
        roster: &[u16],
        intent: Option<&pb::SignedIntent>,
    ) -> Result<round1::Package> {
        let (ceremony_id, key_id, roster, intent) =
            (ceremony_id.to_owned(), key_id.to_owned(), roster.to_vec(), intent.cloned());
        let leader = self.asker();
        self.node
            .blocking(move |n| {
                n.ceremony_part1_from(&ceremony_id, &key_id, kind, &roster, intent.as_ref(), leader.as_deref())
            })
            .await
    }

    async fn ceremony_part2(
        &self,
        ceremony_id: &str,
        round1_map: &BTreeMap<Identifier, round1::Package>,
    ) -> Result<crate::ceremony::Part2Outcome> {
        crate::ceremony::part2_and_deliver(&self.node, ceremony_id, round1_map.clone(), self.asker()).await
    }

    async fn ceremony_deliver(
        &self,
        ceremony_id: &str,
        from: u16,
        to: u16,
        round1_digest: &[u8; 32],
        package: &round2::Package,
    ) -> Result<()> {
        // In process the sender is the node this handle acts for (`on_behalf_of`), exactly as the
        // gRPC service takes it from the caller's certificate; a bare handle is this node itself.
        let sender = crate::hosted::identifier_index(self.caller.as_deref().unwrap_or(&self.node).identifier)?;
        if sender != from {
            return Err(crate::DaemonError::CeremonyRefused(format!(
                "node {sender} cannot deliver a round-2 package as node {from}"
            )));
        }
        let (ceremony_id, digest, package) = (ceremony_id.to_owned(), *round1_digest, package.clone());
        self.node.blocking(move |n| n.ceremony_deliver(&ceremony_id, from, to, digest, package)).await
    }

    async fn ceremony_part3(&self, ceremony_id: &str, round1_digest: &[u8; 32]) -> Result<StagedOutcome> {
        let (ceremony_id, digest, leader) = (ceremony_id.to_owned(), *round1_digest, self.asker());
        self.node.blocking(move |n| n.ceremony_part3_from(&ceremony_id, &digest, leader.as_deref())).await
    }
}

/// Deadline of a ceremony or hosted-key call (DKG/refresh parts, fences, commits, replicas,
/// listings), and tonic's own backstop on every mesh RPC (`Endpoint::timeout`).
///
/// Every peer RPC is small, so anything slower is a sick peer (a hung volume, a wedged process).
/// The deadline is the leader's own clock around the whole call ([`CallClass`]): queue, connect and
/// RPC, so a dead peer's queue never drains one connect timeout at a time. A call past it is
/// [`crate::DaemonError::PeerDeadline`]: in a sign round the member is excluded from that signature,
/// in a ceremony it fails the ceremony (which rolls back), and a hosted-key write treats it as
/// unreachable. It can never cause a nonce reuse: the leader never re-sends a round 2 (it aborts and
/// starts a fresh session), and a peer burns its nonce marker before it computes a share, whether
/// or not anyone is still waiting for the reply.
pub const PEER_RPC_TIMEOUT: Duration = Duration::from_secs(10);
/// Sign round 1 (memory only on the member, with room for a fresh connection).
pub const ROUND1_DEADLINE: Duration = Duration::from_secs(2);
/// Sign round 2 (two fsyncs on the member, plus queueing under a burst).
pub const ROUND2_DEADLINE: Duration = Duration::from_secs(5);
/// Aborting a sign session (memory only).
pub const ABORT_DEADLINE: Duration = Duration::from_secs(1);
/// Control calls: `NodeInfo`, `KeyEpoch`, `CeremonyStatus`.
pub const CONTROL_DEADLINE: Duration = Duration::from_secs(3);
/// The breaker's `NodeInfo` probe.
pub const PROBE_DEADLINE: Duration = Duration::from_secs(2);
/// TCP connect plus TLS handshake and pin check ([`crate::tls::PeerDial`] and the endpoint): one
/// lost SYN (1 s retransmit) plus a few WAN round trips.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// HTTP/2 keepalive on peer channels, also while idle: a PING every 5 s without traffic, and the
/// connection closed when its PONG does not come within 3 s — a dead connection (a partition, a
/// replaced pod, a paused container whose kernel still ACKs) is gone at most 8 s after its last
/// read, and tonic dials afresh (re-resolving the name) on the next call.
pub const H2_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(5);
pub const H2_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(3);
/// While a peer is unreachable, its `NodeInfo` probe runs this often (one at a time).
pub const PROBE_EVERY: Duration = Duration::from_secs(1);
/// A stalled or refusing peer is tried as a trial after this window, doubling on every failed
/// trial up to [`BREAKER_WINDOW_CAP`].
pub const BREAKER_WINDOW: Duration = Duration::from_secs(2);
pub const BREAKER_WINDOW_CAP: Duration = Duration::from_secs(30);
/// The progress test's probe after a sign round passed its deadline with nothing heard meanwhile.
pub const PROGRESS_PROBE_DEADLINE: Duration = Duration::from_secs(1);
/// How long the quorum check waits for probes of unreachable peers before refusing.
pub const QUORUM_PROBE_WAIT: Duration = Duration::from_millis(1500);
/// A probe younger than this is reused by the quorum check.
pub const PROBE_FRESH: Duration = Duration::from_secs(3);
/// Time a sign round leaves for the rest of the signature: a round's deadline is at most the
/// client's time left minus this, and no new subset starts with less than this left.
pub const ROUND_RESERVE: Duration = Duration::from_secs(1);
/// Signatures this node may lead at once before it answers `overloaded` without contacting a
/// member. Provisional: perf's ramp run (the knee) decides the number. Why 512 for now:
///
/// - the blocking pool is tokio's default, 512 threads (`main.rs` does not change it). A signature
///   led here holds at most one of them at a time on this node (its own round, then the
///   aggregation), so up to 512 led signatures cannot queue this leader's own work behind itself;
///   rounds it serves for other leaders share the same pool, which is what its own round deadline
///   ([`Overloaded`](crate::DaemonError::Overloaded) when it misses it) catches;
/// - the per-key session caps on each member bound what one key can hold anyway: at most 256
///   waiting sessions from one opener ([`crate::node::MAX_PENDING_SIGN_SESSIONS_PER_OPENER`]), and
///   this leader opens one per member per attempt, so on one key the members answer `sessions-full`
///   well before 512; the limit here is the bound across keys.
pub const MAX_LEADER_SIGNS_IN_FLIGHT: usize = 512;

/// What a peer call is: its deadline, and what its failure tells the breaker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallClass {
    Round1,
    Round2,
    Abort,
    /// `NodeInfo` and other calls answered from memory: past its deadline the peer is unreachable.
    Control,
    /// `KeyEpoch`, `CeremonyStatus`: control calls that read the peer's key store. Their deadline is
    /// [`CONTROL_DEADLINE`] too, but past it the breaker is not opened — a slow store is not an
    /// unreachable peer (its own readiness probe and the sign rounds judge the store).
    StoreRead,
    Probe,
    /// Ceremony parts and hosted-key writes and reads: [`PEER_RPC_TIMEOUT`], ignored by the breaker.
    Ceremony,
}

impl CallClass {
    /// The call's name in [`crate::DaemonError::PeerDeadline`].
    pub fn name(self) -> &'static str {
        match self {
            CallClass::Round1 => "sign round 1",
            CallClass::Round2 => "sign round 2",
            CallClass::Abort => "sign abort",
            CallClass::Control | CallClass::StoreRead => "a control call",
            CallClass::Probe => "a probe",
            CallClass::Ceremony => "a ceremony or hosted-key call",
        }
    }

    /// The `call` label of `rutli_peer_call_duration_seconds`, for the classes it covers.
    fn metric(self) -> Option<&'static str> {
        match self {
            CallClass::Round1 => Some("sign_round1"),
            CallClass::Round2 => Some("sign_round2"),
            CallClass::Abort => Some("abort"),
            CallClass::Control | CallClass::StoreRead | CallClass::Probe => Some("control"),
            CallClass::Ceremony => None,
        }
    }
}

/// The liveness constants above, as one value: production defaults, overridable by tests
/// ([`GrpcPeer::with_liveness`], [`Node::with_liveness`]). Not configuration: no knob reaches it.
#[derive(Clone, Debug)]
pub struct Liveness {
    pub round1: Duration,
    pub round2: Duration,
    pub abort: Duration,
    pub control: Duration,
    pub probe: Duration,
    pub ceremony: Duration,
    pub probe_every: Duration,
    pub window: Duration,
    pub window_cap: Duration,
    pub progress_probe: Duration,
    pub quorum_wait: Duration,
    pub probe_fresh: Duration,
    pub round_reserve: Duration,
    pub leader_inflight_limit: usize,
    /// A signature's budget without a client deadline ([`crate::orchestrator::SIGN_BUDGET`]).
    pub sign_budget: Duration,
}

impl Default for Liveness {
    fn default() -> Self {
        Self {
            round1: ROUND1_DEADLINE,
            round2: ROUND2_DEADLINE,
            abort: ABORT_DEADLINE,
            control: CONTROL_DEADLINE,
            probe: PROBE_DEADLINE,
            ceremony: PEER_RPC_TIMEOUT,
            probe_every: PROBE_EVERY,
            window: BREAKER_WINDOW,
            window_cap: BREAKER_WINDOW_CAP,
            progress_probe: PROGRESS_PROBE_DEADLINE,
            quorum_wait: QUORUM_PROBE_WAIT,
            probe_fresh: PROBE_FRESH,
            round_reserve: ROUND_RESERVE,
            leader_inflight_limit: MAX_LEADER_SIGNS_IN_FLIGHT,
            sign_budget: crate::orchestrator::SIGN_BUDGET,
        }
    }
}

impl Liveness {
    /// The deadline of a call of `class`.
    pub fn deadline(&self, class: CallClass) -> Duration {
        match class {
            CallClass::Round1 => self.round1,
            CallClass::Round2 => self.round2,
            CallClass::Abort => self.abort,
            CallClass::Control | CallClass::StoreRead => self.control,
            CallClass::Probe => self.probe,
            CallClass::Ceremony => self.ceremony,
        }
    }

    /// How long a taken trial is held before another signature may take it: one round 1 plus one
    /// round 2.
    pub fn trial_hold(&self) -> Duration {
        self.round1 + self.round2
    }
}

/// `fut` within `deadline`, or [`crate::DaemonError::PeerDeadline`] for `peer`.
pub async fn within<T>(
    peer: Identifier,
    class: CallClass,
    deadline: Duration,
    fut: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    match tokio::time::timeout(deadline, fut).await {
        Ok(result) => result,
        Err(_) => Err(crate::DaemonError::PeerDeadline {
            peer: crate::hosted::identifier_index(peer).unwrap_or(0),
            call: class.name(),
            after: deadline,
        }),
    }
}

/// What a peer's failed call tells its breaker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    /// No transport to the peer: connect or TLS failure, a connection closed under the call
    /// (keepalive, GOAWAY), UNAVAILABLE without a `rutli-error` trailer (also an older peer's
    /// key-store refusal).
    Hard,
    /// It answered that its key store is down (the `keystore-down` trailer).
    KeystoreDown,
    /// It answered: a refusal of any kind, UNAVAILABLE with another trailer included.
    Answered,
    /// A client-side timer (tonic's "Timeout expired": the request's own `grpc-timeout`, or the
    /// endpoint's backstop): the caller's deadline, not an answer.
    Silent,
}

/// Classify a peer call's failure for the breaker (and, through [`is_hard_failure`], for the
/// hosted-key write quorum).
pub fn classify(status: &tonic::Status) -> Failure {
    let trailer = status.metadata().get(crate::error::ERROR_TRAILER).and_then(|v| v.to_str().ok());
    match trailer {
        Some(crate::error::KEYSTORE_DOWN) => return Failure::KeystoreDown,
        Some(_) => return Failure::Answered,
        None => {}
    }
    let m = status.message();
    match status.code() {
        tonic::Code::Unavailable => Failure::Hard,
        tonic::Code::Cancelled if m.contains("Timeout expired") => Failure::Silent,
        // tonic reports a connection that failed below the RPC layer as Unknown "transport error",
        // and an HTTP/2 failure as "h2 protocol error: …" (whatever its code). A refusal from our
        // own code always carries a specific code and never these messages.
        tonic::Code::Unknown if m.contains("transport error") || m.contains("connection") => Failure::Hard,
        _ if m.starts_with("h2 protocol error") => Failure::Hard,
        _ => Failure::Answered,
    }
}

/// Whether `e` says the peer could not be reached at all (as opposed to an answer): a transport
/// error, or a status [`classify`] reads as hard.
pub fn is_hard_failure(e: &crate::DaemonError) -> bool {
    match e {
        crate::DaemonError::Transport(_) => true,
        crate::DaemonError::Status(s) => classify(s) == Failure::Hard,
        _ => false,
    }
}

/// A request carrying `deadline` as its `grpc-timeout`, so the peer drops the handler of a call
/// the leader stopped waiting for.
fn timed<T>(msg: T, deadline: Duration) -> tonic::Request<T> {
    let mut req = tonic::Request::new(msg);
    req.set_timeout(deadline);
    req
}

/// A remote cosigner, over gRPC. The channel connects lazily; FROST packages ride as JSON bytes.
/// Keeps this leader's view of the peer's liveness ([`crate::liveness::PeerHealth`]).
pub struct GrpcPeer {
    inner: Arc<GrpcInner>,
}

struct GrpcInner {
    identifier: Identifier,
    client: PeerClient<tonic::transport::Channel>,
    health: Arc<crate::liveness::PeerHealth>,
}

impl GrpcPeer {
    /// A peer at `endpoint`, dialled through `dial` ([`crate::tls::PeerDial`]: the TLS handshake
    /// under the peer's own server name, then its key pins), or in plaintext without one (dev).
    pub fn connect_lazy(identifier: Identifier, endpoint: &str, dial: Option<crate::tls::PeerDial>) -> Result<Self> {
        match dial {
            Some(dial) => {
                let connector = dial.connector();
                Self::connect_lazy_over(identifier, endpoint, &dial, connector)
            }
            None => {
                let ep = tonic::transport::Endpoint::from_shared(endpoint.to_string())
                    .map_err(|e| crate::DaemonError::Config(format!("bad endpoint {endpoint}: {e}")))?
                    .tcp_keepalive(Some(crate::tls::TCP_KEEPALIVE));
                Ok(Self::new(identifier, PeerClient::new(liveness_endpoint(ep).connect_lazy())))
            }
        }
    }

    /// [`GrpcPeer::connect_lazy`] through a connector built from `dial`
    /// ([`crate::tls::PeerDial::connector_over`]): tests run the mesh over in-memory streams.
    pub fn connect_lazy_over<C>(
        identifier: Identifier,
        endpoint: &str,
        dial: &crate::tls::PeerDial,
        connector: crate::tls::PeerConnector<C>,
    ) -> Result<Self>
    where
        C: tonic::codegen::Service<tonic::codegen::http::Uri> + Send + 'static,
        C::Future: Send + 'static,
        C::Error: Into<crate::tls::BoxError>,
        hyper_util::rt::TokioIo<C::Response>: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let channel = liveness_endpoint(dial.endpoint(endpoint)?).connect_with_connector_lazy(connector);
        Ok(Self::new(identifier, PeerClient::new(channel)))
    }

    fn new(identifier: Identifier, client: PeerClient<tonic::transport::Channel>) -> Self {
        let index = crate::hosted::identifier_index(identifier).unwrap_or(0);
        let health = Arc::new(crate::liveness::PeerHealth::new(index, Liveness::default()));
        Self { inner: Arc::new(GrpcInner { identifier, client, health }) }
    }

    /// This peer with other liveness timings (tests). Call before the peer is used.
    pub fn with_liveness(mut self, timing: Liveness) -> Self {
        let inner = Arc::get_mut(&mut self.inner).expect("set the liveness timings before the peer is shared");
        inner.health = Arc::new(crate::liveness::PeerHealth::new(inner.health.peer(), timing));
        self
    }
}

/// The peer endpoint's liveness settings: HTTP/2 keepalive (also while idle), the connect bound,
/// and tonic's per-RPC backstop. The per-call deadlines are the leader's own ([`CallClass`]).
fn liveness_endpoint(ep: tonic::transport::Endpoint) -> tonic::transport::Endpoint {
    ep.timeout(PEER_RPC_TIMEOUT)
        .connect_timeout(CONNECT_TIMEOUT)
        .http2_keep_alive_interval(H2_KEEPALIVE_INTERVAL)
        .keep_alive_timeout(H2_KEEPALIVE_TIMEOUT)
        .keep_alive_while_idle(true)
}

impl GrpcInner {
    fn timing(&self) -> &Liveness {
        self.health.timing()
    }

    fn index(&self) -> u16 {
        self.health.peer()
    }

    /// One RPC of `class` within `deadline` (sent as its `grpc-timeout` by `rpc`), feeding the
    /// breaker and the call-duration histogram; a status error is mapped by `map`.
    async fn call<T, Fut>(
        self: &Arc<Self>,
        class: CallClass,
        deadline: Duration,
        map: impl FnOnce(tonic::Status) -> crate::DaemonError,
        rpc: impl FnOnce(PeerClient<tonic::transport::Channel>) -> Fut,
    ) -> Result<T>
    where
        Fut: std::future::Future<Output = std::result::Result<tonic::Response<T>, tonic::Status>>,
    {
        let mark = self.health.mark();
        let started = tokio::time::Instant::now();
        let outcome = tokio::time::timeout(deadline, rpc(self.client.clone())).await;
        if let Some(call) = class.metric() {
            metrics::histogram!(crate::metrics::PEER_CALL_DURATION, "call" => call)
                .record(started.elapsed().as_secs_f64());
        }
        match outcome {
            // tonic enforces the request's own `grpc-timeout` too, and at the same instant may win
            // the race with the timer above: the same deadline either way.
            Ok(Err(status)) if classify(&status) == Failure::Silent => {
                self.on_deadline(class, mark);
                Err(crate::DaemonError::PeerDeadline { peer: self.index(), call: class.name(), after: deadline })
            }
            Ok(Ok(reply)) => {
                self.health.note_reply(crate::liveness::Load::from_metadata(reply.metadata()));
                match class {
                    CallClass::Round1 => self.health.note_done(crate::liveness::Round::One),
                    CallClass::Round2 => self.health.note_done(crate::liveness::Round::Two),
                    _ => {}
                }
                self.health.on_success(class);
                Ok(reply.into_inner())
            }
            Ok(Err(status)) => {
                self.observe(&status);
                Err(map(status))
            }
            Err(_) => {
                self.on_deadline(class, mark);
                Err(crate::DaemonError::PeerDeadline { peer: self.index(), call: class.name(), after: deadline })
            }
        }
    }

    /// What a failed call's status tells the breaker.
    fn observe(self: &Arc<Self>, status: &tonic::Status) {
        match classify(status) {
            Failure::Hard => self.open(crate::liveness::DownReason::Unreachable),
            Failure::KeystoreDown => {
                self.health.note_reply(crate::liveness::Load::from_metadata(status.metadata()));
                self.open(crate::liveness::DownReason::Refusing);
            }
            Failure::Answered => {
                self.health.note_reply(crate::liveness::Load::from_metadata(status.metadata()));
                self.health.on_answer();
            }
            Failure::Silent => {}
        }
    }

    fn open(self: &Arc<Self>, reason: crate::liveness::DownReason) {
        self.health.open(reason);
        self.ensure_prober();
    }

    /// A call passed its deadline. A sign round is judged by the progress test in the background
    /// (the member is excluded from its signature either way); a memory-only control call or a
    /// probe is an unreachable peer; a control call that reads the store, an abort or a ceremony
    /// call says nothing to the breaker.
    fn on_deadline(self: &Arc<Self>, class: CallClass, mark: crate::liveness::Mark) {
        use crate::liveness::{Judged, Round};
        let round = match class {
            CallClass::Round1 => Round::One,
            CallClass::Round2 => Round::Two,
            CallClass::Control | CallClass::Probe => return self.open(crate::liveness::DownReason::Unreachable),
            CallClass::StoreRead | CallClass::Abort | CallClass::Ceremony => return,
        };
        let Ok(rt) = tokio::runtime::Handle::try_current() else { return };
        // Sorted after up peers until the verdict, so the next signatures do not walk into the same
        // deadline meanwhile.
        self.health.suspect(self.timing().progress_probe + self.timing().abort);
        let inner = self.clone();
        rt.spawn(async move {
            let reason = match inner.health.judge(round, &mark) {
                Judged::Busy => None,
                Judged::Probe => {
                    let probed = inner.probe(mark.at, inner.timing().progress_probe).await;
                    inner.health.judge_probe(round, &mark, probed)
                }
            };
            inner.health.clear_suspect();
            match reason {
                Some(reason) => inner.open(reason),
                None => tracing::debug!(peer = inner.index(), ?round, "a sign round passed its deadline on a busy cosigner (it made progress meanwhile): not marked down"),
            }
        });
    }

    /// One `NodeInfo` probe, single flight: a probe that finished after `since` is reused, one in
    /// flight is joined. Records the answer's load; changes no state (the caller decides).
    async fn probe(self: &Arc<Self>, since: tokio::time::Instant, deadline: Duration) -> crate::liveness::Probed {
        use crate::liveness::Probed;
        let _slot = self.health.probe_slot.lock().await;
        if let Some(last) = self.health.last_probe() {
            if last.at >= since {
                return last.outcome;
            }
        }
        let started = tokio::time::Instant::now();
        let answer =
            tokio::time::timeout(deadline, self.client.clone().node_info(timed(pb::NodeInfoRequest {}, deadline))).await;
        metrics::histogram!(crate::metrics::PEER_CALL_DURATION, "call" => "control")
            .record(started.elapsed().as_secs_f64());
        let outcome = match answer {
            Ok(Ok(reply)) => {
                let load = crate::liveness::Load::from_metadata(reply.metadata());
                self.health.note_reply(load);
                Probed::Answered(load)
            }
            Ok(Err(status)) => match classify(&status) {
                Failure::Hard | Failure::Silent => Probed::Failed,
                Failure::KeystoreDown | Failure::Answered => {
                    let load = crate::liveness::Load::from_metadata(status.metadata());
                    self.health.note_reply(load);
                    Probed::Answered(load)
                }
            },
            Err(_) => Probed::Failed,
        };
        self.health.record_probe(outcome);
        outcome
    }

    /// Start the background prober unless it runs (then wake it). It probes a down peer — every
    /// [`PROBE_EVERY`] while unreachable, at the end of each window while stalled or refusing —
    /// and stops once the peer is up or the peer handle is gone.
    fn ensure_prober(self: &Arc<Self>) {
        if self.health.prober.swap(true, std::sync::atomic::Ordering::AcqRel) {
            self.health.wake.notify_one();
            return;
        }
        let Ok(rt) = tokio::runtime::Handle::try_current() else {
            self.health.prober.store(false, std::sync::atomic::Ordering::Release);
            return;
        };
        let (weak, health) = (Arc::downgrade(self), self.health.clone());
        rt.spawn(async move {
            use std::sync::atomic::Ordering;
            loop {
                let Some(wait) = health.next_probe_in() else {
                    health.prober.store(false, Ordering::Release);
                    // Opened again between the check and the store: carry on, unless another
                    // prober took over.
                    if health.next_probe_in().is_some() && !health.prober.swap(true, Ordering::AcqRel) {
                        continue;
                    }
                    return;
                };
                tokio::select! {
                    _ = tokio::time::sleep(wait) => {}
                    _ = health.wake.notified() => {}
                }
                let Some(inner) = weak.upgrade() else {
                    health.prober.store(false, Ordering::Release);
                    return;
                };
                let probed = inner.probe(tokio::time::Instant::now(), inner.timing().probe).await;
                drop(inner);
                health.after_probe(probed);
            }
        });
    }

    fn deadline(&self, class: CallClass) -> Duration {
        self.timing().deadline(class)
    }
}

#[async_trait]
impl PeerApi for GrpcPeer {
    fn identifier(&self) -> Identifier {
        self.inner.identifier
    }

    fn health(&self) -> Option<&Arc<crate::liveness::PeerHealth>> {
        Some(&self.inner.health)
    }

    async fn reachable_within(&self, fresh: Duration, wait: Duration) -> bool {
        use crate::liveness::Probed;
        let h = &self.inner.health;
        if !h.is_unreachable() && !h.is_suspect() {
            return true;
        }
        if let Some(last) = h.last_probe() {
            if last.at.elapsed() < fresh && matches!(last.outcome, Probed::Failed) {
                return false;
            }
        }
        // Joins the probe a deadline's judgment (or the prober) has in flight, else starts one.
        let probe = self.inner.probe(tokio::time::Instant::now(), wait.min(self.inner.timing().probe));
        match tokio::time::timeout(wait, probe).await {
            Ok(probed) => {
                h.after_probe(probed);
                matches!(probed, Probed::Answered(_)) && !h.is_unreachable()
            }
            Err(_) => false,
        }
    }

    async fn sign_round1(&self, key_id: &str, session_id: &str, ctx: &Round1Ctx) -> Result<SigningCommitments> {
        self.sign_round1_within(key_id, session_id, ctx, self.inner.deadline(CallClass::Round1)).await
    }

    async fn sign_round1_within(
        &self,
        key_id: &str,
        session_id: &str,
        ctx: &Round1Ctx,
        deadline: Duration,
    ) -> Result<SigningCommitments> {
        let msg = pb::SignRound1Request {
            key_id: key_id.into(),
            session_id: session_id.into(),
            epoch: ctx.leader_view.map(|v| v.0).unwrap_or(0),
            pkp_digest: ctx.leader_view.map(|v| v.1.to_vec()).unwrap_or_default(),
            message: ctx.message.clone().unwrap_or_default(),
            signers: ctx.signers.iter().flatten().map(|&i| u32::from(i)).collect(),
            intent: ctx.intent.clone(),
            purpose: if ctx.sign_test { crate::intent::PURPOSE_SIGN_TEST.into() } else { String::new() },
        };
        let leader_view = ctx.leader_view;
        let reply = self
            .inner
            .call(
                CallClass::Round1,
                deadline,
                |s| crate::DaemonError::from_peer_status(s, key_id, leader_view),
                |mut c| async move { c.sign_round1(timed(msg, deadline)).await },
            )
            .await?;
        Ok(serde_json::from_slice(&reply.commitments)?)
    }

    async fn sign_round2(
        &self,
        key_id: &str,
        session_id: &str,
        message: &[u8],
        commitments: &BTreeMap<Identifier, SigningCommitments>,
        intent_digest: Option<&[u8; 32]>,
    ) -> Result<SignatureShare> {
        let deadline = self.inner.deadline(CallClass::Round2);
        self.sign_round2_within(key_id, session_id, message, commitments, intent_digest, deadline).await
    }

    async fn sign_round2_within(
        &self,
        key_id: &str,
        session_id: &str,
        message: &[u8],
        commitments: &BTreeMap<Identifier, SigningCommitments>,
        intent_digest: Option<&[u8; 32]>,
        deadline: Duration,
    ) -> Result<SignatureShare> {
        let msg = pb::SignRound2Request {
            key_id: key_id.into(),
            session_id: session_id.into(),
            message: message.to_vec(),
            commitments_map: serde_json::to_vec(commitments)?,
            intent_digest: intent_digest.map(|d| d.to_vec()).unwrap_or_default(),
        };
        let reply = self
            .inner
            .call(
                CallClass::Round2,
                deadline,
                |s| crate::DaemonError::from_peer_status(s, key_id, None),
                |mut c| async move { c.sign_round2(timed(msg, deadline)).await },
            )
            .await?;
        Ok(serde_json::from_slice(&reply.share)?)
    }

    async fn abort_sign(&self, key_id: &str, session_id: &str) -> Result<()> {
        self.abort_sign_within(key_id, session_id, self.inner.deadline(CallClass::Abort)).await
    }

    async fn abort_sign_within(&self, key_id: &str, session_id: &str, deadline: Duration) -> Result<()> {
        let msg = pb::AbortSignRequest { key_id: key_id.into(), session_id: session_id.into() };
        self.inner
            .call(CallClass::Abort, deadline, crate::DaemonError::Status, |mut c| async move {
                c.abort_sign(timed(msg, deadline)).await
            })
            .await?;
        Ok(())
    }

    async fn ceremony_fence(&self, ceremony_id: &str, key_id: &str, kind: &'static str) -> Result<()> {
        let d = self.inner.deadline(CallClass::Ceremony);
        let msg = pb::CeremonyFenceRequest {
            ceremony_id: ceremony_id.into(),
            key_id: key_id.into(),
            kind: kind.into(),
            ..Default::default()
        };
        self.inner
            .call(CallClass::Ceremony, d, crate::DaemonError::Status, |mut c| async move {
                c.ceremony_fence(timed(msg, d)).await
            })
            .await?;
        Ok(())
    }

    async fn ceremony_release(&self, ceremony_id: &str, key_id: &str) -> Result<()> {
        let d = self.inner.deadline(CallClass::Ceremony);
        let msg = pb::CeremonyReleaseRequest { ceremony_id: ceremony_id.into(), key_id: key_id.into() };
        self.inner
            .call(CallClass::Ceremony, d, crate::DaemonError::Status, |mut c| async move {
                c.ceremony_release(timed(msg, d)).await
            })
            .await?;
        Ok(())
    }

    async fn node_info(&self) -> Result<(u16, [u8; 32])> {
        let d = self.inner.deadline(CallClass::Control);
        let reply = self
            .inner
            .call(CallClass::Control, d, crate::DaemonError::Status, |mut c| async move {
                c.node_info(timed(pb::NodeInfoRequest {}, d)).await
            })
            .await?;
        let pk: [u8; 32] = reply
            .dist_public_key
            .as_slice()
            .try_into()
            .map_err(|_| {
                crate::DaemonError::Config(
                    "peer sent no (or a malformed) distribution key — hosted keys off there?".into(),
                )
            })?;
        Ok((reply.identifier as u16, pk))
    }

    async fn hosted_specs(&self) -> Result<Vec<String>> {
        let d = self.inner.deadline(CallClass::Control);
        let reply = self
            .inner
            .call(CallClass::Control, d, crate::DaemonError::Status, |mut c| async move {
                c.node_info(timed(pb::NodeInfoRequest {}, d)).await
            })
            .await?;
        Ok(reply.hosted_key_specs)
    }

    async fn replicate_key(
        &self,
        ceremony_id: &str,
        key_id: &str,
        spec: &str,
        public_key_der: &[u8],
        wrapped: &crate::wrap::Wrapped,
    ) -> Result<Vec<u8>> {
        let d = self.inner.deadline(CallClass::Ceremony);
        let msg = pb::ReplicateKeyRequest {
            ceremony_id: ceremony_id.into(),
            key_id: key_id.into(),
            spec: spec.into(),
            public_key_der: public_key_der.to_vec(),
            wrapped: Some(to_pb_wrapped(wrapped)),
        };
        let reply = self
            .inner
            .call(
                CallClass::Ceremony,
                d,
                // A conflict keeps its type across the mesh (the `hosted-conflict` trailer).
                |s| crate::DaemonError::from_peer_status(s, key_id, None),
                |mut c| async move { c.replicate_key(timed(msg, d)).await },
            )
            .await?;
        Ok(reply.commitment)
    }

    async fn fetch_key(&self, key_id: &str) -> Result<(String, Vec<u8>, crate::wrap::Wrapped)> {
        let d = self.inner.deadline(CallClass::Ceremony);
        let msg = pb::FetchKeyRequest { key_id: key_id.into(), include_tombstone: false };
        let reply = self
            .inner
            .call(CallClass::Ceremony, d, crate::DaemonError::Status, |mut c| async move {
                c.fetch_key(timed(msg, d)).await
            })
            .await?;
        let wrapped = from_pb_wrapped(reply.wrapped)?;
        Ok((reply.spec, reply.public_key_der, wrapped))
    }

    async fn fetch_key_state(&self, key_id: &str) -> Result<FetchedCopy> {
        let d = self.inner.deadline(CallClass::Ceremony);
        let msg = pb::FetchKeyRequest { key_id: key_id.into(), include_tombstone: true };
        let reply = self
            .inner
            .call(CallClass::Ceremony, d, crate::DaemonError::Status, |mut c| async move {
                c.fetch_key(timed(msg, d)).await
            })
            .await?;
        if let Some(t) = reply.tombstone.filter(|t| t.tombstone) {
            return Ok(FetchedCopy::Tombstone(Box::new(t)));
        }
        Ok(FetchedCopy::Key { spec: reply.spec, wrapped: from_pb_wrapped(reply.wrapped)? })
    }

    async fn list_keys(&self) -> Result<Vec<(String, String, Vec<u8>)>> {
        Ok(self
            .list_inventory()
            .await?
            .into_iter()
            .filter(|k| !k.tombstone)
            .map(|k| (k.key_id, k.spec, k.commitment))
            .collect())
    }

    async fn list_inventory(&self) -> Result<Vec<pb::KeyManifest>> {
        let d = self.inner.deadline(CallClass::Ceremony);
        let reply = self
            .inner
            .call(CallClass::Ceremony, d, crate::DaemonError::Status, |mut c| async move {
                c.list_keys(timed(pb::ListKeysRequest {}, d)).await
            })
            .await?;
        Ok(reply.keys)
    }

    async fn purge_key(&self, ceremony_id: &str, key_id: &str) -> Result<bool> {
        let d = self.inner.deadline(CallClass::Ceremony);
        let msg = pb::PurgeKeyRequest { ceremony_id: ceremony_id.into(), key_id: key_id.into(), intent: None };
        let reply = self
            .inner
            .call(CallClass::Ceremony, d, crate::DaemonError::Status, |mut c| async move {
                c.purge_key(timed(msg, d)).await
            })
            .await?;
        Ok(reply.deleted)
    }

    async fn delete_key(&self, ceremony_id: &str, key_id: &str, intent: &pb::SignedIntent) -> Result<bool> {
        let d = self.inner.deadline(CallClass::Ceremony);
        let msg = pb::PurgeKeyRequest {
            ceremony_id: ceremony_id.into(),
            key_id: key_id.into(),
            intent: Some(intent.clone()),
        };
        let reply = self
            .inner
            .call(CallClass::Ceremony, d, crate::DaemonError::Status, |mut c| async move {
                c.purge_key(timed(msg, d)).await
            })
            .await?;
        Ok(reply.deleted)
    }

    async fn key_epoch(&self, key_id: &str) -> Result<pb::KeyEpochReply> {
        let d = self.inner.deadline(CallClass::StoreRead);
        let msg = pb::KeyEpochRequest { key_id: key_id.into() };
        self.inner
            .call(CallClass::StoreRead, d, crate::DaemonError::Status, |mut c| async move {
                c.key_epoch(timed(msg, d)).await
            })
            .await
    }

    async fn ceremony_begin(
        &self,
        ceremony_id: &str,
        key_id: &str,
        kind: CeremonyKind,
        expect: Option<(u64, [u8; 32])>,
        intent: Option<&pb::SignedIntent>,
    ) -> Result<()> {
        let d = self.inner.deadline(CallClass::Ceremony);
        let msg = pb::CeremonyFenceRequest {
            ceremony_id: ceremony_id.into(),
            key_id: key_id.into(),
            kind: kind.as_str().into(),
            expected_epoch: expect.map(|e| e.0).unwrap_or(0),
            expected_pkp_digest: expect.map(|e| e.1.to_vec()).unwrap_or_default(),
            protocol: crate::ceremony::CEREMONY_PROTOCOL,
            intent: intent.cloned(),
        };
        self.inner
            .call(CallClass::Ceremony, d, crate::error::from_fence_status, |mut c| async move {
                c.ceremony_fence(timed(msg, d)).await
            })
            .await?;
        Ok(())
    }

    async fn ceremony_commit(&self, ceremony_id: &str) -> Result<StatusInfo> {
        let d = self.inner.deadline(CallClass::Ceremony);
        let msg = pb::CeremonyCommitRequest { ceremony_id: ceremony_id.into() };
        let reply = self
            .inner
            .call(CallClass::Ceremony, d, crate::DaemonError::Status, |mut c| async move {
                c.ceremony_commit(timed(msg, d)).await
            })
            .await?;
        status_from_pb(&reply)
    }

    async fn ceremony_status(&self, ceremony_id: &str) -> Result<StatusInfo> {
        let d = self.inner.deadline(CallClass::StoreRead);
        let msg = pb::CeremonyStatusRequest { ceremony_id: ceremony_id.into() };
        let reply = self
            .inner
            .call(CallClass::StoreRead, d, crate::DaemonError::Status, |mut c| async move {
                c.ceremony_status(timed(msg, d)).await
            })
            .await?;
        status_from_pb(&reply)
    }

    async fn ceremony_abort(&self, ceremony_id: &str) -> Result<StatusInfo> {
        let d = self.inner.deadline(CallClass::Ceremony);
        let msg = pb::CeremonyAbortRequest { ceremony_id: ceremony_id.into() };
        let reply = self
            .inner
            .call(CallClass::Ceremony, d, crate::DaemonError::Status, |mut c| async move {
                c.ceremony_abort(timed(msg, d)).await
            })
            .await?;
        status_from_pb(&reply)
    }

    async fn ceremony_protocol(&self) -> Result<u32> {
        let d = self.inner.deadline(CallClass::Control);
        let reply = self
            .inner
            .call(CallClass::Control, d, crate::DaemonError::Status, |mut c| async move {
                c.node_info(timed(pb::NodeInfoRequest {}, d)).await
            })
            .await?;
        Ok(reply.ceremony_protocol)
    }

    async fn ceremony_part1(
        &self,
        ceremony_id: &str,
        key_id: &str,
        kind: CeremonyKind,
        roster: &[u16],
        intent: Option<&pb::SignedIntent>,
    ) -> Result<round1::Package> {
        let d = self.inner.deadline(CallClass::Ceremony);
        let msg = pb::CeremonyPart1Request {
            ceremony_id: ceremony_id.into(),
            key_id: key_id.into(),
            kind: kind.as_str().into(),
            roster: roster.iter().map(|&i| u32::from(i)).collect(),
            protocol: crate::ceremony::CEREMONY_PROTOCOL,
            intent: intent.cloned(),
        };
        let reply = self
            .inner
            .call(CallClass::Ceremony, d, crate::DaemonError::Status, |mut c| async move {
                c.ceremony_part1(timed(msg, d)).await
            })
            .await?;
        Ok(serde_json::from_slice(&reply.round1_package)?)
    }

    async fn ceremony_part2(
        &self,
        ceremony_id: &str,
        round1_map: &BTreeMap<Identifier, round1::Package>,
    ) -> Result<crate::ceremony::Part2Outcome> {
        let d = self.inner.deadline(CallClass::Ceremony);
        let msg = pb::CeremonyPart2Request { ceremony_id: ceremony_id.into(), round1_map: serde_json::to_vec(round1_map)? };
        let reply = self
            .inner
            .call(CallClass::Ceremony, d, crate::DaemonError::Status, |mut c| async move {
                c.ceremony_part2(timed(msg, d)).await
            })
            .await?;
        Ok(crate::ceremony::Part2Outcome {
            round1_digest: to_digest(&reply.round1_digest)?,
            delivered: reply
                .delivered_to
                .iter()
                .map(|&i| u16::try_from(i).map_err(|_| crate::DaemonError::Disagreement("bad identifier".into())))
                .collect::<Result<_>>()?,
        })
    }

    async fn ceremony_deliver(
        &self,
        ceremony_id: &str,
        from: u16,
        to: u16,
        round1_digest: &[u8; 32],
        package: &round2::Package,
    ) -> Result<()> {
        // The package rides inside this TLS session only: dialled under the recipient's own
        // server name, so only that node can read it.
        let bytes = zeroize::Zeroizing::new(serde_json::to_vec(package)?);
        let d = self.inner.deadline(CallClass::Ceremony);
        let msg = pb::CeremonyDeliverRequest {
            ceremony_id: ceremony_id.into(),
            from: u32::from(from),
            to: u32::from(to),
            round1_digest: round1_digest.to_vec(),
            round2_package: bytes.to_vec(),
        };
        self.inner
            .call(CallClass::Ceremony, d, crate::DaemonError::Status, |mut c| async move {
                c.ceremony_deliver(timed(msg, d)).await
            })
            .await?;
        Ok(())
    }

    async fn ceremony_part3(&self, ceremony_id: &str, round1_digest: &[u8; 32]) -> Result<StagedOutcome> {
        let d = self.inner.deadline(CallClass::Ceremony);
        let msg = pb::CeremonyPart3Request { ceremony_id: ceremony_id.into(), round1_digest: round1_digest.to_vec() };
        let reply = self
            .inner
            .call(CallClass::Ceremony, d, crate::DaemonError::Status, |mut c| async move {
                c.ceremony_part3(timed(msg, d)).await
            })
            .await?;
        Ok(StagedOutcome {
            new_epoch: reply.new_epoch,
            new_pkp_digest: to_digest(&reply.new_pkp_digest)?,
            group_key: to_group_key(reply.group_verifying_key)?,
        })
    }
}

fn to_digest(bytes: &[u8]) -> Result<[u8; 32]> {
    bytes.try_into().map_err(|_| crate::DaemonError::Disagreement("digest not 32 bytes".into()))
}

/// [`StatusInfo`] on the wire.
pub fn status_to_pb(info: &StatusInfo) -> pb::CeremonyStatusReply {
    let state = match info.phase {
        Phase::InProgress => pb::CeremonyState::InProgress,
        Phase::Staged => pb::CeremonyState::Staged,
        Phase::Committed => pb::CeremonyState::Committed,
        Phase::Aborted => pb::CeremonyState::Aborted,
    };
    let mut reply = pb::CeremonyStatusReply { state: state as i32, ..Default::default() };
    if let Some(o) = &info.outcome {
        reply.key_id = o.key_id.clone();
        reply.kind = o.kind.clone();
        reply.new_epoch = o.new_epoch;
        reply.new_pkp_digest = hex::decode(&o.new_pkp_digest).unwrap_or_default();
        reply.round1_digest = hex::decode(&o.round1_digest).unwrap_or_default();
    }
    reply
}

/// A peer's `CeremonyStatusReply`. An unknown or unspecified state is an error (never read as a
/// vote either way).
pub fn status_from_pb(reply: &pb::CeremonyStatusReply) -> Result<StatusInfo> {
    let phase = match pb::CeremonyState::try_from(reply.state) {
        Ok(pb::CeremonyState::InProgress) => Phase::InProgress,
        Ok(pb::CeremonyState::Staged) => Phase::Staged,
        Ok(pb::CeremonyState::Committed) => Phase::Committed,
        Ok(pb::CeremonyState::Aborted) => Phase::Aborted,
        _ => {
            return Err(crate::DaemonError::Disagreement(format!(
                "peer reported an unknown ceremony state {}",
                reply.state
            )))
        }
    };
    let outcome = matches!(phase, Phase::Staged | Phase::Committed).then(|| Outcome {
        key_id: reply.key_id.clone(),
        kind: reply.kind.clone(),
        new_epoch: reply.new_epoch,
        new_pkp_digest: hex::encode(&reply.new_pkp_digest),
        round1_digest: hex::encode(&reply.round1_digest),
    });
    Ok(StatusInfo { phase, outcome })
}

pub fn to_pb_wrapped(w: &crate::wrap::Wrapped) -> pb::WrappedKey {
    pb::WrappedKey {
        recipient: w.recipient as u32,
        encapsulated_key: w.encapsulated_key.clone(),
        ciphertext: w.ciphertext.clone(),
        wrap_version: w.version,
    }
}

pub fn from_pb_wrapped(w: Option<pb::WrappedKey>) -> Result<crate::wrap::Wrapped> {
    let w = w.ok_or_else(|| crate::DaemonError::Config("missing wrapped key envelope".into()))?;
    Ok(crate::wrap::Wrapped {
        recipient: w.recipient as u16,
        encapsulated_key: w.encapsulated_key,
        ciphertext: w.ciphertext,
        version: w.wrap_version,
    })
}

fn to_group_key(bytes: Vec<u8>) -> Result<[u8; 32]> {
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| crate::DaemonError::Disagreement("group key not 32 bytes".into()))
}
