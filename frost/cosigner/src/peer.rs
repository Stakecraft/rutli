// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! The peer abstraction the orchestrator drives. A peer is either this node itself
//! ([`LocalPeer`], a direct in-process call) or a remote cosigner ([`GrpcPeer`], over gRPC). The
//! orchestrator is written against [`PeerApi`] and does not care which — which also makes it
//! testable with local peers only, no servers.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use frost_ed25519 as frost;
use frost::keys::dkg::{round1, round2};
use frost::round1::SigningCommitments;
use frost::round2::SignatureShare;
use frost::Identifier;

use crate::ceremony_record::{Outcome, Phase, StatusInfo};
use crate::node::{CeremonyKind, Node, StagedOutcome};
use crate::pb::peer_client::PeerClient;
use crate::pb;
use crate::Result;

// async_trait rewrites every method to return a `#[must_use]` boxed future while our `Result` is
// already `#[must_use]`, which trips clippy 1.99's `double_must_use` inside the macro expansion.
#[allow(clippy::double_must_use)]
#[async_trait]
pub trait PeerApi: Send + Sync {
    fn identifier(&self) -> Identifier;
    async fn sign_round1(&self, key_id: &str, session_id: &str) -> Result<SigningCommitments>;
    async fn sign_round2(
        &self,
        key_id: &str,
        session_id: &str,
        message: &[u8],
        commitments: &BTreeMap<Identifier, SigningCommitments>,
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
    /// This peer's hosted-key inventory: (key_id, spec, commitment).
    async fn list_keys(&self) -> Result<Vec<(String, String, Vec<u8>)>>;
    /// Delete a hosted key on this peer.
    async fn purge_key(&self, ceremony_id: &str, key_id: &str) -> Result<bool>;

    // -- two-phase ceremonies --

    /// This peer's committed epoch / PKP digest for `key_id` and whether a ceremony for it is
    /// staged there (`Peer.KeyEpoch`). The default — a peer that cannot say — makes every ceremony
    /// that needs the answer refuse.
    async fn key_epoch(&self, _key_id: &str) -> Result<pb::KeyEpochReply> {
        Err(crate::DaemonError::Config("this peer does not report key epochs".into()))
    }
    /// The DKG/refresh fence ([`Node::ceremony_begin`]): the per-key guard plus the two-phase
    /// rules; `expect` is the leader's view of the sharing a refresh starts from.
    async fn ceremony_begin(
        &self,
        _ceremony_id: &str,
        _key_id: &str,
        _kind: CeremonyKind,
        _expect: Option<(u64, [u8; 32])>,
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
    /// Part 1 ([`Node::ceremony_part1`]): this peer's round-1 package (public).
    async fn ceremony_part1(
        &self,
        _ceremony_id: &str,
        _key_id: &str,
        _kind: CeremonyKind,
        _roster: &[u16],
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
    async fn sign_round1(&self, key_id: &str, session_id: &str) -> Result<SigningCommitments> {
        let (key_id, session_id) = (key_id.to_owned(), session_id.to_owned());
        self.node.blocking(move |n| n.sign_round1(&key_id, &session_id)).await
    }
    async fn sign_round2(
        &self,
        key_id: &str,
        session_id: &str,
        message: &[u8],
        commitments: &BTreeMap<Identifier, SigningCommitments>,
    ) -> Result<SignatureShare> {
        let (key_id, session_id) = (key_id.to_owned(), session_id.to_owned());
        let (message, commitments) = (message.to_vec(), commitments.clone());
        self.node.blocking(move |n| n.sign_round2(&key_id, &session_id, &message, &commitments)).await
    }
    async fn abort_sign(&self, key_id: &str, session_id: &str) -> Result<()> {
        self.node.abort_sign(key_id, session_id);
        Ok(())
    }
    async fn ceremony_fence(&self, ceremony_id: &str, key_id: &str, kind: &'static str) -> Result<()> {
        self.node.ceremony_fence(ceremony_id, key_id, kind)
    }
    async fn ceremony_release(&self, ceremony_id: &str, key_id: &str) -> Result<()> {
        self.node.ceremony_release(ceremony_id, key_id);
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
        _ceremony_id: &str,
        key_id: &str,
        spec: &str,
        _public_key_der: &[u8],
        wrapped: &crate::wrap::Wrapped,
    ) -> Result<Vec<u8>> {
        let spec = crate::hosted::HostedSpec::parse(spec)?;
        let key = self.node.hosted_unwrap(key_id, spec, wrapped)?; // crypto only, no IO
        let key_id = key_id.to_owned();
        self.node
            .blocking(move |n| {
                n.hosted_store(&key_id, &key)?;
                n.hosted_commitment(&key)
            })
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

    async fn purge_key(&self, _ceremony_id: &str, key_id: &str) -> Result<bool> {
        let key_id = key_id.to_owned();
        self.node.blocking(move |n| n.hosted_delete(&key_id)).await
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
    ) -> Result<()> {
        let (ceremony_id, key_id) = (ceremony_id.to_owned(), key_id.to_owned());
        self.node.blocking(move |n| n.ceremony_begin(&ceremony_id, &key_id, kind, expect)).await
    }

    async fn ceremony_commit(&self, ceremony_id: &str) -> Result<StatusInfo> {
        crate::ceremony::resolve(&self.node, ceremony_id).await
    }

    async fn ceremony_status(&self, ceremony_id: &str) -> Result<StatusInfo> {
        let ceremony_id = ceremony_id.to_owned();
        self.node.blocking(move |n| n.ceremony_status(&ceremony_id)).await
    }

    async fn ceremony_abort(&self, ceremony_id: &str) -> Result<StatusInfo> {
        let ceremony_id = ceremony_id.to_owned();
        self.node.blocking(move |n| n.ceremony_abort(&ceremony_id)).await
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
    ) -> Result<round1::Package> {
        let (ceremony_id, key_id, roster) = (ceremony_id.to_owned(), key_id.to_owned(), roster.to_vec());
        self.node.blocking(move |n| n.ceremony_part1(&ceremony_id, &key_id, kind, &roster)).await
    }

    async fn ceremony_part2(
        &self,
        ceremony_id: &str,
        round1_map: &BTreeMap<Identifier, round1::Package>,
    ) -> Result<crate::ceremony::Part2Outcome> {
        crate::ceremony::part2_and_deliver(&self.node, ceremony_id, round1_map.clone()).await
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
        let (ceremony_id, digest) = (ceremony_id.to_owned(), *round1_digest);
        self.node.blocking(move |n| n.ceremony_part3(&ceremony_id, &digest)).await
    }
}

/// Deadline on every mesh RPC (and on establishing the connection for it).
///
/// Every peer RPC is small — a signing round, a ceremony part, a hosted-key replica or listing — so
/// anything slower is a sick peer (a hung volume, a wedged process), and waiting on it would hold
/// the leader past the driver's own deadline. A timeout surfaces as `CANCELLED: Timeout expired`:
/// in sign round 1 the peer is skipped like any failure, in a ceremony it fails the ceremony (which
/// rolls back), and a hosted-key write treats it as unreachable. It can never cause a nonce reuse:
/// the leader never re-sends a round 2 (it aborts and starts a fresh session), and a peer burns its
/// nonce marker before it computes a share, whether or not anyone is still waiting for the reply.
pub const PEER_RPC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// A remote cosigner, over gRPC. The channel connects lazily; FROST packages ride as JSON bytes.
pub struct GrpcPeer {
    identifier: Identifier,
    client: PeerClient<tonic::transport::Channel>,
}

impl GrpcPeer {
    pub fn connect_lazy(
        identifier: Identifier,
        endpoint: &str,
        tls: Option<tonic::transport::ClientTlsConfig>,
    ) -> Result<Self> {
        let mut ep = tonic::transport::Endpoint::from_shared(endpoint.to_string())
            .map_err(|e| crate::DaemonError::Config(format!("bad endpoint {endpoint}: {e}")))?
            .timeout(PEER_RPC_TIMEOUT)
            .connect_timeout(PEER_RPC_TIMEOUT);
        if let Some(t) = tls {
            ep = ep.tls_config(t)?;
        }
        Ok(Self { identifier, client: PeerClient::new(ep.connect_lazy()) })
    }
}

#[async_trait]
impl PeerApi for GrpcPeer {
    fn identifier(&self) -> Identifier {
        self.identifier
    }

    async fn sign_round1(&self, key_id: &str, session_id: &str) -> Result<SigningCommitments> {
        let reply = self
            .client
            .clone()
            .sign_round1(pb::SignRound1Request {
                key_id: key_id.into(),
                session_id: session_id.into(),
            })
            .await?
            .into_inner();
        Ok(serde_json::from_slice(&reply.commitments)?)
    }

    async fn sign_round2(
        &self,
        key_id: &str,
        session_id: &str,
        message: &[u8],
        commitments: &BTreeMap<Identifier, SigningCommitments>,
    ) -> Result<SignatureShare> {
        let reply = self
            .client
            .clone()
            .sign_round2(pb::SignRound2Request {
                key_id: key_id.into(),
                session_id: session_id.into(),
                message: message.to_vec(),
                commitments_map: serde_json::to_vec(commitments)?,
            })
            .await?
            .into_inner();
        Ok(serde_json::from_slice(&reply.share)?)
    }

    async fn abort_sign(&self, key_id: &str, session_id: &str) -> Result<()> {
        self.client
            .clone()
            .abort_sign(pb::AbortSignRequest {
                key_id: key_id.into(),
                session_id: session_id.into(),
            })
            .await?;
        Ok(())
    }

    async fn ceremony_fence(&self, ceremony_id: &str, key_id: &str, kind: &'static str) -> Result<()> {
        self.client
            .clone()
            .ceremony_fence(pb::CeremonyFenceRequest {
                ceremony_id: ceremony_id.into(),
                key_id: key_id.into(),
                kind: kind.into(),
                ..Default::default()
            })
            .await?;
        Ok(())
    }

    async fn ceremony_release(&self, ceremony_id: &str, key_id: &str) -> Result<()> {
        self.client
            .clone()
            .ceremony_release(pb::CeremonyReleaseRequest {
                ceremony_id: ceremony_id.into(),
                key_id: key_id.into(),
            })
            .await?;
        Ok(())
    }

    async fn node_info(&self) -> Result<(u16, [u8; 32])> {
        let reply = self.client.clone().node_info(pb::NodeInfoRequest {}).await?.into_inner();
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
        let reply = self.client.clone().node_info(pb::NodeInfoRequest {}).await?.into_inner();
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
        let reply = self
            .client
            .clone()
            .replicate_key(pb::ReplicateKeyRequest {
                ceremony_id: ceremony_id.into(),
                key_id: key_id.into(),
                spec: spec.into(),
                public_key_der: public_key_der.to_vec(),
                wrapped: Some(to_pb_wrapped(wrapped)),
            })
            .await?
            .into_inner();
        Ok(reply.commitment)
    }

    async fn fetch_key(&self, key_id: &str) -> Result<(String, Vec<u8>, crate::wrap::Wrapped)> {
        let reply = self
            .client
            .clone()
            .fetch_key(pb::FetchKeyRequest { key_id: key_id.into() })
            .await?
            .into_inner();
        let wrapped = from_pb_wrapped(reply.wrapped)?;
        Ok((reply.spec, reply.public_key_der, wrapped))
    }

    async fn list_keys(&self) -> Result<Vec<(String, String, Vec<u8>)>> {
        let reply = self.client.clone().list_keys(pb::ListKeysRequest {}).await?.into_inner();
        Ok(reply.keys.into_iter().map(|k| (k.key_id, k.spec, k.commitment)).collect())
    }

    async fn purge_key(&self, ceremony_id: &str, key_id: &str) -> Result<bool> {
        let reply = self
            .client
            .clone()
            .purge_key(pb::PurgeKeyRequest {
                ceremony_id: ceremony_id.into(),
                key_id: key_id.into(),
            })
            .await?
            .into_inner();
        Ok(reply.deleted)
    }

    async fn key_epoch(&self, key_id: &str) -> Result<pb::KeyEpochReply> {
        Ok(self.client.clone().key_epoch(pb::KeyEpochRequest { key_id: key_id.into() }).await?.into_inner())
    }

    async fn ceremony_begin(
        &self,
        ceremony_id: &str,
        key_id: &str,
        kind: CeremonyKind,
        expect: Option<(u64, [u8; 32])>,
    ) -> Result<()> {
        self.client
            .clone()
            .ceremony_fence(pb::CeremonyFenceRequest {
                ceremony_id: ceremony_id.into(),
                key_id: key_id.into(),
                kind: kind.as_str().into(),
                expected_epoch: expect.map(|e| e.0).unwrap_or(0),
                expected_pkp_digest: expect.map(|e| e.1.to_vec()).unwrap_or_default(),
                protocol: crate::ceremony::CEREMONY_PROTOCOL,
            })
            .await?;
        Ok(())
    }

    async fn ceremony_commit(&self, ceremony_id: &str) -> Result<StatusInfo> {
        let reply = self
            .client
            .clone()
            .ceremony_commit(pb::CeremonyCommitRequest { ceremony_id: ceremony_id.into() })
            .await?
            .into_inner();
        status_from_pb(&reply)
    }

    async fn ceremony_status(&self, ceremony_id: &str) -> Result<StatusInfo> {
        let reply = self
            .client
            .clone()
            .ceremony_status(pb::CeremonyStatusRequest { ceremony_id: ceremony_id.into() })
            .await?
            .into_inner();
        status_from_pb(&reply)
    }

    async fn ceremony_abort(&self, ceremony_id: &str) -> Result<StatusInfo> {
        let reply = self
            .client
            .clone()
            .ceremony_abort(pb::CeremonyAbortRequest { ceremony_id: ceremony_id.into() })
            .await?
            .into_inner();
        status_from_pb(&reply)
    }

    async fn ceremony_protocol(&self) -> Result<u32> {
        Ok(self.client.clone().node_info(pb::NodeInfoRequest {}).await?.into_inner().ceremony_protocol)
    }

    async fn ceremony_part1(
        &self,
        ceremony_id: &str,
        key_id: &str,
        kind: CeremonyKind,
        roster: &[u16],
    ) -> Result<round1::Package> {
        let reply = self
            .client
            .clone()
            .ceremony_part1(pb::CeremonyPart1Request {
                ceremony_id: ceremony_id.into(),
                key_id: key_id.into(),
                kind: kind.as_str().into(),
                roster: roster.iter().map(|&i| u32::from(i)).collect(),
                protocol: crate::ceremony::CEREMONY_PROTOCOL,
            })
            .await?
            .into_inner();
        Ok(serde_json::from_slice(&reply.round1_package)?)
    }

    async fn ceremony_part2(
        &self,
        ceremony_id: &str,
        round1_map: &BTreeMap<Identifier, round1::Package>,
    ) -> Result<crate::ceremony::Part2Outcome> {
        let reply = self
            .client
            .clone()
            .ceremony_part2(pb::CeremonyPart2Request {
                ceremony_id: ceremony_id.into(),
                round1_map: serde_json::to_vec(round1_map)?,
            })
            .await?
            .into_inner();
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
        self.client
            .clone()
            .ceremony_deliver(pb::CeremonyDeliverRequest {
                ceremony_id: ceremony_id.into(),
                from: u32::from(from),
                to: u32::from(to),
                round1_digest: round1_digest.to_vec(),
                round2_package: bytes.to_vec(),
            })
            .await?;
        Ok(())
    }

    async fn ceremony_part3(&self, ceremony_id: &str, round1_digest: &[u8; 32]) -> Result<StagedOutcome> {
        let reply = self
            .client
            .clone()
            .ceremony_part3(pb::CeremonyPart3Request {
                ceremony_id: ceremony_id.into(),
                round1_digest: round1_digest.to_vec(),
            })
            .await?
            .into_inner();
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
