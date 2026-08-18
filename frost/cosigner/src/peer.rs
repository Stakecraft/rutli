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

use crate::node::Node;
use crate::pb::peer_client::PeerClient;
use crate::pb;
use crate::Result;

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
    async fn dkg_part1(&self, dkg_id: &str, key_id: &str) -> Result<round1::Package>;
    async fn dkg_part2(
        &self,
        dkg_id: &str,
        round1_map: &BTreeMap<Identifier, round1::Package>,
    ) -> Result<BTreeMap<Identifier, round2::Package>>;
    async fn dkg_part3(
        &self,
        dkg_id: &str,
        round1_map: &BTreeMap<Identifier, round1::Package>,
        round2_for_me: &BTreeMap<Identifier, round2::Package>,
    ) -> Result<[u8; 32]>;

    async fn refresh_part1(&self, refresh_id: &str, key_id: &str) -> Result<round1::Package>;
    async fn refresh_part2(
        &self,
        refresh_id: &str,
        round1_map: &BTreeMap<Identifier, round1::Package>,
    ) -> Result<BTreeMap<Identifier, round2::Package>>;
    async fn refresh_part3(
        &self,
        refresh_id: &str,
        round1_map: &BTreeMap<Identifier, round1::Package>,
        round2_for_me: &BTreeMap<Identifier, round2::Package>,
    ) -> Result<[u8; 32]>;

    // -- hosted-key replication --

    /// This peer's identifier and X25519 distribution public key, so material can be wrapped to it.
    async fn node_info(&self) -> Result<(u16, [u8; 32])>;
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
}

/// This node, called in-process.
pub struct LocalPeer {
    node: Arc<Node>,
}

impl LocalPeer {
    pub fn new(node: Arc<Node>) -> Self {
        Self { node }
    }
}

#[async_trait]
impl PeerApi for LocalPeer {
    fn identifier(&self) -> Identifier {
        self.node.identifier
    }
    async fn sign_round1(&self, key_id: &str, session_id: &str) -> Result<SigningCommitments> {
        self.node.sign_round1(key_id, session_id)
    }
    async fn sign_round2(
        &self,
        key_id: &str,
        session_id: &str,
        message: &[u8],
        commitments: &BTreeMap<Identifier, SigningCommitments>,
    ) -> Result<SignatureShare> {
        self.node.sign_round2(key_id, session_id, message, commitments)
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
    async fn dkg_part1(&self, dkg_id: &str, key_id: &str) -> Result<round1::Package> {
        self.node.dkg_part1(dkg_id, key_id)
    }
    async fn dkg_part2(
        &self,
        dkg_id: &str,
        round1_map: &BTreeMap<Identifier, round1::Package>,
    ) -> Result<BTreeMap<Identifier, round2::Package>> {
        self.node.dkg_part2(dkg_id, round1_map)
    }
    async fn dkg_part3(
        &self,
        dkg_id: &str,
        round1_map: &BTreeMap<Identifier, round1::Package>,
        round2_for_me: &BTreeMap<Identifier, round2::Package>,
    ) -> Result<[u8; 32]> {
        self.node.dkg_part3(dkg_id, round1_map, round2_for_me)
    }

    async fn refresh_part1(&self, refresh_id: &str, key_id: &str) -> Result<round1::Package> {
        self.node.refresh_part1(refresh_id, key_id)
    }
    async fn refresh_part2(
        &self,
        refresh_id: &str,
        round1_map: &BTreeMap<Identifier, round1::Package>,
    ) -> Result<BTreeMap<Identifier, round2::Package>> {
        self.node.refresh_part2(refresh_id, round1_map)
    }
    async fn refresh_part3(
        &self,
        refresh_id: &str,
        round1_map: &BTreeMap<Identifier, round1::Package>,
        round2_for_me: &BTreeMap<Identifier, round2::Package>,
    ) -> Result<[u8; 32]> {
        self.node.refresh_part3(refresh_id, round1_map, round2_for_me)
    }

    async fn node_info(&self) -> Result<(u16, [u8; 32])> {
        Ok((crate::hosted::identifier_index(self.node.identifier), self.node.dist_public_key()?))
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
        let key = self.node.hosted_unwrap(key_id, spec, wrapped)?;
        self.node.hosted_store(key_id, &key)?;
        self.node.hosted_commitment(&key)
    }

    async fn fetch_key(&self, key_id: &str) -> Result<(String, Vec<u8>, crate::wrap::Wrapped)> {
        // In-process: the "recipient" is this same node, so wrap to ourselves for a uniform path.
        let key = self.node.hosted_load(key_id)?;
        let (id, pk) = (crate::hosted::identifier_index(self.node.identifier), self.node.dist_public_key()?);
        let w = self.node.hosted_wrap_for(key_id, &key, id, &pk)?;
        let pub_der = if key.spec.is_asymmetric() { key.public_key_der()? } else { Vec::new() };
        Ok((key.spec.as_str().to_string(), pub_der, w))
    }

    async fn list_keys(&self) -> Result<Vec<(String, String, Vec<u8>)>> {
        let mut out = Vec::new();
        for key_id in self.node.hosted_list()? {
            let key = self.node.hosted_load(&key_id)?;
            let commitment = self.node.hosted_commitment(&key)?;
            out.push((key_id, key.spec.as_str().to_string(), commitment));
        }
        Ok(out)
    }

    async fn purge_key(&self, _ceremony_id: &str, key_id: &str) -> Result<bool> {
        self.node.hosted_delete(key_id)
    }
}

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
            .map_err(|e| crate::DaemonError::Config(format!("bad endpoint {endpoint}: {e}")))?;
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

    async fn dkg_part1(&self, dkg_id: &str, key_id: &str) -> Result<round1::Package> {
        let reply = self
            .client
            .clone()
            .dkg_part1(pb::DkgPart1Request {
                dkg_id: dkg_id.into(),
                key_id: key_id.into(),
                identifier: 0, // the peer uses its own configured identifier
                max_signers: 0,
                min_signers: 0,
            })
            .await?
            .into_inner();
        Ok(serde_json::from_slice(&reply.round1_package)?)
    }

    async fn dkg_part2(
        &self,
        dkg_id: &str,
        round1_map: &BTreeMap<Identifier, round1::Package>,
    ) -> Result<BTreeMap<Identifier, round2::Package>> {
        let reply = self
            .client
            .clone()
            .dkg_part2(pb::DkgPart2Request {
                dkg_id: dkg_id.into(),
                round1_map: serde_json::to_vec(round1_map)?,
            })
            .await?
            .into_inner();
        Ok(serde_json::from_slice(&reply.round2_map)?)
    }

    async fn dkg_part3(
        &self,
        dkg_id: &str,
        round1_map: &BTreeMap<Identifier, round1::Package>,
        round2_for_me: &BTreeMap<Identifier, round2::Package>,
    ) -> Result<[u8; 32]> {
        let reply = self
            .client
            .clone()
            .dkg_part3(pb::DkgPart3Request {
                dkg_id: dkg_id.into(),
                round1_map: serde_json::to_vec(round1_map)?,
                round2_map_for_me: serde_json::to_vec(round2_for_me)?,
            })
            .await?
            .into_inner();
        to_group_key(reply.group_verifying_key)
    }

    async fn refresh_part1(&self, refresh_id: &str, key_id: &str) -> Result<round1::Package> {
        let reply = self
            .client
            .clone()
            .refresh_part1(pb::RefreshPart1Request {
                refresh_id: refresh_id.into(),
                key_id: key_id.into(),
            })
            .await?
            .into_inner();
        Ok(serde_json::from_slice(&reply.round1_package)?)
    }

    async fn refresh_part2(
        &self,
        refresh_id: &str,
        round1_map: &BTreeMap<Identifier, round1::Package>,
    ) -> Result<BTreeMap<Identifier, round2::Package>> {
        let reply = self
            .client
            .clone()
            .refresh_part2(pb::DkgPart2Request {
                dkg_id: refresh_id.into(),
                round1_map: serde_json::to_vec(round1_map)?,
            })
            .await?
            .into_inner();
        Ok(serde_json::from_slice(&reply.round2_map)?)
    }

    async fn refresh_part3(
        &self,
        refresh_id: &str,
        round1_map: &BTreeMap<Identifier, round1::Package>,
        round2_for_me: &BTreeMap<Identifier, round2::Package>,
    ) -> Result<[u8; 32]> {
        let reply = self
            .client
            .clone()
            .refresh_part3(pb::DkgPart3Request {
                dkg_id: refresh_id.into(),
                round1_map: serde_json::to_vec(round1_map)?,
                round2_map_for_me: serde_json::to_vec(round2_for_me)?,
            })
            .await?
            .into_inner();
        to_group_key(reply.group_verifying_key)
    }
    async fn node_info(&self) -> Result<(u16, [u8; 32])> {
        let reply = self.client.clone().node_info(pb::NodeInfoRequest {}).await?.into_inner();
        let pk: [u8; 32] = reply
            .dist_public_key
            .as_slice()
            .try_into()
            .map_err(|_| crate::DaemonError::Config("peer sent a malformed distribution key".into()))?;
        Ok((reply.identifier as u16, pk))
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
