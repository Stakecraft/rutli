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
}

fn to_group_key(bytes: Vec<u8>) -> Result<[u8; 32]> {
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| crate::DaemonError::Disagreement("group key not 32 bytes".into()))
}
