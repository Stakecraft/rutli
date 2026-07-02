// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! tonic service implementations: the client-facing [`Signer`] and the mesh-internal [`Peer`].
//! Both are thin — they (de)serialize the wire bytes and delegate to [`Node`] / [`orchestrator`].

use std::collections::BTreeMap;
use std::sync::Arc;

use tonic::{Request, Response, Status};

use crate::node::Node;
use crate::orchestrator::{self, Peers};
use crate::pb;
use crate::pb::peer_server::Peer;
use crate::pb::signer_server::Signer;

pub struct SignerSvc {
    pub node: Arc<Node>,
    pub peers: Peers,
}

#[tonic::async_trait]
impl Signer for SignerSvc {
    async fn health(
        &self,
        _req: Request<pb::HealthRequest>,
    ) -> Result<Response<pb::HealthReply>, Status> {
        Ok(Response::new(pb::HealthReply { ok: true, detail: "serving".into() }))
    }

    async fn group_key(
        &self,
        req: Request<pb::GroupKeyRequest>,
    ) -> Result<Response<pb::GroupKeyReply>, Status> {
        let key = self.node.group_key(&req.into_inner().key_id).map_err(Status::from)?;
        Ok(Response::new(pb::GroupKeyReply { group_verifying_key: key.to_vec() }))
    }

    async fn dkg(&self, req: Request<pb::DkgRequest>) -> Result<Response<pb::DkgReply>, Status> {
        let key_id = req.into_inner().key_id;
        let key = orchestrator::run_dkg(&self.peers, &key_id).await.map_err(Status::from)?;
        Ok(Response::new(pb::DkgReply { group_verifying_key: key.to_vec() }))
    }

    async fn sign(&self, req: Request<pb::SignRequest>) -> Result<Response<pb::SignReply>, Status> {
        let r = req.into_inner();
        let sig = orchestrator::sign(&self.node, &self.peers, &r.key_id, &r.message)
            .await
            .map_err(Status::from)?;
        Ok(Response::new(pb::SignReply { signature: sig.to_vec() }))
    }
}

pub struct PeerSvc {
    pub node: Arc<Node>,
}

#[tonic::async_trait]
impl Peer for PeerSvc {
    async fn sign_round1(
        &self,
        req: Request<pb::SignRound1Request>,
    ) -> Result<Response<pb::SignRound1Reply>, Status> {
        let r = req.into_inner();
        let commitments = self.node.sign_round1(&r.key_id, &r.session_id).map_err(Status::from)?;
        Ok(Response::new(pb::SignRound1Reply {
            commitments: json(&commitments)?,
        }))
    }

    async fn sign_round2(
        &self,
        req: Request<pb::SignRound2Request>,
    ) -> Result<Response<pb::SignRound2Reply>, Status> {
        let r = req.into_inner();
        let commitments: BTreeMap<_, _> = de(&r.commitments_map)?;
        let share = self
            .node
            .sign_round2(&r.key_id, &r.session_id, &r.message, &commitments)
            .map_err(Status::from)?;
        Ok(Response::new(pb::SignRound2Reply { share: json(&share)? }))
    }

    async fn dkg_part1(
        &self,
        req: Request<pb::DkgPart1Request>,
    ) -> Result<Response<pb::DkgPart1Reply>, Status> {
        let r = req.into_inner();
        let package = self.node.dkg_part1(&r.dkg_id, &r.key_id).map_err(Status::from)?;
        Ok(Response::new(pb::DkgPart1Reply { round1_package: json(&package)? }))
    }

    async fn dkg_part2(
        &self,
        req: Request<pb::DkgPart2Request>,
    ) -> Result<Response<pb::DkgPart2Reply>, Status> {
        let r = req.into_inner();
        let round1_map = de(&r.round1_map)?;
        let round2_map = self.node.dkg_part2(&r.dkg_id, &round1_map).map_err(Status::from)?;
        Ok(Response::new(pb::DkgPart2Reply { round2_map: json(&round2_map)? }))
    }

    async fn dkg_part3(
        &self,
        req: Request<pb::DkgPart3Request>,
    ) -> Result<Response<pb::DkgPart3Reply>, Status> {
        let r = req.into_inner();
        let round1_map = de(&r.round1_map)?;
        let round2_for_me = de(&r.round2_map_for_me)?;
        let key = self
            .node
            .dkg_part3(&r.dkg_id, &round1_map, &round2_for_me)
            .map_err(Status::from)?;
        Ok(Response::new(pb::DkgPart3Reply { group_verifying_key: key.to_vec() }))
    }
}

fn json<T: serde::Serialize>(v: &T) -> Result<Vec<u8>, Status> {
    serde_json::to_vec(v).map_err(|e| Status::internal(format!("serialize: {e}")))
}

fn de<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, Status> {
    serde_json::from_slice(bytes).map_err(|e| Status::invalid_argument(format!("deserialize: {e}")))
}
