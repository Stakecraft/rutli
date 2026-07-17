// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! tonic service implementations: the client-facing [`Signer`] and the mesh-internal [`Peer`].
//! Both are thin — they (de)serialize the wire bytes and delegate to [`Node`] / [`orchestrator`].

use std::collections::{BTreeMap, HashSet};
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
    /// When set, only these client-cert CNs may call the sensitive Signer RPCs. `None` = open
    /// (mTLS still enforced by the transport). See `Config::signer_allowlist`.
    pub allowed_cns: Option<Arc<HashSet<String>>>,
}

impl SignerSvc {
    /// Enforce the client-cert allowlist (if configured) for a sensitive Signer call.
    fn authorize<T>(&self, req: &Request<T>) -> Result<(), Status> {
        let Some(allowed) = &self.allowed_cns else { return Ok(()) };
        let certs = req
            .peer_certs()
            .ok_or_else(|| Status::unauthenticated("client certificate required for the Signer API"))?;
        let cn = certs
            .first()
            .and_then(|leaf| cn_of(leaf.as_ref()))
            .ok_or_else(|| Status::unauthenticated("client certificate has no usable Common Name"))?;
        if allowed.contains(&cn) {
            Ok(())
        } else {
            Err(Status::permission_denied(format!(
                "client '{cn}' is not permitted to call the Signer API"
            )))
        }
    }
}

fn record_ceremony(kind: &'static str, ok: bool) {
    let result = if ok { "ok" } else { "error" };
    metrics::counter!(crate::metrics::CEREMONY_REQUESTS, "kind" => kind, "result" => result)
        .increment(1);
}

/// Extract the subject Common Name from a DER-encoded X.509 certificate.
pub fn cn_of(der: &[u8]) -> Option<String> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
    let cn = cert.subject().iter_common_name().next()?.as_str().ok()?.to_string();
    Some(cn)
}

#[tonic::async_trait]
impl Signer for SignerSvc {
    // Health is intentionally NOT allowlisted — it leaks nothing and is useful for liveness.
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
        self.authorize(&req)?;
        let key = self.node.group_key(&req.into_inner().key_id).map_err(Status::from)?;
        Ok(Response::new(pb::GroupKeyReply { group_verifying_key: key.to_vec() }))
    }

    async fn dkg(&self, req: Request<pb::DkgRequest>) -> Result<Response<pb::DkgReply>, Status> {
        self.authorize(&req)?;
        let key_id = req.into_inner().key_id;
        let result = orchestrator::run_dkg(&self.peers, &key_id).await;
        record_ceremony("dkg", result.is_ok());
        let key = result.map_err(Status::from)?;
        Ok(Response::new(pb::DkgReply { group_verifying_key: key.to_vec() }))
    }

    async fn sign(&self, req: Request<pb::SignRequest>) -> Result<Response<pb::SignReply>, Status> {
        self.authorize(&req)?;
        let r = req.into_inner();
        let started = std::time::Instant::now();
        let result = orchestrator::sign(&self.node, &self.peers, &r.key_id, &r.message).await;
        let outcome = if result.is_ok() { "ok" } else { "error" };
        metrics::counter!(crate::metrics::SIGN_REQUESTS, "result" => outcome).increment(1);
        metrics::histogram!(crate::metrics::SIGN_DURATION, "result" => outcome)
            .record(started.elapsed().as_secs_f64());
        let sig = result.map_err(Status::from)?;
        Ok(Response::new(pb::SignReply { signature: sig.to_vec() }))
    }

    async fn refresh(
        &self,
        req: Request<pb::RefreshRequest>,
    ) -> Result<Response<pb::RefreshReply>, Status> {
        self.authorize(&req)?;
        let key_id = req.into_inner().key_id;
        let result = orchestrator::run_refresh(&self.peers, &key_id).await;
        record_ceremony("refresh", result.is_ok());
        let key = result.map_err(Status::from)?;
        Ok(Response::new(pb::RefreshReply { group_verifying_key: key.to_vec() }))
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

    async fn abort_sign(
        &self,
        req: Request<pb::AbortSignRequest>,
    ) -> Result<Response<pb::AbortSignReply>, Status> {
        let r = req.into_inner();
        self.node.abort_sign(&r.key_id, &r.session_id);
        Ok(Response::new(pb::AbortSignReply {}))
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

    async fn refresh_part1(
        &self,
        req: Request<pb::RefreshPart1Request>,
    ) -> Result<Response<pb::DkgPart1Reply>, Status> {
        let r = req.into_inner();
        let package = self.node.refresh_part1(&r.refresh_id, &r.key_id).map_err(Status::from)?;
        Ok(Response::new(pb::DkgPart1Reply { round1_package: json(&package)? }))
    }

    async fn refresh_part2(
        &self,
        req: Request<pb::DkgPart2Request>,
    ) -> Result<Response<pb::DkgPart2Reply>, Status> {
        let r = req.into_inner();
        let round1_map = de(&r.round1_map)?;
        let round2_map = self.node.refresh_part2(&r.dkg_id, &round1_map).map_err(Status::from)?;
        Ok(Response::new(pb::DkgPart2Reply { round2_map: json(&round2_map)? }))
    }

    async fn refresh_part3(
        &self,
        req: Request<pb::DkgPart3Request>,
    ) -> Result<Response<pb::DkgPart3Reply>, Status> {
        let r = req.into_inner();
        let round1_map = de(&r.round1_map)?;
        let round2_for_me = de(&r.round2_map_for_me)?;
        let key =
            self.node.refresh_part3(&r.dkg_id, &round1_map, &round2_for_me).map_err(Status::from)?;
        Ok(Response::new(pb::DkgPart3Reply { group_verifying_key: key.to_vec() }))
    }
}

fn json<T: serde::Serialize>(v: &T) -> Result<Vec<u8>, Status> {
    serde_json::to_vec(v).map_err(|e| Status::internal(format!("serialize: {e}")))
}

fn de<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, Status> {
    serde_json::from_slice(bytes).map_err(|e| Status::invalid_argument(format!("deserialize: {e}")))
}
#[cfg(test)]
mod tests {
    use super::cn_of;

    #[test]
    fn cn_of_extracts_common_name() {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["rutli-cosigner".to_string()]).unwrap();
        params.distinguished_name.push(rcgen::DnType::CommonName, "driver");
        let cert = params.self_signed(&key).unwrap();
        assert_eq!(cn_of(cert.der()).as_deref(), Some("driver"));
    }

    #[test]
    fn cn_of_rejects_garbage() {
        assert_eq!(cn_of(b"not a certificate"), None);
    }
}
