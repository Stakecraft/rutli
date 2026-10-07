// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! tonic service implementations: the client-facing [`Signer`] and the mesh-internal [`Peer`].
//! Both are thin — they (de)serialize the wire bytes and delegate to [`Node`] / [`orchestrator`].
//!
//! Every [`Node`] call that may touch the key store goes through [`Node::blocking`]: on a stalled
//! volume a filesystem call parks its thread, and a handler parked on an async worker would freeze
//! every other RPC, Health and `/metrics` with it (with the shipped 500m CPU limit the runtime has
//! a single worker). Calls that only touch memory or do a little crypto stay inline.

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
    /// How many cosigners must hold a new hosted key before it is reported created, from
    /// `hosted_keys.write_quorum`. Carried here rather than read from a constant so the configured
    /// value is actually honoured.
    pub hosted_write_quorum: usize,
    /// Per-key ceiling on decryptions. The bound on a stolen driver certificate — see
    /// [`crate::ratelimit`].
    pub decrypt_limiter: Arc<crate::ratelimit::DecryptRateLimiter>,
}

impl SignerSvc {
    /// Enforce the client-cert allowlist (if configured) for a sensitive Signer call.
    fn authorize<T>(&self, req: &Request<T>) -> Result<(), Status> {
        authorize_cn(self.allowed_cns.as_deref(), req, "Signer").map(|_| ())
    }

    /// UNAVAILABLE while this node's key store fails its readiness probe — at the entry of every
    /// Signer RPC that touches the store, so a sick node answers uniformly with the code every
    /// driver version fails over on. Never NOT_FOUND (Canton would believe the key is gone) and
    /// never an INTERNAL from deep inside the operation. Not applied to Health or Capabilities.
    fn refuse_if_keystore_down(&self) -> Result<(), Status> {
        self.node.refuse_if_keystore_down().map_err(Status::from)
    }
}

/// Check the caller's mTLS client-cert Common Name against `allowed` (None = open, dev only).
///
/// This is the ONLY thing separating the two APIs: every cosigner cert and the driver cert are
/// signed by the same cluster CA, so transport mTLS proves cluster membership, not role.
fn authorize_cn<T>(
    allowed: Option<&HashSet<String>>,
    req: &Request<T>,
    api: &str,
) -> Result<Option<String>, Status> {
    let Some(allowed) = allowed else { return Ok(None) };
    let certs = req
        .peer_certs()
        .ok_or_else(|| Status::unauthenticated(format!("client certificate required for the {api} API")))?;
    let cn = certs
        .first()
        .and_then(|leaf| cn_of(leaf.as_ref()))
        .ok_or_else(|| Status::unauthenticated("client certificate has no usable Common Name"))?;
    if allowed.contains(&cn) {
        Ok(Some(cn))
    } else {
        Err(Status::permission_denied(format!(
            "client '{cn}' is not permitted to call the {api} API"
        )))
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
    // Health is intentionally NOT allowlisted — it reveals nothing beyond the key-store path and an
    // OS error, and readiness checks need it.
    //
    // It answers ok=false ("NOT_SERVING: …") when this node's key store fails its readiness probe:
    // such a node fails every Sign/Dkg it leads, and a Health that kept saying ok is what let the
    // driver keep choosing one as leader (2026-10-07 incident). The gRPC status stays OK either way
    // — the reply carries the verdict, and the driver reads `ok` (an RPC error also counts as down).
    async fn health(
        &self,
        _req: Request<pb::HealthRequest>,
    ) -> Result<Response<pb::HealthReply>, Status> {
        // Cached for a few seconds and single-flight (crate::health::probe), so a Health flood
        // cannot turn into a probe flood on slow storage.
        let reply = match crate::health::probe(self.node.keystore_health()).await {
            Ok(()) => pb::HealthReply { ok: true, detail: "serving".into() },
            Err(detail) => pb::HealthReply { ok: false, detail: format!("NOT_SERVING: {detail}") },
        };
        Ok(Response::new(reply))
    }

    async fn group_key(
        &self,
        req: Request<pb::GroupKeyRequest>,
    ) -> Result<Response<pb::GroupKeyReply>, Status> {
        self.authorize(&req)?;
        self.refuse_if_keystore_down()?;
        let key_id = req.into_inner().key_id;
        let key = self.node.blocking(move |n| n.group_key(&key_id)).await.map_err(Status::from)?;
        Ok(Response::new(pb::GroupKeyReply { group_verifying_key: key.to_vec() }))
    }

    async fn dkg(&self, req: Request<pb::DkgRequest>) -> Result<Response<pb::DkgReply>, Status> {
        self.authorize(&req)?;
        let key_id = req.into_inner().key_id;
        // A node whose key store failed its readiness probe declines to lead (UNAVAILABLE, so the
        // driver picks another leader) rather than start a ceremony it cannot persist.
        let result = match self.node.refuse_if_keystore_down() {
            Ok(()) => orchestrator::run_dkg(&self.peers, &key_id).await,
            Err(e) => Err(e),
        };
        record_ceremony("dkg", result.is_ok());
        let key = result.map_err(Status::from)?;
        Ok(Response::new(pb::DkgReply { group_verifying_key: key.to_vec() }))
    }

    async fn sign(&self, req: Request<pb::SignRequest>) -> Result<Response<pb::SignReply>, Status> {
        self.authorize(&req)?;
        let r = req.into_inner();
        let started = std::time::Instant::now();
        // Decline to lead while the key store fails its readiness probe: UNAVAILABLE, which every
        // driver version fails over on, instead of an INTERNAL from deep inside the session. Counted
        // as a sign error below so the sick node's own metrics show it.
        let result = match self.node.refuse_if_keystore_down() {
            Ok(()) => orchestrator::sign(&self.node, &self.peers, &r.key_id, &r.message).await,
            Err(e) => Err(e),
        };
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
        let result = match self.node.refuse_if_keystore_down() {
            Ok(()) => orchestrator::run_refresh(&self.peers, &key_id).await,
            Err(e) => Err(e),
        };
        record_ceremony("refresh", result.is_ok());
        let key = result.map_err(Status::from)?;
        Ok(Response::new(pb::RefreshReply { group_verifying_key: key.to_vec() }))
    }

    // -- cluster-hosted (non-FROST) keys --

    async fn capabilities(
        &self,
        _req: Request<pb::CapabilitiesRequest>,
    ) -> Result<Response<pb::CapabilitiesReply>, Status> {
        // Deliberately not allowlisted: it reveals only which algorithms the cluster supports, and
        // the driver needs it before it can do anything else.
        let enabled = self.node.hosted_enabled();
        let specs = if enabled {
            vec![
                crate::hosted::HostedSpec::Rsa2048.as_str().to_string(),
                crate::hosted::HostedSpec::Aes256Gcm.as_str().to_string(),
            ]
        } else {
            Vec::new()
        };
        Ok(Response::new(pb::CapabilitiesReply {
            hosted_key_specs: specs,
            hosted_keys_enabled: enabled,
        }))
    }

    async fn generate_key(
        &self,
        req: Request<pb::GenerateKeyRequest>,
    ) -> Result<Response<pb::GenerateKeyReply>, Status> {
        self.authorize(&req)?;
        let r = req.into_inner();
        let spec = crate::hosted::HostedSpec::parse(&r.spec).map_err(Status::from)?;
        let result = match self.node.refuse_if_keystore_down() {
            Ok(()) => {
                orchestrator::generate_hosted_key(
                    &self.node,
                    &self.peers,
                    &r.key_id,
                    spec,
                    self.hosted_write_quorum,
                )
                .await
            }
            Err(e) => Err(e),
        };
        record_hosted_op("generate", result.is_ok());
        let (key, created, replicas) = result.map_err(Status::from)?;
        let public_key_der = if spec.is_asymmetric() {
            key.public_key_der().map_err(Status::from)?
        } else {
            Vec::new()
        };
        Ok(Response::new(pb::GenerateKeyReply {
            key_id: r.key_id,
            spec: r.spec,
            public_key_der,
            created,
            replicas: replicas as u32,
        }))
    }

    async fn public_key(
        &self,
        req: Request<pb::PublicKeyRequest>,
    ) -> Result<Response<pb::PublicKeyReply>, Status> {
        self.authorize(&req)?;
        self.refuse_if_keystore_down()?;
        let key_id = req.into_inner().key_id;
        let key = self.load_hosted_repairing(&key_id).await?;
        Ok(Response::new(pb::PublicKeyReply {
            spec: key.spec.as_str().to_string(),
            public_key_der: key.public_key_der().map_err(Status::from)?,
        }))
    }

    async fn key_info(
        &self,
        req: Request<pb::KeyInfoRequest>,
    ) -> Result<Response<pb::KeyInfoReply>, Status> {
        self.authorize(&req)?;
        // Above all here: a sick node must not answer `exists: false` for a key it simply cannot read.
        self.refuse_if_keystore_down()?;
        let key_id = req.into_inner().key_id;
        match self.load_hosted_repairing(&key_id).await {
            Ok(key) => {
                let replicas = orchestrator::hosted_replica_count(&self.peers, &key_id).await;
                Ok(Response::new(pb::KeyInfoReply {
                    exists: true,
                    spec: key.spec.as_str().to_string(),
                    created_at: key.created_at,
                    replicas: replicas as u32,
                }))
            }
            Err(e) if e.code() == tonic::Code::NotFound => {
                Ok(Response::new(pb::KeyInfoReply::default()))
            }
            Err(e) => Err(e),
        }
    }

    async fn delete_key(
        &self,
        req: Request<pb::DeleteKeyRequest>,
    ) -> Result<Response<pb::DeleteKeyReply>, Status> {
        self.authorize(&req)?;
        let key_id = req.into_inner().key_id;
        let result = match self.node.refuse_if_keystore_down() {
            Ok(()) => orchestrator::delete_hosted_key(&self.peers, &key_id).await,
            Err(e) => Err(e),
        };
        record_hosted_op("delete", result.is_ok());
        Ok(Response::new(pb::DeleteKeyReply { deleted: result.map_err(Status::from)? }))
    }

    async fn decrypt(
        &self,
        req: Request<pb::DecryptRequest>,
    ) -> Result<Response<pb::DecryptReply>, Status> {
        self.authorize(&req)?;
        // Before charging the budget: a refused call does no work, so it must not spend any.
        self.refuse_if_keystore_down()?;
        let r = req.into_inner();
        // Charge the budget BEFORE any work, including the read-repair fetch: an attacker must not
        // be able to drive cluster traffic at line rate just because the key is not local yet.
        self.charge_decrypt(&r.key_id)?;
        self.load_hosted_repairing(&r.key_id).await?;
        let result = self.node.blocking(move |n| n.hosted_decrypt(&r.key_id, &r.ciphertext)).await;
        record_hosted_op("decrypt", result.is_ok());
        Ok(Response::new(pb::DecryptReply { plaintext: result.map_err(Status::from)? }))
    }

    async fn symmetric_encrypt(
        &self,
        req: Request<pb::SymmetricRequest>,
    ) -> Result<Response<pb::SymmetricReply>, Status> {
        self.authorize(&req)?;
        self.refuse_if_keystore_down()?;
        let r = req.into_inner();
        self.load_hosted_repairing(&r.key_id).await?;
        let result = self.node.blocking(move |n| n.hosted_encrypt_symmetric(&r.key_id, &r.data)).await;
        record_hosted_op("symmetric_encrypt", result.is_ok());
        Ok(Response::new(pb::SymmetricReply { data: result.map_err(Status::from)? }))
    }

    async fn symmetric_decrypt(
        &self,
        req: Request<pb::SymmetricRequest>,
    ) -> Result<Response<pb::SymmetricReply>, Status> {
        self.authorize(&req)?;
        self.refuse_if_keystore_down()?;
        let r = req.into_inner();
        self.charge_decrypt(&r.key_id)?;
        self.load_hosted_repairing(&r.key_id).await?;
        let result = self.node.blocking(move |n| n.hosted_decrypt_symmetric(&r.key_id, &r.data)).await;
        record_hosted_op("symmetric_decrypt", result.is_ok());
        Ok(Response::new(pb::SymmetricReply { data: result.map_err(Status::from)? }))
    }
}

impl SignerSvc {
    /// Load a hosted key, pulling it from a peer first if this node is missing it (read-repair).
    ///
    /// Without this, a request that lands on a lagging replica returns NOT_FOUND — and the driver
    /// deliberately does not fail over on NOT_FOUND, because it is normally authoritative.
    /// Repairing on demand is what makes that assumption safe.
    async fn load_hosted_repairing(
        &self,
        key_id: &str,
    ) -> Result<crate::hosted::HostedKey, Status> {
        if !orchestrator::hosted_exists(&self.node, key_id).await.map_err(Status::from)? {
            orchestrator::repair_hosted_key(&self.node, &self.peers, key_id)
                .await
                .map_err(Status::from)?;
        }
        let id = key_id.to_owned();
        self.node.blocking(move |n| n.hosted_load(&id)).await.map_err(|e| match e {
            crate::DaemonError::UnknownKey(k) => Status::not_found(format!("no such key: {k}")),
            other => Status::from(other),
        })
    }
}

impl SignerSvc {
    /// Charge one decryption against `key_id`'s budget, or refuse.
    ///
    /// Applies to both decrypt paths and not to encryption: encrypting is not an exfiltration
    /// route, and throttling it would break legitimate writes for no security gain.
    fn charge_decrypt(&self, key_id: &str) -> Result<(), Status> {
        self.decrypt_limiter.check(key_id).map_err(|limited| {
            metrics::counter!(crate::metrics::DECRYPT_RATE_LIMITED).increment(1);
            Status::from(crate::DaemonError::RateLimited(limited.to_string()))
        })
    }
}

fn record_hosted_op(op: &'static str, ok: bool) {
    let result = if ok { "ok" } else { "error" };
    metrics::counter!(crate::metrics::HOSTED_KEY_OPS, "op" => op, "result" => result).increment(1);
}



pub struct PeerSvc {
    pub node: Arc<Node>,
    /// Client-cert CNs allowed on the mesh Peer API — the other cosigners. `None` = open (dev
    /// only). Required under TLS: the Peer API is the raw FROST protocol, so a caller that reaches
    /// it on `threshold` nodes can aggregate a signature over an arbitrary message, bypassing the
    /// Signer API's Canton-digest guard and the ceremony fence.
    pub allowed_cns: Option<Arc<HashSet<String>>>,
}

impl PeerSvc {
    fn authorize<T>(&self, req: &Request<T>) -> Result<Option<String>, Status> {
        authorize_cn(self.allowed_cns.as_deref(), req, "Peer")
    }

    /// The node identifier of the authenticated caller, taken from its client-cert CN
    /// (`cosigner<N>`, as issued by scripts/gen-frost-certs.sh).
    ///
    /// Read from the certificate, never from the request body: otherwise any allowlisted peer
    /// could ask for key material wrapped to a node of its choosing.
    fn authenticated_peer<T>(&self, req: &Request<T>) -> Result<u16, Status> {
        let cn = self.authorize(req)?.ok_or_else(|| {
            Status::failed_precondition(
                "hosted-key replication requires peer_allowlist (and therefore TLS) — the caller \
                 must be identified by its certificate",
            )
        })?;
        cn.trim_start_matches(|c: char| !c.is_ascii_digit())
            .parse::<u16>()
            .map_err(|_| {
                Status::permission_denied(format!(
                    "peer certificate CN '{cn}' does not name a cosigner (expected e.g. cosigner2)"
                ))
            })
    }
}

#[tonic::async_trait]
impl Peer for PeerSvc {
    async fn sign_round1(
        &self,
        req: Request<pb::SignRound1Request>,
    ) -> Result<Response<pb::SignRound1Reply>, Status> {
        self.authorize(&req)?;
        let r = req.into_inner();
        let commitments = self
            .node
            .blocking(move |n| n.sign_round1(&r.key_id, &r.session_id))
            .await
            .map_err(Status::from)?;
        Ok(Response::new(pb::SignRound1Reply {
            commitments: json(&commitments)?,
        }))
    }

    async fn sign_round2(
        &self,
        req: Request<pb::SignRound2Request>,
    ) -> Result<Response<pb::SignRound2Reply>, Status> {
        self.authorize(&req)?;
        let r = req.into_inner();
        let commitments: BTreeMap<_, _> = de(&r.commitments_map)?;
        // One blocking call, so burn-before-sign stays exactly as it is inline: round 2 creates
        // and fsyncs the nonce marker, then computes the share — and finishes even if the leader
        // stops waiting, so a burnt session is never half-done.
        let share = self
            .node
            .blocking(move |n| n.sign_round2(&r.key_id, &r.session_id, &r.message, &commitments))
            .await
            .map_err(Status::from)?;
        Ok(Response::new(pb::SignRound2Reply { share: json(&share)? }))
    }

    async fn abort_sign(
        &self,
        req: Request<pb::AbortSignRequest>,
    ) -> Result<Response<pb::AbortSignReply>, Status> {
        self.authorize(&req)?;
        let r = req.into_inner();
        self.node.abort_sign(&r.key_id, &r.session_id);
        Ok(Response::new(pb::AbortSignReply {}))
    }

    async fn ceremony_fence(
        &self,
        req: Request<pb::CeremonyFenceRequest>,
    ) -> Result<Response<pb::CeremonyFenceReply>, Status> {
        self.authorize(&req)?;
        let r = req.into_inner();
        // The guard stores a &'static str, so the wire value is mapped to a known one rather than
        // leaked through — an unknown kind is a protocol error, not something to fence on.
        let kind = match r.kind.as_str() {
            "dkg" => "dkg",
            "refresh" => "refresh",
            // Hosted-key ceremonies take the same per-key guard: generating or deleting a hosted
            // key must not interleave with a DKG/refresh for that id.
            "genkey" => "genkey",
            "delkey" => "delkey",
            other => {
                return Err(Status::invalid_argument(format!(
                    "ceremony kind must be one of \"dkg\", \"refresh\", \"genkey\", \"delkey\"; got {other:?}"
                )))
            }
        };
        self.node.ceremony_fence(&r.ceremony_id, &r.key_id, kind).map_err(Status::from)?;
        Ok(Response::new(pb::CeremonyFenceReply {}))
    }

    async fn ceremony_release(
        &self,
        req: Request<pb::CeremonyReleaseRequest>,
    ) -> Result<Response<pb::CeremonyReleaseReply>, Status> {
        self.authorize(&req)?;
        let r = req.into_inner();
        self.node.ceremony_release(&r.ceremony_id, &r.key_id);
        Ok(Response::new(pb::CeremonyReleaseReply {}))
    }

    async fn dkg_part1(
        &self,
        req: Request<pb::DkgPart1Request>,
    ) -> Result<Response<pb::DkgPart1Reply>, Status> {
        self.authorize(&req)?;
        let r = req.into_inner();
        let package = self
            .node
            .blocking(move |n| n.dkg_part1(&r.dkg_id, &r.key_id))
            .await
            .map_err(Status::from)?;
        Ok(Response::new(pb::DkgPart1Reply { round1_package: json(&package)? }))
    }

    async fn dkg_part2(
        &self,
        req: Request<pb::DkgPart2Request>,
    ) -> Result<Response<pb::DkgPart2Reply>, Status> {
        self.authorize(&req)?;
        let r = req.into_inner();
        let round1_map = de(&r.round1_map)?;
        let round2_map = self.node.dkg_part2(&r.dkg_id, &round1_map).map_err(Status::from)?;
        Ok(Response::new(pb::DkgPart2Reply { round2_map: json(&round2_map)? }))
    }

    async fn dkg_part3(
        &self,
        req: Request<pb::DkgPart3Request>,
    ) -> Result<Response<pb::DkgPart3Reply>, Status> {
        self.authorize(&req)?;
        let r = req.into_inner();
        let round1_map = de(&r.round1_map)?;
        let round2_for_me = de(&r.round2_map_for_me)?;
        let key = self
            .node
            .blocking(move |n| n.dkg_part3(&r.dkg_id, &round1_map, &round2_for_me))
            .await
            .map_err(Status::from)?;
        Ok(Response::new(pb::DkgPart3Reply { group_verifying_key: key.to_vec() }))
    }

    async fn refresh_part1(
        &self,
        req: Request<pb::RefreshPart1Request>,
    ) -> Result<Response<pb::DkgPart1Reply>, Status> {
        self.authorize(&req)?;
        let r = req.into_inner();
        let package = self
            .node
            .blocking(move |n| n.refresh_part1(&r.refresh_id, &r.key_id))
            .await
            .map_err(Status::from)?;
        Ok(Response::new(pb::DkgPart1Reply { round1_package: json(&package)? }))
    }

    async fn refresh_part2(
        &self,
        req: Request<pb::DkgPart2Request>,
    ) -> Result<Response<pb::DkgPart2Reply>, Status> {
        self.authorize(&req)?;
        let r = req.into_inner();
        let round1_map = de(&r.round1_map)?;
        let round2_map = self.node.refresh_part2(&r.dkg_id, &round1_map).map_err(Status::from)?;
        Ok(Response::new(pb::DkgPart2Reply { round2_map: json(&round2_map)? }))
    }

    async fn refresh_part3(
        &self,
        req: Request<pb::DkgPart3Request>,
    ) -> Result<Response<pb::DkgPart3Reply>, Status> {
        self.authorize(&req)?;
        let r = req.into_inner();
        let round1_map = de(&r.round1_map)?;
        let round2_for_me = de(&r.round2_map_for_me)?;
        let key = self
            .node
            .blocking(move |n| n.refresh_part3(&r.dkg_id, &round1_map, &round2_for_me))
            .await
            .map_err(Status::from)?;
        Ok(Response::new(pb::DkgPart3Reply { group_verifying_key: key.to_vec() }))
    }

    // -- hosted-key replication (mesh only; peer_allowlist gates every one of these) --
    //
    // Each refuses with UNAVAILABLE while this node's key store fails its readiness probe. The
    // callers already treat that as an unreachable replica (write quorum, best-effort purge,
    // read-repair and anti-entropy skip it), and on a hung volume it is what stops every peer's
    // anti-entropy sweep from parking another thread here on each pass.

    async fn replicate_key(
        &self,
        req: Request<pb::ReplicateKeyRequest>,
    ) -> Result<Response<pb::ReplicateKeyReply>, Status> {
        self.authorize(&req)?;
        let r = req.into_inner();
        self.node.refuse_if_keystore_down().map_err(Status::from)?;
        let spec = crate::hosted::HostedSpec::parse(&r.spec).map_err(Status::from)?;
        let wrapped = crate::peer::from_pb_wrapped(r.wrapped).map_err(Status::from)?;
        let key = self.node.hosted_unwrap(&r.key_id, spec, &wrapped).map_err(Status::from)?;
        let commitment = self
            .node
            .blocking(move |n| {
                n.hosted_store(&r.key_id, &key)?;
                n.hosted_commitment(&key)
            })
            .await
            .map_err(Status::from)?;
        Ok(Response::new(pb::ReplicateKeyReply { commitment }))
    }

    async fn fetch_key(
        &self,
        req: Request<pb::FetchKeyRequest>,
    ) -> Result<Response<pb::FetchKeyReply>, Status> {
        // Wrap to the *authenticated* caller, identified by its client certificate — never to a
        // recipient named in the request, which any allowlisted peer could forge.
        let recipient = self.authenticated_peer(&req)?;
        self.node.refuse_if_keystore_down().map_err(Status::from)?;
        let r = req.into_inner();
        let key_id = r.key_id.clone();
        let key = self.node.blocking(move |n| n.hosted_load(&key_id)).await.map_err(|e| match e {
            crate::DaemonError::UnknownKey(k) => Status::not_found(format!("no such key: {k}")),
            other => Status::from(other),
        })?;
        let recipient_pub = self.node.dist_public_key_for(recipient).map_err(Status::from)?;
        let wrapped = self
            .node
            .hosted_wrap_for(&r.key_id, &key, recipient, &recipient_pub)
            .map_err(Status::from)?;
        let public_key_der = if key.spec.is_asymmetric() {
            key.public_key_der().map_err(Status::from)?
        } else {
            Vec::new()
        };
        Ok(Response::new(pb::FetchKeyReply {
            spec: key.spec.as_str().to_string(),
            public_key_der,
            wrapped: Some(crate::peer::to_pb_wrapped(&wrapped)),
        }))
    }

    async fn list_keys(
        &self,
        req: Request<pb::ListKeysRequest>,
    ) -> Result<Response<pb::ListKeysReply>, Status> {
        self.authorize(&req)?;
        self.node.refuse_if_keystore_down().map_err(Status::from)?;
        let keys = self
            .node
            .blocking(|n| {
                let mut keys = Vec::new();
                for key_id in n.hosted_list()? {
                    let key = n.hosted_load(&key_id)?;
                    let commitment = n.hosted_commitment(&key)?;
                    keys.push(pb::KeyManifest {
                        key_id,
                        spec: key.spec.as_str().to_string(),
                        created_at: key.created_at,
                        commitment,
                    });
                }
                Ok(keys)
            })
            .await
            .map_err(Status::from)?;
        metrics::gauge!(crate::metrics::HOSTED_KEYS).set(keys.len() as f64);
        Ok(Response::new(pb::ListKeysReply { keys }))
    }

    async fn purge_key(
        &self,
        req: Request<pb::PurgeKeyRequest>,
    ) -> Result<Response<pb::PurgeKeyReply>, Status> {
        self.authorize(&req)?;
        self.node.refuse_if_keystore_down().map_err(Status::from)?;
        let r = req.into_inner();
        let deleted =
            self.node.blocking(move |n| n.hosted_delete(&r.key_id)).await.map_err(Status::from)?;
        Ok(Response::new(pb::PurgeKeyReply { deleted }))
    }

    async fn node_info(
        &self,
        req: Request<pb::NodeInfoRequest>,
    ) -> Result<Response<pb::NodeInfoReply>, Status> {
        self.authorize(&req)?;
        Ok(Response::new(pb::NodeInfoReply {
            identifier: crate::hosted::identifier_index(self.node.identifier) as u32,
            dist_public_key: self.node.dist_public_key().map_err(Status::from)?.to_vec(),
        }))
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

    #[test]
    fn an_allowlist_without_a_client_cert_fails_closed() {
        use std::collections::HashSet;
        // A configured allowlist must REFUSE a caller whose cert we cannot see, never fall through
        // to "allow". (In production the transport enforces mTLS, but the check must not depend on
        // that to be safe.)
        let allowed: HashSet<String> = ["cosigner1".to_string()].into_iter().collect();
        let req = tonic::Request::new(());
        let err = super::authorize_cn(Some(&allowed), &req, "Peer").unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated, "got {err:?}");

        // No allowlist configured = open (plaintext dev mode only).
        assert!(super::authorize_cn(None, &req, "Peer").is_ok());
    }
}
