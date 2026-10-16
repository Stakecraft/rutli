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
    /// Client-cert CNs of the **operator** role (`Config::operator_allowlist`): permitted the
    /// read-only `KeyStatus` and `HostedKeyStatus` and the fixed-message `CeremonySignTest` only —
    /// never `Sign`, DKG, refresh or any hosted-key operation — so verifying a split ceremony or an
    /// imported key needs no credential that can sign arbitrary digests with a namespace key or
    /// decrypt. `None` = no operator role.
    pub operator_cns: Option<Arc<HashSet<String>>>,
    /// How many cosigners must hold a new hosted key before it is reported created, from
    /// `hosted_keys.write_quorum`. Carried here rather than read from a constant so the configured
    /// value is actually honoured.
    pub hosted_write_quorum: usize,
    /// Per-key ceiling on decryptions. The bound on a stolen driver certificate — see
    /// [`crate::ratelimit`].
    pub decrypt_limiter: Arc<crate::ratelimit::DecryptRateLimiter>,
    /// Per-key ceiling on `CeremonySignTest` calls led by this node
    /// (`Config::ceremony_sign_test_rate_limit_per_min`; build with [`ceremony_sign_test_limiter`]).
    /// Each call writes a durable nonce marker on every signer, so the operator role must not be
    /// able to loop it.
    pub ceremony_test_limiter: Arc<crate::ratelimit::DecryptRateLimiter>,
}

/// The `CeremonySignTest` limiter for `per_minute` (0 disables it).
pub fn ceremony_sign_test_limiter(per_minute: u32) -> crate::ratelimit::DecryptRateLimiter {
    crate::ratelimit::DecryptRateLimiter::named(
        per_minute,
        "ceremony sign test",
        "ceremony_sign_test_rate_limit_per_min",
        "someone with an operator or driver certificate looping CeremonySignTest",
    )
}

impl SignerSvc {
    /// Enforce the client-cert allowlist (if configured) for a sensitive Signer call.
    fn authorize<T>(&self, req: &Request<T>) -> Result<(), Status> {
        authorize_cn(self.allowed_cns.as_deref(), req, "Signer").map(|_| ())
    }

    /// For the operator-role RPCs (`KeyStatus`, `CeremonySignTest`): the driver role or the
    /// operator role.
    fn authorize_operator<T>(&self, req: &Request<T>) -> Result<(), Status> {
        authorize_either(self.allowed_cns.as_deref(), self.operator_cns.as_deref(), req)
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

/// Allow a caller whose CN is in `driver` or in `operator`. With no driver allowlist the API is
/// open (plaintext dev), exactly as [`authorize_cn`]; an operator allowlist alone never opens it.
fn authorize_either<T>(
    driver: Option<&HashSet<String>>,
    operator: Option<&HashSet<String>>,
    req: &Request<T>,
) -> Result<(), Status> {
    let Some(driver) = driver else { return Ok(()) };
    match authorize_cn(Some(driver), req, "Signer") {
        Ok(_) => Ok(()),
        Err(refused) => match operator {
            Some(op) => authorize_cn(Some(op), req, "Signer").map(|_| ()),
            None => Err(refused),
        },
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
    crate::tls::subject_cn(&cert)
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

    // Read-only and public values only, but allowlisted (driver or operator role): nothing outside
    // those identities needs to enumerate key provenance.
    async fn key_status(
        &self,
        req: Request<pb::KeyStatusRequest>,
    ) -> Result<Response<pb::KeyStatusReply>, Status> {
        self.authorize_operator(&req)?;
        self.refuse_if_keystore_down()?;
        let key_id = req.into_inner().key_id;
        let reply = self.node.blocking(move |n| n.key_status(&key_id)).await.map_err(Status::from)?;
        Ok(Response::new(reply))
    }

    // The operator role may call this: the message is computed here from the key's provenance, so
    // the caller chooses only WHICH cosigners sign the one fixed test digest, never what is signed.
    async fn ceremony_sign_test(
        &self,
        req: Request<pb::CeremonySignTestRequest>,
    ) -> Result<Response<pb::CeremonySignTestReply>, Status> {
        self.authorize_operator(&req)?;
        self.refuse_if_keystore_down()?;
        let r = req.into_inner();
        // Before any work: every call that gets through burns a durable nonce marker per signer.
        self.ceremony_test_limiter.check(&r.key_id).map_err(|limited| {
            metrics::counter!(crate::metrics::CEREMONY_SIGN_TEST_RATE_LIMITED).increment(1);
            Status::from(crate::DaemonError::RateLimited(limited.to_string()))
        })?;
        let signers: Vec<u16> = r
            .signers
            .iter()
            .map(|&s| u16::try_from(s).map_err(|_| Status::invalid_argument("signer id out of range")))
            .collect::<Result<_, _>>()?;
        let (message, signature) =
            orchestrator::ceremony_sign_test(&self.node, &self.peers, &r.key_id, &signers)
                .await
                .map_err(Status::from)?;
        Ok(Response::new(pb::CeremonySignTestReply {
            message: message.to_vec(),
            signature: signature.to_vec(),
        }))
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

    // Read-only, public half only, and local: no read-repair, so `verify-hosted` sees which nodes
    // really hold the key. Driver or operator role, like KeyStatus.
    async fn hosted_key_status(
        &self,
        req: Request<pb::HostedKeyStatusRequest>,
    ) -> Result<Response<pb::HostedKeyStatusReply>, Status> {
        self.authorize_operator(&req)?;
        self.refuse_if_keystore_down()?;
        let key_id = req.into_inner().key_id;
        let reply =
            self.node.blocking(move |n| n.hosted_key_status(&key_id)).await.map_err(Status::from)?;
        Ok(Response::new(reply))
    }

    // -- cluster-hosted (non-FROST) keys --

    async fn capabilities(
        &self,
        _req: Request<pb::CapabilitiesRequest>,
    ) -> Result<Response<pb::CapabilitiesReply>, Status> {
        // Deliberately not allowlisted: it reveals only which algorithms the cluster supports, and
        // the driver needs it before it can do anything else.
        let enabled = self.node.hosted_enabled();
        let specs = self.node.hosted_specs();
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

    // ECIES: the static ECDH only (docs/hosted-keys-design.md, "Where the trust boundary sits").
    // For a recorded ciphertext, Z is as good as the plaintext — so this is the same capability as
    // Decrypt and is guarded like it: driver allowlist, per-key decryption budget, metrics.
    async fn ecdh_derive(
        &self,
        req: Request<pb::EcdhDeriveRequest>,
    ) -> Result<Response<pb::EcdhDeriveReply>, Status> {
        self.authorize(&req)?;
        self.refuse_if_keystore_down()?;
        let r = req.into_inner();
        // Refused before any budget is charged or any work done: an id reserved for the split
        // ceremony is never a hosted key, and a malformed point is refused from the request alone,
        // without the key (on-curve is checked later, by aws-lc, as part of the agreement).
        crate::node::refuse_reserved_for_hosted(&r.key_id).map_err(Status::from)?;
        crate::hosted::check_uncompressed_p256_point(&r.peer_point).map_err(|e| {
            record_hosted_op("ecdh_derive", false);
            Status::from(e)
        })?;
        // Then the budget, before the read-repair fetch — as for Decrypt.
        self.charge_decrypt(&r.key_id)?;
        self.load_hosted_repairing(&r.key_id).await?;
        // Z stays in its Zeroizing array until the reply is built. The one copy that is not wiped is
        // the reply's own `Vec` (and tonic's encode buffer after it): prost owns those, and the
        // bytes must leave the process anyway. The driver side has the JVM equivalent of this limit.
        let z: zeroize::Zeroizing<[u8; crate::hosted::P256_SHARED_SECRET_LEN]> = match self
            .node
            .blocking(move |n| n.hosted_ecdh(&r.key_id, &r.peer_point))
            .await
        {
            Ok(z) => {
                record_hosted_op("ecdh_derive", true);
                z
            }
            Err(e) => {
                record_hosted_op("ecdh_derive", false);
                return Err(Status::from(e));
            }
        };
        Ok(Response::new(pb::EcdhDeriveReply { shared_secret: z.to_vec() }))
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
    /// Applies to every decrypt path (RSA `Decrypt`, `SymmetricDecrypt`, ECIES `EcdhDerive`) and
    /// not to encryption: encrypting is not an exfiltration route, and throttling it would break
    /// legitimate writes for no security gain.
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
    /// Caller identity for the handlers that act on *who* is calling (FetchKey): client-cert CN →
    /// roster identifier, exact match ([`crate::config::Config::peer_identities`]). `None` falls
    /// back to the strict `cosigner<N>` rule ([`crate::request_auth::identifier_from_cn`]).
    pub peer_ids: Option<Arc<std::collections::HashMap<String, u16>>>,
}

impl PeerSvc {
    fn authorize<T>(&self, req: &Request<T>) -> Result<Option<String>, Status> {
        authorize_cn(self.allowed_cns.as_deref(), req, "Peer")
    }

    /// The sender of a round-2 delivery: the caller's certificate identity, which must equal the
    /// `from` it claims (audit C1 — a node delivers only its own packages). With no peer allowlist
    /// (plaintext dev mode, where nothing on the mesh is authenticated) the claim is taken as is.
    fn delivery_sender<T>(&self, req: &Request<T>, claimed: u32) -> Result<u16, Status> {
        let claimed = u16::try_from(claimed).map_err(|_| Status::invalid_argument("sender out of range"))?;
        if self.allowed_cns.is_none() {
            self.authorize(req)?;
            return Ok(claimed);
        }
        let id = self.authenticated_peer(req)?;
        if id != claimed {
            return Err(Status::permission_denied(format!(
                "the caller is node {id} but delivers as node {claimed} — refusing a round-2 package \
                 under another node's identity"
            )));
        }
        Ok(id)
    }

    /// The node identifier of the authenticated caller, taken from its client-cert CN: the roster
    /// node whose configured `tls_client_cn` (default `cosigner<N>`) it equals exactly.
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
        // Exact match only. Parsing digits out of the CN (as before) let `cosigner-2`, `xcosigner2`
        // or `cosigner02` all pass as node 2 — any allowlisted spelling could claim another node.
        let id = match &self.peer_ids {
            Some(ids) => ids.get(&cn).copied(),
            None => crate::request_auth::identifier_from_cn(&cn),
        };
        id.ok_or_else(|| {
            Status::permission_denied(format!(
                "peer certificate CN '{cn}' is not the configured client CN of any roster node"
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
        // An empty digest is a leader from before epochs: no sharing declared (see the proto).
        let leader_view = match r.pkp_digest.len() {
            0 => None,
            32 => Some((r.epoch, <[u8; 32]>::try_from(r.pkp_digest.as_slice()).expect("32 bytes"))),
            n => return Err(Status::invalid_argument(format!("pkp_digest must be 32 bytes, got {n}"))),
        };
        let ctx = crate::node::Round1Ctx { leader_view };
        let commitments = self
            .node
            .blocking(move |n| n.sign_round1(&r.key_id, &r.session_id, &ctx))
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
        match kind {
            // The share-writing ceremonies take the two-phase fence (staged ceremonies, the
            // leader's expected sharing); it reads the key store.
            "dkg" | "refresh" => {
                if r.protocol < crate::ceremony::CEREMONY_PROTOCOL {
                    return Err(old_leader(r.protocol));
                }
                let kind = crate::node::CeremonyKind::parse(kind).map_err(Status::from)?;
                let expect = match r.expected_pkp_digest.len() {
                    0 => None,
                    32 => Some((r.expected_epoch, r.expected_pkp_digest.as_slice().try_into().expect("32"))),
                    _ => return Err(Status::invalid_argument("expected_pkp_digest must be 32 bytes")),
                };
                self.node
                    .blocking(move |n| n.ceremony_begin(&r.ceremony_id, &r.key_id, kind, expect))
                    .await
                    .map_err(Status::from)?;
            }
            _ => self.node.ceremony_fence(&r.ceremony_id, &r.key_id, kind).map_err(Status::from)?,
        }
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

    // Ceremony protocol 1 (leader-relayed round 2, audit C1): refused outright, so an older leader
    // can neither run a ceremony with this node nor obtain round-2 packages from it.
    async fn dkg_part1(&self, req: Request<pb::DkgPart1Request>) -> Result<Response<pb::DkgPart1Reply>, Status> {
        self.authorize(&req)?;
        Err(relay_refused())
    }

    async fn dkg_part2(&self, req: Request<pb::DkgPart2Request>) -> Result<Response<pb::DkgPart2Reply>, Status> {
        self.authorize(&req)?;
        Err(relay_refused())
    }

    async fn dkg_part3(&self, req: Request<pb::DkgPart3Request>) -> Result<Response<pb::DkgPart3Reply>, Status> {
        self.authorize(&req)?;
        Err(relay_refused())
    }

    async fn refresh_part1(
        &self,
        req: Request<pb::RefreshPart1Request>,
    ) -> Result<Response<pb::DkgPart1Reply>, Status> {
        self.authorize(&req)?;
        Err(relay_refused())
    }

    async fn refresh_part2(&self, req: Request<pb::DkgPart2Request>) -> Result<Response<pb::DkgPart2Reply>, Status> {
        self.authorize(&req)?;
        Err(relay_refused())
    }

    async fn refresh_part3(&self, req: Request<pb::DkgPart3Request>) -> Result<Response<pb::DkgPart3Reply>, Status> {
        self.authorize(&req)?;
        Err(relay_refused())
    }

    async fn ceremony_part1(
        &self,
        req: Request<pb::CeremonyPart1Request>,
    ) -> Result<Response<pb::CeremonyPart1Reply>, Status> {
        self.authorize(&req)?;
        let r = req.into_inner();
        if r.protocol < crate::ceremony::CEREMONY_PROTOCOL {
            return Err(old_leader(r.protocol));
        }
        let kind = crate::node::CeremonyKind::parse(&r.kind).map_err(Status::from)?;
        let roster: Vec<u16> = r
            .roster
            .iter()
            .map(|&i| u16::try_from(i).map_err(|_| Status::invalid_argument("roster identifier out of range")))
            .collect::<Result<_, _>>()?;
        let package = self
            .node
            .blocking(move |n| n.ceremony_part1(&r.ceremony_id, &r.key_id, kind, &roster))
            .await
            .map_err(Status::from)?;
        Ok(Response::new(pb::CeremonyPart1Reply { round1_package: json(&package)? }))
    }

    async fn ceremony_part2(
        &self,
        req: Request<pb::CeremonyPart2Request>,
    ) -> Result<Response<pb::CeremonyPart2Reply>, Status> {
        self.authorize(&req)?;
        let r = req.into_inner();
        let round1_map = de(&r.round1_map)?;
        // Detached: the deliveries to every recipient finish (or the session aborts) even if the
        // leader stops waiting.
        let node = self.node.clone();
        let out = crate::ceremony::detach(async move {
            crate::ceremony::part2_and_deliver(&node, &r.ceremony_id, round1_map).await
        })
        .await
        .map_err(Status::from)?;
        Ok(Response::new(pb::CeremonyPart2Reply {
            round1_digest: out.round1_digest.to_vec(),
            delivered_to: out.delivered.into_iter().map(u32::from).collect(),
        }))
    }

    async fn ceremony_deliver(
        &self,
        req: Request<pb::CeremonyDeliverRequest>,
    ) -> Result<Response<pb::CeremonyDeliverReply>, Status> {
        let from = self.delivery_sender(&req, req.get_ref().from)?;
        let r = req.into_inner();
        let to = u16::try_from(r.to).map_err(|_| Status::invalid_argument("recipient out of range"))?;
        let digest: [u8; 32] = r
            .round1_digest
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("round1_digest must be 32 bytes"))?;
        let package = de(&zeroize::Zeroizing::new(r.round2_package))?;
        self.node
            .blocking(move |n| n.ceremony_deliver(&r.ceremony_id, from, to, digest, package))
            .await
            .map_err(Status::from)?;
        Ok(Response::new(pb::CeremonyDeliverReply {}))
    }

    async fn ceremony_part3(
        &self,
        req: Request<pb::CeremonyPart3Request>,
    ) -> Result<Response<pb::CeremonyPart3Reply>, Status> {
        self.authorize(&req)?;
        let r = req.into_inner();
        let digest: [u8; 32] = r
            .round1_digest
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("round1_digest must be 32 bytes"))?;
        let out = self
            .node
            .blocking(move |n| n.ceremony_part3(&r.ceremony_id, &digest))
            .await
            .map_err(Status::from)?;
        Ok(Response::new(pb::CeremonyPart3Reply {
            new_epoch: out.new_epoch,
            new_pkp_digest: out.new_pkp_digest.to_vec(),
            group_verifying_key: out.group_key.to_vec(),
        }))
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
            identifier: crate::hosted::identifier_index(self.node.identifier).map_err(Status::from)? as u32,
            // Empty with hosted keys off: the reply also carries the ceremony protocol, which every
            // node must report.
            dist_public_key: self.node.dist_public_key().map(|k| k.to_vec()).unwrap_or_default(),
            hosted_key_specs: self.node.hosted_specs(),
            ceremony_protocol: crate::ceremony::CEREMONY_PROTOCOL,
        }))
    }

    async fn key_epoch(
        &self,
        req: Request<pb::KeyEpochRequest>,
    ) -> Result<Response<pb::KeyEpochReply>, Status> {
        self.authorize(&req)?;
        self.node.refuse_if_keystore_down().map_err(Status::from)?;
        let key_id = req.into_inner().key_id;
        let reply = self.node.blocking(move |n| n.key_epoch(&key_id)).await.map_err(Status::from)?;
        Ok(Response::new(reply))
    }

    async fn ceremony_commit(
        &self,
        req: Request<pb::CeremonyCommitRequest>,
    ) -> Result<Response<pb::CeremonyStatusReply>, Status> {
        self.authorize(&req)?;
        let id = req.into_inner().ceremony_id;
        // Detached: a caller that stops waiting must not cut a commit between the promotion and
        // the record (the startup repair would finish it, but there is no need to rely on that).
        let node = self.node.clone();
        let info = crate::ceremony::detach(async move { crate::ceremony::resolve(&node, &id).await })
            .await
            .map_err(Status::from)?;
        Ok(Response::new(crate::peer::status_to_pb(&info)))
    }

    async fn ceremony_status(
        &self,
        req: Request<pb::CeremonyStatusRequest>,
    ) -> Result<Response<pb::CeremonyStatusReply>, Status> {
        self.authorize(&req)?;
        let id = req.into_inner().ceremony_id;
        let info = self.node.blocking(move |n| n.ceremony_status(&id)).await.map_err(Status::from)?;
        Ok(Response::new(crate::peer::status_to_pb(&info)))
    }

    async fn ceremony_abort(
        &self,
        req: Request<pb::CeremonyAbortRequest>,
    ) -> Result<Response<pb::CeremonyStatusReply>, Status> {
        self.authorize(&req)?;
        let id = req.into_inner().ceremony_id;
        let info = self.node.blocking(move |n| n.ceremony_abort(&id)).await.map_err(Status::from)?;
        Ok(Response::new(crate::peer::status_to_pb(&info)))
    }
}

fn relay_refused() -> Status {
    Status::failed_precondition(format!(
        "leader-relayed DKG/refresh (ceremony protocol 1) is disabled on this cosigner: it would hand \
         round-2 secret shares to the leader (audit C1). This node speaks ceremony protocol {} — \
         upgrade every cosigner before running a DKG or refresh",
        crate::ceremony::CEREMONY_PROTOCOL
    ))
}

fn old_leader(protocol: u32) -> Status {
    Status::failed_precondition(format!(
        "the ceremony leader speaks ceremony protocol {protocol}, this cosigner {} — upgrade every \
         cosigner before running a DKG or refresh (a mixed-version cluster refuses ceremonies)",
        crate::ceremony::CEREMONY_PROTOCOL
    ))
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
    fn cn_of_names_nobody_for_two_cns_or_an_undecodable_one() {
        // The same rule the split ceremony's request check uses (tls::subject_cn).
        let key = rcgen::KeyPair::generate().unwrap();
        let mut two = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        two.distinguished_name.push(rcgen::DnType::CommonName, "driver");
        two.distinguished_name.push(rcgen::DnType::CustomDnType(vec![2, 5, 4, 3]), "cosigner1");
        assert_eq!(cn_of(two.self_signed(&key).unwrap().der()), None);
        let mut bmp = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        bmp.distinguished_name
            .push(rcgen::DnType::CommonName, rcgen::DnValue::BmpString("driver".try_into().unwrap()));
        assert_eq!(cn_of(bmp.self_signed(&key).unwrap().der()), None);
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

    #[test]
    fn the_operator_role_never_opens_the_api_and_fails_closed() {
        use std::collections::HashSet;
        let driver: HashSet<String> = ["driver".to_string()].into_iter().collect();
        let operator: HashSet<String> = ["operator".to_string()].into_iter().collect();
        let req = tonic::Request::new(());
        // A configured role set refuses a caller without a certificate, operator role or not.
        let err = super::authorize_either(Some(&driver), Some(&operator), &req).unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
        assert!(super::authorize_either(Some(&driver), None, &req).is_err());
        // Plaintext dev (no driver allowlist) stays open, as every other Signer RPC.
        assert!(super::authorize_either(None, Some(&operator), &req).is_ok());
    }
}
