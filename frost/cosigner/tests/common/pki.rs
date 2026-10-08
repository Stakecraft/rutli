// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Test PKI: a cluster CA and per-node mTLS certificates, as `scripts/gen-frost-certs.sh` issues
//! them (ECDSA P-256 by default), to sign split-ceremony recipient requests in tests. Shared by the
//! crate's unit tests (`request_auth::test_pki`) and the integration tests (`#[path]` include).

#![allow(dead_code)]

use rutli_cosigner::request_auth::NodeSigner;

pub struct TestPki {
    pub ca_pem: String,
    ca_key: rcgen::KeyPair,
    ca: rcgen::Certificate,
}

impl TestPki {
    pub fn new() -> Self {
        Self::with_alg(&rcgen::PKCS_ECDSA_P256_SHA256)
    }

    pub fn with_alg(alg: &'static rcgen::SignatureAlgorithm) -> Self {
        let ca_key = rcgen::KeyPair::generate_for(alg).unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name.push(rcgen::DnType::CommonName, "rutli-frost-cluster-ca");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca = params.self_signed(&ca_key).unwrap();
        Self { ca_pem: ca.pem(), ca_key, ca }
    }

    /// A leaf with subject CN `cn` (P-256), signed by this CA, and its signer.
    pub fn signer(&self, cn: &str) -> NodeSigner {
        self.signer_with(cn, &rcgen::PKCS_ECDSA_P256_SHA256, false)
    }

    pub fn signer_with(
        &self,
        cn: &str,
        alg: &'static rcgen::SignatureAlgorithm,
        expired: bool,
    ) -> NodeSigner {
        let (cert, key) = self.leaf_pem(cn, alg, expired);
        NodeSigner::from_pem(cert.as_bytes(), key.as_bytes()).unwrap()
    }

    /// (certificate PEM, PKCS#8 key PEM) for a leaf with subject CN `cn`.
    pub fn leaf_pem(
        &self,
        cn: &str,
        alg: &'static rcgen::SignatureAlgorithm,
        expired: bool,
    ) -> (String, String) {
        let key = rcgen::KeyPair::generate_for(alg).unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["rutli-cosigner".to_string()]).unwrap();
        params.distinguished_name.push(rcgen::DnType::CommonName, cn);
        if expired {
            params.not_before = rcgen::date_time_ymd(2001, 1, 1);
            params.not_after = rcgen::date_time_ymd(2002, 1, 1);
        }
        let cert = params.signed_by(&key, &self.ca, &self.ca_key).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    pub fn cluster_id(&self) -> String {
        rutli_cosigner::wrap::cluster_id_from_ca(self.ca_pem.as_bytes())
    }
}
