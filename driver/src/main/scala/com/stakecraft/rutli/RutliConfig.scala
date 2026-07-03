// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli

/** Driver-specific configuration, parsed from the `config { ... }` block of the Canton node's
  * `crypto.kms` section.
  *
  *   - `software` (Phase 0): in-process BouncyCastle crypto. Integration testing only.
  *   - `hsm` (Phase 1): keys in a PKCS#11 HSM / enclave. Requires the `hsm` block.
  *   - `frost` (Phase 2, not yet implemented): FROST-ed25519 MPC cluster for the namespace key.
  *
  * @param backend       Which key backend to use: "software" | "hsm" | "frost".
  * @param auditLogging  Emit per-operation audit lines (precursor of the Phase 3 hash-chained log).
  * @param hsm           HSM/PKCS#11 connection config; required when `backend = "hsm"`, and for the
  *                      delegate when `backend = "frost"` with `frost.delegate = "hsm"`.
  * @param frost         FROST cosigner-cluster config; required when `backend = "frost"`.
  */
final case class RutliConfig(
    backend: String = "software",
    auditLogging: Boolean = false,
    hsm: Option[HsmConfig] = None,
    frost: Option[FrostConfig] = None,
)

/** FROST backend config (Phase 2). The namespace/identity Ed25519 key is served by the cosigner
  * cluster; all other keys are served by the `delegate` backend (typically the HSM).
  *
  * @param endpoint  gRPC target of any cosigner's Signer service (e.g. "localhost:9101").
  * @param delegate  Backend for non-FROST keys: "hsm" | "software". Defaults to "hsm".
  * @param tls       Mutual-TLS material for the driver→cluster channel. When absent the channel is
  *                  plaintext (dev only); production must set this.
  */
final case class FrostConfig(
    endpoint: String,
    delegate: String = "hsm",
    tls: Option[FrostTlsConfig] = None,
)

/** Mutual-TLS material for the driver→cluster gRPC channel. The driver presents a client cert
  * signed by the cluster CA; the cluster requires it (mTLS).
  *
  * @param caCert  PEM CA cert (the cluster trust anchor).
  * @param cert    PEM client cert this driver presents.
  * @param key     PEM private key for `cert` (PKCS#8).
  * @param domain  Expected server SAN/authority (overrides the endpoint host for cert validation).
  */
final case class FrostTlsConfig(
    caCert: String,
    cert: String,
    key: String,
    domain: Option[String] = None,
)

/** PKCS#11 connection config for the HSM backend (Phase 1).
  *
  * @param libraryPath  Absolute path to the PKCS#11 module (.so/.dylib), e.g. SoftHSM's
  *                     libsofthsm2.so, or a YubiHSM/Securosys/CloudHSM PKCS#11 library.
  * @param slot         PKCS#11 slot id. Exactly one of `slot` / `slotListIndex` should be set.
  * @param slotListIndex Index into the slot list (0-based) as an alternative to a fixed slot id.
  * @param tokenLabel   Optional CKA token label; used to name/scope the provider instance.
  * @param pin          User PIN. Prefer supplying via `pinEnv` over inlining a secret in config.
  * @param pinEnv       Name of an env var holding the PIN (overrides `pin` when set).
  */
final case class HsmConfig(
    libraryPath: String,
    slot: Option[Long] = None,
    slotListIndex: Option[Int] = Some(0),
    tokenLabel: Option[String] = None,
    pin: Option[String] = None,
    pinEnv: Option[String] = None,
) {

  /** Resolve the PIN from `pinEnv` (preferred) or the inline `pin`. */
  def resolvedPin: Option[String] = pinEnv.flatMap(sys.env.get).orElse(pin)
}
