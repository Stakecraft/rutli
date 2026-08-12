// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli

/** Driver-specific configuration, parsed from the `config { ... }` block of the Canton node's
  * `crypto.kms` section.
  *
  *   - `software` (Phase 0): in-process BouncyCastle crypto. Integration testing only.
  *   - `hsm` (Phase 1): keys in a PKCS#11 HSM / enclave. Requires the `hsm` block.
  *   - `frost` (Phase 2): FROST-ed25519 MPC cluster for the namespace key; other keys delegate to
  *     `hsm`/`software`. Requires the `frost` block.
  *
  * @param backend       Which key backend to use: "software" | "hsm" | "frost".
  * @param auditLogging  Emit per-operation audit lines to the node log.
  * @param auditLogPath  When set, additionally append every operation to a tamper-evident
  *                      hash-chained JSONL audit log at this path (verifiable offline; see
  *                      [[com.stakecraft.rutli.audit.HashChainedAuditLog]]).
  * @param hsm           HSM/PKCS#11 connection config; required when `backend = "hsm"`, and for the
  *                      delegate when `backend = "frost"` with `frost.delegate = "hsm"`.
  * @param frost         FROST cosigner-cluster config; required when `backend = "frost"`.
  * @param approval      M-of-N approval policy. When set, `sign` for matching keys is held until a
  *                      quorum of configured approvers signs the request.
  * @param signingJournal Persistent per-key signing journal (replay detection + optional rate
  *                      limit). See [[com.stakecraft.rutli.guard.SigningJournal]].
  */
final case class RutliConfig(
    backend: String = "software",
    auditLogging: Boolean = false,
    auditLogPath: Option[String] = None,
    hsm: Option[HsmConfig] = None,
    frost: Option[FrostConfig] = None,
    software: Option[SoftwareConfig] = None,
    approval: Option[com.stakecraft.rutli.policy.ApprovalPolicy] = None,
    signingJournal: Option[SigningJournalConfig] = None,
)

/** Software-backend config (applies when `backend = "software"` OR `frost.delegate = "software"`).
  *
  * Without this block the software backend is heap-only: every key dies with the JVM — acceptable
  * for conformance tests, fatal on a real node (a restarted participant cannot decrypt anything
  * addressed to its old encryption key, and that key is unrecoverable). With `dir` set, every
  * generated key is persisted as an AES-256-GCM-sealed file and reloaded on startup.
  *
  * @param dir            Directory for sealed key files (must be durable — on k8s, a PVC).
  * @param sealSecretEnv  Name of the env var holding the seal master secret (e.g.
  *                       `openssl rand -hex 32`, injected from a secret manager). Required when
  *                       `dir` is set — the driver refuses to persist private keys in plaintext.
  */
final case class SoftwareConfig(
    dir: Option[String] = None,
    sealSecretEnv: Option[String] = None,
)

/** Signing-journal config.
  *
  * @param dir            Directory for the append-only per-key journals.
  * @param maxPerWindow   Optional hard cap on signatures per key per rolling window (a runaway /
  *                       compromise brake); omit for detection-only.
  * @param windowSeconds  The rolling window for `maxPerWindow`.
  */
final case class SigningJournalConfig(
    dir: String,
    maxPerWindow: Option[Int] = None,
    windowSeconds: Long = 60,
)

/** FROST backend config (Phase 2). The namespace/identity Ed25519 key is served by the cosigner
  * cluster; all other keys are served by the `delegate` backend (typically the HSM).
  *
  * @param endpoint   Single cosigner Signer endpoint (e.g. "localhost:9101"). Convenience for the
  *                   common one-target config; merged with `endpoints`.
  * @param endpoints  The full cosigner roster for failover (any live node leads a request). Prefer
  *                   this in production so a downed cosigner doesn't block signing.
  * @param delegate   Backend for non-FROST keys: "hsm" | "software". Defaults to "hsm".
  * @param tls        Mutual-TLS material for the driver→cluster channel. When absent the channel is
  *                   plaintext (dev only); production must set this.
  */
final case class FrostConfig(
    endpoint: Option[String] = None,
    endpoints: List[String] = Nil,
    delegate: String = "hsm",
    tls: Option[FrostTlsConfig] = None,
) {

  /** All configured endpoints, `endpoints` first then the single `endpoint`, de-duplicated. */
  def allEndpoints: List[String] = (endpoints ++ endpoint.toList).distinct
}

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
