// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli.backend

import com.digitalasset.canton.crypto.kms.driver.api.v1._
import com.stakecraft.rutli.audit.AuditNotes

import scala.concurrent.Future

/** The internal seam between the Canton-facing `RutliDriver` and a concrete key store.
  *
  * A backend OWNS the private key material and performs all cryptographic operations; the driver
  * (and therefore Canton) never sees a private key. The driver is a thin policy/routing shell over
  * this trait.
  *
  * Planned implementations:
  *   - [[SoftwareBackend]] — Phase 0. In-process BouncyCastle crypto. Integration testing only.
  *   - `HsmBackend`        — Phase 1. Keys sealed in a PKCS#11 HSM / enclave.
  *   - `FrostBackend`      — Phase 2. FROST-ed25519 threshold signing over a t-of-n MPC cluster
  *                           (namespace/identity keys). gRPC/mTLS to the share nodes.
  *   - `DklsBackend`       — Phase 4. Threshold ECDSA (DKLS23) for protocol/sequencer keys.
  *
  * Methods return a `Future` and may fail it with any exception; the driver maps non-
  * [[KmsDriverException]] failures to a non-retryable `KmsDriverException` at the SPI boundary.
  */
trait KmsBackend extends AutoCloseable {

  def supportedSigningKeySpecs: Set[SigningKeySpec]
  def supportedSigningAlgoSpecs: Set[SigningAlgoSpec]
  def supportedEncryptionKeySpecs: Set[EncryptionKeySpec]
  def supportedEncryptionAlgoSpecs: Set[EncryptionAlgoSpec]

  def generateSigningKeyPair(spec: SigningKeySpec, keyName: Option[String]): Future[String]
  def generateEncryptionKeyPair(spec: EncryptionKeySpec, keyName: Option[String]): Future[String]
  def generateSymmetricKey(keyName: Option[String]): Future[String]

  def sign(data: Array[Byte], keyId: String, algo: SigningAlgoSpec): Future[Array[Byte]]
  def decryptAsymmetric(
      ciphertext: Array[Byte],
      keyId: String,
      algo: EncryptionAlgoSpec,
  ): Future[Array[Byte]]
  def encryptSymmetric(data: Array[Byte], keyId: String): Future[Array[Byte]]
  def decryptSymmetric(ciphertext: Array[Byte], keyId: String): Future[Array[Byte]]

  def getPublicKey(keyId: String): Future[PublicKey]
  def keyExistsAndIsActive(keyId: String): Future[Unit]
  def deleteKey(keyId: String): Future[Unit]

  def health: Future[KmsDriverHealth]

  /** Run `op` so that any annotation the backend wants on the calling operation's audit entry
    * (e.g. a FROST leader failover) lands in `notes`. Default: no annotations.
    *
    * `op` must be the direct backend call (`backend.withAuditNotes(n)(backend.sign(...))`):
    * implementations may bind `notes` to the calling thread only for the synchronous part of `op`.
    */
  def withAuditNotes[A](notes: AuditNotes)(op: => Future[A]): Future[A] = op

  override def close(): Unit = ()
}
