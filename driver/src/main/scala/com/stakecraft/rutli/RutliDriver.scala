// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli

import com.digitalasset.canton.crypto.kms.driver.api.v1._
import com.stakecraft.rutli.backend.KmsBackend
import io.opentelemetry.context.Context

import scala.concurrent.{ExecutionContext, Future}
import scala.util.control.NonFatal

/** Canton KMS Driver implementation.
  *
  * This is a thin policy/routing shell: it satisfies the Canton
  * [[com.digitalasset.canton.crypto.kms.driver.api.v1.KmsDriver]] SPI and delegates every key
  * operation to a [[com.stakecraft.rutli.backend.KmsBackend]]. It performs no cryptography of
  * its own and never holds private key material.
  *
  * Later phases add here (not in the backend): M-of-N quorum/approval enforcement, a tamper-evident
  * audit log, and replay/equivocation guards on signing. The OpenTelemetry trace context is
  * accepted per the SPI and can be propagated to those layers.
  */
final class RutliDriver(
    backend: KmsBackend,
    // Passed as constructor params (not read from `backend`) so the trait's `require(...)` checks,
    // which run during construction, see initialized values regardless of field init order.
    override val supportedSigningKeySpecs: Set[SigningKeySpec],
    override val supportedSigningAlgoSpecs: Set[SigningAlgoSpec],
    override val supportedEncryptionKeySpecs: Set[EncryptionKeySpec],
    override val supportedEncryptionAlgoSpecs: Set[EncryptionAlgoSpec],
)(implicit ec: ExecutionContext)
    extends KmsDriver {

  override def health: Future[KmsDriverHealth] = backend.health

  override def generateSigningKeyPair(
      signingKeySpec: SigningKeySpec,
      keyName: Option[String],
  )(traceContext: Context): Future[String] =
    wrap(backend.generateSigningKeyPair(signingKeySpec, keyName))

  override def generateEncryptionKeyPair(
      encryptionKeySpec: EncryptionKeySpec,
      keyName: Option[String],
  )(traceContext: Context): Future[String] =
    wrap(backend.generateEncryptionKeyPair(encryptionKeySpec, keyName))

  override def generateSymmetricKey(keyName: Option[String])(
      traceContext: Context
  ): Future[String] =
    wrap(backend.generateSymmetricKey(keyName))

  override def sign(data: Array[Byte], keyId: String, algoSpec: SigningAlgoSpec)(
      traceContext: Context
  ): Future[Array[Byte]] =
    wrap(backend.sign(data, keyId, algoSpec))

  override def decryptAsymmetric(
      ciphertext: Array[Byte],
      keyId: String,
      algoSpec: EncryptionAlgoSpec,
  )(traceContext: Context): Future[Array[Byte]] =
    wrap(backend.decryptAsymmetric(ciphertext, keyId, algoSpec))

  override def encryptSymmetric(data: Array[Byte], keyId: String)(
      traceContext: Context
  ): Future[Array[Byte]] =
    wrap(backend.encryptSymmetric(data, keyId))

  override def decryptSymmetric(ciphertext: Array[Byte], keyId: String)(
      traceContext: Context
  ): Future[Array[Byte]] =
    wrap(backend.decryptSymmetric(ciphertext, keyId))

  override def getPublicKey(keyId: String)(traceContext: Context): Future[PublicKey] =
    wrap(backend.getPublicKey(keyId))

  override def keyExistsAndIsActive(keyId: String)(traceContext: Context): Future[Unit] =
    wrap(backend.keyExistsAndIsActive(keyId))

  override def deleteKey(keyId: String)(traceContext: Context): Future[Unit] =
    wrap(backend.deleteKey(keyId))

  override def close(): Unit = backend.close()

  /** Ensure every failed operation surfaces as a [[KmsDriverException]] per the SPI contract.
    * Backend-thrown [[KmsDriverException]]s are preserved (including their retryable flag); any
    * other failure is wrapped as non-retryable.
    */
  private def wrap[A](f: => Future[A]): Future[A] =
    (try f
     catch { case NonFatal(e) => Future.failed(e) }).recoverWith {
      case e: KmsDriverException => Future.failed(e)
      case NonFatal(e)           => Future.failed(KmsDriverException(e, retryable = false))
    }
}
