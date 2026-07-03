// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli.backend

import com.digitalasset.canton.crypto.kms.driver.api.v1._
import com.google.protobuf.ByteString
import com.stakecraft.rutli.grpc.{
  DkgRequest,
  GroupKeyRequest,
  HealthRequest,
  SignRequest,
  SignerGrpc,
}
import io.grpc.ManagedChannelBuilder
import org.slf4j.Logger

import java.security.KeyFactory
import java.security.spec.X509EncodedKeySpec
import java.util.concurrent.TimeUnit
import scala.concurrent.duration._
import scala.concurrent.{ExecutionContext, Future, blocking}

/** Phase 2 backend: routes the Ed25519 namespace/identity key to the external FROST cosigner
  * cluster (threshold signing, no node ever holds the whole key). Every other operation — ECDSA
  * signing, RSA/ECIES decryption, symmetric crypto — is delegated to a co-located [[KmsBackend]]
  * (the HSM in production), because threshold-izing those is out of scope (see docs/architecture.md).
  *
  * The driver thus presents a single KMS to Canton while, underneath, the highest-value key lives
  * in MPC and the rest live in the HSM.
  *
  * Routing is by key-id prefix: keys this backend creates on the cluster are tagged `frost-`.
  * `generateSigningKeyPair(EcCurve25519)` runs a distributed key generation on the cluster and
  * returns the cluster key id; `sign` with that id calls the cluster's threshold Sign.
  *
  * v0 talks plaintext gRPC to a single Signer endpoint (any cosigner leads the request). mTLS and
  * multi-endpoint failover are follow-ups.
  */
final class FrostBackend(
    endpoint: String,
    delegate: KmsBackend,
    logger: Logger,
    requestTimeout: FiniteDuration = 60.seconds,
)(implicit ec: ExecutionContext)
    extends KmsBackend {

  import FrostBackend._

  private val channel = ManagedChannelBuilder.forTarget(endpoint).usePlaintext().build()

  private def stub: SignerGrpc.SignerBlockingStub =
    SignerGrpc.newBlockingStub(channel).withDeadlineAfter(requestTimeout.toMillis, TimeUnit.MILLISECONDS)

  // Advertise Ed25519 (served by the cluster) plus whatever the delegate backend supports.
  override def supportedSigningKeySpecs: Set[SigningKeySpec] =
    delegate.supportedSigningKeySpecs + SigningKeySpec.EcCurve25519
  override def supportedSigningAlgoSpecs: Set[SigningAlgoSpec] =
    delegate.supportedSigningAlgoSpecs + SigningAlgoSpec.Ed25519
  override def supportedEncryptionKeySpecs: Set[EncryptionKeySpec] =
    delegate.supportedEncryptionKeySpecs
  override def supportedEncryptionAlgoSpecs: Set[EncryptionAlgoSpec] =
    delegate.supportedEncryptionAlgoSpecs

  override def generateSigningKeyPair(
      spec: SigningKeySpec,
      keyName: Option[String],
  ): Future[String] = spec match {
    case SigningKeySpec.EcCurve25519 =>
      val keyId = frostKeyId(keyName)
      Future {
        logger.info(s"FROST: initiating distributed key generation for $keyId")
        blocking(stub.dkg(DkgRequest.newBuilder().setKeyId(keyId).build()))
        keyId
      }
    case other => delegate.generateSigningKeyPair(other, keyName)
  }

  override def generateEncryptionKeyPair(
      spec: EncryptionKeySpec,
      keyName: Option[String],
  ): Future[String] = delegate.generateEncryptionKeyPair(spec, keyName)

  override def generateSymmetricKey(keyName: Option[String]): Future[String] =
    delegate.generateSymmetricKey(keyName)

  override def sign(data: Array[Byte], keyId: String, algo: SigningAlgoSpec): Future[Array[Byte]] =
    if (isFrostKey(keyId)) Future {
      require(algo == SigningAlgoSpec.Ed25519, s"FROST keys sign Ed25519 only, got $algo")
      val reply = blocking(
        stub.sign(SignRequest.newBuilder().setKeyId(keyId).setMessage(ByteString.copyFrom(data)).build())
      )
      val sig = reply.getSignature.toByteArray
      require(sig.length == 64, s"expected 64-byte Ed25519 signature, got ${sig.length}")
      sig
    }
    else delegate.sign(data, keyId, algo)

  override def decryptAsymmetric(
      ciphertext: Array[Byte],
      keyId: String,
      algo: EncryptionAlgoSpec,
  ): Future[Array[Byte]] = delegate.decryptAsymmetric(ciphertext, keyId, algo)

  override def encryptSymmetric(data: Array[Byte], keyId: String): Future[Array[Byte]] =
    delegate.encryptSymmetric(data, keyId)

  override def decryptSymmetric(ciphertext: Array[Byte], keyId: String): Future[Array[Byte]] =
    delegate.decryptSymmetric(ciphertext, keyId)

  override def getPublicKey(keyId: String): Future[PublicKey] =
    if (isFrostKey(keyId)) Future {
      val reply = blocking(stub.groupKey(GroupKeyRequest.newBuilder().setKeyId(keyId).build()))
      val raw = reply.getGroupVerifyingKey.toByteArray
      require(raw.length == 32, s"expected 32-byte Ed25519 group key, got ${raw.length}")
      PublicKey(ed25519Spki(raw), SigningKeySpec.EcCurve25519)
    }
    else delegate.getPublicKey(keyId)

  override def keyExistsAndIsActive(keyId: String): Future[Unit] =
    if (isFrostKey(keyId)) Future {
      // groupKey returns NOT_FOUND if the cluster has no such key.
      blocking(stub.groupKey(GroupKeyRequest.newBuilder().setKeyId(keyId).build()))
      ()
    }
    else delegate.keyExistsAndIsActive(keyId)

  override def deleteKey(keyId: String): Future[Unit] =
    if (isFrostKey(keyId))
      // The cluster intentionally has no delete — the namespace key is non-rotatable and deleting
      // it would be catastrophic. Deletion is an operator ceremony, not an API call.
      Future.failed(new UnsupportedOperationException("FROST namespace keys cannot be deleted via the API"))
    else delegate.deleteKey(keyId)

  override def health: Future[KmsDriverHealth] = {
    val cluster = Future {
      val ok =
        try blocking(stub.health(HealthRequest.newBuilder().build())).getOk
        catch { case _: Throwable => false }
      if (ok) KmsDriverHealth.Ok else KmsDriverHealth.Degraded("FROST cosigner cluster unreachable")
    }
    // Overall health is the worse of cluster + delegate.
    cluster.flatMap(c => delegate.health.map {
      case KmsDriverHealth.Ok => c
      case worse              => worse
    })
  }

  override def close(): Unit = {
    try {
      channel.shutdown()
      channel.awaitTermination(5, TimeUnit.SECONDS)
      ()
    } finally delegate.close()
  }
}

object FrostBackend {
  private val FrostPrefix = "frost-"

  private def isFrostKey(keyId: String): Boolean = keyId.startsWith(FrostPrefix)

  private def frostKeyId(keyName: Option[String]): String = {
    val name = keyName.map(n => n.replaceAll("[^A-Za-z0-9_-]", "_")).getOrElse("key")
    s"$FrostPrefix$name"
  }

  /** Wrap a raw 32-byte Ed25519 public key in DER X.509 SubjectPublicKeyInfo — what Canton expects
    * from getPublicKey. The 12-byte prefix is the fixed Ed25519 SPKI header (SEQUENCE, alg OID
    * 1.3.101.112, BIT STRING); we re-parse to normalize to exactly the verifier's encoding. */
  private def ed25519Spki(raw: Array[Byte]): Array[Byte] = {
    val header = Array[Byte](0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00)
    val spki = header ++ raw
    KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(spki)).getEncoded
  }
}
