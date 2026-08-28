// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli.backend

import com.digitalasset.canton.crypto.kms.driver.api.v1._
import com.google.protobuf.ByteString
import com.stakecraft.rutli.FrostTlsConfig
import com.stakecraft.rutli.grpc.{
  CapabilitiesRequest,
  DecryptRequest,
  DeleteKeyRequest,
  DkgRequest,
  GenerateKeyRequest,
  GroupKeyRequest,
  HealthRequest,
  KeyInfoRequest,
  PublicKeyRequest,
  SignRequest,
  SignerGrpc,
  SymmetricRequest,
}
import io.grpc.netty.shaded.io.grpc.netty.{GrpcSslContexts, NettyChannelBuilder}
import io.grpc.{ManagedChannel, ManagedChannelBuilder, Status, StatusRuntimeException}
import org.slf4j.Logger

import java.io.File
import java.security.KeyFactory
import java.security.spec.X509EncodedKeySpec
import java.util.concurrent.TimeUnit
import scala.jdk.CollectionConverters._
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
  * '''Availability:''' the backend is configured with the full cosigner roster and fails over
  * across endpoints — any live cosigner can lead a request (the cluster orchestrates the rest). A
  * request is retried on the next endpoint only when the contacted node is unreachable
  * (UNAVAILABLE / DEADLINE_EXCEEDED); a real application error (e.g. NOT_FOUND) from a live node is
  * returned immediately, never masked by trying another node. This removes the single-leader
  * availability gap without any cross-node consensus — FROST sessions are independent, so no Raft
  * log is needed.
  */
class FrostBackend(
    endpoints: Seq[String],
    delegate: KmsBackend,
    logger: Logger,
    tls: Option[FrostTlsConfig] = None,
    requestTimeout: FiniteDuration = 60.seconds,
    hostedKeys: Boolean = false,
)(implicit ec: ExecutionContext)
    extends KmsBackend {

  import FrostBackend._

  require(endpoints.nonEmpty, "FrostBackend needs at least one cosigner endpoint")

  private val channels: Vector[ManagedChannel] = endpoints.toVector.map(buildChannel)

  /** Build the gRPC channel for one endpoint. Overridable so tests can substitute an in-process
    * channel without standing up a TLS listener. */
  protected def buildChannel(endpoint: String): ManagedChannel = tls match {
    case Some(t) =>
      val ssl = GrpcSslContexts
        .forClient()
        .trustManager(new File(t.caCert))
        .keyManager(new File(t.cert), new File(t.key))
        .build()
      val b = NettyChannelBuilder.forTarget(endpoint).sslContext(ssl)
      t.domain.foreach(b.overrideAuthority)
      logger.info(s"FROST: mutual TLS channel to $endpoint")
      b.build()
    case None =>
      logger.warn(s"FROST: plaintext channel to $endpoint (no TLS) — do not use in production")
      ManagedChannelBuilder.forTarget(endpoint).usePlaintext().build()
  }

  private def stubFor(ch: ManagedChannel): SignerGrpc.SignerBlockingStub =
    SignerGrpc.newBlockingStub(ch).withDeadlineAfter(requestTimeout.toMillis, TimeUnit.MILLISECONDS)

  /** Run `op` against cosigner endpoints in order, moving to the next only when the current node is
    * unreachable. Any non-transport gRPC status is a real answer and is rethrown immediately.
    *
    * `retryOn` decides which statuses count as "unreachable, try the next node". The default retries
    * on UNAVAILABLE + DEADLINE_EXCEEDED (safe for idempotent ops: sign, groupKey). A DKG must NOT
    * retry on DEADLINE_EXCEEDED — a slow-but-succeeding ceremony would otherwise be run a second time
    * against another leader — so it passes the connection-only predicate. */
  private def withFailover[A](what: String, retryOn: Status => Boolean = isNodeDown)(
      op: SignerGrpc.SignerBlockingStub => A
  ): A = {
    var lastError: RuntimeException = new IllegalStateException(s"no FROST endpoints for $what")
    channels.iterator.zipWithIndex.foreach { case (ch, i) =>
      try return op(stubFor(ch))
      catch {
        case e: StatusRuntimeException if retryOn(e.getStatus) =>
          logger.warn(s"FROST: $what via ${endpoints(i)} unreachable (${e.getStatus.getCode}); failing over")
          lastError = e
      }
    }
    throw lastError
  }

  /** Which hosted-key specs the cluster actually serves, asked once at startup.
    *
    * Queried rather than hardcoded so a cluster can add a key type without a driver release. An
    * older cluster answers UNIMPLEMENTED, and a cluster that is simply unreachable at startup must
    * not permanently disable the feature either — both fall back to the configured expectation and
    * are logged, because silently advertising fewer specs to Canton would look like a config bug.
    */
  private lazy val clusterSpecs: Set[String] =
    if (!hostedKeys) Set.empty
    else
      try {
        val reply =
          blocking(withFailover("capabilities")(_.capabilities(CapabilitiesRequest.newBuilder().build())))
        if (!reply.getHostedKeysEnabled) {
          logger.warn(
            "FROST: driver has hosted-keys enabled but the cluster reports them disabled — " +
              "non-FROST keys will fall back to the delegate. Set hosted_keys.enabled on the cosigners."
          )
          Set.empty[String]
        } else {
          val specs = reply.getHostedKeySpecsList.asScala.toSet
          logger.info(s"FROST: cluster hosts non-FROST keys (${specs.mkString(", ")})")
          specs
        }
      } catch {
        case e: StatusRuntimeException =>
          logger.warn(
            s"FROST: could not read cluster capabilities (${e.getStatus.getCode}); assuming the " +
              "configured hosted-key specs. Upgrade the cosigners if this persists."
          )
          DefaultHostedSpecs
      }

  private def hostsRsa: Boolean = clusterSpecs.contains(RsaSpec)
  private def hostsAes: Boolean = clusterSpecs.contains(AesSpec)

  // Advertise Ed25519 (threshold-signed by the cluster) plus, when hosted keys are on, the
  // encryption specs the cluster serves — and whatever the delegate still supports on top.
  override def supportedSigningKeySpecs: Set[SigningKeySpec] =
    delegate.supportedSigningKeySpecs + SigningKeySpec.EcCurve25519
  override def supportedSigningAlgoSpecs: Set[SigningAlgoSpec] =
    delegate.supportedSigningAlgoSpecs + SigningAlgoSpec.Ed25519
  override def supportedEncryptionKeySpecs: Set[EncryptionKeySpec] =
    delegate.supportedEncryptionKeySpecs ++
      (if (hostsRsa) Set(EncryptionKeySpec.Rsa2048) else Set.empty)
  override def supportedEncryptionAlgoSpecs: Set[EncryptionAlgoSpec] =
    delegate.supportedEncryptionAlgoSpecs ++
      (if (hostsRsa) Set(EncryptionAlgoSpec.RsaEsOaepSha256) else Set.empty)

  override def generateSigningKeyPair(
      spec: SigningKeySpec,
      keyName: Option[String],
  ): Future[String] = spec match {
    case SigningKeySpec.EcCurve25519 =>
      val keyId = frostKeyId(keyName)
      Future {
        logger.info(s"FROST: initiating distributed key generation for $keyId")
        // DKG is a one-shot ceremony: only fail over if the endpoint is unreachable at the
        // connection level (no ceremony started). Never retry on DEADLINE_EXCEEDED — a slow but
        // in-flight DKG must not be run a second time against another leader.
        blocking(withFailover("dkg", connectionRefused)(_.dkg(DkgRequest.newBuilder().setKeyId(keyId).build())))
        keyId
      }
    case other => delegate.generateSigningKeyPair(other, keyName)
  }

  override def generateEncryptionKeyPair(
      spec: EncryptionKeySpec,
      keyName: Option[String],
  ): Future[String] = spec match {
    case EncryptionKeySpec.Rsa2048 if hostsRsa =>
      val keyId = hostedKeyId("enc", keyName)
      Future {
        logger.info(s"FROST: generating cluster-hosted $RsaSpec key $keyId")
        blocking(generateHosted(keyId, RsaSpec))
        keyId
      }
    case other => delegate.generateEncryptionKeyPair(other, keyName)
  }

  override def generateSymmetricKey(keyName: Option[String]): Future[String] =
    if (hostsAes) {
      val keyId = hostedKeyId("sym", keyName)
      Future {
        logger.info(s"FROST: generating cluster-hosted $AesSpec key $keyId")
        blocking(generateHosted(keyId, AesSpec))
        keyId
      }
    } else delegate.generateSymmetricKey(keyName)

  /** Generate a hosted key on the cluster.
    *
    * `key_id` is caller-supplied and the cluster treats a repeat as a no-op, so this is idempotent
    * and may fail over on a timeout as well as a refused connection — unlike DKG, where a retry
    * could run a second ceremony.
    */
  private def generateHosted(keyId: String, spec: String): Unit = {
    val req = GenerateKeyRequest.newBuilder().setKeyId(keyId).setSpec(spec).build()
    val reply = withFailover("generateKey")(_.generateKey(req))
    logger.info(
      s"FROST: hosted key $keyId ready (created=${reply.getCreated}, replicas=${reply.getReplicas})"
    )
  }

  override def sign(data: Array[Byte], keyId: String, algo: SigningAlgoSpec): Future[Array[Byte]] =
    if (isFrostKey(keyId)) Future {
      require(algo == SigningAlgoSpec.Ed25519, s"FROST keys sign Ed25519 only, got $algo")
      val req = SignRequest.newBuilder().setKeyId(keyId).setMessage(ByteString.copyFrom(data)).build()
      val sig = blocking(withFailover("sign")(_.sign(req))).getSignature.toByteArray
      require(sig.length == 64, s"expected 64-byte Ed25519 signature, got ${sig.length}")
      sig
    }
    else delegate.sign(data, keyId, algo)

  override def decryptAsymmetric(
      ciphertext: Array[Byte],
      keyId: String,
      algo: EncryptionAlgoSpec,
  ): Future[Array[Byte]] =
    if (isHostedKey(keyId)) Future {
      require(
        algo == EncryptionAlgoSpec.RsaEsOaepSha256,
        s"cluster-hosted encryption keys decrypt RSAES-OAEP-SHA256 only, got $algo",
      )
      val req = DecryptRequest
        .newBuilder()
        .setKeyId(keyId)
        .setCiphertext(ByteString.copyFrom(ciphertext))
        .build()
      blocking(withFailover("decrypt")(_.decrypt(req))).getPlaintext.toByteArray
    }
    else delegate.decryptAsymmetric(ciphertext, keyId, algo)

  override def encryptSymmetric(data: Array[Byte], keyId: String): Future[Array[Byte]] =
    if (isHostedKey(keyId)) Future {
      val req =
        SymmetricRequest.newBuilder().setKeyId(keyId).setData(ByteString.copyFrom(data)).build()
      blocking(withFailover("symmetricEncrypt")(_.symmetricEncrypt(req))).getData.toByteArray
    }
    else delegate.encryptSymmetric(data, keyId)

  override def decryptSymmetric(ciphertext: Array[Byte], keyId: String): Future[Array[Byte]] =
    if (isHostedKey(keyId)) Future {
      val req = SymmetricRequest
        .newBuilder()
        .setKeyId(keyId)
        .setData(ByteString.copyFrom(ciphertext))
        .build()
      blocking(withFailover("symmetricDecrypt")(_.symmetricDecrypt(req))).getData.toByteArray
    }
    else delegate.decryptSymmetric(ciphertext, keyId)

  override def getPublicKey(keyId: String): Future[PublicKey] =
    if (isFrostKey(keyId)) Future {
      val req = GroupKeyRequest.newBuilder().setKeyId(keyId).build()
      val raw = blocking(withFailover("groupKey")(_.groupKey(req))).getGroupVerifyingKey.toByteArray
      require(raw.length == 32, s"expected 32-byte Ed25519 group key, got ${raw.length}")
      PublicKey(ed25519Spki(raw), SigningKeySpec.EcCurve25519)
    }
    else if (isHostedKey(keyId)) Future {
      val req = PublicKeyRequest.newBuilder().setKeyId(keyId).build()
      val reply = blocking(withFailover("publicKey")(_.publicKey(req)))
      // The cluster returns X.509 SubjectPublicKeyInfo DER — exactly what Canton's PublicKey wants.
      PublicKey(reply.getPublicKeyDer.toByteArray, EncryptionKeySpec.Rsa2048)
    }
    else delegate.getPublicKey(keyId)

  override def keyExistsAndIsActive(keyId: String): Future[Unit] =
    if (isFrostKey(keyId)) Future {
      // groupKey returns NOT_FOUND if the cluster has no such key.
      blocking(withFailover("groupKey")(_.groupKey(GroupKeyRequest.newBuilder().setKeyId(keyId).build())))
      ()
    }
    else if (isHostedKey(keyId)) Future {
      val reply =
        blocking(withFailover("keyInfo")(_.keyInfo(KeyInfoRequest.newBuilder().setKeyId(keyId).build())))
      if (!reply.getExists) throw new NoSuchElementException(s"key not found or inactive: $keyId")
      ()
    }
    else delegate.keyExistsAndIsActive(keyId)

  override def deleteKey(keyId: String): Future[Unit] =
    if (isFrostKey(keyId))
      // The cluster intentionally has no delete — the namespace key is non-rotatable and deleting
      // it would be catastrophic. Deletion is an operator ceremony, not an API call.
      Future.failed(new UnsupportedOperationException("FROST namespace keys cannot be deleted via the API"))
    else if (isHostedKey(keyId)) Future {
      // Unlike the namespace key, Canton CAN rotate encryption keys, so hosted keys are deletable.
      blocking(withFailover("deleteKey")(_.deleteKey(DeleteKeyRequest.newBuilder().setKeyId(keyId).build())))
      ()
    }
    else delegate.deleteKey(keyId)

  override def health: Future[KmsDriverHealth] = {
    val cluster = Future {
      // Healthy if ANY cosigner answers — the cluster leads from whichever node is reachable.
      val anyUp = channels.iterator.exists { ch =>
        try stubFor(ch).health(HealthRequest.newBuilder().build()).getOk
        catch { case _: Throwable => false }
      }
      if (anyUp) KmsDriverHealth.Ok
      else KmsDriverHealth.Degraded("no FROST cosigner reachable")
    }
    // Overall health is the worse of cluster + delegate.
    cluster.flatMap(c =>
      delegate.health.map {
        case KmsDriverHealth.Ok => c
        case worse              => worse
      }
    )
  }

  override def close(): Unit = {
    try
      channels.foreach { ch =>
        ch.shutdown()
        ch.awaitTermination(5, TimeUnit.SECONDS)
      }
    finally delegate.close()
  }
}

object FrostBackend {
  private val FrostPrefix = "frost-"

  private def isFrostKey(keyId: String): Boolean = keyId.startsWith(FrostPrefix)

  /** Key ids the cluster hosts as whole (replicated, sealed) keys, as opposed to FROST shares. */
  private val HostedPrefix = "rutli-"
  private def isHostedKey(keyId: String): Boolean = keyId.startsWith(HostedPrefix)

  private val RsaSpec = "rsa-2048-oaep-sha256"
  private val AesSpec = "aes-256-gcm"

  /** Assumed cluster capability when the Capabilities RPC is unavailable (older cosigner, or the
    * cluster was unreachable at startup) but the operator configured hosted keys. */
  private val DefaultHostedSpecs = Set(RsaSpec, AesSpec)

  private def hostedKeyId(kind: String, keyName: Option[String]): String = {
    // The cosigner keystore accepts [A-Za-z0-9_-] only, and a UUID keeps retries of *different*
    // logical keys from colliding while GenerateKey stays idempotent for the same id.
    val name = keyName.map(n => s"-${n.replaceAll("[^A-Za-z0-9_-]", "_")}").getOrElse("")
    s"$HostedPrefix$kind$name-${java.util.UUID.randomUUID()}".take(300)
  }

  /** True when the status means "this contact node isn't serving" (so we should try the next),
    * as opposed to a real application answer we must surface. */
  /// Note what is deliberately absent: RESOURCE_EXHAUSTED (the cluster's per-key decryption rate
  /// limit) is NOT retried elsewhere. Every cosigner enforces the same ceiling, so failing over
  /// would merely spread the load an attacker is generating across the cluster. It surfaces to
  /// Canton, which backs off.
  private def isNodeDown(status: Status): Boolean =
    status.getCode == Status.Code.UNAVAILABLE || status.getCode == Status.Code.DEADLINE_EXCEEDED

  /** Stricter predicate for non-idempotent ops (DKG): only the endpoint being unreachable at the
    * connection level — never a timeout, which may mean the op is still running. */
  private def connectionRefused(status: Status): Boolean =
    status.getCode == Status.Code.UNAVAILABLE

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
