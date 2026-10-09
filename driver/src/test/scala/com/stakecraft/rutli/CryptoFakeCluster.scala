// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli

import com.google.protobuf.ByteString
import com.stakecraft.rutli.backend.{FrostBackend, NoDelegateBackend}
import com.stakecraft.rutli.grpc._
import io.grpc.inprocess.{InProcessChannelBuilder, InProcessServerBuilder}
import io.grpc.stub.StreamObserver
import io.grpc.{Server, Status}
import org.slf4j.Logger

import java.math.BigInteger
import java.security._
import java.security.interfaces.ECPublicKey
import java.security.spec.{ECGenParameterSpec, ECPoint, ECPublicKeySpec}
import java.util.concurrent.atomic.AtomicInteger
import javax.crypto.spec.{GCMParameterSpec, SecretKeySpec}
import javax.crypto.{Cipher, KeyAgreement}
import scala.collection.concurrent.TrieMap
import scala.concurrent.ExecutionContext
import scala.concurrent.duration._

/** An in-process cosigner that does the cryptography for real, with the JDK's own providers — an
  * implementation independent of both the cluster (aws-lc) and the driver's ECIES completion
  * (BouncyCastle `IESEngine`):
  *   - FROST ids: an ordinary Ed25519 key per id (DKG/groupKey/sign), enough for Canton to verify;
  *   - `rsa-2048-oaep-sha256`: RSAES-OAEP-SHA256 (SunJCE);
  *   - `aes-256-gcm`: the cluster's `0x01 ‖ nonce ‖ ct‖tag` framing;
  *   - `ec-p256-ecies`: `EcdhDerive` as SunEC's `KeyAgreement("ECDH")`, after the same input rules
  *     as the cosigner (exactly 65 bytes, `0x04`).
  *
  * Counts `EcdhDerive` calls so tests can assert a malformed ciphertext never reached the cluster.
  */
class CryptoFakeCluster(
    specs: Seq[String] = Seq("rsa-2048-oaep-sha256", "aes-256-gcm", "ec-p256-ecies")
) extends SignerGrpc.SignerImplBase {

  val ecdhCalls = new AtomicInteger(0)

  private val ed = TrieMap.empty[String, KeyPair]
  private val hosted = TrieMap.empty[String, (String, Any)] // id -> (spec, key material)
  private val random = new SecureRandom()

  /** Make the EC key for `keyId` a fixed one (known-answer tests). */
  def putEcKey(keyId: String, pair: KeyPair): Unit = hosted(keyId) = ("ec-p256-ecies", pair)

  /** The EC key pair the fake holds under `keyId` (for tests that need the private half). */
  def ecKey(keyId: String): KeyPair = hosted(keyId)._2.asInstanceOf[KeyPair]

  private def reply[A](obs: StreamObserver[A])(a: => A): Unit =
    try { obs.onNext(a); obs.onCompleted() }
    catch { case e: io.grpc.StatusRuntimeException => obs.onError(e) }

  private def notFound(id: String) = Status.NOT_FOUND.withDescription(s"no such key: $id").asRuntimeException()

  override def capabilities(req: CapabilitiesRequest, obs: StreamObserver[CapabilitiesReply]): Unit =
    reply(obs) {
      val b = CapabilitiesReply.newBuilder().setHostedKeysEnabled(true)
      specs.foreach(b.addHostedKeySpecs)
      b.build()
    }

  override def health(req: HealthRequest, obs: StreamObserver[HealthReply]): Unit =
    reply(obs)(HealthReply.newBuilder().setOk(true).build())

  // -- FROST ids, faked with a plain Ed25519 key --

  private def rawEd25519(kp: KeyPair): Array[Byte] = kp.getPublic.getEncoded.takeRight(32)

  override def dkg(req: DkgRequest, obs: StreamObserver[DkgReply]): Unit = reply(obs) {
    if (ed.contains(req.getKeyId)) throw Status.ALREADY_EXISTS.asRuntimeException()
    val kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
    ed(req.getKeyId) = kp
    DkgReply.newBuilder().setGroupVerifyingKey(ByteString.copyFrom(rawEd25519(kp))).build()
  }

  override def groupKey(req: GroupKeyRequest, obs: StreamObserver[GroupKeyReply]): Unit = reply(obs) {
    val kp = ed.getOrElse(req.getKeyId, throw notFound(req.getKeyId))
    GroupKeyReply.newBuilder().setGroupVerifyingKey(ByteString.copyFrom(rawEd25519(kp))).build()
  }

  override def sign(req: SignRequest, obs: StreamObserver[SignReply]): Unit = reply(obs) {
    val kp = ed.getOrElse(req.getKeyId, throw notFound(req.getKeyId))
    val s = Signature.getInstance("Ed25519")
    s.initSign(kp.getPrivate)
    s.update(req.getMessage.toByteArray)
    SignReply.newBuilder().setSignature(ByteString.copyFrom(s.sign())).build()
  }

  // -- hosted keys --

  override def generateKey(req: GenerateKeyRequest, obs: StreamObserver[GenerateKeyReply]): Unit = reply(obs) {
    val created = !hosted.contains(req.getKeyId)
    if (created) {
      val material: Any = req.getSpec match {
        case "rsa-2048-oaep-sha256" =>
          val g = KeyPairGenerator.getInstance("RSA"); g.initialize(2048); g.generateKeyPair()
        case "ec-p256-ecies" =>
          val g = KeyPairGenerator.getInstance("EC"); g.initialize(new ECGenParameterSpec("secp256r1")); g.generateKeyPair()
        case "aes-256-gcm" =>
          val k = new Array[Byte](32); random.nextBytes(k); k
        case other => throw Status.FAILED_PRECONDITION.withDescription(s"spec $other").asRuntimeException()
      }
      hosted(req.getKeyId) = (req.getSpec, material)
    }
    GenerateKeyReply.newBuilder().setKeyId(req.getKeyId).setSpec(req.getSpec).setCreated(created).setReplicas(3).build()
  }

  override def publicKey(req: PublicKeyRequest, obs: StreamObserver[PublicKeyReply]): Unit = reply(obs) {
    hosted.get(req.getKeyId) match {
      case Some((spec, kp: KeyPair)) =>
        PublicKeyReply.newBuilder().setSpec(spec).setPublicKeyDer(ByteString.copyFrom(kp.getPublic.getEncoded)).build()
      case Some(_) => throw Status.FAILED_PRECONDITION.withDescription("no public key").asRuntimeException()
      case None    => throw notFound(req.getKeyId)
    }
  }

  override def keyInfo(req: KeyInfoRequest, obs: StreamObserver[KeyInfoReply]): Unit = reply(obs) {
    val b = KeyInfoReply.newBuilder().setExists(hosted.contains(req.getKeyId)).setReplicas(3)
    hosted.get(req.getKeyId).foreach { case (spec, _) => b.setSpec(spec) }
    b.build()
  }

  override def deleteKey(req: DeleteKeyRequest, obs: StreamObserver[DeleteKeyReply]): Unit = reply(obs) {
    val gone = hosted.remove(req.getKeyId).isDefined || ed.remove(req.getKeyId).isDefined
    DeleteKeyReply.newBuilder().setDeleted(gone).build()
  }

  override def decrypt(req: DecryptRequest, obs: StreamObserver[DecryptReply]): Unit = reply(obs) {
    hosted.get(req.getKeyId) match {
      case Some(("rsa-2048-oaep-sha256", kp: KeyPair)) =>
        val c = Cipher.getInstance("RSA/ECB/OAEPPadding")
        c.init(
          Cipher.DECRYPT_MODE,
          kp.getPrivate,
          new javax.crypto.spec.OAEPParameterSpec(
            "SHA-256",
            "MGF1",
            java.security.spec.MGF1ParameterSpec.SHA256,
            javax.crypto.spec.PSource.PSpecified.DEFAULT,
          ),
        )
        val pt =
          try c.doFinal(req.getCiphertext.toByteArray)
          catch { case _: GeneralSecurityException => throw Status.INVALID_ARGUMENT.withDescription("decryption failed").asRuntimeException() }
        DecryptReply.newBuilder().setPlaintext(ByteString.copyFrom(pt)).build()
      case Some(_) => throw Status.FAILED_PRECONDITION.withDescription("not an RSA key").asRuntimeException()
      case None    => throw notFound(req.getKeyId)
    }
  }

  override def ecdhDerive(req: EcdhDeriveRequest, obs: StreamObserver[EcdhDeriveReply]): Unit = reply(obs) {
    ecdhCalls.incrementAndGet()
    val kp = hosted.get(req.getKeyId) match {
      case Some(("ec-p256-ecies", kp: KeyPair)) => kp
      case Some(_) => throw Status.FAILED_PRECONDITION.withDescription("key cannot perform ECDH").asRuntimeException()
      case None    => throw notFound(req.getKeyId)
    }
    val point = req.getPeerPoint.toByteArray
    if (point.length != 65 || point(0) != 0x04)
      throw Status.INVALID_ARGUMENT.withDescription("not a 65-byte uncompressed point").asRuntimeException()
    val params = kp.getPublic.asInstanceOf[ECPublicKey].getParams
    val w = new ECPoint(new BigInteger(1, point.slice(1, 33)), new BigInteger(1, point.slice(33, 65)))
    val z =
      try {
        val peer = KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(w, params))
        val ka = KeyAgreement.getInstance("ECDH")
        ka.init(kp.getPrivate)
        ka.doPhase(peer, true)
        ka.generateSecret()
      } catch {
        case _: GeneralSecurityException | _: IllegalArgumentException | _: IllegalStateException =>
          throw Status.INVALID_ARGUMENT.withDescription("the peer point is not on P-256").asRuntimeException()
      }
    EcdhDeriveReply.newBuilder().setSharedSecret(ByteString.copyFrom(z)).build()
  }

  private def aes(keyId: String): Array[Byte] = hosted.get(keyId) match {
    case Some(("aes-256-gcm", k: Array[Byte] @unchecked)) => k
    case Some(_) => throw Status.FAILED_PRECONDITION.withDescription("not a symmetric key").asRuntimeException()
    case None    => throw notFound(keyId)
  }

  override def symmetricEncrypt(req: SymmetricRequest, obs: StreamObserver[SymmetricReply]): Unit = reply(obs) {
    val nonce = new Array[Byte](12); random.nextBytes(nonce)
    val c = Cipher.getInstance("AES/GCM/NoPadding")
    c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aes(req.getKeyId), "AES"), new GCMParameterSpec(128, nonce))
    val out = Array[Byte](1) ++ nonce ++ c.doFinal(req.getData.toByteArray)
    SymmetricReply.newBuilder().setData(ByteString.copyFrom(out)).build()
  }

  override def symmetricDecrypt(req: SymmetricRequest, obs: StreamObserver[SymmetricReply]): Unit = reply(obs) {
    val blob = req.getData.toByteArray
    if (blob.length < 13 || blob(0) != 1) throw Status.INVALID_ARGUMENT.asRuntimeException()
    val c = Cipher.getInstance("AES/GCM/NoPadding")
    c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aes(req.getKeyId), "AES"), new GCMParameterSpec(128, blob.slice(1, 13)))
    val pt =
      try c.doFinal(blob.drop(13))
      catch { case _: GeneralSecurityException => throw Status.INVALID_ARGUMENT.asRuntimeException() }
    SymmetricReply.newBuilder().setData(ByteString.copyFrom(pt)).build()
  }
}

object CryptoFakeCluster {

  /** A running in-process server for `fake`, and a FrostBackend (hosted keys on, no delegate)
    * pointed at it. */
  final class Running(val fake: CryptoFakeCluster, val backend: FrostBackend, server: Server) extends AutoCloseable {
    override def close(): Unit =
      try backend.close()
      finally server.shutdownNow()
  }

  def start(fake: CryptoFakeCluster, logger: Logger, keyPrefix: String = "")(implicit ec: ExecutionContext): Running = {
    val name = InProcessServerBuilder.generateName()
    val server = InProcessServerBuilder.forName(name).directExecutor().addService(fake).build().start()
    val backend =
      new FrostBackend(Seq(name), new NoDelegateBackend, logger, None, 30.seconds, hostedKeys = true, keyPrefix = keyPrefix) {
        override protected def buildChannel(endpoint: String): io.grpc.ManagedChannel =
          InProcessChannelBuilder.forName(endpoint).directExecutor().build()
      }
    new Running(fake, backend, server)
  }
}
