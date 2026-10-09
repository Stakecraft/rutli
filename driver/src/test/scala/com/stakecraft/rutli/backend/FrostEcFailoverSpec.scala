// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli.backend

import com.digitalasset.canton.crypto.kms.driver.api.v1._
import com.stakecraft.rutli.CryptoFakeCluster
import com.stakecraft.rutli.grpc._
import io.grpc.inprocess.{InProcessChannelBuilder, InProcessServerBuilder}
import io.grpc.stub.StreamObserver
import io.grpc.{Server, Status, StatusRuntimeException}
import org.bouncycastle.jce.spec.IESParameterSpec
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import org.slf4j.LoggerFactory

import java.security.spec.ECGenParameterSpec
import java.security.{KeyPairGenerator, SecureRandom}
import java.util.concurrent.atomic.AtomicInteger
import javax.crypto.Cipher
import scala.concurrent.duration._
import scala.concurrent.{Await, ExecutionContext, Future}

/** Run-time failover for EC hosted keys (2026-10-09 decision on review M1): a silent cosigner no
  * longer stops the driver advertising ECIES, so a node that turns out to predate `ec-p256-ecies`
  * (or to lack the key) must not be able to answer for an EC key. Its tell-tale answers —
  * UNIMPLEMENTED/NOT_FOUND from EcdhDerive, NOT_FOUND from PublicKey, `exists = false` from KeyInfo —
  * move the request to the next cosigner and do not make that node the preferred leader. For any
  * other key type nothing changes.
  *
  * The roster is [old, current]: `old` is listed first, so it leads every first attempt.
  */
class FrostEcFailoverSpec extends AnyWordSpec with Matchers {

  private implicit val ec: ExecutionContext = ExecutionContext.global
  private val logger = LoggerFactory.getLogger(classOf[FrostEcFailoverSpec])
  private def await[T](f: Future[T]): T = Await.result(f, 30.seconds)
  private val Ecies = EncryptionAlgoSpec.EciesHkdfHmacSha256Aes128Cbc

  /** The up-to-date cosigner: real crypto, with call counters. */
  private final class Current extends CryptoFakeCluster {
    val publicKeyCalls = new AtomicInteger
    val keyInfoCalls = new AtomicInteger
    override def publicKey(req: PublicKeyRequest, obs: StreamObserver[PublicKeyReply]): Unit = {
      publicKeyCalls.incrementAndGet(); super.publicKey(req, obs)
    }
    override def keyInfo(req: KeyInfoRequest, obs: StreamObserver[KeyInfoReply]): Unit = {
      keyInfoCalls.incrementAndGet(); super.keyInfo(req, obs)
    }
  }

  /** A cosigner from before `ec-p256-ecies`, in front of the same key material: it serves RSA as
    * usual, cannot see EC keys (NOT_FOUND / exists=false), and has no EcdhDerive (UNIMPLEMENTED).
    * `missingEverything` makes it answer NOT_FOUND for every PublicKey, `ecdhNotFound` NOT_FOUND
    * instead of UNIMPLEMENTED. */
  private final class Old(real: CryptoFakeCluster) extends SignerGrpc.SignerImplBase {
    val publicKeyCalls, keyInfoCalls, ecdhCalls = new AtomicInteger
    @volatile var missingEverything = false
    @volatile var ecdhNotFound = false
    private def isEc(id: String) = real.specOf(id).contains("ec-p256-ecies")
    override def capabilities(req: CapabilitiesRequest, obs: StreamObserver[CapabilitiesReply]): Unit = {
      obs.onNext(
        CapabilitiesReply.newBuilder().setHostedKeysEnabled(true).addHostedKeySpecs("rsa-2048-oaep-sha256")
          .addHostedKeySpecs("aes-256-gcm").build()
      )
      obs.onCompleted()
    }
    override def generateKey(req: GenerateKeyRequest, obs: StreamObserver[GenerateKeyReply]): Unit =
      real.generateKey(req, obs)
    override def publicKey(req: PublicKeyRequest, obs: StreamObserver[PublicKeyReply]): Unit = {
      publicKeyCalls.incrementAndGet()
      if (missingEverything || isEc(req.getKeyId)) obs.onError(Status.NOT_FOUND.asRuntimeException())
      else real.publicKey(req, obs)
    }
    override def keyInfo(req: KeyInfoRequest, obs: StreamObserver[KeyInfoReply]): Unit = {
      keyInfoCalls.incrementAndGet()
      if (isEc(req.getKeyId)) { obs.onNext(KeyInfoReply.newBuilder().setExists(false).build()); obs.onCompleted() }
      else real.keyInfo(req, obs)
    }
    override def ecdhDerive(req: EcdhDeriveRequest, obs: StreamObserver[EcdhDeriveReply]): Unit = {
      ecdhCalls.incrementAndGet()
      obs.onError((if (ecdhNotFound) Status.NOT_FOUND else Status.UNIMPLEMENTED).asRuntimeException())
    }
    override def decrypt(req: DecryptRequest, obs: StreamObserver[DecryptReply]): Unit = real.decrypt(req, obs)
  }

  private final class Rig extends AutoCloseable {
    val current = new Current
    val old = new Old(current)
    private val names = Seq(InProcessServerBuilder.generateName(), InProcessServerBuilder.generateName())
    private val servers: Seq[Server] = names.zip(Seq[io.grpc.BindableService](old, current)).map { case (n, s) =>
      InProcessServerBuilder.forName(n).directExecutor().addService(s).build().start()
    }
    private var backends = List.empty[FrostBackend]
    /** A fresh backend (no learned specs, `old` preferred). */
    def backend(): FrostBackend = {
      val b = new FrostBackend(names, new NoDelegateBackend, logger, None, 10.seconds, hostedKeys = true) {
        override protected def buildChannel(endpoint: String): io.grpc.ManagedChannel =
          InProcessChannelBuilder.forName(endpoint).directExecutor().build()
      }
      backends ::= b
      b
    }
    def ecKey(id: String): java.security.KeyPair = {
      val g = KeyPairGenerator.getInstance("EC")
      g.initialize(new ECGenParameterSpec("secp256r1"))
      val kp = g.generateKeyPair()
      current.putEcKey(id, kp)
      kp
    }
    override def close(): Unit = { backends.foreach(_.close()); servers.foreach(_.shutdownNow()) }
  }

  private def withRig[A](body: Rig => A): A = { val r = new Rig; try body(r) finally r.close() }

  private def cantonEncrypt(pub: java.security.PublicKey, msg: Array[Byte]): Array[Byte] = {
    val iv = new Array[Byte](16)
    new SecureRandom().nextBytes(iv)
    val c = Cipher.getInstance("ECIESwithSHA256andAES-CBC", new org.bouncycastle.jce.provider.BouncyCastleProvider)
    c.init(Cipher.ENCRYPT_MODE, pub, new IESParameterSpec(Array[Byte](), Array[Byte](), 512, 128, iv))
    iv ++ c.doFinal(msg)
  }

  private def code(t: => Any): Status.Code =
    (the[StatusRuntimeException] thrownBy t).getStatus.getCode

  "an EC hosted key behind an old cosigner" should {

    "fail over on EcdhDerive UNIMPLEMENTED and on NOT_FOUND" in withRig { r =>
      val kp = r.ecKey("rutli-enc-ec")
      val b = r.backend()
      val msg = "through the current node".getBytes
      await(b.decryptAsymmetric(cantonEncrypt(kp.getPublic, msg), "rutli-enc-ec", Ecies)) shouldBe msg
      r.old.ecdhCalls.get shouldBe 1
      r.current.ecdhCalls.get shouldBe 1

      r.old.ecdhNotFound = true
      val b2 = r.backend()
      await(b2.decryptAsymmetric(cantonEncrypt(kp.getPublic, msg), "rutli-enc-ec", Ecies)) shouldBe msg
      r.old.ecdhCalls.get shouldBe 2
    }

    "fail over on PublicKey NOT_FOUND, learn the spec, and not make the old node preferred" in withRig { r =>
      r.ecKey("rutli-enc-ec")
      val b = r.backend()
      await(b.getPublicKey("rutli-enc-ec")).spec shouldBe EncryptionKeySpec.EcP256
      r.old.publicKeyCalls.get shouldBe 1
      // The current node led successfully and is now preferred: the old one is not asked again.
      await(b.keyExistsAndIsActive("rutli-enc-ec"))
      await(b.getPublicKey("rutli-enc-ec"))
      r.old.publicKeyCalls.get shouldBe 1
      r.old.keyInfoCalls.get shouldBe 0
    }

    "fail over on KeyInfo exists=false" in withRig { r =>
      r.ecKey("rutli-enc-ec")
      val b = r.backend()
      await(b.keyExistsAndIsActive("rutli-enc-ec"))
      r.old.keyInfoCalls.get shouldBe 1
      r.current.keyInfoCalls.get shouldBe 1
    }

    "still report a key that no cosigner has as missing" in withRig { r =>
      val b = r.backend()
      code(await(b.getPublicKey("rutli-enc-nowhere"))) shouldBe Status.Code.NOT_FOUND
      an[NoSuchElementException] should be thrownBy await(b.keyExistsAndIsActive("rutli-enc-nowhere"))
    }
  }

  "an RSA hosted key" should {

    "keep NOT_FOUND authoritative once the driver knows the key is RSA" in withRig { r =>
      val b = r.backend()
      val rsa = await(b.generateEncryptionKeyPair(EncryptionKeySpec.Rsa2048, None)) // spec learned
      r.old.missingEverything = true
      val before = r.current.publicKeyCalls.get
      code(await(b.getPublicKey(rsa))) shouldBe Status.Code.NOT_FOUND
      r.current.publicKeyCalls.get shouldBe before // no failover
    }

    "keep the first NOT_FOUND as the answer when another node reveals the key is RSA" in withRig { r =>
      val rsa = await(r.backend().generateEncryptionKeyPair(EncryptionKeySpec.Rsa2048, None))
      r.old.missingEverything = true
      val fresh = r.backend() // has not learned the spec
      code(await(fresh.getPublicKey(rsa))) shouldBe Status.Code.NOT_FOUND
    }
  }
}
