// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli.backend

import com.digitalasset.canton.crypto.kms.driver.api.v1._
import com.stakecraft.rutli.CryptoFakeCluster
import com.stakecraft.rutli.audit.AuditNotes
import com.stakecraft.rutli.grpc._
import io.grpc.inprocess.{InProcessChannelBuilder, InProcessServerBuilder}
import io.grpc.stub.StreamObserver
import io.grpc.{Server, Status}
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

/** Review findings M1(a), L1, L4, L5 on the driver side:
  *   - ECIES is advertised only when every configured cosigner reports `ec-p256-ecies`;
  *   - the first Capabilities probe retries silent cosigners, an unconfirmed result is not cached
  *     forever, and a later confirmation is picked up;
  *   - a decryption failure after a successful EcdhDerive is noted in the operation's audit entry;
  *   - an EC public key from the cluster must be exactly a named-curve P-256 SPKI.
  */
class FrostCapabilitiesSpec extends AnyWordSpec with Matchers {

  private implicit val ec: ExecutionContext = ExecutionContext.global
  private val logger = LoggerFactory.getLogger(classOf[FrostCapabilitiesSpec])
  private def await[T](f: Future[T]): T = Await.result(f, 30.seconds)

  private val Ecies = EncryptionAlgoSpec.EciesHkdfHmacSha256Aes128Cbc
  private val New = Seq("rsa-2048-oaep-sha256", "aes-256-gcm", "ec-p256-ecies")
  private val Old = Seq("rsa-2048-oaep-sha256", "aes-256-gcm")

  /** A crypto-faithful fake that fails its first `failFirst` Capabilities calls with UNAVAILABLE. */
  private class Flaky(specs: Seq[String], failFirst: Int) extends CryptoFakeCluster(specs) {
    val capabilityCalls = new AtomicInteger
    override def capabilities(req: CapabilitiesRequest, obs: StreamObserver[CapabilitiesReply]): Unit =
      if (capabilityCalls.incrementAndGet() <= failFirst) obs.onError(Status.UNAVAILABLE.asRuntimeException())
      else super.capabilities(req, obs)
  }

  private def serve(name: String, fake: CryptoFakeCluster): Server =
    InProcessServerBuilder.forName(name).directExecutor().addService(fake).build().start()

  private def backend(names: Seq[String], budget: FiniteDuration = 5.seconds, requery: FiniteDuration = 60.seconds) =
    new FrostBackend(
      names,
      new NoDelegateBackend,
      logger,
      None,
      10.seconds,
      hostedKeys = true,
      capabilitiesRetryBudget = budget,
      capabilitiesRequery = requery,
    ) {
      override protected def buildChannel(endpoint: String): io.grpc.ManagedChannel =
        InProcessChannelBuilder.forName(endpoint).directExecutor().build()
    }

  private def withServers[A](fakes: Seq[CryptoFakeCluster])(body: Seq[String] => A): A = {
    val names = fakes.map(_ => InProcessServerBuilder.generateName())
    val servers = names.zip(fakes).map { case (n, f) => serve(n, f) }
    try body(names)
    finally servers.foreach(_.shutdownNow())
  }

  "ECIES advertisement (review M1a)" should {

    "require every configured cosigner to report ec-p256-ecies" in {
      withServers(Seq(new CryptoFakeCluster(New), new CryptoFakeCluster(Old), new CryptoFakeCluster(New))) { names =>
        val b = backend(names)
        try {
          b.supportedEncryptionKeySpecs shouldBe Set(EncryptionKeySpec.Rsa2048)
          b.supportedEncryptionAlgoSpecs shouldBe Set(EncryptionAlgoSpec.RsaEsOaepSha256)
          // And nothing routes an EC key to the cluster: it goes to the (refusing) delegate.
          an[UnsupportedOperationException] should be thrownBy
            await(b.generateEncryptionKeyPair(EncryptionKeySpec.EcP256, None))
        } finally b.close()
      }
      withServers(Seq.fill(3)(new CryptoFakeCluster(New))) { names =>
        val b = backend(names)
        try {
          b.supportedEncryptionKeySpecs shouldBe Set(EncryptionKeySpec.Rsa2048, EncryptionKeySpec.EcP256)
          b.supportedEncryptionAlgoSpecs should contain(Ecies)
        } finally b.close()
      }
    }

    "count a cosigner without Capabilities as RSA + AES only" in {
      val ancient = new CryptoFakeCluster(New) {
        override def capabilities(req: CapabilitiesRequest, obs: StreamObserver[CapabilitiesReply]): Unit =
          obs.onError(Status.UNIMPLEMENTED.asRuntimeException())
      }
      withServers(Seq(new CryptoFakeCluster(New), ancient)) { names =>
        val b = backend(names)
        try b.supportedEncryptionKeySpecs shouldBe Set(EncryptionKeySpec.Rsa2048)
        finally b.close()
      }
    }
  }

  "the Capabilities probe (review L1)" should {

    "retry a cosigner that is briefly unavailable at startup" in {
      val flaky = new Flaky(New, failFirst = 2)
      withServers(Seq(new CryptoFakeCluster(New), flaky)) { names =>
        val b = backend(names, budget = 10.seconds)
        try {
          b.supportedEncryptionKeySpecs should contain(EncryptionKeySpec.EcP256)
          flaky.capabilityCalls.get shouldBe 3
        } finally b.close()
      }
    }

    "fall back without EC when a cosigner stays silent, and pick it up once it answers" in {
      val up = new CryptoFakeCluster(New)
      val upName = InProcessServerBuilder.generateName()
      val laterName = InProcessServerBuilder.generateName() // nothing serves this yet
      val upServer = serve(upName, up)
      var later: Option[Server] = None
      val b = backend(Seq(upName, laterName), budget = 300.millis, requery = 200.millis)
      try {
        val started = System.nanoTime()
        b.supportedEncryptionKeySpecs shouldBe Set(EncryptionKeySpec.Rsa2048)
        (System.nanoTime() - started).nanos should be >= 300.millis // the budget was spent retrying
        // Not cached forever: once the silent cosigner answers, the next use after the re-query
        // interval sees ECIES, and an EC key is generated on the cluster rather than refused.
        later = Some(serve(laterName, new CryptoFakeCluster(New)))
        // gRPC's reconnect backoff on the channel to the once-missing name decides when the
        // re-query can reach it; keep asking (each attempt after the re-query interval) for a while.
        val until = System.nanoTime() + 15.seconds.toNanos
        def attempt(): String =
          scala.util.Try(await(b.generateEncryptionKeyPair(EncryptionKeySpec.EcP256, None))) match {
            case scala.util.Success(id) => id
            case scala.util.Failure(_) if System.nanoTime() < until => Thread.sleep(250); attempt()
            case scala.util.Failure(e) => throw e
          }
        val keyId = attempt()
        keyId should startWith("rutli-enc-")
        await(b.getPublicKey(keyId)).spec shouldBe EncryptionKeySpec.EcP256
      } finally {
        b.close()
        upServer.shutdownNow()
        later.foreach(_.shutdownNow())
      }
    }

    "not re-probe before the re-query interval" in {
      val flaky = new Flaky(New, failFirst = Int.MaxValue)
      withServers(Seq(new CryptoFakeCluster(New), flaky)) { names =>
        val b = backend(names, budget = 50.millis, requery = 1.hour)
        try {
          b.supportedEncryptionKeySpecs shouldBe Set(EncryptionKeySpec.Rsa2048)
          val probes = flaky.capabilityCalls.get
          (1 to 5).foreach(_ => b.supportedEncryptionKeySpecs)
          flaky.capabilityCalls.get shouldBe probes
        } finally b.close()
      }
    }
  }

  "an ECIES failure the cluster cannot see (review L4)" should {

    "be noted in the operation's audit entry" in {
      val running = CryptoFakeCluster.start(new CryptoFakeCluster, logger)
      try {
        val keyId = await(running.backend.generateEncryptionKeyPair(EncryptionKeySpec.EcP256, None))
        val iv = new Array[Byte](16)
        new SecureRandom().nextBytes(iv)
        val c = Cipher.getInstance("ECIESwithSHA256andAES-CBC", new org.bouncycastle.jce.provider.BouncyCastleProvider)
        c.init(Cipher.ENCRYPT_MODE, running.fake.ecKey(keyId).getPublic, new IESParameterSpec(Array[Byte](), Array[Byte](), 512, 128, iv))
        val blob = iv ++ c.doFinal("x".getBytes)
        blob(blob.length - 1) = (blob(blob.length - 1) ^ 1).toByte

        val afterEcdh = new AuditNotes
        an[CantonEcies.EciesException] should be thrownBy
          await(running.backend.withAuditNotes(afterEcdh)(running.backend.decryptAsymmetric(blob, keyId, Ecies)))
        afterEcdh.render should include("ecies-failure=after-ecdh")

        val shape = new AuditNotes
        an[CantonEcies.EciesException] should be thrownBy
          await(running.backend.withAuditNotes(shape)(running.backend.decryptAsymmetric(blob.drop(1), keyId, Ecies)))
        shape.render should include("ecies-failure=shape")
      } finally running.close()
    }
  }

  "an EC public key from the cluster (review L5)" should {

    def spki(curve: String): Array[Byte] = {
      val g = KeyPairGenerator.getInstance("EC")
      g.initialize(new ECGenParameterSpec(curve))
      g.generateKeyPair().getPublic.getEncoded
    }

    "be exactly a named-curve P-256 SPKI with an uncompressed point" in {
      val good = spki("secp256r1")
      FrostBackend.hostedPublicKey("k", "ec-p256-ecies", good).spec shouldBe EncryptionKeySpec.EcP256
      good.take(27) shouldBe FrostBackend.P256SpkiPrefix

      val wrongOid = good.clone(); wrongOid(22) = 0x08 // prime256v1 -> another OID, same length
      val compressed = good.take(23) ++ Array[Byte](0x03, 0x22, 0x00, 0x02) ++ good.slice(27, 59) // 0x02 ‖ X
      for ((what, bad) <- Seq(
             "P-384" -> spki("secp384r1"),
             "other curve OID" -> wrongOid,
             "compressed point" -> compressed,
             "trailing byte" -> (good :+ 0.toByte),
             "garbage" -> Array[Byte](1, 2, 3),
           ))
        withClue(what) {
          an[IllegalStateException] should be thrownBy FrostBackend.hostedPublicKey("k", "ec-p256-ecies", bad)
        }
    }
  }
}
