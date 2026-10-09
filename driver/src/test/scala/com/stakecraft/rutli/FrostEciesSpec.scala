// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli

import com.digitalasset.canton.crypto.kms.driver.api.v1._
import com.google.protobuf.ByteString
import com.stakecraft.rutli.backend.CantonEcies
import com.stakecraft.rutli.grpc._
import io.grpc.Status
import io.grpc.stub.StreamObserver
import io.opentelemetry.context.Context
import org.bouncycastle.jce.spec.IESParameterSpec
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import org.slf4j.LoggerFactory

import java.math.BigInteger
import java.security.interfaces.{ECPrivateKey, ECPublicKey}
import java.security.spec.{ECPoint, ECPrivateKeySpec, ECPublicKeySpec}
import java.security.{KeyFactory, KeyPair, PublicKey => JPublicKey, SecureRandom}
import javax.crypto.{Cipher, KeyAgreement}
import scala.concurrent.duration._
import scala.concurrent.{Await, ExecutionContext, Future}
import scala.util.Try

/** ECIES (`EciesHkdfHmacSha256Aes128Cbc`) through a cluster-hosted P-256 key — milestone C2/C3.
  *
  * The encryptor is BouncyCastle's JCE cipher configured exactly as Canton 3.6.1's
  * `JcePureCrypto.encryptWithEciesP256HmacSha256Aes128Cbc` does it (`ECIESwithSHA256andAES-CBC`,
  * `IESParameterSpec([], [], 512, 128, iv)`, IV prepended). The ECDH is the fake cluster's, on the
  * JDK's own SunEC, and the rest is the driver's `IESEngine` completion — so a pass means three
  * independent pieces agree byte for byte. With `CONFORMANCE=1` the upstream suite repeats the
  * round trip with Canton's real `JcePureCrypto` ([[RutliDriverFrostConformanceTest]]).
  */
class FrostEciesSpec extends AnyWordSpec with Matchers {

  private implicit val ec: ExecutionContext = ExecutionContext.global
  private val logger = LoggerFactory.getLogger(classOf[FrostEciesSpec])
  private def await[T](f: Future[T]): T = Await.result(f, 30.seconds)
  private val bc = new org.bouncycastle.jce.provider.BouncyCastleProvider
  private val rnd = new SecureRandom()
  private val Ecies = EncryptionAlgoSpec.EciesHkdfHmacSha256Aes128Cbc

  /** Canton's encryptor, verbatim in effect (JcePureCrypto.scala:521-565 with 146-165). */
  private def cantonEncrypt(pub: JPublicKey, plaintext: Array[Byte]): Array[Byte] = {
    val iv = new Array[Byte](16)
    rnd.nextBytes(iv)
    val c = Cipher.getInstance("ECIESwithSHA256andAES-CBC", bc)
    c.init(Cipher.ENCRYPT_MODE, pub, new IESParameterSpec(Array[Byte](), Array[Byte](), 512, 128, iv), rnd)
    iv ++ c.doFinal(plaintext)
  }

  /** Canton's decryptor (JcePureCrypto.scala:695-750), as the reference for the differential. */
  private def cantonDecrypt(kp: KeyPair, blob: Array[Byte]): Try[Array[Byte]] = Try {
    val c = Cipher.getInstance("ECIESwithSHA256andAES-CBC", bc)
    c.init(Cipher.DECRYPT_MODE, kp.getPrivate, new IESParameterSpec(Array[Byte](), Array[Byte](), 512, 128, blob.take(16)))
    c.doFinal(blob.drop(16))
  }

  private def jcaZ(kp: KeyPair, point: Array[Byte]): Array[Byte] = {
    val params = kp.getPublic.asInstanceOf[ECPublicKey].getParams
    val w = new ECPoint(new BigInteger(1, point.slice(1, 33)), new BigInteger(1, point.slice(33, 65)))
    val ka = KeyAgreement.getInstance("ECDH")
    ka.init(kp.getPrivate)
    ka.doPhase(KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(w, params)), true)
    ka.generateSecret()
  }

  private def withEcKey[A](body: (CryptoFakeCluster.Running, String, KeyPair) => A): A = {
    val running = CryptoFakeCluster.start(new CryptoFakeCluster, logger)
    try {
      val keyId = await(running.backend.generateEncryptionKeyPair(EncryptionKeySpec.EcP256, Some("enc")))
      body(running, keyId, running.fake.ecKey(keyId))
    } finally running.close()
  }

  private def hex(s: String): Array[Byte] = s.grouped(2).map(Integer.parseInt(_, 16).toByte).toArray

  "the frost backend's ECIES support" should {

    "advertise EcP256 and ECIES only when the cluster reports ec-p256-ecies" in {
      val withEc = CryptoFakeCluster.start(new CryptoFakeCluster, logger)
      try {
        withEc.backend.supportedEncryptionKeySpecs should contain(EncryptionKeySpec.EcP256)
        withEc.backend.supportedEncryptionAlgoSpecs should contain(Ecies)
        withEc.backend.supportedEncryptionKeySpecs should contain(EncryptionKeySpec.Rsa2048)
      } finally withEc.close()

      val rsaOnly = CryptoFakeCluster.start(new CryptoFakeCluster(Seq("rsa-2048-oaep-sha256", "aes-256-gcm")), logger)
      try {
        rsaOnly.backend.supportedEncryptionKeySpecs shouldBe Set(EncryptionKeySpec.Rsa2048)
        rsaOnly.backend.supportedEncryptionAlgoSpecs shouldBe Set(EncryptionAlgoSpec.RsaEsOaepSha256)
      } finally rsaOnly.close()

      // An older cluster without Capabilities: the fallback never includes EC (it could not serve
      // EcdhDerive).
      val old = new CryptoFakeCluster {
        override def capabilities(req: CapabilitiesRequest, obs: StreamObserver[CapabilitiesReply]): Unit =
          obs.onError(Status.UNIMPLEMENTED.asRuntimeException())
      }
      val r = CryptoFakeCluster.start(old, logger)
      try r.backend.supportedEncryptionKeySpecs should not contain EncryptionKeySpec.EcP256
      finally r.close()
    }

    "mint the key type Canton asks for and report its real spec" in withEcKey { (r, keyId, kp) =>
      keyId should startWith("rutli-enc-enc-")
      val pk = await(r.backend.getPublicKey(keyId))
      pk.spec shouldBe EncryptionKeySpec.EcP256
      pk.key shouldBe kp.getPublic.getEncoded
      // RSA stays what it was.
      val rsaId = await(r.backend.generateEncryptionKeyPair(EncryptionKeySpec.Rsa2048, None))
      await(r.backend.getPublicKey(rsaId)).spec shouldBe EncryptionKeySpec.Rsa2048
    }

    "decrypt what Canton encrypts, for every plaintext length up to the 256-byte bound" in withEcKey { (r, keyId, kp) =>
      CantonEcies.MaxPlaintextLength shouldBe 127
      val lengths = (0 to CantonEcies.MaxPlaintextLength) ++ Seq.fill(300)(rnd.nextInt(CantonEcies.MaxPlaintextLength + 1))
      lengths.foreach { n =>
        val msg = new Array[Byte](n)
        rnd.nextBytes(msg)
        val blob = cantonEncrypt(kp.getPublic, msg)
        blob.length should be <= CantonEcies.MaxCiphertextLength
        val out = await(r.backend.decryptAsymmetric(blob, keyId, Ecies))
        out shouldBe msg
        out shouldBe cantonDecrypt(kp, blob).get
      }
    }

    "refuse a ciphertext over Canton's 256-byte bound without asking the cluster" in withEcKey { (r, keyId, kp) =>
      val blob = cantonEncrypt(kp.getPublic, new Array[Byte](CantonEcies.MaxPlaintextLength + 1))
      blob.length shouldBe 257
      val before = r.fake.ecdhCalls.get
      an[CantonEcies.EciesException] should be thrownBy await(r.backend.decryptAsymmetric(blob, keyId, Ecies))
      r.fake.ecdhCalls.get shouldBe before
    }

    "refuse malformed shapes before any cluster call" in withEcKey { (r, keyId, kp) =>
      val blob = cantonEncrypt(kp.getPublic, "session key".getBytes)
      val v = blob.slice(16, 81)
      val compressed = blob.take(16) ++ Array[Byte]((2 + (v(64) & 1)).toByte) ++ v.slice(1, 33) ++ blob.drop(81)
      val hybrid = blob.clone(); hybrid(16) = (6 + (v(64) & 1)).toByte
      val offCurve = blob.clone(); offCurve(80) = (offCurve(80) ^ 1).toByte
      val zeroPoint = blob.clone(); java.util.Arrays.fill(zeroPoint, 17, 81, 0.toByte)
      val cases = Seq(
        "empty"                -> Array.emptyByteArray,
        "truncated by one"     -> blob.dropRight(1),
        "one byte too long"    -> (blob :+ 0.toByte),
        "no ciphertext block"  -> (blob.take(81) ++ blob.takeRight(32)),
        "partial block"        -> (blob.take(81) ++ blob.slice(81, 89) ++ blob.takeRight(32)),
        "compressed point"     -> compressed,
        "hybrid point"         -> hybrid,
        "point off the curve"  -> offCurve,
        "(0,0)"                -> zeroPoint,
      )
      val before = r.fake.ecdhCalls.get
      cases.foreach { case (what, bad) =>
        withClue(what) {
          an[CantonEcies.EciesException] should be thrownBy await(r.backend.decryptAsymmetric(bad, keyId, Ecies))
          cantonDecrypt(kp, bad).isFailure shouldBe true
        }
      }
      r.fake.ecdhCalls.get shouldBe before
    }

    "fail on a tampered V, ciphertext or tag, as Canton's own decryptor does" in withEcKey { (r, keyId, kp) =>
      val msg = new Array[Byte](100)
      rnd.nextBytes(msg)
      val blob = cantonEncrypt(kp.getPublic, msg)
      // V replaced by another valid point (the key's own public point): a different Z, so the MAC
      // fails. A bit flip in V usually leaves the curve and is refused earlier (above).
      val ownPoint = r.fake.ecKey(keyId).getPublic.getEncoded.takeRight(65)
      val otherV = blob.take(16) ++ ownPoint ++ blob.drop(81)
      val tampered = Seq("V" -> otherV) ++
        Seq(81, 100, blob.length - 33).map(i => s"ciphertext[$i]" -> flip(blob, i)) ++
        Seq(blob.length - 32, blob.length - 1).map(i => s"tag[$i]" -> flip(blob, i))
      tampered.foreach { case (what, bad) =>
        withClue(what) {
          val e = the[CantonEcies.EciesException] thrownBy await(r.backend.decryptAsymmetric(bad, keyId, Ecies))
          e.getMessage shouldBe "ECIES decryption failed" // one answer for every cryptographic failure
          cantonDecrypt(kp, bad).isFailure shouldBe true
        }
      }
    }

    "treat the unauthenticated IV exactly as Canton does (CBC malleability of the first block)" in withEcKey {
      (r, keyId, kp) =>
        // Canton's ECIES MACs only the CBC ciphertext: the IV it prepends is outside the tag. A
        // flipped IV bit therefore flips the same bit of the first plaintext block, and BouncyCastle's
        // own decryptor accepts it. The driver must agree with Canton byte for byte, so it does too
        // — this pins that upstream property rather than hiding it (docs/hosted-keys-design.md).
        val msg = new Array[Byte](40)
        rnd.nextBytes(msg)
        val blob = cantonEncrypt(kp.getPublic, msg)
        val bad = flip(blob, 3)
        val reference = cantonDecrypt(kp, bad).get
        await(r.backend.decryptAsymmetric(bad, keyId, Ecies)) shouldBe reference
        reference shouldBe flip(msg, 3)
    }

    "reach the KDF with all 32 bytes of a Z that starts with zero" in withEcKey { (r, keyId, kp) =>
      // ~1 in 256 ephemeral keys gives a Z with a leading zero byte; BigInteger drops it unless it
      // is padded back to the field size, which is the bug this pins.
      val msg = "leading zero".getBytes
      val blob = Iterator
        .continually(cantonEncrypt(kp.getPublic, msg))
        .find(b => jcaZ(kp, b.slice(16, 81))(0) == 0)
        .get
      await(r.backend.decryptAsymmetric(blob, keyId, Ecies)) shouldBe msg
    }

    "agree on Z with the cosigner's known-answer vector" in {
      // The vector of frost/cosigner/src/hosted.rs (independent Python P-256): the JDK's ECDH
      // gives the same Z, so aws-lc (cluster), Python and SunEC (this fake) agree.
      val d = new BigInteger("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721", 16)
      val q = hex(
        "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6" +
          "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299"
      )
      val v = hex(
        "041f5efe3b2928f7db57c6befca0428a5833ea10b2e70fada8ccf40478c29bbcdb" +
          "3a143c9e3f9982325a7750a8b095d0b3feaf12fd01ef6172739b82e9ec62c421"
      )
      val gen = java.security.KeyPairGenerator.getInstance("EC")
      gen.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"))
      val params = gen.generateKeyPair().getPublic.asInstanceOf[ECPublicKey].getParams
      val kf = KeyFactory.getInstance("EC")
      val priv = kf.generatePrivate(new ECPrivateKeySpec(d, params)).asInstanceOf[ECPrivateKey]
      val pub = kf.generatePublic(
        new ECPublicKeySpec(new ECPoint(new BigInteger(1, q.slice(1, 33)), new BigInteger(1, q.slice(33, 65))), params)
      )
      val kp = new KeyPair(pub, priv)

      val fake = new CryptoFakeCluster
      val r = CryptoFakeCluster.start(fake, logger)
      try {
        fake.putEcKey("rutli-enc-kat", kp)
        jcaZ(kp, v).map("%02x".format(_)).mkString shouldBe
          "605c4045e713174af954ea4740a93c48b42298ab59425be60430752ace33dc1e"
        val msg = "known answer".getBytes
        await(r.backend.decryptAsymmetric(cantonEncrypt(pub, msg), "rutli-enc-kat", Ecies)) shouldBe msg
      } finally r.close()
    }

    "refuse a shared secret that is the wrong length or the wrong value" in {
      for (z <- Seq(new Array[Byte](31), new Array[Byte](33), new Array[Byte](32))) {
        val liar = new CryptoFakeCluster {
          override def ecdhDerive(req: EcdhDeriveRequest, obs: StreamObserver[EcdhDeriveReply]): Unit = {
            obs.onNext(EcdhDeriveReply.newBuilder().setSharedSecret(ByteString.copyFrom(z)).build())
            obs.onCompleted()
          }
        }
        val r = CryptoFakeCluster.start(liar, logger)
        try {
          val keyId = await(r.backend.generateEncryptionKeyPair(EncryptionKeySpec.EcP256, None))
          val blob = cantonEncrypt(liar.ecKey(keyId).getPublic, "x".getBytes)
          an[CantonEcies.EciesException] should be thrownBy await(r.backend.decryptAsymmetric(blob, keyId, Ecies))
        } finally r.close()
      }
    }

    "never decrypt ECIES with an RSA key, nor RSA with an EC key" in withEcKey { (r, ecId, kp) =>
      val rsaId = await(r.backend.generateEncryptionKeyPair(EncryptionKeySpec.Rsa2048, None))
      val blob = cantonEncrypt(kp.getPublic, "x".getBytes)
      val e = the[io.grpc.StatusRuntimeException] thrownBy await(r.backend.decryptAsymmetric(blob, rsaId, Ecies))
      e.getStatus.getCode shouldBe Status.Code.FAILED_PRECONDITION
      val e2 = the[io.grpc.StatusRuntimeException] thrownBy
        await(r.backend.decryptAsymmetric(new Array[Byte](256), ecId, EncryptionAlgoSpec.RsaEsOaepSha256))
      e2.getStatus.getCode shouldBe Status.Code.FAILED_PRECONDITION
    }

    "surface a refusal to Canton as a non-retryable KmsDriverException" in withEcKey { (r, keyId, kp) =>
      val driver = new RutliDriver(
        r.backend,
        logger,
        auditLogging = true,
        auditLog = None,
        new com.stakecraft.rutli.policy.ApprovalGate {
          override def authorize(keyId: String, data: Array[Byte]): Future[Unit] = Future.unit
        },
        signingJournal = None,
        r.backend.supportedSigningKeySpecs,
        r.backend.supportedSigningAlgoSpecs,
        r.backend.supportedEncryptionKeySpecs,
        r.backend.supportedEncryptionAlgoSpecs,
      )
      val ctx = Context.root()
      val msg = "through the SPI".getBytes
      val blob = cantonEncrypt(kp.getPublic, msg)
      await(driver.decryptAsymmetric(blob, keyId, Ecies)(ctx)) shouldBe msg
      val e = the[KmsDriverException] thrownBy await(driver.decryptAsymmetric(flip(blob, blob.length - 1), keyId, Ecies)(ctx))
      e.retryable shouldBe false
    }
  }

  private def flip(a: Array[Byte], i: Int): Array[Byte] = {
    val b = a.clone()
    b(i) = (b(i) ^ 1).toByte
    b
  }
}
