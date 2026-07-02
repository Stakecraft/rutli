// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli

import com.digitalasset.canton.crypto.kms.driver.api.v1._
import io.opentelemetry.context.Context
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.security.spec.X509EncodedKeySpec
import java.security.{KeyFactory, Security, Signature => JSignature}
import java.util.ServiceLoader
import javax.crypto.Cipher
import scala.concurrent.duration._
import scala.concurrent.{Await, ExecutionContext, Future}
import scala.jdk.CollectionConverters._

/** Self-contained spec for the Phase 0 driver (no Canton test artifacts required).
  *
  * The important assertions verify signatures with providers OTHER than the one that produced them
  * (BouncyCastle signs; the stock JDK verifies where it can). That cross-library check is the point
  * of Phase 0: the driver's output must be a standard format any stock verifier — Canton's included
  * — accepts: Ed25519 = raw 64-byte R‖S, ECDSA = DER, public keys = X.509 SubjectPublicKeyInfo.
  */
class RutliDriverSpec extends AnyWordSpec with Matchers {

  private implicit val ec: ExecutionContext = ExecutionContext.global
  private val ctx: Context = Context.root()
  private def await[A](f: Future[A]): A = Await.result(f, 30.seconds)

  private def newDriver(): RutliDriver = {
    val factory = new RutliDriverFactory
    factory.create(RutliConfig(), _ => org.slf4j.LoggerFactory.getLogger("test"), ec)
  }

  private val data = "canton topology transaction hash".getBytes

  "ServiceLoader" should {
    "discover the factory via META-INF/services (v1)" in {
      val factories = ServiceLoader.load(classOf[KmsDriverFactory]).iterator().asScala.toList
      factories.map(_.name) should contain(RutliDriverFactory.driverName)
    }
  }

  "RutliDriverFactory" should {
    "parse an empty config to defaults" in {
      val factory = new RutliDriverFactory
      val parsed = factory.configReader.from(com.typesafe.config.ConfigFactory.empty().root())
      parsed shouldBe Right(RutliConfig())
    }
    "reject an unknown backend" in {
      val factory = new RutliDriverFactory
      an[IllegalArgumentException] should be thrownBy
        factory.create(RutliConfig(backend = "hsm"), _ => org.slf4j.LoggerFactory.getLogger("t"), ec)
    }
  }

  "RutliDriver signing" should {

    "produce Ed25519 signatures the stock JDK verifier accepts (raw 64-byte concat)" in {
      val driver = newDriver()
      val keyId = await(driver.generateSigningKeyPair(SigningKeySpec.EcCurve25519, Some("ns"))(ctx))
      val sig = await(driver.sign(data, keyId, SigningAlgoSpec.Ed25519)(ctx))

      sig.length shouldBe 64 // Canton's `concat` format: R‖S, no envelope

      val pub = await(driver.getPublicKey(keyId)(ctx))
      pub.spec shouldBe SigningKeySpec.EcCurve25519
      // Parse SPKI + verify with the stock JDK provider (NOT BouncyCastle).
      val jdkKey = KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(pub.key))
      val verifier = JSignature.getInstance("Ed25519")
      verifier.initVerify(jdkKey)
      verifier.update(data)
      verifier.verify(sig) shouldBe true
    }

    "produce P-256 ECDSA signatures the stock JDK verifier accepts (DER)" in {
      val driver = newDriver()
      val keyId = await(driver.generateSigningKeyPair(SigningKeySpec.EcP256, None)(ctx))
      val sig = await(driver.sign(data, keyId, SigningAlgoSpec.EcDsaSha256)(ctx))

      sig(0) shouldBe 0x30.toByte // DER SEQUENCE tag

      val pub = await(driver.getPublicKey(keyId)(ctx))
      val jdkKey = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(pub.key))
      val verifier = JSignature.getInstance("SHA256withECDSA")
      verifier.initVerify(jdkKey)
      verifier.update(data)
      verifier.verify(sig) shouldBe true
    }

    "produce P-384 ECDSA signatures the stock JDK verifier accepts (DER)" in {
      val driver = newDriver()
      val keyId = await(driver.generateSigningKeyPair(SigningKeySpec.EcP384, None)(ctx))
      val sig = await(driver.sign(data, keyId, SigningAlgoSpec.EcDsaSha384)(ctx))
      val pub = await(driver.getPublicKey(keyId)(ctx))
      val jdkKey = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(pub.key))
      val verifier = JSignature.getInstance("SHA384withECDSA")
      verifier.initVerify(jdkKey)
      verifier.update(data)
      verifier.verify(sig) shouldBe true
    }

    "produce secp256k1 ECDSA signatures BouncyCastle verifies (JDK dropped the curve)" in {
      val driver = newDriver()
      val keyId = await(driver.generateSigningKeyPair(SigningKeySpec.EcSecp256k1, None)(ctx))
      val sig = await(driver.sign(data, keyId, SigningAlgoSpec.EcDsaSha256)(ctx))
      val pub = await(driver.getPublicKey(keyId)(ctx))
      val bcKey =
        KeyFactory.getInstance("EC", "BC").generatePublic(new X509EncodedKeySpec(pub.key))
      val verifier = JSignature.getInstance("SHA256withECDSA", "BC")
      verifier.initVerify(bcKey)
      verifier.update(data)
      verifier.verify(sig) shouldBe true
    }

    "fail non-retryably on an algorithm/key-spec mismatch" in {
      val driver = newDriver()
      val keyId = await(driver.generateSigningKeyPair(SigningKeySpec.EcP256, None)(ctx))
      val ex = the[KmsDriverException] thrownBy
        await(driver.sign(data, keyId, SigningAlgoSpec.Ed25519)(ctx))
      ex.retryable shouldBe false
    }

    "fail non-retryably for an unknown key id" in {
      val driver = newDriver()
      val ex = the[KmsDriverException] thrownBy
        await(driver.sign(data, "no-such-key", SigningAlgoSpec.Ed25519)(ctx))
      ex.retryable shouldBe false
    }
  }

  "RutliDriver encryption" should {

    "decrypt RSA-2048 OAEP-SHA256 ciphertext produced by the stock JDK" in {
      val driver = newDriver()
      val keyId = await(driver.generateEncryptionKeyPair(EncryptionKeySpec.Rsa2048, None)(ctx))
      val pub = await(driver.getPublicKey(keyId)(ctx))
      // Encrypt with the stock JDK against the exported SPKI key; driver must decrypt.
      // NOTE: explicit OAEPParameterSpec is required — the JDK's named transformation defaults MGF1
      // to SHA-1 even in "OAEPWithSHA-256AndMGF1Padding", while rsa-oaep-sha256 (Canton / RFC 8017
      // as used by AWS KMS et al.) means MGF1-SHA256 throughout.
      val jdkKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(pub.key))
      val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
      val oaep = new javax.crypto.spec.OAEPParameterSpec(
        "SHA-256",
        "MGF1",
        new java.security.spec.MGF1ParameterSpec("SHA-256"),
        javax.crypto.spec.PSource.PSpecified.DEFAULT,
      )
      cipher.init(Cipher.ENCRYPT_MODE, jdkKey, oaep)
      val ciphertext = cipher.doFinal(data)

      val plain = await(driver.decryptAsymmetric(ciphertext, keyId, EncryptionAlgoSpec.RsaEsOaepSha256)(ctx))
      plain shouldBe data
    }

    "roundtrip symmetric encryption (AES-128-GCM)" in {
      val driver = newDriver()
      val keyId = await(driver.generateSymmetricKey(None)(ctx))
      val ct = await(driver.encryptSymmetric(data, keyId)(ctx))
      ct should not equal data
      await(driver.decryptSymmetric(ct, keyId)(ctx)) shouldBe data
    }
  }

  "RutliDriver lifecycle" should {
    "report health Ok, track key existence, and delete keys" in {
      val driver = newDriver()
      await(driver.health) shouldBe KmsDriverHealth.Ok

      val keyId = await(driver.generateSigningKeyPair(SigningKeySpec.EcCurve25519, None)(ctx))
      await(driver.keyExistsAndIsActive(keyId)(ctx)) // must not throw

      await(driver.deleteKey(keyId)(ctx))
      a[KmsDriverException] should be thrownBy await(driver.keyExistsAndIsActive(keyId)(ctx))
    }
  }
}

object RutliDriverSpec {
  // Ensure BC registered for the secp256k1 cross-check even if SoftwareBackend init order changes.
  if (Security.getProvider("BC") == null)
    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider())
}
