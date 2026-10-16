// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli

import com.digitalasset.canton.crypto.kms.driver.api.v1._
import com.stakecraft.rutli.backend.{SoftKeyStore, SoftwareBackend}
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.nio.file.Files
import java.security.KeyFactory
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.spec.{OAEPParameterSpec, PSource}
import java.security.spec.MGF1ParameterSpec
import scala.concurrent.Await
import scala.concurrent.duration._

/** Regression for the devnet incident: a participant restart must not lose SoftwareBackend keys.
  * The failure mode is unrecoverable — Canton peers keep encrypting to the published (old) key, so
  * a "fresh" key cannot decrypt catch-up traffic. These tests restart the backend (new instance,
  * same sealed dir) and require the old ciphertext to still decrypt.
  */
class SoftwareBackendPersistenceSpec extends AnyWordSpec with Matchers {

  private def await[T](f: scala.concurrent.Future[T]): T = Await.result(f, 10.seconds)

  private def rsaEncrypt(pubDer: Array[Byte], plaintext: Array[Byte]): Array[Byte] = {
    val pub = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(pubDer))
    val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
    val oaep = new OAEPParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), PSource.PSpecified.DEFAULT)
    cipher.init(Cipher.ENCRYPT_MODE, pub, oaep)
    cipher.doFinal(plaintext)
  }

  "SoftwareBackend with sealed persistence" should {

    "serve pre-restart ciphertext after a restart (the incident regression)" in {
      val dir = Files.createTempDirectory("rutli-softkeys")
      val secret = "test-master-secret".getBytes

      // "Before the upgrade": generate keys, publish the encryption public key, receive ciphertext.
      val before = new SoftwareBackend(Some(new SoftKeyStore(dir, secret)))
      val encId = await(before.generateEncryptionKeyPair(EncryptionKeySpec.Rsa2048, Some("enc")))
      val symId = await(before.generateSymmetricKey(Some("sym")))
      val sigId = await(before.generateSigningKeyPair(SigningKeySpec.EcCurve25519, Some("ns")))
      val pubDer = await(before.getPublicKey(encId)).key
      val secretMsg = "view payload encrypted by a peer".getBytes
      val asymCt = rsaEncrypt(pubDer, secretMsg)
      val symCt = await(before.encryptSymmetric(secretMsg, symId))
      before.close()

      // "After the upgrade": a NEW JVM-equivalent — new backend instance, same sealed dir.
      val after = new SoftwareBackend(Some(new SoftKeyStore(dir, secret)))
      await(after.decryptAsymmetric(asymCt, encId, EncryptionAlgoSpec.RsaEsOaepSha256)) shouldBe secretMsg
      await(after.decryptSymmetric(symCt, symId)) shouldBe secretMsg
      await(after.sign("topology tx".getBytes, sigId, SigningAlgoSpec.Ed25519)).length shouldBe 64
      await(after.getPublicKey(encId)).key shouldBe pubDer
      await(after.keyExistsAndIsActive(encId))
    }

    "refuse to load with the wrong seal secret" in {
      val dir = Files.createTempDirectory("rutli-softkeys")
      val a = new SoftwareBackend(Some(new SoftKeyStore(dir, "right secret".getBytes)))
      await(a.generateEncryptionKeyPair(EncryptionKeySpec.Rsa2048, None))

      // Wrong secret must fail loudly at construction — never silently start with no keys.
      an[Exception] should be thrownBy {
        new SoftwareBackend(Some(new SoftKeyStore(dir, "wrong secret".getBytes)))
      }
    }

    "not resurrect deleted keys after a restart" in {
      val dir = Files.createTempDirectory("rutli-softkeys")
      val secret = "s".getBytes
      val a = new SoftwareBackend(Some(new SoftKeyStore(dir, secret)))
      val id = await(a.generateEncryptionKeyPair(EncryptionKeySpec.Rsa2048, None))
      await(a.deleteKey(id))

      val b = new SoftwareBackend(Some(new SoftKeyStore(dir, secret)))
      an[Exception] should be thrownBy await(b.keyExistsAndIsActive(id))
    }

    "fail key creation when the directory fsync fails, instead of reporting the key as created (RUTLI-06)" in {
      val dir = Files.createTempDirectory("rutli-softkeys")
      val failing = new SoftKeyStore(dir, "s".getBytes, _ => throw new java.io.IOException("fsync dir: EIO"))
      val backend = new SoftwareBackend(Some(failing))
      val ex = the[java.io.IOException] thrownBy
        await(backend.generateSigningKeyPair(SigningKeySpec.EcCurve25519, Some("ns")))
      ex.getMessage should include("EIO")
      an[java.io.IOException] should be thrownBy
        await(backend.generateEncryptionKeyPair(EncryptionKeySpec.Rsa2048, None))
      an[java.io.IOException] should be thrownBy await(backend.generateSymmetricKey(None))
    }

    "keep heap-only behavior when persistence is not configured" in {
      val a = new SoftwareBackend()
      val id = await(a.generateEncryptionKeyPair(EncryptionKeySpec.Rsa2048, None))
      val b = new SoftwareBackend()
      an[Exception] should be thrownBy await(b.keyExistsAndIsActive(id))
    }
  }
}
