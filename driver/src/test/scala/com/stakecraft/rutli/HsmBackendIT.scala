// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli

import com.digitalasset.canton.crypto.kms.driver.api.v1._
import com.stakecraft.rutli.backend.HsmBackend
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.security.spec.X509EncodedKeySpec
import java.security.{KeyFactory, Signature => JSignature}
import javax.crypto.Cipher
import scala.concurrent.duration._
import scala.concurrent.{Await, Future}

/** Live PKCS#11 integration test for [[HsmBackend]]. Skips (cancels) unless a token is configured.
  *
  * Run against SoftHSM:
  * {{{
  *   export SOFTHSM2_CONF=$HOME/.rutli-softhsm/softhsm2.conf
  *   export RUTLI_HSM_LIB=$(find /opt/homebrew -name libsofthsm2.so | head -1)
  *   export RUTLI_HSM_PIN=1234
  *   sbt driver/test
  * }}}
  */
class HsmBackendIT extends AnyWordSpec with Matchers {

  private val lib = sys.env.get("RUTLI_HSM_LIB")
  private val pin = sys.env.getOrElse("RUTLI_HSM_PIN", "1234")
  private def await[A](f: Future[A]): A = Await.result(f, 60.seconds)
  private val data = "canton topology transaction digest".getBytes

  private def backend(): HsmBackend = {
    assume(lib.isDefined, "set RUTLI_HSM_LIB (+ SOFTHSM2_CONF, RUTLI_HSM_PIN) to run HSM tests")
    new HsmBackend(
      HsmConfig(libraryPath = lib.get, slotListIndex = Some(0), pin = Some(pin))
    )
  }

  "HsmBackend (PKCS#11)" should {

    "generate a P-256 key, sign on the token, and the stock JDK verifies the DER signature" in {
      val b = backend()
      val keyId = await(b.generateSigningKeyPair(SigningKeySpec.EcP256, Some("it-p256")))
      val sig = await(b.sign(data, keyId, SigningAlgoSpec.EcDsaSha256))
      sig(0) shouldBe 0x30.toByte

      val pub = await(b.getPublicKey(keyId))
      pub.spec shouldBe SigningKeySpec.EcP256
      val jdkKey = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(pub.key))
      val v = JSignature.getInstance("SHA256withECDSA")
      v.initVerify(jdkKey); v.update(data)
      v.verify(sig) shouldBe true

      await(b.deleteKey(keyId))
      a[Exception] should be thrownBy await(b.keyExistsAndIsActive(keyId))
      b.close()
    }

    "generate a P-384 key and produce a JDK-verifiable signature" in {
      val b = backend()
      val keyId = await(b.generateSigningKeyPair(SigningKeySpec.EcP384, None))
      val sig = await(b.sign(data, keyId, SigningAlgoSpec.EcDsaSha384))
      val pub = await(b.getPublicKey(keyId))
      val jdkKey = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(pub.key))
      val v = JSignature.getInstance("SHA384withECDSA")
      v.initVerify(jdkKey); v.update(data)
      v.verify(sig) shouldBe true
      b.close()
    }

    "sign Ed25519 on the token when the module exposes the mechanism (raw 64-byte concat)" in {
      val b = backend()
      assume(
        b.supportedSigningKeySpecs.contains(SigningKeySpec.EcCurve25519),
        "token/JDK does not expose an Ed25519 PKCS#11 mechanism",
      )
      val keyId = await(b.generateSigningKeyPair(SigningKeySpec.EcCurve25519, Some("it-ns")))
      val sig = await(b.sign(data, keyId, SigningAlgoSpec.Ed25519))
      sig.length shouldBe 64
      val pub = await(b.getPublicKey(keyId))
      val jdkKey = KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(pub.key))
      val v = JSignature.getInstance("Ed25519")
      v.initVerify(jdkKey); v.update(data)
      v.verify(sig) shouldBe true
      b.close()
    }

    "decrypt RSA-2048 OAEP-SHA256 ciphertext produced by the stock JDK" in {
      val b = backend()
      val keyId = await(b.generateEncryptionKeyPair(EncryptionKeySpec.Rsa2048, None))
      val pub = await(b.getPublicKey(keyId))
      val jdkKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(pub.key))
      val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
      val oaep = new javax.crypto.spec.OAEPParameterSpec(
        "SHA-256",
        "MGF1",
        new java.security.spec.MGF1ParameterSpec("SHA-256"),
        javax.crypto.spec.PSource.PSpecified.DEFAULT,
      )
      cipher.init(Cipher.ENCRYPT_MODE, jdkKey, oaep)
      val ct = cipher.doFinal(data)
      await(b.decryptAsymmetric(ct, keyId, EncryptionAlgoSpec.RsaEsOaepSha256)) shouldBe data
      b.close()
    }

    "roundtrip AES-128-GCM symmetric encryption on the token" in {
      val b = backend()
      val keyId = await(b.generateSymmetricKey(None))
      val ct = await(b.encryptSymmetric(data, keyId))
      ct should not equal data
      await(b.decryptSymmetric(ct, keyId)) shouldBe data
      b.close()
    }

    "reject an algorithm/key-spec mismatch" in {
      val b = backend()
      val keyId = await(b.generateSigningKeyPair(SigningKeySpec.EcP256, None))
      an[Exception] should be thrownBy await(b.sign(data, keyId, SigningAlgoSpec.EcDsaSha384))
      b.close()
    }

    "persist keys on the token across backend instances (simulated restart)" in {
      val b1 = backend()
      val keyId = await(b1.generateSigningKeyPair(SigningKeySpec.EcP256, Some("persist")))
      val pub1 = await(b1.getPublicKey(keyId))
      b1.close() // logout + drop provider — simulates process restart

      val b2 = backend() // fresh login to the same token
      await(b2.keyExistsAndIsActive(keyId)) // must still be there
      val sig = await(b2.sign(data, keyId, SigningAlgoSpec.EcDsaSha256))
      val pub2 = await(b2.getPublicKey(keyId))
      pub2.key shouldBe pub1.key // same public key survived

      val jdkKey =
        KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(pub2.key))
      val v = JSignature.getInstance("SHA256withECDSA")
      v.initVerify(jdkKey); v.update(data)
      v.verify(sig) shouldBe true

      await(b2.deleteKey(keyId))
      b2.close()
    }
  }
}
