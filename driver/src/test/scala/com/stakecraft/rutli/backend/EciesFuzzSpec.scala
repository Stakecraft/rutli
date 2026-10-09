// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli.backend

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.IESParameterSpec
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.security.interfaces.ECPublicKey
import java.security.spec.{ECGenParameterSpec, ECPublicKeySpec, ECPoint => JEcPoint}
import java.security.{KeyFactory, KeyPair, KeyPairGenerator, SecureRandom}
import javax.crypto.{Cipher, KeyAgreement}
import scala.collection.mutable
import scala.util.Try

/** Randomised differential of [[CantonEcies]] against BouncyCastle's own JCE decryptor — the
  * decryptor Canton itself uses (`JcePureCrypto.scala:695-750`). Ported from the Track C
  * adversarial review.
  *
  * For each fresh P-256 key: one Canton-shaped ciphertext of a random length 0..127 must decrypt to
  * its plaintext, then single-bit mutations (anywhere, in the IV, in the last CBC block, past `V`)
  * must get the same answer from both decryptors — both refuse, or both return the same bytes (the
  * IV is outside Canton's MAC, so some IV flips are accepted by both, by design upstream).
  *
  * Default size is small enough for every `sbt driver/test` (200 keys, 2000 mutations). The
  * review's full size: `RUTLI_ECIES_FUZZ_KEYS=3000 RUTLI_ECIES_FUZZ_MUTATIONS=4` (12000 mutations).
  */
class EciesFuzzSpec extends AnyWordSpec with Matchers {

  private val bc = new BouncyCastleProvider
  private val rnd = new SecureRandom()

  private def envInt(name: String, default: Int): Int =
    sys.env.get(name).flatMap(v => Try(v.trim.toInt).toOption).filter(_ > 0).getOrElse(default)

  private val Keys = envInt("RUTLI_ECIES_FUZZ_KEYS", 200)
  private val MutationsPerKey = envInt("RUTLI_ECIES_FUZZ_MUTATIONS", 10)

  private def gen(): KeyPair = {
    val g = KeyPairGenerator.getInstance("EC", bc)
    g.initialize(new ECGenParameterSpec("secp256r1"), rnd)
    g.generateKeyPair()
  }

  private def spec(iv: Array[Byte]) = new IESParameterSpec(Array[Byte](), Array[Byte](), 512, 128, iv)

  private def cantonEncrypt(kp: KeyPair, msg: Array[Byte]): Array[Byte] = {
    val iv = new Array[Byte](16)
    rnd.nextBytes(iv)
    val c = Cipher.getInstance("ECIESwithSHA256andAES-CBC", bc)
    c.init(Cipher.ENCRYPT_MODE, kp.getPublic, spec(iv), rnd)
    iv ++ c.doFinal(msg)
  }

  private def cantonDecrypt(kp: KeyPair, blob: Array[Byte]): Try[Array[Byte]] = Try {
    require(blob.length >= 16)
    val c = Cipher.getInstance("ECIESwithSHA256andAES-CBC", bc)
    c.init(Cipher.DECRYPT_MODE, kp.getPrivate, spec(blob.take(16)))
    c.doFinal(blob.drop(16))
  }

  /** The cluster's job (ECDH), here on BouncyCastle's JCE KeyAgreement. */
  private def z(kp: KeyPair, point: Array[Byte]): Array[Byte] = {
    val params = kp.getPublic.asInstanceOf[ECPublicKey].getParams
    val w = new JEcPoint(new java.math.BigInteger(1, point.slice(1, 33)), new java.math.BigInteger(1, point.slice(33, 65)))
    val pub = KeyFactory.getInstance("EC", bc).generatePublic(new ECPublicKeySpec(w, params))
    val ka = KeyAgreement.getInstance("ECDH", bc)
    ka.init(kp.getPrivate)
    ka.doPhase(pub, true)
    ka.generateSecret()
  }

  private def driver(kp: KeyPair, blob: Array[Byte]): Try[Array[Byte]] = Try {
    val p = CantonEcies.parse(blob)
    CantonEcies.decrypt(p, z(kp, p.ephemeralPoint))
  }

  private def flipBit(a: Array[Byte], i: Int): Unit = a(i) = (a(i) ^ (1 << rnd.nextInt(8))).toByte

  "CantonEcies" should {
    s"agree with BouncyCastle's JCE decryptor on $Keys keys and ${Keys * MutationsPerKey} mutations" in {
      var mismatches = 0
      val notes = mutable.ArrayBuffer.empty[String]
      for (_ <- 0 until Keys) {
        val kp = gen()
        val msg = new Array[Byte](rnd.nextInt(CantonEcies.MaxPlaintextLength + 1))
        rnd.nextBytes(msg)
        val blob = cantonEncrypt(kp, msg)
        val clean = driver(kp, blob)
        if (!(clean.isSuccess && java.util.Arrays.equals(clean.get, msg))) {
          mismatches += 1
          notes += s"clean ciphertext, len=${msg.length}: $clean"
        }
        for (_ <- 0 until MutationsPerKey) {
          val m = blob.clone()
          rnd.nextInt(4) match {
            case 0 => flipBit(m, rnd.nextInt(m.length))                         // anywhere
            case 1 => flipBit(m, rnd.nextInt(16))                               // the IV
            case 2 => flipBit(m, m.length - 32 - 1 - rnd.nextInt(16))           // last CBC block
            case _ => flipBit(m, 81 + rnd.nextInt(m.length - 81))               // past V
          }
          (cantonDecrypt(kp, m), driver(kp, m)) match {
            case (scala.util.Success(a), scala.util.Success(b)) if !java.util.Arrays.equals(a, b) =>
              mismatches += 1; notes += "both accept, different plaintexts"
            case (scala.util.Failure(e), scala.util.Success(_)) =>
              mismatches += 1; notes += s"driver accepts, JCE refuses: $e"
            case (scala.util.Success(_), scala.util.Failure(e)) =>
              mismatches += 1; notes += s"JCE accepts, driver refuses: $e"
            case _ => ()
          }
        }
      }
      withClue(notes.take(20).mkString("\n")) { mismatches shouldBe 0 }
    }

    "refuse a compressed V (the KDF covers V as written, so BouncyCastle refuses it too)" in {
      val kp = gen()
      val blob = cantonEncrypt(kp, "hi".getBytes)
      val v = blob.slice(16, 81)
      val compressed = Array[Byte]((if ((v(64) & 1) == 1) 3 else 2).toByte) ++ v.slice(1, 33)
      val cblob = blob.take(16) ++ compressed ++ blob.drop(81)
      cantonDecrypt(kp, cblob).isSuccess shouldBe false
      the[CantonEcies.EciesException] thrownBy CantonEcies.parse(cblob) // before any cluster call
    }
  }
}
