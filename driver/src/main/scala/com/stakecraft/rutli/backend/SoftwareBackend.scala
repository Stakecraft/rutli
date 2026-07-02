// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli.backend

import com.digitalasset.canton.crypto.kms.driver.api.v1._
import org.bouncycastle.jce.provider.BouncyCastleProvider

import java.security.{KeyPair, KeyPairGenerator, SecureRandom, Security, Signature}
import java.security.spec.{ECGenParameterSpec, MGF1ParameterSpec}
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.spec.{GCMParameterSpec, OAEPParameterSpec, PSource}
import javax.crypto.{Cipher, KeyGenerator, SecretKey}
import scala.concurrent.Future
import scala.util.Try

/** Phase 0 backend: in-process software crypto via BouncyCastle.
  *
  * ⚠️ NOT FOR PRODUCTION. Private keys live in this JVM's heap. Its sole purpose is to prove the
  * Canton KMS Driver integration end-to-end and to pass the upstream conformance suite. Production
  * uses an HSM/enclave (Phase 1) or the FROST MPC cluster (Phase 2).
  *
  * Output formats are chosen to match Canton's verifier exactly:
  *   - Ed25519 signatures are raw 64-byte R‖S (`concat`) — BouncyCastle's Ed25519 `Signature`
  *     produces exactly this.
  *   - ECDSA signatures are DER-encoded (`der`) — `SHAxxxwithECDSA` produces DER.
  *   - Exported public keys are DER-encoded X.509 SubjectPublicKeyInfo; EC points are uncompressed,
  *     as required by [[PublicKey]].
  *
  * Phase 0 scope note: asymmetric encryption supports only RSA-2048 OAEP-SHA256 (Canton's KMS-mode
  * default). The Canton-specific ECIES construction is deferred, so `EcP256` encryption keys are
  * intentionally NOT advertised in [[supportedEncryptionKeySpecs]].
  */
final class SoftwareBackend extends KmsBackend {

  import SoftwareBackend._

  private val store = new ConcurrentHashMap[String, Stored]()

  override val supportedSigningKeySpecs: Set[SigningKeySpec] =
    Set(
      SigningKeySpec.EcCurve25519,
      SigningKeySpec.EcP256,
      SigningKeySpec.EcP384,
      SigningKeySpec.EcSecp256k1,
    )

  override val supportedSigningAlgoSpecs: Set[SigningAlgoSpec] =
    Set(SigningAlgoSpec.Ed25519, SigningAlgoSpec.EcDsaSha256, SigningAlgoSpec.EcDsaSha384)

  override val supportedEncryptionKeySpecs: Set[EncryptionKeySpec] =
    Set(EncryptionKeySpec.Rsa2048) // Phase 0: RSA-OAEP only; ECIES(P-256) deferred.

  override val supportedEncryptionAlgoSpecs: Set[EncryptionAlgoSpec] =
    Set(EncryptionAlgoSpec.RsaEsOaepSha256)

  override def generateSigningKeyPair(
      spec: SigningKeySpec,
      keyName: Option[String],
  ): Future[String] = Future.fromTry(Try {
    val kp = spec match {
      case SigningKeySpec.EcCurve25519 => keyPair("Ed25519")
      case SigningKeySpec.EcP256       => ecKeyPair("secp256r1")
      case SigningKeySpec.EcP384       => ecKeyPair("secp384r1")
      case SigningKeySpec.EcSecp256k1  => ecKeyPair("secp256k1")
    }
    val id = keyId("sig", keyName)
    store.put(id, StoredSigning(kp, spec))
    id
  })

  override def generateEncryptionKeyPair(
      spec: EncryptionKeySpec,
      keyName: Option[String],
  ): Future[String] = Future.fromTry(Try {
    val kp = spec match {
      case EncryptionKeySpec.Rsa2048 => rsaKeyPair(2048)
      case EncryptionKeySpec.EcP256 =>
        throw new UnsupportedOperationException(
          "ECIES(P-256) encryption is deferred in the Phase 0 SoftwareBackend; use Rsa2048"
        )
    }
    val id = keyId("enc", keyName)
    store.put(id, StoredEncryption(kp, spec))
    id
  })

  override def generateSymmetricKey(keyName: Option[String]): Future[String] =
    Future.fromTry(Try {
      val gen = KeyGenerator.getInstance("AES")
      gen.init(128) // AES-128-GCM, matching Canton's only symmetric spec.
      val id = keyId("sym", keyName)
      store.put(id, StoredSymmetric(gen.generateKey()))
      id
    })

  override def sign(data: Array[Byte], keyId: String, algo: SigningAlgoSpec): Future[Array[Byte]] =
    Future.fromTry(Try {
      lookup(keyId) match {
        case StoredSigning(kp, spec) =>
          requireCompatible(algo, spec)
          val sig = Signature.getInstance(jcaSigAlgo(algo), Bc)
          sig.initSign(kp.getPrivate)
          sig.update(data)
          sig.sign()
        case _ => throw notASigningKey(keyId)
      }
    })

  override def decryptAsymmetric(
      ciphertext: Array[Byte],
      keyId: String,
      algo: EncryptionAlgoSpec,
  ): Future[Array[Byte]] = Future.fromTry(Try {
    lookup(keyId) match {
      case StoredEncryption(kp, _) =>
        algo match {
          case EncryptionAlgoSpec.RsaEsOaepSha256 =>
            val cipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA-256AndMGF1Padding", Bc)
            val oaep = new OAEPParameterSpec(
              "SHA-256",
              "MGF1",
              new MGF1ParameterSpec("SHA-256"),
              PSource.PSpecified.DEFAULT,
            )
            cipher.init(Cipher.DECRYPT_MODE, kp.getPrivate, oaep)
            cipher.doFinal(ciphertext)
          case EncryptionAlgoSpec.EciesHkdfHmacSha256Aes128Cbc =>
            throw new UnsupportedOperationException(
              "ECIES decryption is deferred in the Phase 0 SoftwareBackend"
            )
        }
      case _ => throw notAnEncryptionKey(keyId)
    }
  })

  override def encryptSymmetric(data: Array[Byte], keyId: String): Future[Array[Byte]] =
    Future.fromTry(Try {
      lookup(keyId) match {
        case StoredSymmetric(key) =>
          val iv = new Array[Byte](GcmIvLen)
          secureRandom.nextBytes(iv)
          val cipher = Cipher.getInstance("AES/GCM/NoPadding", Bc)
          cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GcmTagBits, iv))
          iv ++ cipher.doFinal(data) // prepend IV
        case _ => throw notASymmetricKey(keyId)
      }
    })

  override def decryptSymmetric(ciphertext: Array[Byte], keyId: String): Future[Array[Byte]] =
    Future.fromTry(Try {
      lookup(keyId) match {
        case StoredSymmetric(key) =>
          val (iv, ct) = ciphertext.splitAt(GcmIvLen)
          val cipher = Cipher.getInstance("AES/GCM/NoPadding", Bc)
          cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GcmTagBits, iv))
          cipher.doFinal(ct)
        case _ => throw notASymmetricKey(keyId)
      }
    })

  override def getPublicKey(keyId: String): Future[PublicKey] = Future.fromTry(Try {
    lookup(keyId) match {
      case StoredSigning(kp, spec)    => PublicKey(kp.getPublic.getEncoded, spec)
      case StoredEncryption(kp, spec) => PublicKey(kp.getPublic.getEncoded, spec)
      case _ => throw new NoSuchElementException(s"key has no public part: $keyId")
    }
  })

  override def keyExistsAndIsActive(keyId: String): Future[Unit] =
    if (store.containsKey(keyId)) Future.unit
    else Future.failed(new NoSuchElementException(s"key not found or inactive: $keyId"))

  override def deleteKey(keyId: String): Future[Unit] = Future.fromTry(Try {
    store.remove(keyId)
    ()
  })

  override def health: Future[KmsDriverHealth] = Future.successful(KmsDriverHealth.Ok)

  override def close(): Unit = store.clear() // best-effort; software backend has no secure erasure

  // -- helpers --

  private def lookup(id: String): Stored = {
    val s = store.get(id)
    if (s == null) throw new NoSuchElementException(s"key not found: $id")
    s
  }
}

object SoftwareBackend {

  if (Security.getProvider("BC") == null) Security.addProvider(new BouncyCastleProvider())
  private val Bc = "BC"

  private val GcmIvLen = 12
  private val GcmTagBits = 128
  private val secureRandom = new SecureRandom()

  private sealed trait Stored
  private final case class StoredSigning(kp: KeyPair, spec: SigningKeySpec) extends Stored
  private final case class StoredEncryption(kp: KeyPair, spec: EncryptionKeySpec) extends Stored
  private final case class StoredSymmetric(key: SecretKey) extends Stored

  private def keyId(prefix: String, keyName: Option[String]): String = {
    val name = keyName.map(n => s"-${n.replaceAll("[^A-Za-z0-9_.-]", "_")}").getOrElse("")
    s"$prefix$name-${UUID.randomUUID()}".take(300)
  }

  private def keyPair(algorithm: String): KeyPair =
    KeyPairGenerator.getInstance(algorithm, Bc).generateKeyPair()

  private def ecKeyPair(curve: String): KeyPair = {
    val gen = KeyPairGenerator.getInstance("EC", Bc)
    gen.initialize(new ECGenParameterSpec(curve), secureRandom)
    gen.generateKeyPair()
  }

  private def rsaKeyPair(bits: Int): KeyPair = {
    val gen = KeyPairGenerator.getInstance("RSA", Bc)
    gen.initialize(bits, secureRandom)
    gen.generateKeyPair()
  }

  private def jcaSigAlgo(algo: SigningAlgoSpec): String = algo match {
    case SigningAlgoSpec.Ed25519     => "Ed25519"
    case SigningAlgoSpec.EcDsaSha256 => "SHA256withECDSA"
    case SigningAlgoSpec.EcDsaSha384 => "SHA384withECDSA"
  }

  /** Reject algorithm/key-spec mismatches (SPI requires a non-retryable failure). */
  private def requireCompatible(algo: SigningAlgoSpec, keySpec: SigningKeySpec): Unit = {
    val ok = (algo, keySpec) match {
      case (SigningAlgoSpec.Ed25519, SigningKeySpec.EcCurve25519)                             => true
      case (SigningAlgoSpec.EcDsaSha256, SigningKeySpec.EcP256 | SigningKeySpec.EcSecp256k1)  => true
      case (SigningAlgoSpec.EcDsaSha384, SigningKeySpec.EcP384)                                => true
      case _                                                                                   => false
    }
    if (!ok)
      throw new IllegalArgumentException(
        s"signing algorithm $algo is not compatible with key spec $keySpec"
      )
  }

  private def notASigningKey(id: String) =
    new NoSuchElementException(s"key is not a signing key: $id")
  private def notAnEncryptionKey(id: String) =
    new NoSuchElementException(s"key is not an encryption key: $id")
  private def notASymmetricKey(id: String) =
    new NoSuchElementException(s"key is not a symmetric key: $id")
}
