// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli.backend

import com.digitalasset.canton.crypto.kms.driver.api.v1._
import com.stakecraft.rutli.HsmConfig
import org.bouncycastle.cert.jcajce.{JcaX509CertificateConverter, JcaX509v3CertificateBuilder}
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder

import java.math.BigInteger
import java.security.cert.X509Certificate
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.{
  KeyPair,
  KeyPairGenerator,
  KeyStore,
  MessageDigest,
  PrivateKey,
  Provider,
  SecureRandom,
  Security,
  Signature => JSignature,
}
import java.time.Instant
import java.util.concurrent.atomic.AtomicInteger
import java.util.{Date, UUID}
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.{Cipher, KeyGenerator, SecretKey}
import javax.security.auth.x500.X500Principal
import scala.concurrent.Future
import scala.util.Try

/** Phase 1 backend: keys live in a PKCS#11 HSM / enclave; the driver only sees public keys and
  * signatures. Uses the JDK's built-in SunPKCS11 provider, so it works with SoftHSM (dev) and any
  * PKCS#11 HSM (YubiHSM, Securosys, CloudHSM, Nitro-Enclave PKCS#11 shim) in production.
  *
  * Persistence model: keys are token objects, retrieved by label. Because a PKCS#11 KeyStore stores
  * private keys as `PrivateKeyEntry`s (which require a certificate), each generated key is wrapped
  * in a long-lived self-signed X.509 certificate whose subject encodes the label. The certificate
  * is a storage envelope only — never used for PKI. The key's spec is encoded in the label prefix
  * so it survives restarts without an external side table.
  *
  * Scope: signing (Ed25519 / ECDSA P-256,P-384,secp256k1) + RSA-2048 OAEP-SHA256 decryption +
  * AES-128-GCM symmetric, all on the token. Ed25519-on-PKCS#11 depends on the module + JDK build
  * exposing the EdDSA mechanism; declared support is probed at startup (see supportedSigningKeySpecs).
  *
  * NOT YET verified against a broad matrix of production HSMs — validated against SoftHSM 2.7. Treat
  * as pre-production until exercised on the target HSM.
  */
final class HsmBackend(config: HsmConfig) extends KmsBackend {

  import HsmBackend._

  private val provider: Provider = installProvider(config)
  private val pin: Array[Char] =
    config.resolvedPin.map(_.toCharArray).getOrElse(Array.emptyCharArray)

  private val keyStore: KeyStore = {
    val ks = KeyStore.getInstance("PKCS11", provider)
    ks.load(null, pin)
    ks
  }

  // Probe once whether the token+JDK expose an Ed25519 mechanism; advertise it only if so.
  private val ed25519Supported: Boolean =
    Try {
      KeyPairGenerator.getInstance("Ed25519", provider).generateKeyPair()
    }.isSuccess

  override val supportedSigningKeySpecs: Set[SigningKeySpec] = {
    val base: Set[SigningKeySpec] =
      Set(SigningKeySpec.EcP256, SigningKeySpec.EcP384, SigningKeySpec.EcSecp256k1)
    if (ed25519Supported) base + SigningKeySpec.EcCurve25519 else base
  }

  override val supportedSigningAlgoSpecs: Set[SigningAlgoSpec] = {
    val base: Set[SigningAlgoSpec] = Set(SigningAlgoSpec.EcDsaSha256, SigningAlgoSpec.EcDsaSha384)
    if (ed25519Supported) base + SigningAlgoSpec.Ed25519 else base
  }

  override val supportedEncryptionKeySpecs: Set[EncryptionKeySpec] = Set(EncryptionKeySpec.Rsa2048)
  override val supportedEncryptionAlgoSpecs: Set[EncryptionAlgoSpec] =
    Set(EncryptionAlgoSpec.RsaEsOaepSha256)

  override def generateSigningKeyPair(
      spec: SigningKeySpec,
      keyName: Option[String],
  ): Future[String] = Future.fromTry(Try {
    val kp = spec match {
      case SigningKeySpec.EcCurve25519 => ed25519KeyPair()
      case SigningKeySpec.EcP256       => ecKeyPair("secp256r1")
      case SigningKeySpec.EcP384       => ecKeyPair("secp384r1")
      case SigningKeySpec.EcSecp256k1  => ecKeyPair("secp256k1")
    }
    persistKeyPair(specTag(spec), keyName, kp)
  })

  override def generateEncryptionKeyPair(
      spec: EncryptionKeySpec,
      keyName: Option[String],
  ): Future[String] = Future.fromTry(Try {
    spec match {
      case EncryptionKeySpec.Rsa2048 =>
        val gen = KeyPairGenerator.getInstance("RSA", provider)
        gen.initialize(2048)
        persistKeyPair(TagRsa2048, keyName, gen.generateKeyPair())
      case EncryptionKeySpec.EcP256 =>
        throw new UnsupportedOperationException("ECIES(P-256) is not supported by the HSM backend")
    }
  })

  override def generateSymmetricKey(keyName: Option[String]): Future[String] =
    Future.fromTry(Try {
      val gen = KeyGenerator.getInstance("AES", provider)
      gen.init(128)
      val id = label(TagAes, keyName)
      keyStore.setKeyEntry(id, gen.generateKey(), null, null)
      id
    })

  override def sign(data: Array[Byte], keyId: String, algo: SigningAlgoSpec): Future[Array[Byte]] =
    Future.fromTry(Try {
      requireCompatible(algo, specTagOf(keyId))
      val priv = privateKey(keyId)
      algo match {
        // ECDSA: hash in software, then single-part raw sign on the token (NONEwithECDSA →
        // CKM_ECDSA via C_Sign). Avoids C_SignUpdate, which SoftHSM and some HSMs don't implement.
        // The output DER is identical to SHAxxxwithECDSA over the same message.
        case SigningAlgoSpec.EcDsaSha256 => rawEcdsa(priv, MessageDigest.getInstance("SHA-256").digest(data))
        case SigningAlgoSpec.EcDsaSha384 => rawEcdsa(priv, MessageDigest.getInstance("SHA-384").digest(data))
        case SigningAlgoSpec.Ed25519 =>
          val sig = JSignature.getInstance("Ed25519", provider)
          sig.initSign(priv); sig.update(data); sig.sign()
      }
    })

  private def rawEcdsa(priv: PrivateKey, digest: Array[Byte]): Array[Byte] = {
    val sig = JSignature.getInstance("NONEwithECDSA", provider)
    sig.initSign(priv)
    sig.update(digest)
    sig.sign()
  }

  override def decryptAsymmetric(
      ciphertext: Array[Byte],
      keyId: String,
      algo: EncryptionAlgoSpec,
  ): Future[Array[Byte]] = Future.fromTry(Try {
    algo match {
      case EncryptionAlgoSpec.RsaEsOaepSha256 =>
        // SunPKCS11 rejects OAEP padding at the JCA layer regardless of token capability, so we do
        // the *secret* half on the token (raw RSA modexp, CKM_RSA_X_509 / NoPadding) and the OAEP
        // de-padding — which needs no secret — in software. The private key never leaves the HSM.
        val modBytes = {
          val pub = keyStore.getCertificate(keyId).getPublicKey.asInstanceOf[RSAPublicKey]
          (pub.getModulus.bitLength + 7) / 8
        }
        val cipher = Cipher.getInstance("RSA/ECB/NoPadding", provider)
        cipher.init(Cipher.DECRYPT_MODE, privateKey(keyId))
        val em = leftPad(cipher.doFinal(ciphertext), modBytes)
        oaepSha256Decode(em, modBytes)
      case EncryptionAlgoSpec.EciesHkdfHmacSha256Aes128Cbc =>
        throw new UnsupportedOperationException("ECIES decryption is not supported by the HSM backend")
    }
  })

  override def encryptSymmetric(data: Array[Byte], keyId: String): Future[Array[Byte]] =
    Future.fromTry(Try {
      val key = secretKey(keyId)
      val iv = new Array[Byte](GcmIvLen)
      secureRandom.nextBytes(iv)
      val cipher = Cipher.getInstance("AES/GCM/NoPadding", provider)
      cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GcmTagBits, iv))
      iv ++ cipher.doFinal(data)
    })

  override def decryptSymmetric(ciphertext: Array[Byte], keyId: String): Future[Array[Byte]] =
    Future.fromTry(Try {
      val (iv, ct) = ciphertext.splitAt(GcmIvLen)
      val cipher = Cipher.getInstance("AES/GCM/NoPadding", provider)
      cipher.init(Cipher.DECRYPT_MODE, secretKey(keyId), new GCMParameterSpec(GcmTagBits, iv))
      cipher.doFinal(ct)
    })

  override def getPublicKey(keyId: String): Future[PublicKey] = Future.fromTry(Try {
    val cert = keyStore.getCertificate(keyId)
    if (cert == null) throw new NoSuchElementException(s"key not found: $keyId")
    PublicKey(cert.getPublicKey.getEncoded, keySpecOf(keyId))
  })

  override def keyExistsAndIsActive(keyId: String): Future[Unit] =
    if (keyStore.containsAlias(keyId)) Future.unit
    else Future.failed(new NoSuchElementException(s"key not found or inactive: $keyId"))

  override def deleteKey(keyId: String): Future[Unit] = Future.fromTry(Try {
    if (keyStore.containsAlias(keyId)) keyStore.deleteEntry(keyId)
  })

  override def health: Future[KmsDriverHealth] =
    Future.successful(
      if (Try(keyStore.size()).isSuccess) KmsDriverHealth.Ok
      else KmsDriverHealth.Failed("PKCS#11 keystore not reachable")
    )

  override def close(): Unit = Try(provider.asInstanceOf[java.security.AuthProvider].logout())

  // -- helpers --

  private def ecKeyPair(curve: String): KeyPair = {
    val gen = KeyPairGenerator.getInstance("EC", provider)
    gen.initialize(new ECGenParameterSpec(curve))
    gen.generateKeyPair()
  }

  private def ed25519KeyPair(): KeyPair =
    KeyPairGenerator.getInstance("Ed25519", provider).generateKeyPair()

  /** Persist a keypair as a token PrivateKeyEntry. A PKCS#11 KeyStore requires a certificate
    * alongside the private key; we attach a storage-envelope cert that carries the token's PUBLIC
    * key (so getPublicKey works) but is signed by an ephemeral in-JVM key — never the token. This
    * keeps key generation free of any token signing operation (portable across HSMs that don't do
    * multi-part signing), and the cert's signature is never validated by anyone. */
  private def persistKeyPair(tag: String, keyName: Option[String], kp: KeyPair): String = {
    val id = label(tag, keyName)
    val cert = storageCert(id, kp.getPublic)
    keyStore.setKeyEntry(id, kp.getPrivate, null, Array[java.security.cert.Certificate](cert))
    id
  }

  private def storageCert(subject: String, publicKey: java.security.PublicKey): X509Certificate = {
    val now = Date.from(Instant.parse("2020-01-01T00:00:00Z"))
    val until = Date.from(Instant.parse("2120-01-01T00:00:00Z"))
    val subjectDn = new X500Principal(s"CN=$subject,O=rutli")
    val issuerDn = new X500Principal("CN=rutli-storage-envelope,O=rutli")
    val builder = new JcaX509v3CertificateBuilder(
      issuerDn,
      BigInteger.valueOf(serial.incrementAndGet().toLong),
      now,
      until,
      subjectDn,
      publicKey, // the TOKEN's public key — this is what getPublicKey exports
    )
    // Signed by an ephemeral software key, purely to satisfy the X.509 structure.
    val signer =
      new JcaContentSignerBuilder("SHA256withECDSA").build(HsmBackend.envelopeSigningKey.getPrivate)
    new JcaX509CertificateConverter().getCertificate(builder.build(signer))
  }

  private def privateKey(keyId: String): PrivateKey = {
    // PKCS#11 KeyStore: password must be null (the store is already unlocked via C_Login).
    val k = keyStore.getKey(keyId, null)
    if (k == null) throw new NoSuchElementException(s"key not found: $keyId")
    k.asInstanceOf[PrivateKey]
  }

  private def secretKey(keyId: String): SecretKey = {
    val k = keyStore.getKey(keyId, null)
    if (k == null) throw new NoSuchElementException(s"symmetric key not found: $keyId")
    k.asInstanceOf[SecretKey]
  }
}

object HsmBackend {

  private val serial = new AtomicInteger(0)
  private val secureRandom = new SecureRandom()

  /** Ephemeral in-JVM key used only to sign storage-envelope certificates (see storageCert). Never
    * touches the token; its signature is never validated. */
  private lazy val envelopeSigningKey: KeyPair = {
    val g = KeyPairGenerator.getInstance("EC")
    g.initialize(new ECGenParameterSpec("secp256r1"))
    g.generateKeyPair()
  }
  private val GcmIvLen = 12
  private val GcmTagBits = 128

  private val TagEd25519 = "ed25519"
  private val TagP256 = "p256"
  private val TagP384 = "p384"
  private val TagK256 = "k256"
  private val TagRsa2048 = "rsa2048"
  private val TagAes = "aes"

  /** Configure and install a SunPKCS11 provider instance for this HSM. Inline `--`-config avoids a
    * temp file. Each backend instance gets its own named provider. */
  private def installProvider(config: HsmConfig): Provider = {
    val name = config.tokenLabel.map(sanitize).getOrElse("rutli") + "-" + UUID.randomUUID().toString.take(8)
    val slotLine =
      config.slot.map(s => s"slot=$s").orElse(config.slotListIndex.map(i => s"slotListIndex=$i")).getOrElse("slotListIndex=0")
    val conf =
      s"""--name=$name
         |library=${config.libraryPath}
         |$slotLine
         |""".stripMargin
    val base = Security.getProvider("SunPKCS11")
    if (base == null)
      throw new IllegalStateException("SunPKCS11 provider not available in this JDK")
    val p = base.configure(conf)
    Security.addProvider(p)
    p
  }

  private def sanitize(s: String): String = s.replaceAll("[^A-Za-z0-9_.-]", "_")

  private def label(tag: String, keyName: Option[String]): String = {
    val name = keyName.map(n => s"-${sanitize(n)}").getOrElse("")
    s"$tag$name-${UUID.randomUUID()}".take(200)
  }

  private def specTag(spec: SigningKeySpec): String = spec match {
    case SigningKeySpec.EcCurve25519 => TagEd25519
    case SigningKeySpec.EcP256       => TagP256
    case SigningKeySpec.EcP384       => TagP384
    case SigningKeySpec.EcSecp256k1  => TagK256
  }

  private def specTagOf(keyId: String): SigningKeySpec = keyId.takeWhile(_ != '-') match {
    case TagEd25519 => SigningKeySpec.EcCurve25519
    case TagP256    => SigningKeySpec.EcP256
    case TagP384    => SigningKeySpec.EcP384
    case TagK256    => SigningKeySpec.EcSecp256k1
    case other      => throw new IllegalArgumentException(s"key $keyId is not a signing key ($other)")
  }

  private def keySpecOf(keyId: String): KeySpec = keyId.takeWhile(_ != '-') match {
    case TagEd25519 => SigningKeySpec.EcCurve25519
    case TagP256    => SigningKeySpec.EcP256
    case TagP384    => SigningKeySpec.EcP384
    case TagK256    => SigningKeySpec.EcSecp256k1
    case TagRsa2048 => EncryptionKeySpec.Rsa2048
    case other      => throw new IllegalArgumentException(s"key $keyId has no exportable public key ($other)")
  }

  private def leftPad(b: Array[Byte], len: Int): Array[Byte] =
    if (b.length >= len) b.takeRight(len) else Array.fill(len - b.length)(0.toByte) ++ b

  /** EME-OAEP decode (RFC 8017 §7.1.2) with SHA-256 and empty label, over a raw RSA block already
    * decrypted by the token. No secret material involved. */
  private def oaepSha256Decode(em: Array[Byte], k: Int): Array[Byte] = {
    val hLen = 32
    val lHash = MessageDigest.getInstance("SHA-256").digest(Array.emptyByteArray)
    val maskedSeed = em.slice(1, 1 + hLen)
    val maskedDB = em.slice(1 + hLen, k)
    val seed = xorBytes(maskedSeed, mgf1(maskedDB, hLen))
    val db = xorBytes(maskedDB, mgf1(seed, k - hLen - 1))
    if (em(0) != 0 || !java.util.Arrays.equals(db.slice(0, hLen), lHash))
      throw new IllegalArgumentException("OAEP decode failed (leading byte / lHash mismatch)")
    var i = hLen
    while (i < db.length && db(i) == 0) i += 1
    if (i >= db.length || db(i) != 1)
      throw new IllegalArgumentException("OAEP decode failed (0x01 separator not found)")
    db.slice(i + 1, db.length)
  }

  private def mgf1(seed: Array[Byte], length: Int): Array[Byte] = {
    val md = MessageDigest.getInstance("SHA-256")
    val out = new Array[Byte](length)
    var counter = 0
    var filled = 0
    while (filled < length) {
      md.reset()
      md.update(seed)
      md.update(
        Array[Byte](
          ((counter >>> 24) & 0xff).toByte,
          ((counter >>> 16) & 0xff).toByte,
          ((counter >>> 8) & 0xff).toByte,
          (counter & 0xff).toByte,
        )
      )
      val block = md.digest()
      val n = math.min(block.length, length - filled)
      System.arraycopy(block, 0, out, filled, n)
      filled += n
      counter += 1
    }
    out
  }

  private def xorBytes(a: Array[Byte], b: Array[Byte]): Array[Byte] = {
    val out = new Array[Byte](a.length)
    var i = 0
    while (i < a.length) { out(i) = (a(i) ^ b(i)).toByte; i += 1 }
    out
  }

  private def requireCompatible(algo: SigningAlgoSpec, keySpec: SigningKeySpec): Unit = {
    val ok = (algo, keySpec) match {
      case (SigningAlgoSpec.Ed25519, SigningKeySpec.EcCurve25519)                            => true
      case (SigningAlgoSpec.EcDsaSha256, SigningKeySpec.EcP256 | SigningKeySpec.EcSecp256k1) => true
      case (SigningAlgoSpec.EcDsaSha384, SigningKeySpec.EcP384)                              => true
      case _                                                                                  => false
    }
    if (!ok)
      throw new IllegalArgumentException(
        s"signing algorithm $algo is not compatible with key spec $keySpec"
      )
  }
}
