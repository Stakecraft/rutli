// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli.backend

import org.bouncycastle.asn1.x9.ECNamedCurveTable
import org.bouncycastle.crypto.engines.{AESEngine, IESEngine}
import org.bouncycastle.crypto.generators.KDF2BytesGenerator
import org.bouncycastle.crypto.macs.HMac
import org.bouncycastle.crypto.modes.CBCBlockCipher
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher
import org.bouncycastle.crypto.params.{
  AsymmetricKeyParameter,
  ECDomainParameters,
  ECPublicKeyParameters,
  IESWithCipherParameters,
  ParametersWithIV,
}
import org.bouncycastle.crypto.util.DigestFactory
import org.bouncycastle.crypto.{BasicAgreement, CipherParameters, KeyParser}

import java.io.InputStream
import java.math.BigInteger
import java.util

/** Canton's ECIES (`EciesHkdfHmacSha256Aes128Cbc`) on the decrypting side, for a P-256 key whose
  * private half lives in the cosigner cluster.
  *
  * The one secret-dependent step — the static ECDH `Z = x(d·V)` — is the cluster's `EcdhDerive`.
  * Everything after it is public computation on `Z`, and it runs here in '''BouncyCastle's own
  * `IESEngine`''', assembled exactly as BouncyCastle's JCE assembles it for the cipher Canton
  * encrypts with, with the ECDH swapped for an agreement that returns the `Z` the cluster computed.
  * Nothing about the KDF, the MAC or its length tag is reimplemented by hand: that framing is
  * BouncyCastle's, quirks included, so the bytes Canton's encryptor produces are, by construction,
  * the bytes this decryptor accepts.
  *
  * '''What Canton 3.6.1 sends''' (`community/base/src/main/scala/com/digitalasset/canton/crypto/
  * provider/jce/JcePureCrypto.scala`):
  *   - encrypt, `encryptWithEciesP256HmacSha256Aes128Cbc` (lines 521-565): a fresh 16-byte IV, then
  *     `Cipher.getInstance("ECIESwithSHA256andAES-CBC", BC)` initialised with
  *     `IESParameterSpec(derivation = [], encoding = [], macKeySize = 512, cipherKeySize = 128, iv)`
  *     (lines 146-165), and the IV '''prepended''' by Canton itself: `iv ‖ doFinal(plaintext)`;
  *   - BouncyCastle's `doFinal` writes `V ‖ C ‖ T`: the ephemeral public key `V` as an
  *     uncompressed SEC1 point (65 bytes; `IESParameterSpec`'s point compression defaults to off),
  *     the AES-128-CBC/PKCS#7 ciphertext `C`, and the 32-byte HMAC-SHA256 tag `T`;
  *   - decrypt (lines 695-750) splits the IV off at 16 bytes and hands the rest to the same cipher.
  *   - Through a KMS, the whole blob reaches the driver's `decryptAsymmetric` capped at 256 bytes
  *     (`crypto/provider/kms/KmsPrivateCrypto.scala:294`, `ByteString256`), and the plaintext must
  *     come back in at most 190 (`crypto/kms/driver/v1/DriverKms.scala:281-299`, `ByteString190`).
  *
  * '''How BouncyCastle builds that cipher''' (bcprov 1.85, the version Canton 3.6.1 ships):
  * `IESCipher.ECIESwithSHA256andAESCBC` is `ECIESwithCipher(CBCBlockCipher(AESEngine), ivLength =
  * 16, SHA-256, SHA-256)`, i.e. `new IESEngine(new ECDHBasicAgreement, new KDF2BytesGenerator(SHA-256),
  * new HMac(SHA-256), new PaddedBufferedBlockCipher(CBC(AES)))`; on decrypt, `IESCipher.engineDoFinal`
  * calls `engine.init(privateKey, ParametersWithIV(IESWithCipherParameters(derivationV, encodingV,
  * macKeySize, cipherKeySize), iv), new ECIESPublicKeyParser(curve))` and `engine.processBlock(V ‖ C ‖
  * T)`. [[decrypt]] makes exactly those calls, with two substitutions: the agreement (Z from the
  * cluster, bound to this `V`) and the key parser (uncompressed points only).
  *
  * Inside `IESEngine` (for the record — none of it is reimplemented here): `K = KDF2-SHA256(V ‖ Z,
  * 80 bytes)` — over `V ‖ Z`, not `Z` alone, because the parser set `V` — split as AES key
  * `K[0..16)` and MAC key `K[16..80)`; `T` is checked as `HMAC-SHA256(K_mac, C ‖ encodingV ‖
  * L2)` with `L2` the 8-byte big-endian bit length of the (empty) encoding vector, in constant time,
  * '''before''' the CBC padding is examined, so a padding failure is never observable on its own.
  * The name says HKDF; it is KDF2.
  */
object CantonEcies {

  /** AES-128-CBC IV Canton prepends (`ivSizeForAesCbcInBytes`). */
  val IvLength: Int = 16

  /** Uncompressed SEC1 P-256 point. */
  val PointLength: Int = 65

  /** HMAC-SHA256 tag. */
  val TagLength: Int = 32

  /** The 32-byte x-coordinate the cluster returns (`ECDHBasicAgreement`, padded to the field). */
  val SharedSecretLength: Int = 32

  /** Canton's bound on what reaches `decryptAsymmetric` (`ByteString256`). */
  val MaxCiphertextLength: Int = 256

  /** `IESParameterSpec` as Canton builds it (`JcePureCrypto.scala` 146-165). */
  val MacKeySizeBits: Int = 512
  val CipherKeySizeBits: Int = 128

  private val AesBlock = 16
  private val Overhead = IvLength + PointLength + TagLength

  /** The smallest well-formed blob: PKCS#7 always emits at least one block. */
  val MinCiphertextLength: Int = Overhead + AesBlock

  /** The largest plaintext that fits in [[MaxCiphertextLength]]: 128 bytes of CBC ciphertext, less
    * the mandatory padding byte. */
  val MaxPlaintextLength: Int = ((MaxCiphertextLength - Overhead) / AesBlock) * AesBlock - 1

  private lazy val p256: ECDomainParameters = new ECDomainParameters(ECNamedCurveTable.getByName("secp256r1"))

  /** A ciphertext blob split the way Canton built it. `body` is `V ‖ C ‖ T`, what `IESEngine` reads. */
  final class Parsed private[CantonEcies] (val iv: Array[Byte], val ephemeralPoint: Array[Byte], val body: Array[Byte])

  /** Every refusal of [[parse]] and [[decrypt]]. One message for every cryptographic failure (bad
    * MAC, bad padding, a `Z` that does not belong): what went wrong must not be observable. Shape
    * errors — lengths, encodings, a point not on the curve — are public facts about the input and
    * say so. */
  final class EciesException(message: String) extends RuntimeException(message)

  private def refuse(msg: String): Nothing = throw new EciesException(s"ECIES ciphertext refused: $msg")

  /** Split and check a blob before anything is sent to the cluster. Strict: the exact shape Canton
    * produces, nothing else.
    *   - `16 + 65 + 16·k + 32` bytes for `k ≥ 1`, and at most 256;
    *   - `V` uncompressed (`0x04`) and on P-256 (BouncyCastle's point decoding and public-point
    *     validation: on the curve, not infinity), checked here as well as on the cluster. */
  def parse(ciphertext: Array[Byte]): Parsed = {
    val n = ciphertext.length
    if (n > MaxCiphertextLength) refuse(s"$n bytes exceeds Canton's $MaxCiphertextLength-byte bound")
    if (n < MinCiphertextLength) refuse(s"$n bytes is shorter than the minimum $MinCiphertextLength")
    if ((n - Overhead) % AesBlock != 0)
      refuse(s"$n bytes is not iv(16) + point(65) + whole AES blocks + tag(32)")
    val iv = util.Arrays.copyOfRange(ciphertext, 0, IvLength)
    val point = util.Arrays.copyOfRange(ciphertext, IvLength, IvLength + PointLength)
    if (point(0) != 0x04) refuse(f"the ephemeral key is not an uncompressed point (tag 0x${point(0)}%02x)")
    validPoint(point)
    new Parsed(iv, point, util.Arrays.copyOfRange(ciphertext, IvLength, n))
  }

  /** BouncyCastle's own decoding + validation (on the curve, not infinity, order). */
  private def validPoint(encoded: Array[Byte]): ECPublicKeyParameters =
    try new ECPublicKeyParameters(p256.getCurve.decodePoint(encoded), p256)
    catch { case _: IllegalArgumentException => refuse("the ephemeral key is not a point on P-256") }

  /** Complete the decryption with the `z` the cluster returned for `parsed.ephemeralPoint`. */
  def decrypt(parsed: Parsed, z: Array[Byte]): Array[Byte] = {
    if (z.length != SharedSecretLength)
      throw new EciesException(s"ECIES: the cluster returned a ${z.length}-byte shared secret, expected 32")
    val engine = new IESEngine(
      new PrecomputedAgreement(parsed.ephemeralPoint, z),
      new KDF2BytesGenerator(DigestFactory.createSHA256()),
      new HMac(DigestFactory.createSHA256()),
      new PaddedBufferedBlockCipher(CBCBlockCipher.newInstance(AESEngine.newInstance())),
    )
    val params = new ParametersWithIV(
      new IESWithCipherParameters(Array.emptyByteArray, Array.emptyByteArray, MacKeySizeBits, CipherKeySizeBits),
      parsed.iv,
    )
    // IESEngine hands this to the agreement's init and nothing else; the private key is in the
    // cluster, so there is nothing to put in it.
    engine.init(new AsymmetricKeyParameter(true), params, UncompressedPointParser)
    val plaintext =
      try engine.processBlock(parsed.body, 0, parsed.body.length)
      catch {
        // org.bouncycastle.crypto.InvalidCipherTextException (MAC, padding, length) and anything
        // else from the engine: one opaque answer.
        case _: Exception => throw new EciesException("ECIES decryption failed")
      }
    if (plaintext.length > MaxPlaintextLength) throw new EciesException("ECIES decryption failed")
    plaintext
  }

  /** `IESEngine`'s key parser: exactly one 65-byte uncompressed point, validated by BouncyCastle.
    * (`ECIESPublicKeyParser` would also take compressed and hybrid encodings; Canton writes neither.) */
  private object UncompressedPointParser extends KeyParser {
    override def readKey(stream: InputStream): org.bouncycastle.crypto.params.AsymmetricKeyParameter = {
      val encoded = stream.readNBytes(PointLength)
      if (encoded.length != PointLength || encoded(0) != 0x04)
        throw new java.io.IOException("not an uncompressed P-256 point")
      validPoint(encoded)
    }
  }

  /** The agreement step, already done by the cluster: answers `Z` for the one point it was computed
    * for and refuses any other. `IESEngine` pads the result to [[getFieldSize]] bytes with
    * `BigIntegers.asUnsignedByteArray`, exactly as for `ECDHBasicAgreement` — a `Z` with leading zero
    * bytes reaches the KDF as the same 32 bytes. */
  private final class PrecomputedAgreement(point: Array[Byte], z: Array[Byte]) extends BasicAgreement {
    // Same answer as ECDHBasicAgreement.getFieldSize for P-256: (256 + 7) / 8.
    override def getFieldSize: Int = (p256.getCurve.getFieldSize + 7) / 8
    override def init(param: CipherParameters): Unit = ()
    override def calculateAgreement(pubKey: CipherParameters): BigInteger = pubKey match {
      case k: ECPublicKeyParameters if util.Arrays.equals(k.getQ.getEncoded(false), point) =>
        new BigInteger(1, z)
      case _ => throw new IllegalStateException("shared secret does not belong to this ephemeral key")
    }
  }
}
