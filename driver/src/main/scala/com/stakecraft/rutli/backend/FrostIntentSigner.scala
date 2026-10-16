// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli.backend

import com.google.protobuf.ByteString
import com.stakecraft.rutli.grpc.{IntentApproval, SignIntent, SignedIntent}
import com.stakecraft.rutli.policy.ApprovalProof
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.openssl.{PEMKeyPair, PEMParser}
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter

import java.io.{FileInputStream, FileReader}
import java.nio.charset.StandardCharsets.UTF_8
import java.security.cert.{CertificateFactory, X509Certificate}
import java.security.interfaces.{ECPublicKey, RSAPublicKey}
import java.security.{PrivateKey, SecureRandom, Signature}
import scala.jdk.CollectionConverters._
import scala.util.Using

/** Signs the FROST signing intents (audit C2) with the driver's **mTLS identity** — the client
  * certificate and key it already presents to the cosigners (`frost.tls.cert` / `frost.tls.key`).
  *
  * An intent is the driver's signed authorization for exactly one signature: cluster, key, the
  * 34-byte digest, a random request id, a short validity and the approvals the approval gate
  * collected. Every cosigner taking part verifies it — the chain to the cluster CA, that the
  * signer's CN is on its `signer_allowlist` (and its key pinned, if configured), the signature
  * over `"rutli-intent-v1\n" ‖ intent bytes`, and the contents — before it commits to a nonce, and
  * again before it releases its share. So neither a compromised cosigner nor a compromised leader
  * can obtain a signature the driver did not ask for.
  *
  * The serialized [[SignIntent]] is carried as bytes ([[SignedIntent.intent]]): the cosigners
  * verify exactly what was signed, with no canonicalization step to disagree on.
  */
final class FrostIntentSigner private (
    chain: Seq[X509Certificate],
    key: PrivateKey,
    val signatureAlg: String,
    jcaAlg: String,
) {

  import FrostIntentSigner._

  /** The signer's certificate CN, for logs. */
  def subject: String = chain.head.getSubjectX500Principal.getName

  /** Sign one intent for `keyId` over `digest`, valid from `nowMillis` for `lifetimeMillis`, carrying
    * `approval`. `requestId` is the same across every leader the driver fails over to, so the
    * cosigners charge one driver call once. */
  def sign(
      clusterId: String,
      keyId: String,
      digest: Array[Byte],
      requestId: Array[Byte],
      approval: ApprovalProof,
      nowMillis: Long,
      lifetimeMillis: Long,
  ): SignedIntent = {
    val b = SignIntent
      .newBuilder()
      .setVersion(Version)
      .setClusterId(clusterId)
      .setPurpose(PurposeSign)
      .setKeyId(keyId)
      .setDigest(ByteString.copyFrom(digest))
      .setRequestId(ByteString.copyFrom(requestId))
      .setIssuedAtMs(nowMillis)
      .setNotAfterMs(nowMillis + lifetimeMillis)
    if (!approval.isEmpty) {
      b.setApprovalNonce(ByteString.copyFrom(approval.nonce))
      approval.approvals.foreach { case (id, sig) =>
        b.addApprovals(IntentApproval.newBuilder().setApproverId(id).setSignature(ByteString.copyFrom(sig)))
      }
    }
    signBytes(b.build().toByteArray)
  }

  /** Sign a hosted-key delete intent (audit M2) for `keyId`: purpose `delete-key`, digest
    * SHA-256("rutli-delete-key-v1\n" ‖ keyId). The cosigners honour it only if this certificate's
    * CN is on their `hosted_keys.delete_allowlist` — by default it is not, so the driver cannot
    * delete hosted keys unless an operator grants it the delete role. */
  def signDelete(
      clusterId: String,
      keyId: String,
      requestId: Array[Byte],
      nowMillis: Long,
      lifetimeMillis: Long,
  ): SignedIntent =
    signBytes(
      SignIntent
        .newBuilder()
        .setVersion(Version)
        .setClusterId(clusterId)
        .setPurpose(PurposeDeleteKey)
        .setKeyId(keyId)
        .setDigest(ByteString.copyFrom(deleteDigest(keyId)))
        .setRequestId(ByteString.copyFrom(requestId))
        .setIssuedAtMs(nowMillis)
        .setNotAfterMs(nowMillis + lifetimeMillis)
        .build()
        .toByteArray
    )

  private def signBytes(intent: Array[Byte]): SignedIntent = {
    val s = Signature.getInstance(jcaAlg)
    s.initSign(key)
    s.update(Context)
    s.update(intent)
    val out = SignedIntent
      .newBuilder()
      .setIntent(ByteString.copyFrom(intent))
      .setSignatureAlg(signatureAlg)
      .setSignature(ByteString.copyFrom(s.sign()))
    chain.foreach(c => out.addSignerChain(ByteString.copyFrom(c.getEncoded)))
    out.build()
  }
}

object FrostIntentSigner {

  /** Domain separation, as the cosigners verify it (`intent.rs`): the signature can never be taken
    * for a TLS transcript or anything else this key signs. */
  val Context: Array[Byte] = "rutli-intent-v1\n".getBytes(UTF_8)
  val Version = 1
  val PurposeSign = "sign"
  val PurposeDeleteKey = "delete-key"

  /** The digest a delete intent carries, as the cosigners compute it (`intent::delete_digest`). */
  def deleteDigest(keyId: String): Array[Byte] = {
    val md = java.security.MessageDigest.getInstance("SHA-256")
    md.update("rutli-delete-key-v1\n".getBytes(UTF_8))
    md.update(keyId.getBytes(UTF_8))
    md.digest()
  }
  val RequestIdBytes = 16

  private val rng = new SecureRandom()

  /** A fresh 16-byte request id. */
  def newRequestId(): Array[Byte] = { val b = new Array[Byte](RequestIdBytes); rng.nextBytes(b); b }

  /** Load the mTLS identity: `certPath` holds the certificate chain (leaf first) as PEM, `keyPath`
    * its private key — PKCS#8, SEC1 (`EC PRIVATE KEY`) or PKCS#1. Fails if the key does not belong
    * to the leaf. */
  def load(certPath: String, keyPath: String): FrostIntentSigner = {
    val chain = Using.resource(new FileInputStream(certPath)) { in =>
      CertificateFactory.getInstance("X.509").generateCertificates(in).asScala.toSeq.collect {
        case c: X509Certificate => c
      }
    }
    require(chain.nonEmpty, s"no certificate in $certPath")
    val key = Using.resource(new PEMParser(new FileReader(keyPath))) { p =>
      val converter = new JcaPEMKeyConverter()
      p.readObject() match {
        case k: PrivateKeyInfo => converter.getPrivateKey(k)
        case k: PEMKeyPair     => converter.getKeyPair(k).getPrivate
        case other =>
          throw new IllegalArgumentException(
            s"$keyPath: not a private key (${Option(other).fold("empty")(_.getClass.getSimpleName)})"
          )
      }
    }
    val (alg, jca) = chain.head.getPublicKey match {
      case k: ECPublicKey if k.getParams.getCurve.getField.getFieldSize == 256 => ("ecdsa-p256-sha256", "SHA256withECDSA")
      case k: ECPublicKey if k.getParams.getCurve.getField.getFieldSize == 384 => ("ecdsa-p384-sha384", "SHA384withECDSA")
      case _: RSAPublicKey => ("rsa-pkcs1-sha256", "SHA256withRSA")
      case k if k.getAlgorithm == "Ed25519" || k.getAlgorithm == "EdDSA" => ("ed25519", "Ed25519")
      case k => throw new IllegalArgumentException(s"$certPath: unsupported key ${k.getAlgorithm} for signing intents")
    }
    // The key must belong to the certificate the cosigners will check the signature against.
    val probe = "rutli-intent-key-check".getBytes(UTF_8)
    val sig = { val s = Signature.getInstance(jca); s.initSign(key); s.update(probe); s.sign() }
    val ok = { val v = Signature.getInstance(jca); v.initVerify(chain.head.getPublicKey); v.update(probe); v.verify(sig) }
    require(ok, s"$keyPath does not belong to the certificate in $certPath")
    new FrostIntentSigner(chain, key, alg, jca)
  }
}
