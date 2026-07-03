// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli

import com.digitalasset.canton.crypto.kms.driver.api.v1._
import com.stakecraft.rutli.backend.{FrostBackend, SoftwareBackend}
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.security.spec.X509EncodedKeySpec
import java.security.{KeyFactory, Signature => JSignature}
import scala.concurrent.duration._
import scala.concurrent.{Await, ExecutionContext, Future}

/** Live end-to-end test of the FROST backend against a running cosigner cluster. Skips unless
  * `RUTLI_FROST_ENDPOINT` points at a Signer endpoint (e.g. `localhost:9101`).
  *
  * Proves the full Phase 2 chain minus Canton: the KMS driver's backend runs a distributed key
  * generation on the cluster, then threshold-signs Canton's 34-byte payload, and the resulting
  * 64-byte signature verifies under the DKG group key with the stock JDK Ed25519 verifier.
  * Non-FROST keys are shown to still work via the delegate backend.
  */
class FrostBackendIT extends AnyWordSpec with Matchers {

  private val endpoint = sys.env.get("RUTLI_FROST_ENDPOINT")
  private implicit val ec: ExecutionContext = ExecutionContext.global
  private def await[A](f: Future[A]): A = Await.result(f, 90.seconds)
  private val digest = { // Canton-shaped 34-byte payload: 0x1220 ‖ 32 bytes
    val d = new Array[Byte](34); d(0) = 0x12; d(1) = 0x20
    for (i <- 2 until 34) d(i) = (i * 7).toByte
    d
  }

  // Optional mTLS material (RUTLI_FROST_CA/CERT/KEY). When set, the channel is mutual-TLS.
  private val tls: Option[FrostTlsConfig] = for {
    ca <- sys.env.get("RUTLI_FROST_CA")
    cert <- sys.env.get("RUTLI_FROST_CERT")
    key <- sys.env.get("RUTLI_FROST_KEY")
  } yield FrostTlsConfig(ca, cert, key, sys.env.get("RUTLI_FROST_DOMAIN").orElse(Some("localhost")))

  private def backend(eps: Seq[String]): FrostBackend =
    new FrostBackend(eps, new SoftwareBackend(), org.slf4j.LoggerFactory.getLogger("frost-it"), tls)

  private def backend(): FrostBackend = {
    assume(endpoint.isDefined, "set RUTLI_FROST_ENDPOINT (e.g. localhost:9101) to run FROST e2e tests")
    backend(Seq(endpoint.get))
  }

  "FrostBackend against a live cluster" should {

    "run DKG for the namespace key, then threshold-sign a Canton payload the JDK verifies" in {
      val b = backend()
      try {
        val keyId = await(b.generateSigningKeyPair(SigningKeySpec.EcCurve25519, Some("participant1")))
        keyId should startWith("frost-")

        val pub = await(b.getPublicKey(keyId))
        pub.spec shouldBe SigningKeySpec.EcCurve25519
        val jdkKey = KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(pub.key))

        val sig = await(b.sign(digest, keyId, SigningAlgoSpec.Ed25519))
        sig.length shouldBe 64

        val v = JSignature.getInstance("Ed25519")
        v.initVerify(jdkKey); v.update(digest)
        v.verify(sig) shouldBe true

        await(b.keyExistsAndIsActive(keyId)) // must not throw
      } finally b.close()
    }

    "delegate non-Ed25519 keys to the delegate backend (P-256 signs locally)" in {
      val b = backend()
      try {
        val keyId = await(b.generateSigningKeyPair(SigningKeySpec.EcP256, None))
        keyId should not startWith "frost-"
        val sig = await(b.sign(digest, keyId, SigningAlgoSpec.EcDsaSha256))
        val pub = await(b.getPublicKey(keyId))
        val jdkKey = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(pub.key))
        val v = JSignature.getInstance("SHA256withECDSA")
        v.initVerify(jdkKey); v.update(digest)
        v.verify(sig) shouldBe true
      } finally b.close()
    }

    "report healthy when the cluster is reachable" in {
      val b = backend()
      try await(b.health) shouldBe KmsDriverHealth.Ok
      finally b.close()
    }

    "fail over past a dead endpoint to a live cosigner" in {
      // A dead endpoint first, then the real one. Failover must skip the dead node transparently.
      val b = backend(Seq("127.0.0.1:6553", endpoint.getOrElse("localhost:9101")))
      try {
        await(b.health) shouldBe KmsDriverHealth.Ok
        val keyId = await(b.generateSigningKeyPair(SigningKeySpec.EcCurve25519, Some("failover")))
        val pub = await(b.getPublicKey(keyId))
        val sig = await(b.sign(digest, keyId, SigningAlgoSpec.Ed25519))
        val jdkKey = KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(pub.key))
        val v = JSignature.getInstance("Ed25519")
        v.initVerify(jdkKey); v.update(digest)
        v.verify(sig) shouldBe true
      } finally b.close()
    }
  }
}
