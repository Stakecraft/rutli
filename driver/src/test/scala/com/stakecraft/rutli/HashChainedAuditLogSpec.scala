// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli

import com.digitalasset.canton.crypto.kms.driver.api.v1._
import com.stakecraft.rutli.audit.HashChainedAuditLog
import io.opentelemetry.context.Context
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.nio.file.{Files, Path}
import scala.concurrent.duration._
import scala.concurrent.{Await, ExecutionContext, Future}
import scala.jdk.CollectionConverters._

class HashChainedAuditLogSpec extends AnyWordSpec with Matchers {

  private def tmpLog(): Path = {
    val dir = Files.createTempDirectory("rutli-audit")
    dir.resolve("audit.jsonl")
  }

  "HashChainedAuditLog" should {

    "append entries and verify the full chain" in {
      val path = tmpLog()
      val log = HashChainedAuditLog.open(path.toString)
      log.append("sign", "keyId=frost-ns algo=Ed25519 inBytes=34 sigBytes=64 outcome=ok")
      log.append("getPublicKey", "keyId=frost-ns spec=EcCurve25519 outcome=ok")
      log.append("sign", "keyId=frost-ns outcome=failed error=boom \"quoted\" \\slash")
      log.close()

      HashChainedAuditLog.verify(path.toString) shouldBe Right(3L)
    }

    "detect tampering at the exact entry" in {
      val path = tmpLog()
      val log = HashChainedAuditLog.open(path.toString)
      (1 to 5).foreach(i => log.append("op", s"entry $i"))
      log.close()

      val lines = Files.readAllLines(path).asScala.toVector
      // Tamper with entry 3's detail (keep valid JSON shape).
      val tampered = lines.updated(2, lines(2).replace("entry 3", "entry X"))
      Files.write(path, tampered.mkString("\n").concat("\n").getBytes)

      HashChainedAuditLog.verify(path.toString) shouldBe Left(3L)
    }

    "detect a deleted entry" in {
      val path = tmpLog()
      val log = HashChainedAuditLog.open(path.toString)
      (1 to 4).foreach(i => log.append("op", s"entry $i"))
      log.close()

      val lines = Files.readAllLines(path).asScala.toVector
      Files.write(path, (lines.take(1) ++ lines.drop(2)).mkString("\n").concat("\n").getBytes)

      HashChainedAuditLog.verify(path.toString).isLeft shouldBe true
    }

    "continue the chain across restarts" in {
      val path = tmpLog()
      val log1 = HashChainedAuditLog.open(path.toString)
      log1.append("op", "before restart")
      log1.close()

      val log2 = HashChainedAuditLog.open(path.toString) // resume
      log2.append("op", "after restart")
      log2.close()

      HashChainedAuditLog.verify(path.toString) shouldBe Right(2L)
    }

    "record driver operations end-to-end and verify" in {
      implicit val ec: ExecutionContext = ExecutionContext.global
      val path = tmpLog()
      val factory = new RutliDriverFactory
      val driver = factory.create(
        RutliConfig(auditLogPath = Some(path.toString)),
        _ => org.slf4j.LoggerFactory.getLogger("audit-test"),
        ec,
      )
      def await[A](f: Future[A]): A = Await.result(f, 30.seconds)
      val ctx = Context.root()

      val keyId = await(driver.generateSigningKeyPair(SigningKeySpec.EcCurve25519, Some("ns"))(ctx))
      await(driver.sign(Array.fill(34)(1.toByte), keyId, SigningAlgoSpec.Ed25519)(ctx))
      an[Exception] should be thrownBy await(driver.sign(Array(1.toByte), "missing", SigningAlgoSpec.Ed25519)(ctx))
      driver.close()

      // 3 operations recorded (including the failed one), chain intact.
      HashChainedAuditLog.verify(path.toString) shouldBe Right(3L)
      val content = new String(Files.readAllBytes(path))
      content should include("generateSigningKeyPair")
      content should include("outcome=failed")
      content should not include "\"signature\"" // never logs key material or signatures
    }

    "fail a sign closed when the durable audit append fails" in {
      implicit val ec: ExecutionContext = ExecutionContext.global
      def await[A](f: Future[A]): A = Await.result(f, 30.seconds)
      val ctx = Context.root()

      // An audit sink that always throws on append.
      val throwingSink = new com.stakecraft.rutli.audit.AuditSink {
        override def append(op: String, detail: String): Unit = throw new java.io.IOException("disk full")
        override def close(): Unit = ()
      }
      val backend = new com.stakecraft.rutli.backend.SoftwareBackend()
      val driver = new RutliDriver(
        backend,
        org.slf4j.LoggerFactory.getLogger("audit-failclosed"),
        auditLogging = false,
        auditLog = Some(throwingSink),
        com.stakecraft.rutli.policy.AutoApproveGate,
        signingJournal = None,
        backend.supportedSigningKeySpecs,
        backend.supportedSigningAlgoSpecs,
        backend.supportedEncryptionKeySpecs,
        backend.supportedEncryptionAlgoSpecs,
      )
      // Provision the key on the backend directly (bypass the audited driver path), then sign
      // through the driver: even a *successful* backend sign must not return its result when the
      // durable audit entry could not be written.
      val keyId = await(backend.generateSigningKeyPair(SigningKeySpec.EcCurve25519, Some("ns")))
      val ex = the[KmsDriverException] thrownBy
        await(driver.sign(Array.fill(34)(7.toByte), keyId, SigningAlgoSpec.Ed25519)(ctx))
      ex.getMessage.toLowerCase should include("audit")
      ex.retryable shouldBe false
    }
  }
}
