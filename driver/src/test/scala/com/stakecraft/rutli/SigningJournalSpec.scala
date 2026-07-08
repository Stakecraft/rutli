// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli

import com.digitalasset.canton.crypto.kms.driver.api.v1._
import com.stakecraft.rutli.guard.SigningJournal
import io.opentelemetry.context.Context
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.nio.file.{Files, Path}
import scala.concurrent.duration._
import scala.concurrent.{Await, ExecutionContext, Future}
import scala.jdk.CollectionConverters._

class SigningJournalSpec extends AnyWordSpec with Matchers {

  private val logger = org.slf4j.LoggerFactory.getLogger("journal-test")
  private def tmpDir(): String = Files.createTempDirectory("rutli-journal").toString
  private def journalFiles(dir: String): Vector[Path] =
    Files.list(java.nio.file.Paths.get(dir)).iterator().asScala.toVector

  "SigningJournal" should {

    "record distinct digests and flag repeats without blocking them" in {
      val dir = tmpDir()
      val j = new SigningJournal(dir, None, 60, logger)
      j.record("frost-ns", "aaa".getBytes)
      j.record("frost-ns", "bbb".getBytes)
      j.record("frost-ns", "aaa".getBytes) // repeat — must be allowed
      j.distinctCount("frost-ns") shouldBe 2

      val content = new String(Files.readAllBytes(journalFiles(dir).head))
      content.linesIterator.size shouldBe 3      // every sign recorded, incl. the repeat
      content should include("\"repeat\":true") // the repeat is flagged
    }

    "never store key material — only the digest" in {
      val dir = tmpDir()
      val j = new SigningJournal(dir, None, 60, logger)
      j.record("frost-ns", "secret-topology-bytes".getBytes)
      val content = new String(Files.readAllBytes(journalFiles(dir).head))
      content should not include "secret-topology-bytes"
    }

    "enforce a per-key rate limit as a hard stop" in {
      val j = new SigningJournal(tmpDir(), Some(2), 60, logger)
      val t0 = 1_000_000L
      j.record("frost-ns", "a".getBytes, t0)
      j.record("frost-ns", "b".getBytes, t0 + 10)
      val ex = the[SecurityException] thrownBy j.record("frost-ns", "c".getBytes, t0 + 20)
      ex.getMessage should include("rate limit")
      // A different key is unaffected; and the window sliding forward frees capacity.
      j.record("other-key", "a".getBytes, t0 + 20)
      j.record("frost-ns", "d".getBytes, t0 + 61_000)
    }

    "rebuild its distinct-digest set from disk on restart" in {
      val dir = tmpDir()
      val j1 = new SigningJournal(dir, None, 60, logger)
      j1.record("frost-ns", "aaa".getBytes)
      j1.record("frost-ns", "bbb".getBytes)

      val j2 = new SigningJournal(dir, None, 60, logger)
      j2.recover()
      j2.record("frost-ns", "aaa".getBytes) // seen before restart -> flagged repeat
      j2.distinctCount("frost-ns") shouldBe 2
    }
  }

  "RutliDriver with a signing journal" should {
    "journal every signature and rate-limit end-to-end" in {
      implicit val ec: ExecutionContext = ExecutionContext.global
      val dir = tmpDir()
      val factory = new RutliDriverFactory
      val driver = factory.create(
        RutliConfig(signingJournal = Some(SigningJournalConfig(dir, maxPerWindow = Some(3), windowSeconds = 3600))),
        _ => logger,
        ec,
      )
      def await[A](f: Future[A]): A = Await.result(f, 10.seconds)
      val ctx = Context.root()
      val keyId = await(driver.generateSigningKeyPair(SigningKeySpec.EcCurve25519, Some("ns"))(ctx))

      // 3 signatures fit under the limit.
      (1 to 3).foreach(i => await(driver.sign(Array.fill(34)(i.toByte), keyId, SigningAlgoSpec.Ed25519)(ctx)).length shouldBe 64)
      // The 4th trips the limit and fails non-retryably.
      val ex = the[KmsDriverException] thrownBy
        await(driver.sign(Array.fill(34)(9.toByte), keyId, SigningAlgoSpec.Ed25519)(ctx))
      ex.retryable shouldBe false

      driver.close()
      // The journal recorded the successful signs (the 4th failed before signing).
      val content = new String(Files.readAllBytes(journalFiles(dir).head))
      content.linesIterator.count(_.contains(keyId)) should be >= 3
    }
  }
}
