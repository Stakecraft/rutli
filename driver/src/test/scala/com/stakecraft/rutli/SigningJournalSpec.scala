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

  /** A test clock that drives BOTH the journal's monotonic window and its line timestamps. */
  private final class Clock(var ms: Long) {
    def nanos: Long = ms * 1000000L
    def journal(dir: String, max: Option[Int], windowSeconds: Long): SigningJournal =
      new SigningJournal(dir, max, windowSeconds, logger, () => nanos)
    def record(j: SigningJournal, key: String, data: String, atMs: Long): Unit = { ms = atMs; j.record(key, data.getBytes, atMs) }
  }

  "SigningJournal" should {

    "keep the rate limit enforced across a restart (recover rebuilds the window)" in {
      val dir = tmpDir()
      val t0 = 1000000L // fixed clock so the test is deterministic
      val clock = new Clock(t0)
      // Fill the window: 3 signs allowed per 60s.
      val j1 = clock.journal(dir, Some(3), 60)
      clock.record(j1, "frost-ns", "a", t0)
      clock.record(j1, "frost-ns", "b", t0 + 1000)
      clock.record(j1, "frost-ns", "c", t0 + 2000)

      // Restart: a fresh journal over the same dir must reconstruct the window, not reset it.
      val j2 = clock.journal(dir, Some(3), 60)
      clock.ms = t0 + 3000
      j2.recover(nowMillis = t0 + 3000)
      // A 4th sign still inside the 60s window is refused — the limiter survived the restart.
      a[SecurityException] should be thrownBy clock.record(j2, "frost-ns", "d", t0 + 3000)

      // Well after the window, the limit has cleared.
      clock.record(j2, "frost-ns", "e", t0 + 61000)
    }

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
      val t0 = 1_000_000L
      val clock = new Clock(t0)
      val j = clock.journal(tmpDir(), Some(2), 60)
      clock.record(j, "frost-ns", "a", t0)
      clock.record(j, "frost-ns", "b", t0 + 10)
      val ex = the[SecurityException] thrownBy clock.record(j, "frost-ns", "c", t0 + 20)
      ex.getMessage should include("rate limit")
      // A different key is unaffected; and the window sliding forward frees capacity.
      clock.record(j, "other-key", "a", t0 + 20)
      clock.record(j, "frost-ns", "d", t0 + 61_000)
    }

    "not let future-dated journal entries poison the rate-limit window (M6)" in {
      val dir = tmpDir()
      val t0 = 1_000_000L
      val yearMs = 365L * 24 * 3600 * 1000
      // A clock stepped a year ahead while 2 signs were journaled (limit 2 per 60s)...
      val skewed = new Clock(t0 + yearMs)
      val j1 = skewed.journal(dir, Some(2), 60)
      skewed.record(j1, "frost-ns", "a", t0 + yearMs)
      skewed.record(j1, "frost-ns", "b", t0 + yearMs + 1)

      // ...then the clock is corrected and the driver restarts. The future stamps are clamped to
      // now, so the lock-out lasts one window, not a year.
      val clock = new Clock(t0)
      val j2 = clock.journal(dir, Some(2), 60)
      j2.recover(nowMillis = t0)
      a[SecurityException] should be thrownBy clock.record(j2, "frost-ns", "c", t0 + 10)
      clock.record(j2, "frost-ns", "d", t0 + 61_000) // a normal window later, capacity is back
    }

    "use the monotonic clock in-process: a wall-clock step does not move the window (M6)" in {
      val clock = new Clock(5_000_000L)
      val j = clock.journal(tmpDir(), Some(1), 60)
      j.record("frost-ns", "a".getBytes, 5_000_000L)
      // The wall-clock argument jumps a year forward, but the monotonic window has not moved.
      a[SecurityException] should be thrownBy j.record("frost-ns", "b".getBytes, 5_000_000L + 365L * 24 * 3600 * 1000)
      clock.ms += 61_000 // real elapsed time frees the slot
      j.record("frost-ns", "c".getBytes, 5_000_000L)
    }

    "never exceed the rate limit under concurrent signs (M6, atomic check-and-add)" in {
      val dir = tmpDir()
      val j = new SigningJournal(dir, Some(5), 3600, logger)
      val pool = java.util.concurrent.Executors.newFixedThreadPool(16)
      try {
        val granted = new java.util.concurrent.atomic.AtomicInteger
        val refused = new java.util.concurrent.atomic.AtomicInteger
        val start = new java.util.concurrent.CountDownLatch(1)
        val tasks = (1 to 64).map { i =>
          pool.submit(new Runnable {
            def run(): Unit = {
              start.await()
              try { j.record("frost-ns", s"digest-$i".getBytes); granted.incrementAndGet() }
              catch { case _: SecurityException => refused.incrementAndGet() }
              ()
            }
          })
        }
        start.countDown()
        tasks.foreach(_.get())
        granted.get shouldBe 5
        refused.get shouldBe 59
        new String(Files.readAllBytes(journalFiles(dir).head)).linesIterator.size shouldBe 5
      } finally pool.shutdownNow()
    }

    "fail recovery closed on a malformed line in the middle of a journal (M6)" in {
      val dir = tmpDir()
      val j1 = new SigningJournal(dir, None, 60, logger)
      j1.record("frost-ns", "a".getBytes)
      j1.record("frost-ns", "b".getBytes)
      val f = journalFiles(dir).head
      val lines = Files.readAllLines(f).asScala.toVector
      Files.write(f, (lines.head + "\nthis is not a journal line\n" + lines(1) + "\n").getBytes)

      val ex = the[IllegalStateException] thrownBy new SigningJournal(dir, None, 60, logger).recover()
      ex.getMessage should include("malformed")
    }

    "fail recovery closed when a journal cannot be read (M6)" in {
      val dir = tmpDir()
      // A directory named like a journal: listing finds it, reading it fails.
      Files.createDirectory(java.nio.file.Paths.get(dir, "stuck.jsonl"))
      an[java.io.IOException] should be thrownBy new SigningJournal(dir, None, 60, logger).recover()
    }

    "drop a torn newline-less final line on recovery, and keep appending cleanly (M6)" in {
      val dir = tmpDir()
      val j1 = new SigningJournal(dir, None, 60, logger)
      j1.record("frost-ns", "a".getBytes)
      val f = journalFiles(dir).head
      // A crash mid-append: half a line, no newline.
      Files.write(f, """{"ts":"2026-01-01T00:00:00Z","keyId":"frost-ns","dig""".getBytes, java.nio.file.StandardOpenOption.APPEND)

      val j2 = new SigningJournal(dir, None, 60, logger)
      j2.recover()
      j2.distinctCount("frost-ns") shouldBe 1
      j2.record("frost-ns", "b".getBytes)
      // The torn bytes were truncated, so the file is whole lines again and recovers strictly.
      val j3 = new SigningJournal(dir, None, 60, logger)
      j3.recover()
      j3.distinctCount("frost-ns") shouldBe 2
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
