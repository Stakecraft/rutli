// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli

import com.stakecraft.rutli.audit.HashChainedAuditLog
import com.stakecraft.rutli.guard.SigningJournal
import com.stakecraft.rutli.tools.StateCheck
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import org.slf4j.LoggerFactory

import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, Path, StandardOpenOption}

/** The pre-upgrade state check predicts exactly what the fail-closed driver will do, and never
  * writes. */
class StateCheckSpec extends AnyWordSpec with Matchers {

  private val logger = LoggerFactory.getLogger(classOf[StateCheckSpec])

  private def run(args: String*): (Int, String) = {
    val sb = new StringBuilder
    val code = StateCheck.run(args.toArray, l => sb.append(l).append('\n'), l => sb.append(l).append('\n'))
    (code, sb.toString)
  }

  private def appendRaw(p: Path, s: String): Unit =
    Files.write(p, s.getBytes(UTF_8), StandardOpenOption.APPEND)

  private def auditLog(entries: Int): Path = {
    val p = Files.createTempDirectory("statecheck-audit").resolve("audit.jsonl")
    val log = HashChainedAuditLog.open(p.toString)
    (1 to entries).foreach(i => log.append("sign", s"key=frost-ns n=$i"))
    log.close()
    p
  }

  private def journal(): Path = {
    val d = Files.createTempDirectory("statecheck-journal")
    val j = new SigningJournal(d.toString, None, 60, logger)
    j.record("frost-ns", Array[Byte](1, 2, 3))
    j.record("frost-ns", Array[Byte](4, 5, 6))
    d
  }

  private def onlyFile(d: Path): Path = Files.list(d).iterator().next()

  "StateCheck" should {
    "pass a clean audit log and journal" in {
      val (code, out) = run("--audit-log", auditLog(3).toString, "--journal-dir", journal().toString)
      code shouldBe 0
      out should include("3 entries, hash chain intact")
      out should include("1 file(s), 2 entries")
    }

    "pass, and report, a torn final line without touching the file" in {
      val a = auditLog(2)
      appendRaw(a, """{"seq":3,"ts":"2026-10""")
      val d = journal()
      appendRaw(onlyFile(d), """{"ts":"2026""")
      val (before, beforeJ) = (Files.readAllBytes(a).toVector, Files.readAllBytes(onlyFile(d)).toVector)
      val (code, out) = run("--audit-log", a.toString, "--journal-dir", d.toString)
      code shouldBe 0
      out should include("torn final line")
      Files.readAllBytes(a).toVector shouldBe before
      Files.readAllBytes(onlyFile(d)).toVector shouldBe beforeJ
      // ...and the driver indeed starts on both.
      HashChainedAuditLog.open(a.toString).close()
      new SigningJournal(d.toString, None, 60, logger).recover()
    }

    "fail on a malformed audit line or a broken chain, exactly where open refuses" in {
      val a = auditLog(3)
      val lines = new String(Files.readAllBytes(a), UTF_8).split("\n")
      Files.write(a, (lines.updated(1, lines(1).replace("n=2", "n=X")).mkString("\n") + "\n").getBytes(UTF_8))
      val (code, out) = run("--audit-log", a.toString)
      code shouldBe 1
      out should include("entry 2")
      an[IllegalStateException] should be thrownBy HashChainedAuditLog.open(a.toString)
    }

    "fail on a malformed journal line, exactly where recovery fails closed" in {
      val d = journal()
      appendRaw(onlyFile(d), "not json\n")
      val (code, out) = run("--journal-dir", d.toString)
      code shouldBe 1
      out should include("line 3 is malformed")
      an[IllegalStateException] should be thrownBy new SigningJournal(d.toString, None, 60, logger).recover()
    }

    "refuse bad usage" in {
      run()._1 shouldBe 2
      run("--audit-log")._1 shouldBe 2
    }
  }
}
