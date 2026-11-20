// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli.backend

import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.nio.file.Files

/** The pin store against the audit log at startup. */
class PinAuditSpec extends AnyWordSpec with Matchers {

  private def pin(keyId: String, key: String) = GroupKeyPin(keyId, key, "dkg", List("c1:9101"), Nil, "2026-11-20T12:00:00Z")
  private val (k1, k2) = ("11" * 32, "22" * 32)

  "PinAudit" should {

    "read back what it writes, the last entry winning" in {
      val details = List(PinAudit.detail(pin("frost-a", k1)), PinAudit.detail(pin("frost-a", k2), recovered = true))
      PinAudit.recorded(details) shouldBe Map("frost-a" -> k2)
    }

    "find rewritten, unrecorded and lost pins, and leave retired ones alone" in {
      val dir = Files.createTempDirectory("rutli-pin-audit")
      Files.createDirectories(dir.resolve("retired"))
      Files.write(dir.resolve("retired").resolve("frost-old.pin.2026-11-20"), Array[Byte](1))
      val pins = Map("frost-a" -> pin("frost-a", k1), "frost-b" -> pin("frost-b", k1), "frost-c" -> pin("frost-c", k1))
      val recorded = Map("frost-a" -> k1, "frost-b" -> k2, "frost-gone" -> k1, "frost-old" -> k1)
      val r = PinAudit.reconcile(pins, recorded, dir)
      r.mismatched shouldBe List("frost-b")
      r.unrecorded.map(_.keyId) shouldBe List("frost-c")
      r.lost shouldBe Set("frost-gone")
    }
  }
}
