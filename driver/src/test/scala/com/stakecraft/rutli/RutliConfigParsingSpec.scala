// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli

import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import pureconfig.ConfigSource

/** The driver's `config { ... }` block as Canton hands it over, parsed through the factory's
  * reader. Optional knobs must default so an existing deployment's config keeps parsing unchanged.
  */
class RutliConfigParsingSpec extends AnyWordSpec with Matchers {

  private val factory = new RutliDriverFactory
  private implicit val reader: pureconfig.ConfigReader[RutliConfig] = factory.configReader

  private def parse(hocon: String): RutliConfig =
    ConfigSource.string(hocon).load[RutliConfig] match {
      case Right(c)  => c
      case Left(err) => fail(s"config did not parse: ${err.prettyPrint()}")
    }

  "the frost block" should {
    "default key-prefix to empty when absent, keeping existing deployments' ids" in {
      val c = parse("""
        backend = "frost"
        frost = { endpoint = "cosigner-1:9101", hosted-keys = true, delegate = "none" }
      """)
      c.frost.map(_.keyPrefix) shouldBe Some("")
    }

    "read endpoints with a per-endpoint tls-name, a bare string still meaning no name" in {
      val c = parse("""
        backend = "frost"
        frost = {
          endpoints = [
            { url = "rutli-node-1.rutli.svc:9101", tls-name = "cosigner1" },
            { url = "rutli-node-2.rutli.svc:9101", tls-name = "cosigner2" },
            "legacy-host:9101"
          ]
          endpoint = "rutli-node-1.rutli.svc:9101"
        }
      """)
      c.frost.map(_.allEndpoints) shouldBe Some(
        List(
          FrostEndpoint("rutli-node-1.rutli.svc:9101", Some("cosigner1")),
          FrostEndpoint("rutli-node-2.rutli.svc:9101", Some("cosigner2")),
          FrostEndpoint("legacy-host:9101", None),
        )
      )
    }

    "read key-prefix" in {
      val c = parse("""
        backend = "frost"
        frost = { endpoints = ["c1:9101", "c2:9102"], key-prefix = "soak1-" }
      """)
      c.frost.map(_.keyPrefix) shouldBe Some("soak1-")
      c.frost.map(_.allEndpoints.map(_.url)) shouldBe Some(List("c1:9101", "c2:9102"))
    }
  }
}
