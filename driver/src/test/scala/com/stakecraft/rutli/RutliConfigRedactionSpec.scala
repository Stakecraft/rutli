// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli

import com.typesafe.config.ConfigRenderOptions
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

/** The confidential [[RutliDriverFactory.configWriter]] is what Canton uses when it echoes a
  * driver's config back (logs / its config API). It must not leak secrets: the inline HSM PIN, and
  * the on-disk path of the driver's TLS private key.
  */
class RutliConfigRedactionSpec extends AnyWordSpec with Matchers {

  private val factory = new RutliDriverFactory

  private val config = RutliConfig(
    backend = "frost",
    hsm = Some(HsmConfig(libraryPath = "/usr/lib/softhsm/libsofthsm2.so", pin = Some("supersecret-pin"))),
    frost = Some(
      FrostConfig(
        endpoint = Some("cosigner-1:9101"),
        tls = Some(
          FrostTlsConfig(
            caCert = "/etc/rutli/ca.crt",
            cert = "/etc/rutli/driver.crt",
            key = "/etc/rutli/driver.key",
            domain = Some("rutli-cosigner"),
          )
        ),
      )
    ),
  )

  private def render(confidential: Boolean): String =
    factory.configWriter(confidential).to(config).render(ConfigRenderOptions.concise())

  "the confidential config writer" should {
    "redact the HSM PIN and the TLS private-key path" in {
      val out = render(confidential = true)
      out should not include "supersecret-pin"
      out should not include "/etc/rutli/driver.key"
      out should include("<redacted>")
      // Non-secret material (public certs) is still rendered.
      out should include("/etc/rutli/ca.crt")
      out should include("/etc/rutli/driver.crt")
    }

    "keep all fields verbatim when not confidential" in {
      val out = render(confidential = false)
      out should include("supersecret-pin")
      out should include("/etc/rutli/driver.key")
    }
  }
}
