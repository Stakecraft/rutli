// Copyright 2026 StakeCraft LLC
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli

import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import pureconfig.ConfigSource
import pureconfig.error.{ConvertFailure, UnknownKey}

/** The driver's `config { ... }` block as Canton hands it over, parsed through the factory's
  * reader. Optional knobs must default so an existing deployment's config keeps parsing unchanged.
  * Unknown keys are refused in every block: a misspelt key must not silently leave a control off.
  */
class RutliConfigParsingSpec extends AnyWordSpec with Matchers {

  private val factory = new RutliDriverFactory
  private implicit val reader: pureconfig.ConfigReader[RutliConfig] = factory.configReader

  private def parse(hocon: String): RutliConfig =
    ConfigSource.string(hocon).load[RutliConfig] match {
      case Right(c)  => c
      case Left(err) => fail(s"config did not parse: ${err.prettyPrint()}")
    }

  /** A list index in a failure path, written the same way whatever pureconfig prints for it
    * (`rules.0`, `rules[0]` or `rules(0)`): the tests care about the key and where it sits. */
  private def dotted(s: String): String = s.replaceAll("""[\[(](\d+)[\])]""", ".$1")

  /** Parse a config that must be refused for one unknown key. The failure must name the key and
    * its full path (`path` with list indices dotted, e.g. `approval.rules.0.treshold`). */
  private def refusedFor(hocon: String, key: String, path: String): Unit =
    ConfigSource.string(hocon).load[RutliConfig] match {
      case Right(c) => fail(s"config with unknown key '$path' parsed: $c")
      case Left(err) =>
        err.toList.collect { case ConvertFailure(UnknownKey(k), _, p) => (k, dotted(p)) } should contain(key -> path)
        dotted(err.prettyPrint()) should include(path)
    }

  "unknown keys" should {
    "be refused at the top level" in {
      refusedFor(
        """backend = "software"
        audit-loging = true""",
        "audit-loging",
        "audit-loging",
      )
    }

    "be refused for a misspelt approval block, which therefore cannot fall back to auto-approve" in {
      refusedFor(
        """
        backend = "software"
        aproval {
          inbox-dir = "/var/rutli/approvals"
          rules = [{ key-id-prefix = "frost-", mode = "quorum", threshold = 1 }]
          approvers = [{ id = "alice", public-key-base64 = "MCowBQYDK2VwAyEA" }]
        }
      """,
        "aproval",
        "aproval",
      )
    }

    "be refused inside frost" in {
      refusedFor(
        """backend = "frost"
        frost = { endpoint = "c1:9101", sign-intent = off }""",
        "sign-intent",
        "frost.sign-intent",
      )
    }

    "be refused inside frost.tls" in {
      refusedFor(
        """backend = "frost"
        frost = {
          endpoint = "c1:9101"
          tls = { ca-cert = "/c/ca.crt", cert = "/c/d.crt", key = "/c/d.key", allow-expired = true }
        }""",
        "allow-expired",
        "frost.tls.allow-expired",
      )
    }

    "be refused inside an approval rule" in {
      refusedFor(
        """
        approval {
          inbox-dir = "/var/rutli/approvals"
          rules = [{ key-id-prefix = "frost-", mode = "quorum", treshold = 1 }]
          approvers = [{ id = "alice", public-key-base64 = "MCowBQYDK2VwAyEA" }]
        }
      """,
        "treshold",
        "approval.rules.0.treshold",
      )
    }

    "be refused inside an endpoint object" in {
      refusedFor(
        """backend = "frost"
        frost = { endpoints = [ "c0:9101", { url = "c1:9101", tls-nme = "cosigner1" } ] }""",
        "tls-nme",
        "frost.endpoints.1.tls-nme",
      )
    }

    "be refused inside signing-journal, software and hsm" in {
      refusedFor("""signing-journal = { dir = "/j", max-per-windw = 10 }""", "max-per-windw", "signing-journal.max-per-windw")
      refusedFor("""software = { dir = "/s", seal-secret = "X" }""", "seal-secret", "software.seal-secret")
      refusedFor(
        """backend = "hsm"
        hsm = { library-path = "/l.so", pin_env = "P" }""",
        "pin_env",
        "hsm.pin_env",
      )
    }
  }

  "an approver's key" should {
    def approvers(entry: String): String =
      s"""approval { inbox-dir = "/var/rutli/approvals", rules = [], approvers = [ $entry ] }"""

    def refused(entry: String): String =
      ConfigSource.string(approvers(entry)).load[RutliConfig] match {
        case Right(c)  => fail(s"approver $entry parsed: $c")
        case Left(err) => dotted(err.prettyPrint())
      }

    "be read under public-key-base64, the name the docs and `approve keygen` print" in {
      val c = parse(approvers("""{ id = "alice", public-key-base64 = "MCowBQYDK2VwAyEA" }"""))
      c.approval.map(_.approvers.map(a => a.id -> a.publicKeyBase64)) shouldBe Some(List("alice" -> "MCowBQYDK2VwAyEA"))
    }

    "be read under public-key-base-64 too, the only name releases up to 0.4.0 read" in {
      val c = parse(approvers("""{ id = "alice", public-key-base-64 = "MCowBQYDK2VwAyEA" }"""))
      c.approval.map(_.approvers.map(a => a.id -> a.publicKeyBase64)) shouldBe Some(List("alice" -> "MCowBQYDK2VwAyEA"))
    }

    "be refused when both names are set" in {
      refused("""{ id = "alice", public-key-base64 = "MCowBQYDK2VwAyEA", public-key-base-64 = "MCowBQYDK2VwAyEB" }""") should
        include("keep one")
    }

    "be refused when it is missing, naming the documented key" in {
      refused("""{ id = "alice" }""") should include("public-key-base64")
    }

    "not hide an unknown key next to it" in {
      refusedFor(
        approvers("""{ id = "alice", public-key-base64 = "MCowBQYDK2VwAyEA", pubkey = "x" }"""),
        "pubkey",
        "approval.approvers.0.pubkey",
      )
    }
  }

  "an approval rule" should {
    val alice = """{ id = "alice", public-key-base64 = "MCowBQYDK2VwAyEA" }"""
    def approval(rules: String, approvers: String = alice): String =
      s"""approval { inbox-dir = "/var/rutli/approvals", rules = [ $rules ], approvers = [ $approvers ] }"""

    /** Parse a config that must be refused for its approval rules: (path, message) of each failure. */
    def refusedRules(hocon: String): List[(String, String)] =
      ConfigSource.string(hocon).load[RutliConfig] match {
        case Right(c) => fail(s"approval rules parsed: $c")
        case Left(err) =>
          err.toList.collect { case ConvertFailure(r: RutliDriverFactory.InvalidApprovalRule, _, p) =>
            (dotted(p), r.description)
          }
      }

    "refuse a misspelt mode at the rule's mode key, naming the rule and the value, never auto-approving" in {
      val failures = refusedRules(approval("""{ key-id-prefix = "frost-", mode = "quorom", threshold = 1 }"""))
      failures.map(_._1) shouldBe List("approval.rules.0.mode")
      failures.head._2 should include("\"frost-\"")
      failures.head._2 should include("\"quorom\"")
    }

    "refuse a mode in another letter case, as the cosigners do" in {
      val failures = refusedRules(
        approval("""{ key-id-prefix = "frost-import-sig-", mode = "auto" }, { key-id-prefix = "frost-", mode = "Quorum", threshold = 1 }""")
      )
      failures.map(_._1) shouldBe List("approval.rules.1.mode")
      failures.head._2 should include("\"Quorum\"")
    }

    "read quorum and auto, with quorum the default" in {
      val c = parse(approval("""{ key-id-prefix = "frost-import-sig-", mode = "auto" }, { key-id-prefix = "frost-", threshold = 1 }"""))
      c.approval.map(_.rules.map(_.mode)) shouldBe Some(List("auto", "quorum"))
      c.approval.flatMap(_.thresholdFor("frost-ns")) shouldBe Some(1)
      c.approval.flatMap(_.thresholdFor("frost-import-sig-1")) shouldBe None
    }

    "refuse a quorum rule with no approvers configured as a config error, not a stack trace" in {
      val failures = refusedRules(approval("""{ key-id-prefix = "frost-", mode = "quorum", threshold = 1 }""", approvers = ""))
      failures.map(_._1) shouldBe List("approval.rules")
      failures.head._2 should include("threshold 1")
      failures.head._2 should include("(0)")
    }

    "refuse a quorum rule that an earlier auto rule with an empty prefix covers" in {
      val failures = refusedRules(
        approval("""{ key-id-prefix = "", mode = "auto" }, { key-id-prefix = "frost-", mode = "quorum", threshold = 1 }""")
      )
      failures.map(_._1) shouldBe List("approval.rules")
      failures.head._2 should include("never applies")
    }

    "accept an empty prefix on a quorum rule: it holds every key" in {
      parse(approval("""{ key-id-prefix = "", mode = "quorum", threshold = 1 }""")).approval.flatMap(_.thresholdFor("any")) shouldBe
        Some(1)
    }
  }

  "a config with every block set" should {
    lazy val full = parse("""
      backend = "frost"
      audit-logging = true
      audit-log-path = "/rutli-state/audit.jsonl"
      signing-journal = { dir = "/rutli-state/journal", max-per-window = 100, window-seconds = 30 }
      software = { dir = "/rutli-state/softkeys", seal-secret-env = "RUTLI_SOFT_SEAL_SECRET" }
      hsm = { library-path = "/l.so", slot-list-index = 0, token-label = "t", pin = "1234", pin-env = "P" }
      approval {
        inbox-dir = "/var/rutli/approvals"
        timeout = 30m
        poll-interval = 2s
        rules = [
          { key-id-prefix = "soak1-frost-import-sig-", mode = "auto" },
          { key-id-prefix = "soak1-frost-", mode = "quorum", threshold = 2 }
        ]
        approvers = [
          { id = "alice", public-key-base64 = "MCowBQYDK2VwAyEA" },
          { id = "bob",   public-key-base-64 = "MCowBQYDK2VwAyEB" }
        ]
      }
      frost = {
        endpoints = [ { url = "c1:9101", tls-name = "cosigner1" }, "c2:9102" ]
        endpoint = "c3:9103"
        delegate = "software"
        hosted-keys = true
        key-prefix = "soak1-"
        cluster-id = "453bb4aea2088bb5"
        sign-intents = on
        tls = { ca-cert = "/c/ca.crt", cert = "/c/d.crt", key = "/c/d.key", domain = "rutli-cosigner", allow-expired-ca = false }
      }
    """)

    "parse" in {
      full.approval.map(_.rules.size) shouldBe Some(2)
      full.frost.map(_.allEndpoints.size) shouldBe Some(3)
      full.signingJournal.flatMap(_.maxPerWindow) shouldBe Some(100)
    }

    "read back what the config writer emits, confidential or not (Canton echoes the config)" in {
      factory.configReader.from(factory.configWriter(confidential = false).to(full)) shouldBe Right(full)
      val redacted = factory.configReader.from(factory.configWriter(confidential = true).to(full))
      redacted.map(_.frost.flatMap(_.tls).map(_.key)) shouldBe Right(Some("<redacted>"))
      redacted.map(_.hsm.flatMap(_.pin)) shouldBe Right(None)
    }
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

    "read sign-intents (audit F5), on by default" in {
      parse("""backend = "frost"
        frost = { endpoint = "c1:9101" }""").frost.map(_.signIntentsEnabled) shouldBe Some(true)
      parse("""backend = "frost"
        frost = { endpoint = "c1:9101", sign-intents = off }""").frost.map(_.signIntentsEnabled) shouldBe Some(false)
      parse("""backend = "frost"
        frost = { endpoint = "c1:9101", sign-intents = on }""").frost.map(_.signIntentsEnabled) shouldBe Some(true)
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
