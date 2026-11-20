// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli

import com.stakecraft.rutli.policy.{ApprovalPolicy, ApprovalRule, Approver}
import com.stakecraft.rutli.tools.ConfigCheck
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import org.slf4j.LoggerFactory

import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.Files

/** The driver's production profile: a fully enforced config has no finding, each setting broken on
  * its own fires exactly its own row, production refuses at startup, lab and unset do not, and
  * ConfigCheck reports the same list offline. */
class ProductionProfileSpec extends AnyWordSpec with Matchers {

  import ProductionProfile._

  private val logger = LoggerFactory.getLogger(classOf[ProductionProfileSpec])

  private val endpoints = List(
    FrostEndpoint("rutli-node-1:9101", Some("cosigner1")),
    FrostEndpoint("rutli-node-2:9101", Some("cosigner2")),
    FrostEndpoint("rutli-node-3:9101", Some("cosigner3")),
  )

  private val enforced = RutliConfig(
    backend = "frost",
    auditLogPath = Some("/var/rutli/audit.jsonl"),
    hsm = Some(HsmConfig(libraryPath = "/usr/lib/pkcs11.so", pinEnv = Some("HSM_PIN"))),
    frost = Some(
      FrostConfig(
        endpoints = endpoints,
        delegate = "hsm",
        tls = Some(FrostTlsConfig("/certs/ca.crt", "/certs/driver.crt", "/certs/driver.key")),
        clusterId = Some("0123456789abcdef"),
        pinDir = Some("/var/rutli/pins"),
        expectedGroupKeys = Map("frost-namespace" -> ("ab" * 32)),
      )
    ),
    approval = Some(
      ApprovalPolicy(
        rules = List(ApprovalRule("frost-namespace", "quorum", 1)),
        approvers = List(Approver("alice", "MCowBQYDK2VwAyEA")),
        inboxDir = "/var/rutli/approvals",
      )
    ),
    signingJournal = Some(SigningJournalConfig("/var/rutli/journal")),
    profile = Some("production"),
  )

  private def frost(c: RutliConfig)(f: FrostConfig => FrostConfig): RutliConfig = c.copy(frost = c.frost.map(f))

  "a fully enforced config" should {
    "have no finding, and start under production" in {
      findings(enforced) shouldBe Nil
      noException should be thrownBy enforce(enforced, logger)
    }
  }

  "each setting" should {
    "break exactly its own row" in {
      val tls = enforced.frost.get.tls.get
      val breaks: List[(String, Level, RutliConfig)] = List(
        ("backend", Required, enforced.copy(backend = "hsm")),
        ("frost.delegate", Required, frost(enforced)(_.copy(delegate = "software"))),
        ("frost.delegate", Required, frost(enforced)(_.copy(delegate = "none"))),
        ("frost.tls", Required, frost(enforced)(_.copy(tls = None))),
        ("frost.tls.allow-expired-ca", Required, frost(enforced)(_.copy(tls = Some(tls.copy(allowExpiredCa = true))))),
        ("frost.endpoints", Required, frost(enforced)(_.copy(endpoints = endpoints.take(1)))),
        ("frost.endpoints", Required, frost(enforced)(_.copy(endpoints = endpoints.updated(1, FrostEndpoint("rutli-node-2:9101"))))),
        ("frost.endpoints", Required, frost(enforced)(_.copy(endpoints = endpoints.updated(1, FrostEndpoint("rutli-node-2:9101", Some("cosigner1")))))),
        ("frost.sign-intents", Required, frost(enforced)(_.copy(signIntents = "off"))),
        ("frost.cluster-id", Required, frost(enforced)(_.copy(clusterId = None))),
        ("frost.pin-dir", Required, frost(enforced)(_.copy(pinDir = None))),
        ("frost.expected-group-keys", Advisory, frost(enforced)(_.copy(expectedGroupKeys = Map.empty))),
        ("audit-log-path", Required, enforced.copy(auditLogPath = None)),
        ("signing-journal", Required, enforced.copy(signingJournal = None)),
        ("hsm.pin", Required, enforced.copy(hsm = enforced.hsm.map(_.copy(pin = Some("1234"), pinEnv = None)))),
        ("hsm.pin", Required, enforced.copy(hsm = enforced.hsm.map(_.copy(pin = Some("1234"))))),
        ("hsm.pin", Required, enforced.copy(hsm = enforced.hsm.map(_.copy(pinEnv = None)))),
        ("approval", Advisory, enforced.copy(approval = None)),
        (
          "approval",
          Advisory,
          enforced.copy(approval = enforced.approval.map(_.copy(rules = List(ApprovalRule("rutli-enc-", "quorum", 1))))),
        ),
      )
      breaks.foreach { case (setting, level, cfg) =>
        withClue(s"$setting: ${findings(cfg)}") {
          findings(cfg).map(f => (f.setting, f.level)) shouldBe List((setting, level))
        }
      }
    }

    "accept delegate none with hosted keys" in {
      findings(frost(enforced)(_.copy(delegate = "none", hostedKeys = true))) shouldBe Nil
    }

    "follow the key prefix for the namespace-key approval rule" in {
      val prefixed = frost(enforced)(f => f.copy(keyPrefix = "p1-", expectedGroupKeys = Map("p1-frost-namespace" -> ("ab" * 32))))
      findings(prefixed).map(_.setting) shouldBe List("approval")
      val covered = prefixed.copy(approval = prefixed.approval.map(_.copy(rules = List(ApprovalRule("p1-frost-", "quorum", 1)))))
      findings(covered) shouldBe Nil
    }
  }

  "the profile" should {
    "refuse a production start naming every gap, and let lab and unset start" in {
      val gaps = frost(enforced.copy(signingJournal = None))(_.copy(clusterId = None))
      val e = the[IllegalArgumentException] thrownBy enforce(gaps, logger)
      e.getMessage should include("2 enforcement setting(s)")
      e.getMessage should (include("signing-journal") and include("frost.cluster-id") and include(Doc))
      noException should be thrownBy enforce(gaps.copy(profile = Some("lab")), logger)
      noException should be thrownBy enforce(gaps.copy(profile = None), logger)
      // Advisory findings never refuse.
      noException should be thrownBy enforce(enforced.copy(approval = None), logger)
    }

    "refuse a value that is neither production nor lab" in {
      an[IllegalArgumentException] should be thrownBy enforce(enforced.copy(profile = Some("staging")), logger)
    }
  }

  "ConfigCheck" should {
    def check(hocon: String, extra: String*): (Int, String) = {
      val f = Files.createTempFile("rutli-config-check", ".conf")
      Files.write(f, hocon.getBytes(UTF_8))
      val sb = new StringBuilder
      val code = ConfigCheck.run((Seq("--config", f.toString) ++ extra).toArray, l => sb.append(l).append('\n'), l => sb.append(l).append('\n'))
      (code, sb.toString)
    }
    val block =
      """profile = "production"
        |backend = "frost"
        |audit-log-path = "/var/rutli/audit.jsonl"
        |signing-journal = { dir = "/var/rutli/journal" }
        |hsm = { library-path = "/usr/lib/pkcs11.so", pin-env = "HSM_PIN" }
        |frost = {
        |  endpoints = [
        |    { url = "rutli-node-1:9101", tls-name = "cosigner1" },
        |    { url = "rutli-node-2:9101", tls-name = "cosigner2" }
        |  ]
        |  tls = { ca-cert = "/certs/ca.crt", cert = "/certs/driver.crt", key = "/certs/driver.key" }
        |  cluster-id = "0123456789abcdef"
        |  pin-dir = "/var/rutli/pins"
        |  expected-group-keys { frost-namespace = "abababababababababababababababababababababababababababababababab" }
        |}
        |""".stripMargin

    "exit 0 with only the advisory finding for an enforced block" in {
      val (code, out) = check(block)
      code shouldBe 0
      out should (include("0 required and 1 advisory") and include("[advisory] approval") and include("meets the production profile"))
    }

    "exit 1 and list each gap, under any profile" in {
      val (code, out) = check(block.replace("cluster-id = \"0123456789abcdef\"", "").replace("profile = \"production\"", "profile = \"lab\""))
      code shouldBe 1
      out should (include("profile lab, 1 required") and include("[required] frost.cluster-id"))
    }

    "read the driver block out of a Canton config with --at" in {
      val canton = s"canton.participants.participant1.crypto.kms.config = {\n$block\n}"
      val (code, out) = check(canton, "--at", "canton.participants.participant1.crypto.kms.config")
      code shouldBe 0
      out should include("meets the production profile")
    }

    "exit 2 for an unknown key, an unknown profile, or bad usage" in {
      check(block + "\naudit-log-paht = \"/x\"\n")._1 shouldBe 2
      check(block.replace("\"production\"", "\"staging\""))._1 shouldBe 2
      check(block.replace("cluster-id =", "sign-intents = \"maybe\"\n  cluster-id ="))._1 shouldBe 2
      ConfigCheck.run(Array("--nope"), _ => (), _ => ()) shouldBe 2
    }
  }
}
