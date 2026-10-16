// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli

import com.digitalasset.canton.crypto.kms.driver.api.v1._
import com.stakecraft.rutli.policy._
import io.opentelemetry.context.Context
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, Path, Paths}
import java.security.spec.PKCS8EncodedKeySpec
import java.security.{KeyFactory, KeyPair, KeyPairGenerator, PrivateKey, Signature}
import java.util.Base64
import scala.concurrent.duration._
import scala.concurrent.{Await, ExecutionContext, Future}
import scala.jdk.CollectionConverters._

class ApprovalGateSpec extends AnyWordSpec with Matchers {

  private implicit val ec: ExecutionContext = ExecutionContext.global
  private val logger = org.slf4j.LoggerFactory.getLogger("approval-test")
  private val ctx = Context.root()

  private def approverKeypair(): KeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
  private def pubB64(kp: KeyPair): String = Base64.getEncoder.encodeToString(kp.getPublic.getEncoded)

  private def approver(id: String, kp: KeyPair): Approver = Approver(id, pubB64(kp))

  /** Simulate an approver: sign the requestId of the single pending request for `keyId`, dropping
    * the approval file the gate expects. */
  private def dropApproval(inbox: String, approverId: String, priv: PrivateKey): Unit = {
    val pending = Paths.get(inbox, "pending")
    val approvals = Paths.get(inbox, "approvals")
    Files.createDirectories(approvals)
    val reqFile = Files.list(pending).iterator().asScala.find(_.toString.endsWith(".json")).get
    val json = Files.readString(reqFile)
    val requestId = "\"requestId\":\"(.*?)\"".r.findFirstMatchIn(json).get.group(1)
    val sig = Signature.getInstance("Ed25519")
    sig.initSign(priv); sig.update(requestId.getBytes(UTF_8))
    val b64 = Base64.getEncoder.encodeToString(sig.sign())
    Files.write(
      approvals.resolve(s"$requestId.$approverId.sig"),
      s"""{"approverId":"$approverId","requestId":"$requestId","signature":"$b64"}""".getBytes(UTF_8),
    )
  }

  private def newInbox(): String = Files.createTempDirectory("rutli-approval").toString

  private def policy(inbox: String, approvers: List[Approver], threshold: Int, timeout: FiniteDuration) =
    ApprovalPolicy(
      rules = List(ApprovalRule("frost-", "quorum", threshold)),
      approvers = approvers,
      inboxDir = inbox,
      timeout = timeout,
      pollInterval = 50.millis,
    )

  "ApprovalPolicy" should {

    "warn when a quorum rule on <p>frost-import- would also hold carried protocol keys (B6)" in {
      val approvers = List(approver("a", approverKeypair()))
      def rules(rs: ApprovalRule*) = ApprovalPolicy(rs.toList, approvers, newInbox())
      val namespaceRule = ApprovalRule("acme1-frost-import-", "quorum", 1)

      val bare = rules(namespaceRule).carriedProtocolKeyWarnings
      bare should have size 2
      bare.foreach(_ should include("acme1-frost-import-"))
      bare.exists(_.contains("acme1-frost-import-sig-")) shouldBe true
      bare.exists(_.contains("acme1-frost-import-seqauth-")) shouldBe true

      // The documented fix: auto rules for the protocol ids first.
      rules(
        ApprovalRule("acme1-frost-import-sig-", "auto"),
        ApprovalRule("acme1-frost-import-seqauth-", "auto"),
        namespaceRule,
      ).carriedProtocolKeyWarnings shouldBe empty
      // Half fixed: one warning left.
      rules(ApprovalRule("acme1-frost-import-sig-", "auto"), namespaceRule).carriedProtocolKeyWarnings should have size 1
      // Naming the namespace id exactly, or an auto rule, holds nothing it should not.
      rules(ApprovalRule("acme1-frost-import-cb0e86a9", "quorum", 1)).carriedProtocolKeyWarnings shouldBe empty
      rules(ApprovalRule("acme1-frost-import-", "auto")).carriedProtocolKeyWarnings shouldBe empty
    }
  }

  "FileApprovalGate" should {

    "auto-approve keys that match no rule" in {
      val gate = new FileApprovalGate(policy(newInbox(), List(approver("a", approverKeypair())), 1, 2.seconds), logger)
      Await.result(gate.authorize("hsm-some-key", "x".getBytes), 1.second) shouldBe (())
    }

    "release a gated sign once the threshold of valid approvals arrives" in {
      val inbox = newInbox()
      val a = approverKeypair(); val b = approverKeypair()
      val gate = new FileApprovalGate(policy(inbox, List(approver("alice", a), approver("bob", b)), 2, 10.seconds), logger)

      val f = gate.authorize("frost-participant1-namespace", "digest".getBytes)
      eventually(pendingExists(inbox))
      dropApproval(inbox, "alice", a.getPrivate)
      dropApproval(inbox, "bob", b.getPrivate)

      Await.result(f, 5.seconds) shouldBe (())
    }

    "not count the same approver twice" in {
      val inbox = newInbox()
      val a = approverKeypair(); val b = approverKeypair()
      val gate = new FileApprovalGate(policy(inbox, List(approver("alice", a), approver("bob", b)), 2, 1500.millis), logger)

      val f = gate.authorize("frost-x", "d".getBytes)
      eventually(pendingExists(inbox))
      dropApproval(inbox, "alice", a.getPrivate) // only one distinct approver

      val ex = the[Exception] thrownBy Await.result(f, 5.seconds)
      ex.getMessage should include("did not reach 2 approvals")
    }

    "reject a forged approval signature" in {
      val inbox = newInbox()
      val a = approverKeypair()
      val gate = new FileApprovalGate(policy(inbox, List(approver("alice", a)), 1, 1500.millis), logger)

      val f = gate.authorize("frost-x", "d".getBytes)
      eventually(pendingExists(inbox))
      // Drop an approval for "alice" but signed by a DIFFERENT (attacker) key.
      dropApproval(inbox, "alice", approverKeypair().getPrivate)

      val ex = the[Exception] thrownBy Await.result(f, 5.seconds)
      ex.getMessage should include("did not reach")
    }

    "time out when no approvals arrive" in {
      val gate = new FileApprovalGate(policy(newInbox(), List(approver("a", approverKeypair())), 1, 400.millis), logger)
      val ex = the[Exception] thrownBy Await.result(gate.authorize("frost-x", "d".getBytes), 5.seconds)
      ex shouldBe a[SecurityException]
    }
  }

  "RutliDriver with an approval policy" should {
    "block a gated sign until a quorum approves, then proceed end-to-end" in {
      val inbox = newInbox()
      val a = approverKeypair(); val b = approverKeypair()
      // Gate ALL software-backend signing keys (their ids are `sig-…`).
      val pol = ApprovalPolicy(
        rules = List(ApprovalRule("sig-", "quorum", 2)),
        approvers = List(approver("alice", a), approver("bob", b)),
        inboxDir = inbox,
        timeout = 10.seconds,
        pollInterval = 50.millis,
      )
      val factory = new RutliDriverFactory
      val driver = factory.create(RutliConfig(approval = Some(pol)), _ => logger, ec)

      val keyId = Await.result(driver.generateSigningKeyPair(SigningKeySpec.EcCurve25519, Some("ns"))(ctx), 5.seconds)

      // Kick off a gated sign; it must NOT complete before approvals arrive.
      val signF: Future[Array[Byte]] =
        driver.sign(Array.fill(34)(7.toByte), keyId, SigningAlgoSpec.Ed25519)(ctx)
      eventually(pendingExists(inbox))
      an[Exception] should be thrownBy Await.result(signF, 300.millis) // still blocked (times out here)

      // Two distinct approvers authorize -> the sign completes with a real 64-byte signature.
      dropApproval(inbox, "alice", a.getPrivate)
      dropApproval(inbox, "bob", b.getPrivate)
      Await.result(signF, 5.seconds).length shouldBe 64

      // A gated sign with no approvals fails as non-retryable per the SPI contract.
      val pol2 = pol.copy(timeout = 300.millis)
      val d2 = new RutliDriverFactory().create(RutliConfig(approval = Some(pol2)), _ => logger, ec)
      val k2 = Await.result(d2.generateSigningKeyPair(SigningKeySpec.EcP256, None)(ctx), 5.seconds)
      val ex = the[KmsDriverException] thrownBy
        Await.result(d2.sign(Array.fill(34)(1.toByte), k2, SigningAlgoSpec.EcDsaSha256)(ctx), 5.seconds)
      ex.retryable shouldBe false
      d2.close()
      driver.close()
    }
  }

  "ApproveCli" should {

    def pendingFile(inbox: String): Path =
      Files.list(Paths.get(inbox, "pending")).iterator().asScala.find(_.toString.endsWith(".json")).get
    def sigFiles(inbox: String): Vector[Path] =
      Files.list(Paths.get(inbox, "approvals")).iterator().asScala.toVector

    "recompute the requestId, sign an untampered request, and the gate accepts it (M7)" in {
      val inbox = newInbox()
      val a = approverKeypair()
      val gate = new FileApprovalGate(policy(inbox, List(approver("alice", a)), 1, 10.seconds), logger)

      val f = gate.authorize("frost-ns", "digest".getBytes)
      eventually(pendingExists(inbox))
      val res = ApproveCli.approveInbox(inbox, "alice", a.getPrivate, None)
      res.approved.size shouldBe 1
      res.refused shouldBe empty
      Await.result(f, 5.seconds) shouldBe (())
    }

    "refuse to sign a pending file whose displayed digest was swapped (M7)" in {
      val inbox = newInbox()
      val a = approverKeypair()
      val gate = new FileApprovalGate(policy(inbox, List(approver("alice", a)), 1, 1500.millis), logger)

      val f = gate.authorize("frost-ns", "the real operation".getBytes)
      eventually(pendingExists(inbox))
      // Someone with write access to the inbox shows the approver a digest they expect, while the
      // requestId (what would be signed) stays bound to the real one.
      val file = pendingFile(inbox)
      val json = Files.readString(file)
      val shown = FileApprovalGate.hex(FileApprovalGate.sha256("what the approver expects".getBytes))
      Files.writeString(file, "\"digest\":\"[0-9a-f]+\"".r.replaceAllIn(json, "\"digest\":\"" + shown + "\""))

      val res = ApproveCli.approveInbox(inbox, "alice", a.getPrivate, None)
      res.approved shouldBe empty
      res.refused should have size 1
      sigFiles(inbox) shouldBe empty
      the[Exception] thrownBy Await.result(f, 5.seconds) // never approved, so the gate times out
    }

    "refuse a swapped keyId or nonce, and a requestId that is not a hash at all (M7)" in {
      val digestHex = FileApprovalGate.hex(FileApprovalGate.sha256("op".getBytes))
      val nonce = Array.fill(16)(3.toByte)
      val id = FileApprovalGate.requestIdFor("frost-ns", FileApprovalGate.sha256("op".getBytes), nonce)
      val nonceHex = FileApprovalGate.hex(nonce)
      ApproveCli.requestIdMatches(id, "frost-ns", digestHex, nonceHex) shouldBe true
      ApproveCli.requestIdMatches(id, "frost-other", digestHex, nonceHex) shouldBe false
      ApproveCli.requestIdMatches(id, "frost-ns", digestHex, "00" * 16) shouldBe false
      ApproveCli.requestIdMatches("../../etc/passwd", "frost-ns", digestHex, nonceHex) shouldBe false
      ApproveCli.requestIdMatches(id, "frost-ns", "zz", nonceHex) shouldBe false
    }
  }

  private def pendingExists(inbox: String): Boolean = {
    val p = Paths.get(inbox, "pending")
    Files.isDirectory(p) && Files.list(p).iterator().asScala.exists(_.toString.endsWith(".json"))
  }

  private def eventually(cond: => Boolean): Unit = {
    val deadline = System.nanoTime() + 3.seconds.toNanos
    while (!cond && System.nanoTime() < deadline) Thread.sleep(20)
    if (!cond) fail("condition not met in time")
  }
}
