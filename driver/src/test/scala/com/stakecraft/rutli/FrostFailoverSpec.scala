// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli

import com.digitalasset.canton.crypto.kms.driver.api.v1._
import com.google.protobuf.ByteString
import com.stakecraft.rutli.audit.{AuditNotes, AuditSink}
import com.stakecraft.rutli.backend.{FrostBackend, NoDelegateBackend}
import com.stakecraft.rutli.grpc._
import io.grpc.inprocess.{InProcessChannelBuilder, InProcessServerBuilder}
import io.grpc.stub.StreamObserver
import io.grpc.{Server, Status}
import io.opentelemetry.context.Context
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import org.slf4j.LoggerFactory

import java.security.KeyPairGenerator
import java.util.concurrent.atomic.AtomicInteger
import scala.collection.mutable
import scala.concurrent.duration._
import scala.concurrent.{Await, ExecutionContext, Future}

/** Leader failover across a cosigner roster, against in-process fake cosigners.
  *
  * Regression for the 2026-10-07 DevNet soak incident: cosigner-0's key store became unreadable, it
  * stayed "ready" and answered every Sign with `INTERNAL: io: Permission denied (os error 13)`, and
  * because the driver only failed over on transport errors and cosigner-0 led the roster, one sick
  * node was a total signing outage while cosigners 1 and 2 were healthy.
  */
class FrostFailoverSpec extends AnyWordSpec with Matchers {

  private implicit val ec: ExecutionContext = ExecutionContext.global
  private val logger = LoggerFactory.getLogger(classOf[FrostFailoverSpec])
  private def await[T](f: Future[T]): T = Await.result(f, 10.seconds)

  /** What the 2026-10-07 incident looked like: INTERNAL, with an OS "permission denied" text. Not a
    * policy refusal (that is a real PERMISSION_DENIED, tested separately). */
  private val InternalIoError = Status.INTERNAL.withDescription("io: Permission denied (os error 13)")

  /** The cluster's Ed25519 key: the driver pins its public half and verifies every signature. */
  private val GroupKeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
  private val GroupVerifyingKey: Array[Byte] = GroupKeyPair.getPublic.getEncoded.takeRight(32)

  private def groupSign(msg: Array[Byte]): Array[Byte] = {
    val s = java.security.Signature.getInstance("Ed25519")
    s.initSign(GroupKeyPair.getPrivate); s.update(msg); s.sign()
  }

  /** A well-formed Ed25519 signature by a key that is not the group key: what a lying leader sends. */
  private val OtherKeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
  private def otherSign(msg: Array[Byte]): Array[Byte] = {
    val s = java.security.Signature.getInstance("Ed25519")
    s.initSign(OtherKeyPair.getPrivate); s.update(msg); s.sign()
  }

  /** One fake cosigner: per-RPC call counters and a switchable failure per RPC (`None` = serve). */
  private final class FakeCosigner(index: Int) extends SignerGrpc.SignerImplBase {
    val name: String = s"rutli-cosigner-$index-${InProcessServerBuilder.generateName()}"

    val signCalls = new AtomicInteger
    val dkgCalls = new AtomicInteger
    val groupKeyCalls = new AtomicInteger
    val generateKeyCalls = new AtomicInteger

    @volatile var signFails: Option[Status] = None
    /** Answer every Sign with a 64-byte signature the group key does not verify. */
    @volatile var signLies: Boolean = false
    /** Per-call override, by call number (1 = first Sign): runs before the answer, may block. */
    @volatile var signGate: Int => Option[Status] = _ => None
    @volatile var dkgFails: Option[Status] = None
    @volatile var groupKeyFails: Option[Status] = None
    @volatile var generateKeyFails: Option[Status] = None

    private def answer[R](fails: Option[Status], obs: StreamObserver[R])(reply: => R): Unit =
      fails match {
        case Some(st) => obs.onError(st.asRuntimeException())
        case None     => obs.onNext(reply); obs.onCompleted()
      }

    override def sign(req: SignRequest, obs: StreamObserver[SignReply]): Unit = {
      val call = signCalls.incrementAndGet()
      val msg = req.getMessage.toByteArray
      answer(signGate(call).orElse(signFails), obs)(
        SignReply.newBuilder().setSignature(ByteString.copyFrom(if (signLies) otherSign(msg) else groupSign(msg))).build()
      )
    }

    override def dkg(req: DkgRequest, obs: StreamObserver[DkgReply]): Unit = {
      dkgCalls.incrementAndGet()
      answer(dkgFails, obs)(DkgReply.newBuilder().setGroupVerifyingKey(ByteString.copyFrom(GroupVerifyingKey)).build())
    }

    override def groupKey(req: GroupKeyRequest, obs: StreamObserver[GroupKeyReply]): Unit = {
      groupKeyCalls.incrementAndGet()
      answer(groupKeyFails, obs)(
        GroupKeyReply.newBuilder().setGroupVerifyingKey(ByteString.copyFrom(GroupVerifyingKey)).build()
      )
    }

    override def capabilities(req: CapabilitiesRequest, obs: StreamObserver[CapabilitiesReply]): Unit =
      answer(None, obs)(
        CapabilitiesReply
          .newBuilder()
          .setHostedKeysEnabled(true)
          .addHostedKeySpecs("rsa-2048-oaep-sha256")
          .addHostedKeySpecs("aes-256-gcm")
          .build()
      )

    override def generateKey(req: GenerateKeyRequest, obs: StreamObserver[GenerateKeyReply]): Unit = {
      generateKeyCalls.incrementAndGet()
      answer(generateKeyFails, obs)(
        GenerateKeyReply.newBuilder().setKeyId(req.getKeyId).setSpec(req.getSpec).setCreated(true).build()
      )
    }
  }

  /** Stand up `n` fake cosigners and a FrostBackend whose roster lists them in order. */
  private def withCluster[A](
      n: Int,
      hostedKeys: Boolean = false,
      // Serve each call on a thread of its own, so a fake can block (stop answering) without
      // blocking the client: needed by the deadline tests.
      threaded: Boolean = false,
      budget: FiniteDuration = 10.seconds,
      signAttempt: FiniteDuration = 5.seconds,
      recovery: FiniteDuration = 60.seconds,
  )(
      body: (FrostBackend, IndexedSeq[FakeCosigner]) => A
  ): A = {
    val fakes = (0 until n).map(new FakeCosigner(_))
    val servers: Seq[Server] = fakes.map { f =>
      val b = InProcessServerBuilder.forName(f.name).addService(f)
      (if (threaded) b else b.directExecutor()).build().start()
    }
    val backend =
      new FrostBackend(
        fakes.map(_.name),
        new NoDelegateBackend,
        logger,
        None,
        budget,
        hostedKeys,
        signAttemptTimeout = signAttempt,
        leaderRecovery = recovery,
      ) {
        override protected def buildChannel(endpoint: String): io.grpc.ManagedChannel =
          InProcessChannelBuilder.forName(endpoint).directExecutor().build()
      }
    try body(backend, fakes)
    finally {
      backend.close()
      servers.foreach(_.shutdownNow())
    }
  }

  private val Digest = Array.fill(34)(7.toByte)
  /** What every healthy cosigner returns for `Digest` (Ed25519 is deterministic). Who served is
    * asserted through the per-cosigner call counters instead. */
  private lazy val Signed = groupSign(Digest)

  private def signNoted(backend: FrostBackend, notes: AuditNotes): Array[Byte] =
    await(backend.withAuditNotes(notes)(backend.sign(Digest, "frost-ns", SigningAlgoSpec.Ed25519)))

  "FrostBackend leader failover" should {

    "route a sign around a leader that answers INTERNAL, and note the hop for the audit entry" in {
      withCluster(2) { case (backend, Seq(a, b)) =>
        a.signFails = Some(InternalIoError)
        val notes = new AuditNotes
        signNoted(backend, notes) shouldBe Signed
        a.signCalls.get shouldBe 1
        b.signCalls.get shouldBe 1
        notes.render shouldBe s"failover=${a.name}→${b.name} reason=INTERNAL"
      }
    }

    "lead from the last healthy cosigner afterwards, without re-trying the sick one" in {
      withCluster(2) { case (backend, Seq(a, b)) =>
        a.signFails = Some(InternalIoError)
        signNoted(backend, new AuditNotes) shouldBe Signed

        val second = new AuditNotes
        signNoted(backend, second) shouldBe Signed
        a.signCalls.get shouldBe 1 // not contacted again
        b.signCalls.get shouldBe 2
        second.isEmpty shouldBe true
        second.render shouldBe ""
      }
    }

    "never re-run a DKG ceremony on another leader after a leader-side INTERNAL" in {
      withCluster(2) { case (backend, Seq(a, b)) =>
        a.dkgFails = Some(InternalIoError)
        val notes = new AuditNotes
        val err = intercept[io.grpc.StatusRuntimeException] {
          await(backend.withAuditNotes(notes)(backend.generateSigningKeyPair(SigningKeySpec.EcCurve25519, Some("ns"))))
        }
        err.getStatus.getCode shouldBe Status.Code.INTERNAL
        a.dkgCalls.get shouldBe 1
        b.dkgCalls.get shouldBe 0
        notes.isEmpty shouldBe true

        // ...and the next DKG starts on A again: the INTERNAL does not take the lead from it.
        a.dkgFails = None
        await(backend.generateSigningKeyPair(SigningKeySpec.EcCurve25519, Some("ns"))) shouldBe "frost-ns"
        a.dkgCalls.get shouldBe 2
        b.dkgCalls.get shouldBe 0
      }
    }

    "never re-run a DKG on another leader after DEADLINE_EXCEEDED, but do on a refused connection" in {
      withCluster(2) { case (backend, Seq(a, b)) =>
        a.dkgFails = Some(Status.DEADLINE_EXCEEDED)
        intercept[io.grpc.StatusRuntimeException] {
          await(backend.generateSigningKeyPair(SigningKeySpec.EcCurve25519, Some("slow")))
        }.getStatus.getCode shouldBe Status.Code.DEADLINE_EXCEEDED
        b.dkgCalls.get shouldBe 0

        // The ceremony may still be running on A, so A keeps the lead: the next DKG starts there,
        // and a refused connection fails over to B.
        a.dkgFails = Some(Status.UNAVAILABLE)
        val notes = new AuditNotes
        await(backend.withAuditNotes(notes)(backend.generateSigningKeyPair(SigningKeySpec.EcCurve25519, Some("ns")))) shouldBe
          "frost-ns"
        a.dkgCalls.get shouldBe 2
        b.dkgCalls.get shouldBe 1
        notes.render shouldBe s"failover=${a.name}→${b.name} reason=UNAVAILABLE"
      }
    }

    "return a policy, auth, rate-limit or request refusal at once, without trying another node" in {
      for (
        code <- Seq(Status.PERMISSION_DENIED, Status.UNAUTHENTICATED, Status.RESOURCE_EXHAUSTED, Status.INVALID_ARGUMENT)
      )
        withClue(code.getCode) {
          withCluster(2) { case (backend, Seq(a, b)) =>
            a.signFails = Some(code)
            val notes = new AuditNotes
            intercept[io.grpc.StatusRuntimeException](signNoted(backend, notes)).getStatus.getCode shouldBe
              code.getCode
            b.signCalls.get shouldBe 0 // not retried on another node
            notes.isEmpty shouldBe true

            // These signs carry no intent (no TLS here): the leader alone checks who asks, so its
            // refusal does not move the next call to another node. (With an intent it does; see
            // FrostSigningIntentSpec.)
            a.signFails = None
            signNoted(backend, new AuditNotes) shouldBe Signed
            a.signCalls.get shouldBe 2
            b.signCalls.get shouldBe 0
          }
        }
    }

    "fail a sign over on a leader's NOT_FOUND, FAILED_PRECONDITION or ABORTED, and lead from the next node" in {
      // The group key is pinned before a sign, so the cluster agreed the key exists: these answers
      // are about that leader's own state, and another leader can sign.
      for (code <- Seq(Status.NOT_FOUND, Status.FAILED_PRECONDITION, Status.ABORTED, Status.UNIMPLEMENTED))
        withClue(code.getCode) {
          withCluster(2) { case (backend, Seq(a, b)) =>
            a.signFails = Some(code)
            val notes = new AuditNotes
            signNoted(backend, notes) shouldBe Signed
            notes.render shouldBe s"failover=${a.name}→${b.name} reason=${code.getCode}"

            signNoted(backend, new AuditNotes) shouldBe Signed
            a.signCalls.get shouldBe 1
            b.signCalls.get shouldBe 2
          }
        }
    }

    "serve getPublicKey from the cosigners that answer when one is UNKNOWN, and fail keyExistsAndIsActive over" in {
      // getPublicKey asks the whole roster for agreement (two identical answers needed), so a sick
      // node is simply not counted; keyExistsAndIsActive is a plain failover read.
      withCluster(3) { case (backend, Seq(a, b, _)) =>
        a.groupKeyFails = Some(Status.UNKNOWN.withDescription("handler panicked"))
        val pk = await(backend.getPublicKey("frost-ns"))
        pk.spec shouldBe SigningKeySpec.EcCurve25519
        pk.key.takeRight(32) shouldBe GroupVerifyingKey
        a.groupKeyCalls.get shouldBe 1

        val notes = new AuditNotes
        await(backend.withAuditNotes(notes)(backend.keyExistsAndIsActive("frost-ns")))
        notes.render shouldBe s"failover=${a.name}→${b.name} reason=UNKNOWN"
        a.groupKeyCalls.get shouldBe 2
        b.groupKeyCalls.get shouldBe 2
      }
    }

    "throw the last error, with every hop noted, when no cosigner can serve" in {
      withCluster(3) { case (backend, Seq(a, b, c)) =>
        Seq(a, b, c).zipWithIndex.foreach { case (f, i) =>
          f.signFails = Some(Status.INTERNAL.withDescription(s"sick-$i"))
        }
        val notes = new AuditNotes
        val err = intercept[io.grpc.StatusRuntimeException](signNoted(backend, notes))
        err.getStatus.getCode shouldBe Status.Code.INTERNAL
        err.getStatus.getDescription shouldBe "sick-2"
        notes.render shouldBe
          s"failover=${a.name}→${b.name} reason=INTERNAL failover=${b.name}→${c.name} reason=INTERNAL"
        Seq(a, b, c).map(_.signCalls.get) shouldBe Seq(1, 1, 1)
      }
    }

    "walk the ring from the preferred leader, wrapping past the end of the roster" in {
      withCluster(3) { case (backend, Seq(a, b, c)) =>
        // Move the preferred leader to C...
        a.signFails = Some(Status.UNAVAILABLE)
        b.signFails = Some(Status.UNAVAILABLE)
        signNoted(backend, new AuditNotes) shouldBe Signed
        // ...then make C sick: the next leader tried is A (ring order), not B.
        a.signFails = None
        c.signFails = Some(InternalIoError)
        val notes = new AuditNotes
        signNoted(backend, notes) shouldBe Signed
        notes.render shouldBe s"failover=${c.name}→${a.name} reason=INTERNAL"
        b.signCalls.get shouldBe 1
      }
    }

    "not fail a hosted-key write over on a leader-side INTERNAL" in {
      withCluster(2, hostedKeys = true) { case (backend, Seq(a, b)) =>
        a.generateKeyFails = Some(InternalIoError)
        intercept[io.grpc.StatusRuntimeException] {
          await(backend.generateEncryptionKeyPair(EncryptionKeySpec.Rsa2048, Some("enc")))
        }.getStatus.getCode shouldBe Status.Code.INTERNAL
        b.generateKeyCalls.get shouldBe 0

        // ...but it still fails over when the node is down: GenerateKey is idempotent by key id.
        // (A's error took its preference, so this call starts at B.)
        a.generateKeyFails = None
        b.generateKeyFails = Some(Status.UNAVAILABLE)
        await(backend.generateEncryptionKeyPair(EncryptionKeySpec.Rsa2048, Some("enc"))) should startWith("rutli-enc")
        b.generateKeyCalls.get shouldBe 1
        a.generateKeyCalls.get shouldBe 2
      }
    }

    "withhold a signature that does not verify, and sign through the next leader in the same call" in {
      withCluster(3) { case (backend, Seq(a, b, c)) =>
        a.signLies = true
        val notes = new AuditNotes
        signNoted(backend, notes) shouldBe Signed
        notes.render shouldBe s"sig-verify=failed failover=${a.name}→${b.name} reason=BAD_SIGNATURE"
        Seq(a, b, c).map(_.signCalls.get) shouldBe Seq(1, 1, 0)
      }
    }

    "not lead from a cosigner that returned a bad signature on later calls" in {
      withCluster(3) { case (backend, Seq(a, b, c)) =>
        a.signLies = true
        signNoted(backend, new AuditNotes) shouldBe Signed
        val later = new AuditNotes
        signNoted(backend, later) shouldBe Signed
        signNoted(backend, later) shouldBe Signed
        later.isEmpty shouldBe true
        Seq(a, b, c).map(_.signCalls.get) shouldBe Seq(1, 3, 0)
      }
    }

    "route around endpoint 0 lying from process start, for every call" in {
      // Endpoint 0 is the first preferred leader; before, its bad answer kept it preferred and every
      // sign failed. Now no call after the first one asks it at all.
      withCluster(3) { case (backend, Seq(a, b, c)) =>
        a.signLies = true
        (1 to 5).foreach(_ => signNoted(backend, new AuditNotes) shouldBe Signed)
        Seq(a, b, c).map(_.signCalls.get) shouldBe Seq(1, 5, 0)
      }
    }

    "take the preference from a leader that starts lying after it was preferred" in {
      withCluster(3) { case (backend, Seq(a, b, c)) =>
        a.signFails = Some(Status.UNAVAILABLE)
        signNoted(backend, new AuditNotes) shouldBe Signed // B is now the preferred leader
        a.signFails = None
        b.signLies = true
        val notes = new AuditNotes
        signNoted(backend, notes) shouldBe Signed
        notes.render shouldBe s"sig-verify=failed failover=${b.name}→${c.name} reason=BAD_SIGNATURE"
        signNoted(backend, new AuditNotes) shouldBe Signed
        Seq(a, b, c).map(_.signCalls.get) shouldBe Seq(1, 2, 2)
      }
    }

    "fail non-retryably with does-not-verify when every cosigner lies, asking each once" in {
      withCluster(3) { case (backend, Seq(a, b, c)) =>
        Seq(a, b, c).foreach(_.signLies = true)
        val notes = new AuditNotes
        val err = intercept[KmsDriverException](signNoted(backend, notes))
        err.retryable shouldBe false
        err.getMessage should include("does not verify")
        notes.render shouldBe
          s"sig-verify=failed failover=${a.name}→${b.name} reason=BAD_SIGNATURE " +
          s"sig-verify=failed failover=${b.name}→${c.name} reason=BAD_SIGNATURE sig-verify=failed"
        Seq(a, b, c).map(_.signCalls.get) shouldBe Seq(1, 1, 1)
      }
    }

    "keep an honest leader preferred call after call, and the healthy one after a failover" in {
      withCluster(3) { case (backend, Seq(a, b, c)) =>
        (1 to 4).foreach(_ => signNoted(backend, new AuditNotes) shouldBe Signed)
        Seq(a, b, c).map(_.signCalls.get) shouldBe Seq(4, 0, 0)

        a.signFails = Some(Status.UNAVAILABLE)
        signNoted(backend, new AuditNotes) shouldBe Signed
        a.signFails = None // recovered, but B served last and stays the leader
        (1 to 3).foreach(_ => signNoted(backend, new AuditNotes) shouldBe Signed)
        Seq(a, b, c).map(_.signCalls.get) shouldBe Seq(5, 4, 0)
      }
    }

    "refuse a bad signature from a single-endpoint roster, non-retryably" in {
      withCluster(1) { case (backend, Seq(a)) =>
        a.signLies = true
        val notes = new AuditNotes
        val err = intercept[KmsDriverException](signNoted(backend, notes))
        err.retryable shouldBe false
        err.getMessage should include("does not verify")
        notes.render shouldBe "sig-verify=failed"
        a.signCalls.get shouldBe 1
      }
    }

    "keep a read on the same node after it answers RESOURCE_EXHAUSTED" in {
      withCluster(2) { case (backend, Seq(a, b)) =>
        a.groupKeyFails = Some(Status.RESOURCE_EXHAUSTED)
        intercept[io.grpc.StatusRuntimeException](await(backend.keyExistsAndIsActive("frost-ns"))).getStatus.getCode shouldBe
          Status.Code.RESOURCE_EXHAUSTED
        a.groupKeyFails = None
        await(backend.keyExistsAndIsActive("frost-ns"))
        a.groupKeyCalls.get shouldBe 2
        b.groupKeyCalls.get shouldBe 0
      }
    }

    "not let a slow success put back a leader that a newer call demoted" in {
      withCluster(2) { case (backend, Seq(a, b)) =>
        val entered = new java.util.concurrent.CountDownLatch(1)
        val release = new java.util.concurrent.CountDownLatch(1)
        // A's first sign waits for the test and then succeeds; its later ones fail UNAVAILABLE.
        a.signGate = { call =>
          if (call == 1) {
            entered.countDown()
            release.await(10, java.util.concurrent.TimeUnit.SECONDS)
            None
          } else Some(Status.UNAVAILABLE)
        }
        val slow = backend.sign(Digest, "frost-ns", SigningAlgoSpec.Ed25519)
        entered.await(10, java.util.concurrent.TimeUnit.SECONDS) shouldBe true

        // A newer call finds A failing, demotes it and signs on B.
        val second = new AuditNotes
        signNoted(backend, second) shouldBe Signed
        second.render shouldBe s"failover=${a.name}→${b.name} reason=UNAVAILABLE"

        // The slow call now succeeds on A, but must not make A the leader again.
        release.countDown()
        await(slow) shouldBe Signed
        val third = new AuditNotes
        signNoted(backend, third) shouldBe Signed
        third.isEmpty shouldBe true
        a.signCalls.get shouldBe 2
        b.signCalls.get shouldBe 2
      }
    }

    "still fail over when the caller supplies no audit notes" in {
      withCluster(2) { case (backend, Seq(a, b)) =>
        a.signFails = Some(InternalIoError)
        await(backend.sign(Digest, "frost-ns", SigningAlgoSpec.Ed25519)) shouldBe Signed
      }
    }
  }

  "RutliDriver over a FrostBackend" should {

    "record a failover in the sign's own audit entry, and none for a refused DKG" in {
      /** Captures appended entries in memory, in order. */
      final class RecordingSink extends AuditSink {
        val entries: mutable.Buffer[(String, String)] = mutable.Buffer.empty
        override def append(op: String, detail: String): Unit = synchronized { entries += (op -> detail) }
        override def close(): Unit = ()
      }

      // Hosted keys on: the SPI refuses a driver that advertises no encryption specs, and with
      // `delegate = none` the cluster is what supplies them.
      withCluster(3, hostedKeys = true) { case (backend, Seq(a, b, c)) =>
        val sink = new RecordingSink
        val driver = new RutliDriver(
          backend,
          logger,
          auditLogging = true,
          auditLog = Some(sink),
          // Approves, but asynchronously on another thread, as a real M-of-N quorum does: the
          // backend sign then runs in a Future callback, and the failover must still reach the
          // sign's audit entry.
          new com.stakecraft.rutli.policy.ApprovalGate {
            override def authorize(keyId: String, data: Array[Byte]): Future[Unit] = Future(Thread.sleep(20))
          },
          signingJournal = None,
          backend.supportedSigningKeySpecs,
          backend.supportedSigningAlgoSpecs,
          backend.supportedEncryptionKeySpecs,
          backend.supportedEncryptionAlgoSpecs,
        )
        val ctx = Context.root()
        a.signFails = Some(InternalIoError)
        a.dkgFails = Some(InternalIoError)

        // DKG first, while A is still the preferred leader: refused, not retried elsewhere.
        intercept[KmsDriverException] {
          await(driver.generateSigningKeyPair(SigningKeySpec.EcCurve25519, Some("ns2"))(ctx))
        }
        b.dkgCalls.get shouldBe 0
        c.dkgCalls.get shouldBe 0

        // A DKG's INTERNAL does not take the lead (the ceremony may still be running there), so
        // the sign starts at A and fails over.
        await(driver.sign(Digest, "frost-ns", SigningAlgoSpec.Ed25519)(ctx)) shouldBe Signed

        val dkgEntry = sink.entries.collectFirst { case ("generateSigningKeyPair", d) => d }.get
        dkgEntry should include("outcome=failed")
        dkgEntry should not include "failover="

        val signEntry = sink.entries.collectFirst { case ("sign", d) => d }.get
        signEntry shouldBe
          s"keyId=frost-ns algo=${SigningAlgoSpec.Ed25519} inBytes=34 msg=${RutliDriver.sha256Hex(Digest)} " +
          s"failover=${a.name}→${b.name} reason=INTERNAL sigBytes=64 outcome=ok"
      }
    }
  }

  "FrostBackend deadlines (keepalive and per-attempt)" should {

    "fail a sign over after the sign attempt deadline, not after the whole budget" in {
      withCluster(3, threaded = true, budget = 10.seconds, signAttempt = 300.millis) { case (b, Seq(a, next, _)) =>
        a.signGate = _ => { Thread.sleep(3000); None } // stops answering
        val t0 = System.nanoTime()
        await(b.sign(Digest, "frost-ns", SigningAlgoSpec.Ed25519)) shouldBe Signed
        (System.nanoTime() - t0).nanos should be < 2500.millis
        next.signCalls.get shouldBe 1
      }
    }

    "stop at the request budget with DEADLINE_EXCEEDED, without asking the cosigners left" in {
      withCluster(3, threaded = true, budget = 1500.millis, signAttempt = 1.second) { case (b, fakes) =>
        fakes.foreach(_.signGate = _ => { Thread.sleep(3000); None })
        val t0 = System.nanoTime()
        val e = the[io.grpc.StatusRuntimeException] thrownBy await(b.sign(Digest, "frost-ns", SigningAlgoSpec.Ed25519))
        e.getStatus.getCode shouldBe Status.Code.DEADLINE_EXCEEDED
        (System.nanoTime() - t0).nanos should be < 2800.millis
        fakes(2).signCalls.get shouldBe 0
      }
    }

    "give the lead back to the first cosigner once leaderRecovery has passed" in {
      withCluster(3, recovery = 300.millis) { case (b, Seq(a, next, _)) =>
        a.signGate = call => if (call == 1) Some(Status.UNAVAILABLE) else None
        await(b.sign(Digest, "frost-ns", SigningAlgoSpec.Ed25519)) shouldBe Signed
        await(b.sign(Digest, "frost-ns", SigningAlgoSpec.Ed25519)) shouldBe Signed
        (a.signCalls.get, next.signCalls.get) shouldBe ((1, 2)) // the lead stayed on the next one
        Thread.sleep(500)
        await(b.sign(Digest, "frost-ns", SigningAlgoSpec.Ed25519)) shouldBe Signed
        a.signCalls.get shouldBe 2 // and came back
      }
    }
  }

  "RutliDriver over a FrostBackend, retryability" should {

    def driverOf(backend: FrostBackend) =
      new RutliDriver(
        backend,
        logger,
        auditLogging = false,
        auditLog = None,
        com.stakecraft.rutli.policy.AutoApproveGate,
        signingJournal = None,
        backend.supportedSigningKeySpecs,
        backend.supportedSigningAlgoSpecs,
        backend.supportedEncryptionKeySpecs,
        backend.supportedEncryptionAlgoSpecs,
      )
    def failure(f: => Future[_]): KmsDriverException = the[KmsDriverException] thrownBy await(f)

    "report a cluster that cannot be reached, or a spent budget, as retryable" in {
      withCluster(3, hostedKeys = true) { case (b, fakes) =>
        fakes.foreach(_.signFails = Some(Status.UNAVAILABLE))
        failure(driverOf(b).sign(Digest, "frost-ns", SigningAlgoSpec.Ed25519)(Context.root())).retryable shouldBe true
      }
      withCluster(3, hostedKeys = true, threaded = true, budget = 1.second, signAttempt = 400.millis) { case (b, fakes) =>
        fakes.foreach(_.signGate = _ => { Thread.sleep(2000); None })
        failure(driverOf(b).sign(Digest, "frost-ns", SigningAlgoSpec.Ed25519)(Context.root())).retryable shouldBe true
      }
    }

    "report a policy refusal and a bad signature as not retryable" in {
      withCluster(3, hostedKeys = true) { case (b, Seq(a, _, _)) =>
        a.signFails = Some(Status.PERMISSION_DENIED.withDescription("not on the signer_acl"))
        failure(driverOf(b).sign(Digest, "frost-ns", SigningAlgoSpec.Ed25519)(Context.root())).retryable shouldBe false
      }
      withCluster(3, hostedKeys = true) { case (b, fakes) =>
        fakes.foreach(_.signLies = true)
        failure(driverOf(b).sign(Digest, "frost-ns", SigningAlgoSpec.Ed25519)(Context.root())).retryable shouldBe false
      }
    }
  }
}
