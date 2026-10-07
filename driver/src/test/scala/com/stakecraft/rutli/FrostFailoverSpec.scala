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

  private val PermissionDenied = Status.INTERNAL.withDescription("io: Permission denied (os error 13)")

  /** A valid 32-byte Ed25519 public key, so the driver's SPKI re-parse accepts it. */
  private val GroupVerifyingKey: Array[Byte] = {
    val spki = KeyPairGenerator.getInstance("Ed25519").generateKeyPair().getPublic.getEncoded
    spki.takeRight(32)
  }

  /** One fake cosigner: per-RPC call counters and a switchable failure per RPC (`None` = serve). */
  private final class FakeCosigner(index: Int) extends SignerGrpc.SignerImplBase {
    val name: String = s"rutli-cosigner-$index-${InProcessServerBuilder.generateName()}"
    /** This cosigner's signature: 64 bytes of its own index, so a test can tell who signed. */
    val signature: Array[Byte] = Array.fill(64)(index.toByte)

    val signCalls = new AtomicInteger
    val dkgCalls = new AtomicInteger
    val groupKeyCalls = new AtomicInteger
    val generateKeyCalls = new AtomicInteger

    @volatile var signFails: Option[Status] = None
    @volatile var dkgFails: Option[Status] = None
    @volatile var groupKeyFails: Option[Status] = None
    @volatile var generateKeyFails: Option[Status] = None

    private def answer[R](fails: Option[Status], obs: StreamObserver[R])(reply: => R): Unit =
      fails match {
        case Some(st) => obs.onError(st.asRuntimeException())
        case None     => obs.onNext(reply); obs.onCompleted()
      }

    override def sign(req: SignRequest, obs: StreamObserver[SignReply]): Unit = {
      signCalls.incrementAndGet()
      answer(signFails, obs)(SignReply.newBuilder().setSignature(ByteString.copyFrom(signature)).build())
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
  private def withCluster[A](n: Int, hostedKeys: Boolean = false)(
      body: (FrostBackend, IndexedSeq[FakeCosigner]) => A
  ): A = {
    val fakes = (0 until n).map(new FakeCosigner(_))
    val servers: Seq[Server] = fakes.map { f =>
      InProcessServerBuilder.forName(f.name).directExecutor().addService(f).build().start()
    }
    val backend =
      new FrostBackend(fakes.map(_.name), new NoDelegateBackend, logger, None, 10.seconds, hostedKeys) {
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

  private def signNoted(backend: FrostBackend, notes: AuditNotes): Array[Byte] =
    await(backend.withAuditNotes(notes)(backend.sign(Digest, "frost-ns", SigningAlgoSpec.Ed25519)))

  "FrostBackend leader failover" should {

    "route a sign around a leader that answers INTERNAL, and note the hop for the audit entry" in {
      withCluster(2) { case (backend, Seq(a, b)) =>
        a.signFails = Some(PermissionDenied)
        val notes = new AuditNotes
        signNoted(backend, notes) shouldBe b.signature
        a.signCalls.get shouldBe 1
        b.signCalls.get shouldBe 1
        notes.render shouldBe s"failover=${a.name}→${b.name} reason=INTERNAL"
      }
    }

    "lead from the last healthy cosigner afterwards, without re-trying the sick one" in {
      withCluster(2) { case (backend, Seq(a, b)) =>
        a.signFails = Some(PermissionDenied)
        signNoted(backend, new AuditNotes) shouldBe b.signature

        val second = new AuditNotes
        signNoted(backend, second) shouldBe b.signature
        a.signCalls.get shouldBe 1 // not contacted again
        b.signCalls.get shouldBe 2
        second.isEmpty shouldBe true
        second.render shouldBe ""
      }
    }

    "never re-run a DKG ceremony on another leader after a leader-side INTERNAL" in {
      withCluster(2) { case (backend, Seq(a, b)) =>
        a.dkgFails = Some(PermissionDenied)
        val notes = new AuditNotes
        val err = intercept[io.grpc.StatusRuntimeException] {
          await(backend.withAuditNotes(notes)(backend.generateSigningKeyPair(SigningKeySpec.EcCurve25519, Some("ns"))))
        }
        err.getStatus.getCode shouldBe Status.Code.INTERNAL
        a.dkgCalls.get shouldBe 1
        b.dkgCalls.get shouldBe 0
        notes.isEmpty shouldBe true
      }
    }

    "never re-run a DKG on another leader after DEADLINE_EXCEEDED, but do on a refused connection" in {
      withCluster(2) { case (backend, Seq(a, b)) =>
        a.dkgFails = Some(Status.DEADLINE_EXCEEDED)
        intercept[io.grpc.StatusRuntimeException] {
          await(backend.generateSigningKeyPair(SigningKeySpec.EcCurve25519, Some("slow")))
        }.getStatus.getCode shouldBe Status.Code.DEADLINE_EXCEEDED
        b.dkgCalls.get shouldBe 0

        a.dkgFails = Some(Status.UNAVAILABLE)
        val notes = new AuditNotes
        await(backend.withAuditNotes(notes)(backend.generateSigningKeyPair(SigningKeySpec.EcCurve25519, Some("ns")))) shouldBe
          "frost-ns"
        b.dkgCalls.get shouldBe 1
        notes.render shouldBe s"failover=${a.name}→${b.name} reason=UNAVAILABLE"
      }
    }

    "surface a real answer from a live leader immediately, and keep leading from it" in {
      for (code <- Seq(Status.NOT_FOUND, Status.RESOURCE_EXHAUSTED, Status.INVALID_ARGUMENT, Status.PERMISSION_DENIED))
        withClue(code.getCode) {
          withCluster(2) { case (backend, Seq(a, b)) =>
            a.signFails = Some(code)
            val notes = new AuditNotes
            intercept[io.grpc.StatusRuntimeException](signNoted(backend, notes)).getStatus.getCode shouldBe
              code.getCode
            b.signCalls.get shouldBe 0
            notes.isEmpty shouldBe true

            // The node answered, so it is still the preferred leader.
            a.signFails = None
            signNoted(backend, new AuditNotes) shouldBe a.signature
            a.signCalls.get shouldBe 2
            b.signCalls.get shouldBe 0
          }
        }
    }

    "fail getPublicKey and keyExistsAndIsActive over on UNKNOWN" in {
      withCluster(2) { case (backend, Seq(a, b)) =>
        a.groupKeyFails = Some(Status.UNKNOWN.withDescription("handler panicked"))
        val notes = new AuditNotes
        val pk = await(backend.withAuditNotes(notes)(backend.getPublicKey("frost-ns")))
        pk.spec shouldBe SigningKeySpec.EcCurve25519
        pk.key.takeRight(32) shouldBe GroupVerifyingKey
        notes.render shouldBe s"failover=${a.name}→${b.name} reason=UNKNOWN"

        await(backend.keyExistsAndIsActive("frost-ns"))
        a.groupKeyCalls.get shouldBe 1
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
        signNoted(backend, new AuditNotes) shouldBe c.signature
        // ...then make C sick: the next leader tried is A (ring order), not B.
        a.signFails = None
        c.signFails = Some(PermissionDenied)
        val notes = new AuditNotes
        signNoted(backend, notes) shouldBe a.signature
        notes.render shouldBe s"failover=${c.name}→${a.name} reason=INTERNAL"
        b.signCalls.get shouldBe 1
      }
    }

    "not fail a hosted-key write over on a leader-side INTERNAL" in {
      withCluster(2, hostedKeys = true) { case (backend, Seq(a, b)) =>
        a.generateKeyFails = Some(PermissionDenied)
        intercept[io.grpc.StatusRuntimeException] {
          await(backend.generateEncryptionKeyPair(EncryptionKeySpec.Rsa2048, Some("enc")))
        }.getStatus.getCode shouldBe Status.Code.INTERNAL
        b.generateKeyCalls.get shouldBe 0

        // ...but it still fails over when the node is down: GenerateKey is idempotent by key id.
        a.generateKeyFails = Some(Status.UNAVAILABLE)
        await(backend.generateEncryptionKeyPair(EncryptionKeySpec.Rsa2048, Some("enc"))) should startWith("rutli-enc")
        b.generateKeyCalls.get shouldBe 1
      }
    }

    "still fail over when the caller supplies no audit notes" in {
      withCluster(2) { case (backend, Seq(a, b)) =>
        a.signFails = Some(PermissionDenied)
        await(backend.sign(Digest, "frost-ns", SigningAlgoSpec.Ed25519)) shouldBe b.signature
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
        a.signFails = Some(PermissionDenied)
        a.dkgFails = Some(PermissionDenied)

        // DKG first, while A is still the preferred leader: refused, not retried elsewhere.
        intercept[KmsDriverException] {
          await(driver.generateSigningKeyPair(SigningKeySpec.EcCurve25519, Some("ns2"))(ctx))
        }
        b.dkgCalls.get shouldBe 0
        c.dkgCalls.get shouldBe 0

        await(driver.sign(Digest, "frost-ns", SigningAlgoSpec.Ed25519)(ctx)) shouldBe b.signature

        val dkgEntry = sink.entries.collectFirst { case ("generateSigningKeyPair", d) => d }.get
        dkgEntry should include("outcome=failed")
        dkgEntry should not include "failover="

        val signEntry = sink.entries.collectFirst { case ("sign", d) => d }.get
        signEntry shouldBe
          s"keyId=frost-ns algo=${SigningAlgoSpec.Ed25519} inBytes=34 " +
          s"failover=${a.name}→${b.name} reason=INTERNAL sigBytes=64 outcome=ok"
      }
    }
  }
}
