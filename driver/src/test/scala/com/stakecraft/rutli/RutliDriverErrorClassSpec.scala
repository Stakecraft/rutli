// Copyright 2026 StakeCraft LLC
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli

import com.digitalasset.canton.crypto.kms.driver.api.v1._
import com.stakecraft.rutli.audit.AuditSink
import com.stakecraft.rutli.backend.KmsBackend
import io.grpc.{Metadata, Status}
import io.opentelemetry.context.Context
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import org.slf4j.LoggerFactory

import scala.collection.mutable
import scala.concurrent.duration._
import scala.concurrent.{Await, ExecutionContext, Future}

/** The error class Canton sees. Canton retries a retryable KMS error without limit and never
  * retries a final one, so the driver's mapping at the SPI boundary decides between an outage that
  * heals by itself and one that does not: a cosigner or the network being down, a deadline, and the
  * cosigners' "not now" (ABORTED) are retryable; everything else a node decided, and every failure
  * the driver cannot name, is final.
  */
class RutliDriverErrorClassSpec extends AnyWordSpec with Matchers {

  private implicit val ec: ExecutionContext = ExecutionContext.global
  private val logger = LoggerFactory.getLogger(classOf[RutliDriverErrorClassSpec])
  private val ctx = Context.root()
  private def await[T](f: Future[T]): T = Await.result(f, 10.seconds)

  /** A backend whose key-existence check does whatever the test says; nothing else is called. */
  private final class Scripted(exists: () => Future[Unit]) extends KmsBackend {
    private def unused[A](op: String): Future[A] = Future.failed(new AssertionError(s"$op is not part of this test"))
    override val supportedSigningKeySpecs: Set[SigningKeySpec] = Set(SigningKeySpec.EcCurve25519)
    override val supportedSigningAlgoSpecs: Set[SigningAlgoSpec] = Set(SigningAlgoSpec.Ed25519)
    override val supportedEncryptionKeySpecs: Set[EncryptionKeySpec] = Set(EncryptionKeySpec.Rsa2048)
    override val supportedEncryptionAlgoSpecs: Set[EncryptionAlgoSpec] = Set(EncryptionAlgoSpec.RsaEsOaepSha256)
    override def generateSigningKeyPair(s: SigningKeySpec, n: Option[String]): Future[String] = unused("generateSigningKeyPair")
    override def generateEncryptionKeyPair(s: EncryptionKeySpec, n: Option[String]): Future[String] =
      unused("generateEncryptionKeyPair")
    override def generateSymmetricKey(n: Option[String]): Future[String] = unused("generateSymmetricKey")
    override def sign(d: Array[Byte], k: String, a: SigningAlgoSpec): Future[Array[Byte]] = unused("sign")
    override def decryptAsymmetric(c: Array[Byte], k: String, a: EncryptionAlgoSpec): Future[Array[Byte]] =
      unused("decryptAsymmetric")
    override def encryptSymmetric(d: Array[Byte], k: String): Future[Array[Byte]] = unused("encryptSymmetric")
    override def decryptSymmetric(c: Array[Byte], k: String): Future[Array[Byte]] = unused("decryptSymmetric")
    override def getPublicKey(k: String): Future[PublicKey] = unused("getPublicKey")
    override def keyExistsAndIsActive(k: String): Future[Unit] = exists()
    override def deleteKey(k: String): Future[Unit] = unused("deleteKey")
    override def health: Future[KmsDriverHealth] = Future.successful(KmsDriverHealth.Ok)
  }

  private final class RecordingSink extends AuditSink {
    val entries: mutable.Buffer[(String, String)] = mutable.Buffer.empty
    override def append(op: String, detail: String): Unit = synchronized { entries += (op -> detail); () }
    override def close(): Unit = ()
  }

  private def driverOver(exists: () => Future[Unit], sink: Option[AuditSink] = None): RutliDriver = {
    val backend = new Scripted(exists)
    new RutliDriver(
      backend,
      logger,
      auditLogging = false,
      auditLog = sink,
      com.stakecraft.rutli.policy.AutoApproveGate,
      signingJournal = None,
      backend.supportedSigningKeySpecs,
      backend.supportedSigningAlgoSpecs,
      backend.supportedEncryptionKeySpecs,
      backend.supportedEncryptionAlgoSpecs,
    )
  }

  /** What Canton gets when the backend's check ends as `exists` says. */
  private def atCanton(exists: () => Future[Unit], sink: Option[AuditSink] = None): KmsDriverException =
    the[KmsDriverException] thrownBy await(driverOver(exists, sink).keyExistsAndIsActive("frost-ns")(ctx))

  "RutliDriver" should {

    "report UNAVAILABLE, DEADLINE_EXCEEDED and ABORTED from the cluster as retryable, every other status as final" in {
      val retryable = Set(Status.Code.UNAVAILABLE, Status.Code.DEADLINE_EXCEEDED, Status.Code.ABORTED)
      for (code <- Status.Code.values().toSeq if code != Status.Code.OK) withClue(s"$code: ") {
        val status = Status.fromCode(code).withDescription("from a cosigner")
        val ex = atCanton(() => Future.failed(status.asRuntimeException()))
        ex.retryable shouldBe retryable(code)
        ex.getCause shouldBe a[io.grpc.StatusRuntimeException]
      }
    }

    "report the cosigners' \"not now\" as retryable: a ceremony holding the key, a session that is gone" in {
      // The ceremony messages are the cosigner's own (frost/cosigner/src/error.rs).
      val notNow = Seq(
        "a dkg ceremony (id dkg-0123456789abcdef0123456789abcdef) is already in progress for key frost-ns",
        "a refresh ceremony (id refresh-0123456789abcdef0123456789abcdef) is already in progress for key frost-ns",
        "unknown session: sign-1",
        "ceremony dkg-01 for key frost-ns was superseded by a newer ceremony — refusing to persist",
      )
      for (message <- notNow) withClue(s"$message: ") {
        atCanton(() => Future.failed(Status.ABORTED.withDescription(message).asRuntimeException())).retryable shouldBe true
      }
    }

    "report ABORTED for conflicting hosted-key material as final, by the cosigner's reason trailer or its message" in {
      def aborted(message: String, reason: Option[String]): KmsDriverException = {
        val trailers = new Metadata
        reason.foreach(r => trailers.put(Metadata.Key.of("rutli-error", Metadata.ASCII_STRING_MARSHALLER), r))
        atCanton(() => Future.failed(Status.ABORTED.withDescription(message).asRuntimeException(trailers)))
      }
      val conflict = "hosted key conflict for rutli-enc-1: cosigner 2 holds other material"
      aborted(conflict, Some("hosted-conflict")).retryable shouldBe false
      aborted("aborted", Some("hosted-conflict")).retryable shouldBe false
      // Should the trailer not reach the driver, the cosigner's message still makes it final.
      aborted(conflict, None).retryable shouldBe false
      // Any other reason, or none, is the plain "try again".
      aborted("unknown session: sign-1", Some("sessions-full")).retryable shouldBe true
      aborted("unknown session: sign-1", None).retryable shouldBe true
    }

    "report a member's \"ceremony already in progress\" as retryable when a leader passes it on as INTERNAL" in {
      // What a client gets when the contention is detected on a member and the leader loses the
      // member's code: INTERNAL with the member's status rendered into the message.
      val wrapped = "rpc status: status: Aborted, message: \"a dkg ceremony (id dkg-0123456789abcdef0123456789abcdef) " +
        "is already in progress for key frost-ns\""
      atCanton(() => Future.failed(Status.INTERNAL.withDescription(wrapped).asRuntimeException())).retryable shouldBe true

      // Nothing wider: any other INTERNAL is a node's failure, also one that only mentions progress.
      for (
        other <- Seq(
          "io: Permission denied (os error 13)",
          "dkg part 2 failed: a share is already in progress of being written",
          "rpc status: status: Aborted, message: \"unknown session: sign-1\"",
          "a dkg ceremony (id dkg-0123456789abcdef0123456789abcdef) is already in progress for key frost-ns",
          "rpc status: status: Internal, message: \"a dkg ceremony (id dkg-01) is already in progress for key frost-ns\"",
        )
      ) withClue(s"$other: ") {
        atCanton(() => Future.failed(Status.INTERNAL.withDescription(other).asRuntimeException())).retryable shouldBe false
      }
      atCanton(() => Future.failed(Status.INTERNAL.asRuntimeException())).retryable shouldBe false
    }

    "pass the backend's own verdict through unchanged, retryable or final" in {
      for (retry <- Seq(true, false)) withClue(s"retryable=$retry: ") {
        val verdict = KmsDriverException(new SecurityException("the backend's verdict"), retryable = retry)
        val ex = atCanton(() => Future.failed(verdict))
        ex shouldBe theSameInstanceAs(verdict)
        ex.retryable shouldBe retry
      }
    }

    "report any other failure as final" in {
      val ex = atCanton(() => Future.failed(new NoSuchElementException("key not found or inactive: frost-ns")))
      ex.retryable shouldBe false
      ex.getCause shouldBe a[NoSuchElementException]
    }

    "report a backend that throws instead of failing its Future as final, with a failed audit entry" in {
      val sink = new RecordingSink
      val ex = atCanton(() => throw new IllegalStateException("thrown, not returned"), Some(sink))
      ex.retryable shouldBe false
      ex.getCause.getMessage shouldBe "thrown, not returned"
      sink.entries.toList match {
        case List((op, detail)) =>
          op shouldBe "keyExistsAndIsActive"
          detail should (startWith("keyId=frost-ns") and include("outcome=failed"))
        case other => fail(s"expected one audit entry, got $other")
      }
    }
  }
}
