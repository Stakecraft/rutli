// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli

import com.digitalasset.canton.crypto.kms.driver.api.v1._
import com.google.protobuf.ByteString
import com.stakecraft.rutli.backend.{FrostBackend, NoDelegateBackend}
import com.stakecraft.rutli.grpc._
import io.grpc.inprocess.{InProcessChannelBuilder, InProcessServerBuilder}
import io.grpc.stub.StreamObserver
import io.grpc.{Metadata, Status}
import io.opentelemetry.context.Context
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import org.slf4j.LoggerFactory

import java.security.{KeyPair, KeyPairGenerator, Signature}
import java.util.concurrent.atomic.AtomicInteger
import scala.concurrent.duration._
import scala.concurrent.{Await, ExecutionContext, Future}

/** The cosigners' "not now" — ABORTED for a ceremony that holds the key or a session that is gone —
  * must reach Canton as retryable: Canton retries a retryable KMS error and never retries a final
  * one, so a final error here is a key that is never generated or a signature never asked for
  * again, for a condition that clears by itself. Through the whole driver: in-process cosigners, the
  * FROST backend, and the error class the SPI hands to Canton.
  */
class FrostNotNowSpec extends AnyWordSpec with Matchers {

  private implicit val ec: ExecutionContext = ExecutionContext.global
  private val logger = LoggerFactory.getLogger(classOf[FrostNotNowSpec])
  private val ctx = Context.root()
  private def await[T](f: Future[T]): T = Await.result(f, 10.seconds)

  private val Group: KeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
  private val GroupRaw: Array[Byte] = Group.getPublic.getEncoded.takeRight(32)
  private def groupSign(msg: Array[Byte]): Array[Byte] = {
    val s = Signature.getInstance("Ed25519")
    s.initSign(Group.getPrivate)
    s.update(msg)
    s.sign()
  }
  private val Digest: Array[Byte] = Array.fill(34)(7.toByte)

  // The cosigner's own messages (frost/cosigner/src/error.rs).
  private val DkgInProgress =
    Status.ABORTED.withDescription(
      "a dkg ceremony (id dkg-0123456789abcdef0123456789abcdef) is already in progress for key frost-ns"
    )

  /** The same refusal from a member, as a leader passes it on when it loses the member's code. */
  private val DkgInProgressOnMember = Status.INTERNAL.withDescription(
    "rpc status: status: Aborted, message: \"a dkg ceremony (id dkg-0123456789abcdef0123456789abcdef) is already in progress " +
      "for key frost-ns\""
  )
  private val SessionGone = Status.ABORTED.withDescription("unknown session: sign-1")

  /** One cosigner. DKG, Sign and GenerateKey can be made to fail with a status (and trailers). */
  private final class Node extends SignerGrpc.SignerImplBase {
    val name: String = s"notnow-${InProcessServerBuilder.generateName()}"
    val dkgCalls, signCalls, generateCalls = new AtomicInteger
    @volatile var dkgFails: Option[Status] = None
    @volatile var signFails: Option[Status] = None
    @volatile var generateFails: Option[(Status, Metadata)] = None

    override def capabilities(req: CapabilitiesRequest, obs: StreamObserver[CapabilitiesReply]): Unit = {
      obs.onNext(
        CapabilitiesReply
          .newBuilder()
          .setHostedKeysEnabled(true)
          .addHostedKeySpecs("rsa-2048-oaep-sha256")
          .addHostedKeySpecs("aes-256-gcm")
          .build()
      )
      obs.onCompleted()
    }
    override def groupKey(req: GroupKeyRequest, obs: StreamObserver[GroupKeyReply]): Unit = {
      obs.onNext(GroupKeyReply.newBuilder().setGroupVerifyingKey(ByteString.copyFrom(GroupRaw)).build())
      obs.onCompleted()
    }
    override def dkg(req: DkgRequest, obs: StreamObserver[DkgReply]): Unit = {
      dkgCalls.incrementAndGet()
      dkgFails match {
        case Some(status) => obs.onError(status.asRuntimeException())
        case None         =>
          obs.onNext(DkgReply.newBuilder().setGroupVerifyingKey(ByteString.copyFrom(GroupRaw)).build())
          obs.onCompleted()
      }
    }
    override def sign(req: SignRequest, obs: StreamObserver[SignReply]): Unit = {
      signCalls.incrementAndGet()
      signFails match {
        case Some(status) => obs.onError(status.asRuntimeException())
        case None         =>
          obs.onNext(SignReply.newBuilder().setSignature(ByteString.copyFrom(groupSign(req.getMessage.toByteArray))).build())
          obs.onCompleted()
      }
    }
    override def generateKey(req: GenerateKeyRequest, obs: StreamObserver[GenerateKeyReply]): Unit = {
      generateCalls.incrementAndGet()
      generateFails match {
        case Some((status, trailers)) => obs.onError(status.asRuntimeException(trailers))
        case None                     =>
          obs.onNext(GenerateKeyReply.newBuilder().setKeyId(req.getKeyId).setSpec(req.getSpec).setCreated(true).build())
          obs.onCompleted()
      }
    }
  }

  /** Three cosigners and the driver over them, as Canton calls it. */
  private def withDriver[A](body: (RutliDriver, IndexedSeq[Node]) => A): A = {
    val nodes = (0 until 3).map(_ => new Node)
    val servers = nodes.map(node => InProcessServerBuilder.forName(node.name).directExecutor().addService(node).build().start())
    // Sticky signs, so a sign starts at the first cosigner and the order asked is the roster's.
    val backend =
      new FrostBackend(
        nodes.map(_.name),
        new NoDelegateBackend,
        logger,
        None,
        10.seconds,
        hostedKeys = true,
        rotateSigns = false
      ) {
        override protected def buildChannel(endpoint: String): io.grpc.ManagedChannel =
          InProcessChannelBuilder.forName(endpoint).directExecutor().build()
      }
    val driver = new RutliDriver(
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
    try body(driver, nodes)
    finally {
      driver.close()
      servers.foreach(_.shutdownNow())
    }
  }

  private def generateNamespaceKey(driver: RutliDriver): Future[String] =
    driver.generateSigningKeyPair(SigningKeySpec.EcCurve25519, Some("ns"))(ctx)
  private def failure(f: => Future[_]): KmsDriverException = the[KmsDriverException] thrownBy await(f)

  "a DKG that meets a ceremony already holding the key" should {

    "be retryable for Canton, not re-run on another cosigner, and succeed when Canton retries" in {
      for (refusal <- Seq(DkgInProgress, DkgInProgressOnMember)) withClue(s"${refusal.getCode}: ") {
        withDriver { (driver, nodes) =>
          nodes(0).dkgFails = Some(refusal)
          val ex = failure(generateNamespaceKey(driver))
          ex.retryable shouldBe true
          ex.getMessage should include("is already in progress")
          nodes.map(_.dkgCalls.get) shouldBe Seq(1, 0, 0)

          // The other ceremony is over: Canton's retry goes to the same leader and gets the key.
          nodes(0).dkgFails = None
          await(generateNamespaceKey(driver)) shouldBe "frost-ns"
          nodes.map(_.dkgCalls.get) shouldBe Seq(2, 0, 0)
        }
      }
    }

    "stay final for any other internal error of the leader" in {
      withDriver { (driver, nodes) =>
        nodes(0).dkgFails = Some(Status.INTERNAL.withDescription("io: Permission denied (os error 13)"))
        failure(generateNamespaceKey(driver)).retryable shouldBe false
        nodes.map(_.dkgCalls.get) shouldBe Seq(1, 0, 0)
      }
    }
  }

  "a sign that every cosigner answers with ABORTED" should {

    "be retryable for Canton once each cosigner was asked, and be signed when Canton retries" in {
      for (refusal <- Seq(SessionGone, DkgInProgress)) withClue(s"${refusal.getDescription}: ") {
        withDriver { (driver, nodes) =>
          nodes.foreach(_.signFails = Some(refusal))
          failure(driver.sign(Digest, "frost-ns", SigningAlgoSpec.Ed25519)(ctx)).retryable shouldBe true
          nodes.map(_.signCalls.get) shouldBe Seq(1, 1, 1)

          nodes.foreach(_.signFails = None)
          await(driver.sign(Digest, "frost-ns", SigningAlgoSpec.Ed25519)(ctx)) shouldBe groupSign(Digest)
        }
      }
    }

    "be signed within the call when only the leader answers so" in {
      withDriver { (driver, nodes) =>
        nodes(0).signFails = Some(SessionGone)
        await(driver.sign(Digest, "frost-ns", SigningAlgoSpec.Ed25519)(ctx)) shouldBe groupSign(Digest)
        nodes.map(_.signCalls.get) shouldBe Seq(1, 1, 0)
      }
    }
  }

  "a hosted key generation that a cosigner aborts" should {

    def reason(value: Option[String]): Metadata = {
      val trailers = new Metadata
      value.foreach(v => trailers.put(Metadata.Key.of("rutli-error", Metadata.ASCII_STRING_MARSHALLER), v))
      trailers
    }
    val conflict = Status.ABORTED.withDescription("hosted key: cosigners hold different material under this id")

    "be final when the cosigners hold conflicting material under the id (the reason trailer reaches the driver)" in {
      withDriver { (driver, nodes) =>
        nodes(0).generateFails = Some(conflict -> reason(Some("hosted-conflict")))
        failure(driver.generateSymmetricKey(Some("wrap"))(ctx)).retryable shouldBe false
        nodes.map(_.generateCalls.get) shouldBe Seq(1, 0, 0)
      }
    }

    "be retryable when it is aborted for any other reason" in {
      withDriver { (driver, nodes) =>
        nodes(0).generateFails = Some(conflict -> reason(None))
        failure(driver.generateSymmetricKey(Some("wrap"))(ctx)).retryable shouldBe true
        nodes.map(_.generateCalls.get) shouldBe Seq(1, 0, 0)
      }
    }
  }
}
