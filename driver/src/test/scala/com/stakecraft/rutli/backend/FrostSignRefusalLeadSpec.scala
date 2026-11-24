// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli.backend

import com.digitalasset.canton.crypto.kms.driver.api.v1._
import com.google.protobuf.ByteString
import com.stakecraft.rutli.audit.AuditNotes
import com.stakecraft.rutli.grpc._
import io.grpc.inprocess.{InProcessChannelBuilder, InProcessServerBuilder}
import io.grpc.stub.StreamObserver
import io.grpc.{Status, StatusRuntimeException}
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import org.slf4j.LoggerFactory

import java.security.{KeyPair, KeyPairGenerator, Signature}
import java.util.concurrent.atomic.AtomicInteger
import scala.concurrent.duration._
import scala.concurrent.{Await, ExecutionContext, Future}

/** A sign leader that answers from its own state — it lacks the share, a ceremony holds the key, it
  * runs an old release — loses the lead only when another leader then signs. When every leader
  * answers so, none is at fault, and none may leave the sign rotation: with
  * `frost.sign-leader = rotate` a cosigner that lost the lead is not a sign start for
  * `leader-recovery`, for any key. A leader that returns a signature the pinned key does not
  * verify, fails internally or cannot be reached still loses the lead at once.
  *
  * Three cosigners. What the tests look at is where the signs start once every cosigner signs
  * again: untouched, each starts every third sign.
  */
class FrostSignRefusalLeadSpec extends AnyWordSpec with Matchers {

  private implicit val ec: ExecutionContext = ExecutionContext.global
  private val logger = LoggerFactory.getLogger(classOf[FrostSignRefusalLeadSpec])
  private def await[T](f: Future[T]): T = Await.result(f, 10.seconds)

  private val FrostKey = "frost-ns"
  private val Digest: Array[Byte] = Array.fill(34)(7.toByte)

  private val Group: KeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
  private val Other: KeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
  private def signWith(kp: KeyPair, msg: Array[Byte]): Array[Byte] = {
    val s = Signature.getInstance("Ed25519")
    s.initSign(kp.getPrivate)
    s.update(msg)
    s.sign()
  }

  /** One cosigner. It answers the group key always; a sign it serves, refuses with `refuses`, or
    * answers with a signature by another key (`lies`). Sign calls are counted. */
  private final class Node extends SignerGrpc.SignerImplBase {
    val name: String = s"signlead-${InProcessServerBuilder.generateName()}"
    val signs = new AtomicInteger
    @volatile var refuses: Option[Status] = None
    @volatile var lies: Boolean = false

    def heal(): Unit = {
      refuses = None
      lies = false
    }

    override def groupKey(req: GroupKeyRequest, obs: StreamObserver[GroupKeyReply]): Unit = {
      obs.onNext(
        GroupKeyReply.newBuilder().setGroupVerifyingKey(ByteString.copyFrom(Group.getPublic.getEncoded.takeRight(32))).build()
      )
      obs.onCompleted()
    }
    override def sign(req: SignRequest, obs: StreamObserver[SignReply]): Unit = {
      signs.incrementAndGet()
      refuses match {
        case Some(status) => obs.onError(status.asRuntimeException())
        case None         =>
          val signature = signWith(if (lies) Other else Group, req.getMessage.toByteArray)
          obs.onNext(SignReply.newBuilder().setSignature(ByteString.copyFrom(signature)).build())
          obs.onCompleted()
      }
    }
  }

  /** Three cosigners and a backend over them, with the group key pinned (no sign turn is used). */
  private def withCluster[A](rotate: Boolean = true)(body: (FrostBackend, IndexedSeq[Node]) => A): A = {
    val nodes = (0 until 3).map(_ => new Node)
    val servers = nodes.map(node => InProcessServerBuilder.forName(node.name).directExecutor().addService(node).build().start())
    val backend =
      new FrostBackend(nodes.map(_.name), new NoDelegateBackend, logger, None, 10.seconds, rotateSigns = rotate) {
        override protected def buildChannel(endpoint: String): io.grpc.ManagedChannel =
          InProcessChannelBuilder.forName(endpoint).directExecutor().build()
      }
    try {
      await(backend.getPublicKey(FrostKey))
      body(backend, nodes)
    } finally {
      backend.close()
      servers.foreach(_.shutdownNow())
    }
  }

  private def sign(backend: FrostBackend, notes: AuditNotes = new AuditNotes): Array[Byte] =
    await(backend.withAuditNotes(notes)(backend.sign(Digest, FrostKey, SigningAlgoSpec.Ed25519)))

  /** Sign `count` times, every one served, and say how many sign calls each cosigner got. */
  private def starts(backend: FrostBackend, nodes: IndexedSeq[Node], count: Int): Seq[Int] = {
    val before = nodes.map(_.signs.get)
    (1 to count).foreach(_ => sign(backend) shouldBe signWith(Group, Digest))
    nodes.map(_.signs.get).zip(before).map { case (now, prev) => now - prev }
  }

  // What a leader answers from its own state (frost/cosigner/src/error.rs): no share for the key,
  // a ceremony holding it or a session gone, a stale share or a refused ceremony state, an old release.
  private val ownState: Seq[Status] = Seq(
    Status.NOT_FOUND.withDescription("unknown key: frost-ns"),
    Status.ABORTED.withDescription(
      "a refresh ceremony (id refresh-0123456789abcdef0123456789abcdef) is already in progress for key frost-ns"
    ),
    Status.FAILED_PRECONDITION.withDescription("stale share"),
    Status.UNIMPLEMENTED,
  )

  "a sign that every leader refuses from its own state" should {

    "leave the sign rotation as it was" in {
      for (status <- ownState) withClue(s"${status.getCode}: ") {
        withCluster() { (backend, nodes) =>
          nodes.foreach(_.refuses = Some(status))
          val thrown = intercept[StatusRuntimeException](sign(backend))
          thrown.getStatus.getCode shouldBe status.getCode
          nodes.map(_.signs.get) shouldBe Seq(1, 1, 1)

          nodes.foreach(_.heal())
          starts(backend, nodes, 6) shouldBe Seq(2, 2, 2)
        }
      }
    }

    "leave it so when the sign is repeated, as Canton does for a ceremony in progress" in {
      for (status <- ownState) withClue(s"${status.getCode}: ") {
        withCluster() { (backend, nodes) =>
          nodes.foreach(_.refuses = Some(status))
          (1 to 4).foreach(_ => intercept[StatusRuntimeException](sign(backend)))
          nodes.foreach(_.heal())
          starts(backend, nodes, 6) shouldBe Seq(2, 2, 2)
        }
      }
    }

    "keep the lead where it was in sticky mode" in {
      for (status <- ownState) withClue(s"${status.getCode}: ") {
        withCluster(rotate = false) { (backend, nodes) =>
          nodes.foreach(_.refuses = Some(status))
          intercept[StatusRuntimeException](sign(backend))
          nodes.foreach(_.heal())
          starts(backend, nodes, 3) shouldBe Seq(3, 0, 0)
        }
      }
    }
  }

  "a leader that cannot sign while another leader signs" should {

    "lose the lead once the other has signed: it is not a sign start until leader-recovery has passed" in {
      for (status <- ownState) withClue(s"${status.getCode}: ") {
        withCluster() { (backend, nodes) =>
          nodes(0).refuses = Some(status)
          val notes = new AuditNotes
          sign(backend, notes) shouldBe signWith(Group, Digest) // turn 0: the first refuses, the second signs
          notes.render shouldBe s"failover=${nodes(0).name}→${nodes(1).name} reason=${status.getCode}"
          nodes.map(_.signs.get) shouldBe Seq(1, 1, 0)

          // The first signs again, but it lost the lead a moment ago: turns 3 and 6 skip it.
          nodes(0).heal()
          starts(backend, nodes, 6) shouldBe Seq(0, 4, 2)
        }
      }
    }

    "lose the lead to the leader that signed in sticky mode" in {
      for (status <- ownState) withClue(s"${status.getCode}: ") {
        withCluster(rotate = false) { (backend, nodes) =>
          nodes(0).refuses = Some(status)
          sign(backend) shouldBe signWith(Group, Digest)
          nodes(0).heal()
          starts(backend, nodes, 3) shouldBe Seq(0, 3, 0)
        }
      }
    }

    "keep its place when the others could not be reached and the sign ends retryable" in {
      for (status <- ownState) withClue(s"${status.getCode}: ") {
        withCluster() { (backend, nodes) =>
          nodes(0).refuses = Some(status)
          nodes(1).refuses = Some(Status.UNAVAILABLE)
          nodes(2).refuses = Some(Status.UNAVAILABLE)
          val notes = new AuditNotes
          val thrown = intercept[StatusRuntimeException](sign(backend, notes))
          thrown.getStatus.getCode shouldBe Status.Code.UNAVAILABLE
          notes.render should include("unconfirmed=")

          // The two that were unreachable lost the lead; the first is the only start left.
          nodes.foreach(_.heal())
          starts(backend, nodes, 6) shouldBe Seq(6, 0, 0)
        }
      }
    }
  }

  "a leader that fails in a way that is its fault" should {

    "lose the lead at once, also when no leader signs" in {
      // A signature the pinned key does not verify, an internal error, no answer: each leader is
      // demoted as it fails. With all three demoted the signs fall back to the preferred leader.
      val faults: Seq[(String, Node => Unit)] = Seq(
        "bad signature" -> ((n: Node) => n.lies = true),
        "INTERNAL" -> ((n: Node) => n.refuses = Some(Status.INTERNAL.withDescription("key store unreadable"))),
        "UNAVAILABLE" -> ((n: Node) => n.refuses = Some(Status.UNAVAILABLE)),
      )
      for ((name, fault) <- faults) withClue(s"$name: ") {
        withCluster() { (backend, nodes) =>
          nodes.foreach(fault)
          intercept[Exception](sign(backend))
          nodes.map(_.signs.get) shouldBe Seq(1, 1, 1)

          nodes.foreach(_.heal())
          starts(backend, nodes, 6) shouldBe Seq(6, 0, 0)
        }
      }
    }

    "lose the lead at once when it returns a bad signature and the next leader signs" in {
      withCluster() { (backend, nodes) =>
        nodes(0).lies = true
        val notes = new AuditNotes
        sign(backend, notes) shouldBe signWith(Group, Digest)
        notes.render shouldBe s"sig-verify=failed failover=${nodes(0).name}→${nodes(1).name} reason=BAD_SIGNATURE"
        nodes(0).heal()
        starts(backend, nodes, 6) shouldBe Seq(0, 4, 2)
      }
    }
  }
}
