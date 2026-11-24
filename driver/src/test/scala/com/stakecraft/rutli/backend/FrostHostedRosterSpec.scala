// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli.backend

import com.digitalasset.canton.crypto.kms.driver.api.v1._
import com.google.protobuf.ByteString
import com.stakecraft.rutli.RutliDriver
import com.stakecraft.rutli.audit.AuditNotes
import com.stakecraft.rutli.grpc._
import io.grpc.inprocess.{InProcessChannelBuilder, InProcessServerBuilder}
import io.grpc.stub.StreamObserver
import io.grpc.{Status, StatusRuntimeException}
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import org.slf4j.LoggerFactory

import java.util.concurrent.atomic.AtomicInteger
import scala.concurrent.duration._
import scala.concurrent.{Await, ExecutionContext, Future}

/** The calls on a hosted key the driver knows not to be EC — RSA decrypt, symmetric encrypt and
  * decrypt, PublicKey and KeyInfo for an RSA key — took the first cosigner's "not found" as the
  * cluster's answer. They now follow the rule of the FROST and EC calls
  * ([[FrostStaleVsUnreachableSpec]], whose states and outcomes are reused here): the next cosigner
  * is asked, "not found" is final once all but one cosigner said so, and the call is retryable
  * while a cosigner that may hold the key could not be reached.
  */
class FrostHostedRosterSpec extends AnyWordSpec with Matchers {

  import FrostStaleVsUnreachableSpec._

  private implicit val ec: ExecutionContext = ExecutionContext.global
  private val logger = LoggerFactory.getLogger(classOf[FrostHostedRosterSpec])
  private def await[T](f: Future[T]): T = Await.result(f, 10.seconds)

  private val RsaKey = "rutli-enc-rsa"
  private val AesKey = "rutli-sym-aes"
  private val Rsa = "rsa-2048-oaep-sha256"
  private val Data: Array[Byte] = "payload".getBytes

  /** One cosigner in a switchable state ([[Holds]], [[Missing]] or [[Failing]]). It does no
    * cryptography: what matters here is which cosigner is asked and what the caller gets. */
  private final class Node extends SignerGrpc.SignerImplBase {
    val name: String = s"hosted-${InProcessServerBuilder.generateName()}"
    @volatile var state: State = Holds
    val asked = new AtomicInteger

    private def serve[R](obs: StreamObserver[R])(holds: => R)(missing: => Unit): Unit = {
      asked.incrementAndGet()
      state match {
        case Failing(status)  => obs.onError(status.asRuntimeException())
        case Missing          => missing
        case Holds | OtherKey =>
          obs.onNext(holds)
          obs.onCompleted()
      }
    }
    private def noSuchKey[R](obs: StreamObserver[R]): Unit =
      obs.onError(Status.NOT_FOUND.withDescription("no such key").asRuntimeException())

    override def decrypt(req: DecryptRequest, obs: StreamObserver[DecryptReply]): Unit =
      serve(obs)(DecryptReply.newBuilder().setPlaintext(req.getCiphertext).build())(noSuchKey(obs))
    override def symmetricEncrypt(req: SymmetricRequest, obs: StreamObserver[SymmetricReply]): Unit =
      serve(obs)(SymmetricReply.newBuilder().setData(req.getData).build())(noSuchKey(obs))
    override def symmetricDecrypt(req: SymmetricRequest, obs: StreamObserver[SymmetricReply]): Unit =
      serve(obs)(SymmetricReply.newBuilder().setData(req.getData).build())(noSuchKey(obs))
    override def publicKey(req: PublicKeyRequest, obs: StreamObserver[PublicKeyReply]): Unit =
      serve(obs)(PublicKeyReply.newBuilder().setSpec(Rsa).setPublicKeyDer(ByteString.copyFrom(Array[Byte](1, 2, 3))).build())(
        noSuchKey(obs)
      )
    override def keyInfo(req: KeyInfoRequest, obs: StreamObserver[KeyInfoReply]): Unit =
      serve(obs)(KeyInfoReply.newBuilder().setExists(true).setSpec(Rsa).build()) {
        obs.onNext(KeyInfoReply.newBuilder().setExists(false).build())
        obs.onCompleted()
      }
  }

  /** Cosigners in `states`, in roster order, and a backend over them. With `learnFirst` the backend
    * reads the key's public key while every cosigner holds it, so it knows the key is RSA. */
  private def withCluster[A](states: Seq[State], learnFirst: Boolean)(body: (FrostBackend, IndexedSeq[Node]) => A): A = {
    val nodes = states.toIndexedSeq.map(_ => new Node)
    val servers = nodes.map(node => InProcessServerBuilder.forName(node.name).directExecutor().addService(node).build().start())
    val backend =
      new FrostBackend(nodes.map(_.name), new NoDelegateBackend, logger, None, 10.seconds, hostedKeys = true) {
        override protected def buildChannel(endpoint: String): io.grpc.ManagedChannel =
          InProcessChannelBuilder.forName(endpoint).directExecutor().build()
      }
    try {
      if (learnFirst) await(backend.getPublicKey(RsaKey)).spec shouldBe EncryptionKeySpec.Rsa2048
      nodes.zip(states).foreach { case (node, s) => node.state = s }
      nodes.foreach(_.asked.set(0))
      body(backend, nodes)
    } finally {
      backend.close()
      servers.foreach(_.shutdownNow())
    }
  }

  private def hasStatus(t: Throwable, code: Status.Code): Boolean = t match {
    case e: StatusRuntimeException => e.getStatus.getCode == code
    case _                         => false
  }
  private def isNotFound(t: Throwable): Boolean = hasStatus(t, Status.Code.NOT_FOUND)
  private def codeOf(f: => Any): Status.Code = intercept[StatusRuntimeException](f).getStatus.getCode

  // `pinFirst` is used as "learn first that the key is RSA".
  private val calls: Seq[Call] = Seq(
    Call(
      "decryptAsymmetric, RSA",
      Missing,
      pinFirst = false,
      _.decryptAsymmetric(Data, RsaKey, EncryptionAlgoSpec.RsaEsOaepSha256),
      isNotFound,
    ),
    Call("encryptSymmetric", Missing, pinFirst = false, _.encryptSymmetric(Data, AesKey), isNotFound),
    Call("decryptSymmetric", Missing, pinFirst = false, _.decryptSymmetric(Data, AesKey), isNotFound),
    Call("getPublicKey, key known to be RSA", Missing, pinFirst = true, _.getPublicKey(RsaKey), isNotFound),
    Call(
      "keyExistsAndIsActive, key known to be RSA",
      Missing,
      pinFirst = true,
      _.keyExistsAndIsActive(RsaKey),
      _.isInstanceOf[NoSuchElementException],
    ),
  )

  private val Internal: State = Failing(Status.INTERNAL.withDescription("key store unreadable"))

  /** The rule, restated from what the cosigners do: a holder serves the call; else "not found" is
    * final once all but one cosigner said so; else an unreachable cosigner makes it retryable; else
    * every cosigner answered, and "not found" stands if one said so, the internal error if none. */
  private def expected(states: Seq[State], unreachable: State): Outcome = {
    val quorum = math.max(1, states.size - 1)
    if (states.contains(Holds)) Served
    else if (states.count(_ == Missing) >= quorum) OwnAnswerFinal
    else if (states.contains(unreachable)) Retryable
    else if (states.contains(Missing)) OwnAnswerFinal
    else InternalFinal
  }

  /** Run `call` over `states` and check it ends as [[expected]] says. */
  private def check(call: Call, states: Seq[State], down: Status): Unit = {
    val unreachable: State = Failing(down)
    withCluster(states, call.pinFirst) { (backend, nodes) =>
      val notes = new AuditNotes
      val result = scala.util.Try(await(backend.withAuditNotes(notes)(call.run(backend))))
      def thrown: Throwable = result.failed.getOrElse(fail("the call succeeded"))
      def everyCosignerAskedOnce(): Unit = {
        nodes.map(_.asked.get) shouldBe states.map(_ => 1)
        ()
      }
      expected(states, unreachable) match {
        case Served =>
          result.isSuccess shouldBe true
        case OwnAnswerFinal =>
          call.isOwnFinal(thrown) shouldBe true
          val retried = thrown match {
            case e: StatusRuntimeException => RutliDriver.transient(e.getStatus)
            case _                         => false
          }
          retried shouldBe false
          notes.render should not include "unconfirmed="
          everyCosignerAskedOnce()
        case Retryable =>
          thrown shouldBe a[StatusRuntimeException]
          val got = thrown.asInstanceOf[StatusRuntimeException].getStatus
          got.getCode shouldBe down.getCode
          RutliDriver.transient(got) shouldBe true
          everyCosignerAskedOnce()
          if (states.contains(Missing)) {
            notes.render should include(s"unconfirmed=${nodes(states.lastIndexOf(unreachable)).name} reason=${down.getCode}")
            thrown.getMessage should include("not a final answer")
          } else notes.render should not include "unconfirmed="
        case InternalFinal =>
          hasStatus(thrown, Status.Code.INTERNAL) shouldBe true
          notes.render should not include "unconfirmed="
          everyCosignerAskedOnce()
      }
      ()
    }
  }

  private def sequences(alphabet: Seq[State], n: Int): Seq[Seq[State]] =
    if (n == 0) Seq(Seq.empty[State])
    else for (head <- alphabet; tail <- sequences(alphabet, n - 1)) yield head +: tail

  "a call on a hosted key the driver knows not to be EC, over three cosigners" should {

    "end the same way for the same answers in whatever order the cosigners are asked" in {
      val down = Status.UNAVAILABLE
      for (call <- calls; states <- sequences(Seq(Holds, Missing, Failing(down), Internal), 3))
        withClue(s"${call.name}, ${states.mkString(" ")}: ")(check(call, states, down))
    }

    "treat a cosigner that did not answer within the attempt deadline as unreachable" in {
      val down = Status.DEADLINE_EXCEEDED
      for (call <- calls; states <- sequences(Seq(Missing, Failing(down), Internal), 3))
        withClue(s"${call.name}, ${states.mkString(" ")}: ")(check(call, states, down))
    }

    "be served by the cosigner that holds the key when the leader answers \"not found\", and lead from it afterwards" in {
      for (call <- calls) withClue(s"${call.name}: ") {
        withCluster(Seq(Missing, Holds, Holds), call.pinFirst) { (backend, nodes) =>
          val notes = new AuditNotes
          await(backend.withAuditNotes(notes)(call.run(backend)))
          notes.render shouldBe s"failover=${nodes(0).name}→${nodes(1).name} reason=NOT_FOUND"
          nodes.map(_.asked.get) shouldBe Seq(1, 1, 0)
          // The cosigner without the key lost the lead: the next call does not ask it.
          await(call.run(backend))
          nodes.map(_.asked.get) shouldBe Seq(1, 2, 0)
        }
      }
    }

    "fail retryably for one \"not found\" and two unreachable cosigners, and be served once one is back" in {
      val down = Status.UNAVAILABLE
      for (call <- calls; at <- 0 to 2) withClue(s"${call.name}, not found at $at: ") {
        val states = Seq.tabulate[State](3)(i => if (i == at) Missing else Failing(down))
        expected(states, Failing(down)) shouldBe Retryable
        check(call, states, down)
      }
      for (call <- calls) withClue(s"${call.name}: ") {
        withCluster(Seq(Failing(down), Missing, Failing(down)), call.pinFirst) { (backend, nodes) =>
          codeOf(await(call.run(backend))) shouldBe Status.Code.UNAVAILABLE
          nodes(2).state = Holds
          await(call.run(backend)) // Canton's retry
        }
      }
    }

    "end as \"not found\", final, once two cosigners said so, although the third is unreachable" in {
      val down = Status.UNAVAILABLE
      for (call <- calls; at <- 0 to 2) withClue(s"${call.name}, unreachable at $at: ") {
        val states = Seq.tabulate[State](3)(i => if (i == at) Failing(down) else Missing)
        expected(states, Failing(down)) shouldBe OwnAnswerFinal
        check(call, states, down)
      }
    }
  }

  "the same calls over five cosigners" should {

    def rotations(states: Seq[State]): Seq[Seq[State]] = states.indices.map(i => states.drop(i) ++ states.take(i))
    val down: State = Failing(Status.UNAVAILABLE)

    "stay retryable with three \"not found\" and two unreachable, and be final with four and one" in {
      for (call <- calls) withClue(s"${call.name}: ") {
        for (states <- rotations(Seq(Missing, down, Missing, down, Missing))) withClue(states.mkString(" ")) {
          expected(states, down) shouldBe Retryable
          check(call, states, Status.UNAVAILABLE)
        }
        for (states <- rotations(Seq(Missing, Missing, down, Missing, Missing))) withClue(states.mkString(" ")) {
          expected(states, down) shouldBe OwnAnswerFinal
          check(call, states, Status.UNAVAILABLE)
        }
      }
    }
  }

  "a rate limit" should {

    "be returned at once and never routed around, also after another cosigner's \"not found\"" in {
      val limited: State = Failing(Status.RESOURCE_EXHAUSTED.withDescription("hosted-key decryption rate limit"))
      for (call <- calls) withClue(s"${call.name}: ") {
        withCluster(Seq(limited, Holds, Holds), call.pinFirst) { (backend, nodes) =>
          codeOf(await(call.run(backend))) shouldBe Status.Code.RESOURCE_EXHAUSTED
          // It keeps the lead: the per-node limit must not become n times the limit.
          codeOf(await(call.run(backend))) shouldBe Status.Code.RESOURCE_EXHAUSTED
          nodes.map(_.asked.get) shouldBe Seq(2, 0, 0)
        }
        withCluster(Seq(Missing, limited, Holds), call.pinFirst) { (backend, nodes) =>
          codeOf(await(call.run(backend))) shouldBe Status.Code.RESOURCE_EXHAUSTED
          nodes.map(_.asked.get) shouldBe Seq(1, 1, 0)
        }
      }
    }
  }
}
