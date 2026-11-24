// Copyright 2026 StakeCraft LLC
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli.backend

import com.digitalasset.canton.crypto.kms.driver.api.v1._
import com.google.protobuf.ByteString
import com.stakecraft.rutli.audit.AuditNotes
import com.stakecraft.rutli.grpc._
import com.stakecraft.rutli.{CryptoFakeCluster, RutliDriver}
import io.grpc.inprocess.{InProcessChannelBuilder, InProcessServerBuilder}
import io.grpc.stub.StreamObserver
import io.grpc.{Status, StatusRuntimeException}
import org.bouncycastle.jce.spec.IESParameterSpec
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import org.slf4j.LoggerFactory

import java.security.spec.ECGenParameterSpec
import java.security.{KeyPair, KeyPairGenerator, SecureRandom, Signature}
import java.util.concurrent.atomic.AtomicInteger
import javax.crypto.Cipher
import scala.concurrent.duration._
import scala.concurrent.{Await, ExecutionContext, Future}

/** One cosigner's own answer — "not found", "another key", "I cannot sign" — is not the cluster's
  * while another cosigner could not be reached: that one may hold the key. Canton never retries a
  * final error, so such a call must fail with the unreachable cosigner's status (retryable), in
  * whatever order the endpoints were asked. The answer becomes final once all but one endpoint gave
  * it (2 of 3, 4 of 5): one cosigner alone cannot use a threshold key, whatever the threshold, and
  * of a hosted key the driver saw two copies before it returned the id.
  *
  * Every cosigner is in one state per test: it holds the key, it gives its own negative answer, it
  * fails with a status, or it cannot be reached.
  */
class FrostStaleVsUnreachableSpec extends AnyWordSpec with Matchers {

  import FrostStaleVsUnreachableSpec._

  private implicit val ec: ExecutionContext = ExecutionContext.global
  private val logger = LoggerFactory.getLogger(classOf[FrostStaleVsUnreachableSpec])
  private def await[T](f: Future[T]): T = Await.result(f, 10.seconds)

  private val FrostKey = "frost-ns"
  private val HostedKey = "rutli-enc-ec"
  private val Ecies = EncryptionAlgoSpec.EciesHkdfHmacSha256Aes128Cbc
  // BouncyCastle's name for Canton's ECIES scheme: ECIES, SHA-256, AES-CBC.
  private val EciesTransformation = Seq("ECIES", "with", "SHA256", "and", "AES-CBC").mkString

  private val Group: KeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
  private val Other: KeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
  private def raw(kp: KeyPair): Array[Byte] = kp.getPublic.getEncoded.takeRight(32)
  private def signWith(kp: KeyPair, msg: Array[Byte]): Array[Byte] = {
    val s = Signature.getInstance("Ed25519")
    s.initSign(kp.getPrivate)
    s.update(msg)
    s.sign()
  }
  private val Digest: Array[Byte] = Array.fill(34)(7.toByte)

  private def ecPair(): KeyPair = {
    val g = KeyPairGenerator.getInstance("EC")
    g.initialize(new ECGenParameterSpec("secp256r1"))
    g.generateKeyPair()
  }
  private val EcPair: KeyPair = ecPair()
  private val Plaintext: Array[Byte] = "for the cosigner that holds the key".getBytes
  private val Ciphertext: Array[Byte] = {
    val iv = new Array[Byte](16)
    new SecureRandom().nextBytes(iv)
    val c = Cipher.getInstance(EciesTransformation, new org.bouncycastle.jce.provider.BouncyCastleProvider)
    c.init(Cipher.ENCRYPT_MODE, EcPair.getPublic, new IESParameterSpec(Array[Byte](), Array[Byte](), 512, 128, iv))
    iv ++ c.doFinal(Plaintext)
  }

  /** One cosigner in a switchable state. For the hosted key it answers as `holder` does while it
    * holds the key. Every key call is counted. */
  private final class Node(holder: CryptoFakeCluster, wrongHolder: CryptoFakeCluster) extends SignerGrpc.SignerImplBase {
    val name: String = s"stale-${InProcessServerBuilder.generateName()}"
    @volatile var state: State = Holds
    val asked = new AtomicInteger

    /** Count the call, fail it if this node is failing, else answer by state. */
    private def serve[R](obs: StreamObserver[R])(holds: => Unit)(missing: => Unit): Unit = {
      asked.incrementAndGet()
      state match {
        case Failing(status)  => obs.onError(status.asRuntimeException())
        case Missing          => missing
        case Holds | OtherKey => holds
      }
    }
    private def noSuchKey[R](obs: StreamObserver[R]): Unit =
      obs.onError(Status.NOT_FOUND.withDescription("no such key").asRuntimeException())

    override def groupKey(req: GroupKeyRequest, obs: StreamObserver[GroupKeyReply]): Unit =
      serve(obs) {
        val key = if (state == OtherKey) raw(Other) else raw(Group)
        obs.onNext(GroupKeyReply.newBuilder().setGroupVerifyingKey(ByteString.copyFrom(key)).build())
        obs.onCompleted()
      }(noSuchKey(obs))
    override def sign(req: SignRequest, obs: StreamObserver[SignReply]): Unit =
      serve(obs) {
        val signature = signWith(if (state == OtherKey) Other else Group, req.getMessage.toByteArray)
        obs.onNext(SignReply.newBuilder().setSignature(ByteString.copyFrom(signature)).build())
        obs.onCompleted()
      }(noSuchKey(obs))
    override def keyInfo(req: KeyInfoRequest, obs: StreamObserver[KeyInfoReply]): Unit =
      serve(obs)(holder.keyInfo(req, obs)) {
        obs.onNext(KeyInfoReply.newBuilder().setExists(false).build())
        obs.onCompleted()
      }
    override def publicKey(req: PublicKeyRequest, obs: StreamObserver[PublicKeyReply]): Unit =
      serve(obs)(holder.publicKey(req, obs))(noSuchKey(obs))
    override def ecdhDerive(req: EcdhDeriveRequest, obs: StreamObserver[EcdhDeriveReply]): Unit =
      serve(obs)((if (state == OtherKey) wrongHolder else holder).ecdhDerive(req, obs))(noSuchKey(obs))
  }

  /** Cosigners in `states`, in roster order, and a backend over them. With `pinFirst` the FROST
    * key is pinned while every cosigner still holds it, as for a key the driver has used before. */
  private def withCluster[A](states: Seq[State], pinFirst: Boolean = false)(body: (FrostBackend, IndexedSeq[Node]) => A): A = {
    val holder = new CryptoFakeCluster
    holder.putEcKey(HostedKey, EcPair)
    // A cosigner with stale or corrupt material: another P-256 key under the same id.
    val wrongHolder = new CryptoFakeCluster
    wrongHolder.putEcKey(HostedKey, ecPair())
    val nodes = states.toIndexedSeq.map(_ => new Node(holder, wrongHolder))
    val servers = nodes.map(node => InProcessServerBuilder.forName(node.name).directExecutor().addService(node).build().start())
    val backend =
      new FrostBackend(nodes.map(_.name), new NoDelegateBackend, logger, None, 10.seconds, hostedKeys = true) {
        override protected def buildChannel(endpoint: String): io.grpc.ManagedChannel =
          InProcessChannelBuilder.forName(endpoint).directExecutor().build()
      }
    try {
      if (pinFirst) await(backend.getPublicKey(FrostKey))
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
  private def isFinalRefusal(t: Throwable): Boolean = t match {
    case e: KmsDriverException => !e.retryable
    case _                     => false
  }
  private def signIt(b: FrostBackend): Future[Any] = b.sign(Digest, FrostKey, SigningAlgoSpec.Ed25519)

  private val calls: Seq[Call] = Seq(
    Call(
      "keyExistsAndIsActive, EC hosted key",
      Missing,
      pinFirst = false,
      _.keyExistsAndIsActive(HostedKey),
      _.isInstanceOf[NoSuchElementException],
    ),
    Call("getPublicKey, EC hosted key", Missing, pinFirst = false, _.getPublicKey(HostedKey), isNotFound),
    Call(
      "decryptAsymmetric, ECIES",
      Missing,
      pinFirst = false,
      _.decryptAsymmetric(Ciphertext, HostedKey, Ecies),
      isNotFound,
    ),
    Call("keyExistsAndIsActive, FROST key not pinned", Missing, pinFirst = false, _.keyExistsAndIsActive(FrostKey), isNotFound),
    Call(
      "keyExistsAndIsActive, pinned FROST key, NOT_FOUND",
      Missing,
      pinFirst = true,
      _.keyExistsAndIsActive(FrostKey),
      isNotFound
    ),
    Call(
      "keyExistsAndIsActive, pinned FROST key, another key",
      OtherKey,
      pinFirst = true,
      _.keyExistsAndIsActive(FrostKey),
      isFinalRefusal,
    ),
    Call("sign, leader NOT_FOUND", Missing, pinFirst = true, signIt, isNotFound),
    Call("sign, leader's signature does not verify", OtherKey, pinFirst = true, signIt, isFinalRefusal),
    Call(
      "sign, leader FAILED_PRECONDITION",
      Failing(Status.FAILED_PRECONDITION),
      pinFirst = true,
      signIt,
      hasStatus(_, Status.Code.FAILED_PRECONDITION),
      counts = false,
    ),
    Call(
      "sign, leader ABORTED",
      Failing(Status.ABORTED),
      pinFirst = true,
      signIt,
      hasStatus(_, Status.Code.ABORTED),
      counts = false
    ),
    Call(
      "sign, leader UNIMPLEMENTED",
      Failing(Status.UNIMPLEMENTED),
      pinFirst = true,
      signIt,
      hasStatus(_, Status.Code.UNIMPLEMENTED),
      counts = false,
    ),
  )

  private val Internal: State = Failing(Status.INTERNAL.withDescription("key store unreadable"))

  /** The rule under test, restated from what the cosigners do and nothing else: a holder serves
    * the call; else the own answer is final once `quorum` cosigners gave it; else an unreachable
    * cosigner makes it retryable; else every cosigner answered, and the own answer stands if one
    * gave it, the internal error if none did. */
  private def expected(states: Seq[State], own: State, unreachable: State, quorum: Int): Outcome =
    if (states.contains(Holds)) Served
    else if (states.count(_ == own) >= quorum) OwnAnswerFinal
    else if (states.contains(unreachable)) Retryable
    else if (states.contains(own)) OwnAnswerFinal
    else InternalFinal

  /** Run `call` over `states` and check it ends as [[expected]] says. */
  private def check(call: Call, states: Seq[State], down: Status): Unit = {
    val unreachable: State = Failing(down)
    val quorum = call.quorum(states.size)
    withCluster(states, call.pinFirst) { (backend, nodes) =>
      val notes = new AuditNotes
      val result = scala.util.Try(await(backend.withAuditNotes(notes)(call.run(backend))))
      def thrown: Throwable = result.failed.getOrElse(fail("the call succeeded"))
      def everyCosignerAskedOnce(): Unit = {
        nodes.map(_.asked.get) shouldBe states.map(_ => 1)
        ()
      }
      expected(states, call.own, unreachable, quorum) match {
        case Served =>
          result.isSuccess shouldBe true
        case OwnAnswerFinal =>
          call.isOwnFinal(thrown) shouldBe true
          // The roster's verdict is the cosigners' own answer. For Canton that is final, except
          // ABORTED, the cosigners' "not now", which the driver reports as retryable whoever said it.
          val retried = thrown match {
            case e: StatusRuntimeException => RutliDriver.transient(e)
            case _                         => false
          }
          retried shouldBe hasStatus(thrown, Status.Code.ABORTED)
          notes.render should not include "unconfirmed="
          everyCosignerAskedOnce()
        case Retryable =>
          thrown shouldBe a[StatusRuntimeException]
          val got = thrown.asInstanceOf[StatusRuntimeException].getStatus
          got.getCode shouldBe down.getCode
          RutliDriver.transient(got) shouldBe true
          everyCosignerAskedOnce()
          // Noted, naming the unreachable cosigner asked last, exactly when some cosigner gave its
          // own answer; with none, the error is simply the unreachable cosigner's.
          if (states.contains(call.own)) {
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

  /** Every sequence of `n` states from `alphabet`: each multiset in every order. */
  private def sequences(alphabet: Seq[State], n: Int): Seq[Seq[State]] =
    if (n == 0) Seq(Seq.empty[State])
    else for (head <- alphabet; tail <- sequences(alphabet, n - 1)) yield head +: tail

  "a call that every cosigner may answer for itself, over three cosigners" should {

    "end the same way for the same answers in whatever order the cosigners are asked" in {
      val down = Status.UNAVAILABLE
      for (call <- calls; states <- sequences(Seq(Holds, call.own, Failing(down), Internal), 3))
        withClue(s"${call.name}, ${states.mkString(" ")}: ")(check(call, states, down))
    }

    "treat a cosigner that did not answer within the attempt deadline as unreachable" in {
      val down = Status.DEADLINE_EXCEEDED
      for (call <- calls; states <- sequences(Seq(call.own, Failing(down), Internal), 3))
        withClue(s"${call.name}, ${states.mkString(" ")}: ")(check(call, states, down))
    }

    "fail retryably for one cosigner's own answer and two unreachable cosigners, in every order" in {
      // The case the rule exists for: a final error here would tell Canton the key does not exist,
      // or that the signature cannot be made, while the two cosigners that were down hold the key.
      val down = Status.UNAVAILABLE
      for (call <- calls; at <- 0 to 2) withClue(s"${call.name}, own answer at $at: ") {
        val states = Seq.tabulate[State](3)(i => if (i == at) call.own else Failing(down))
        expected(states, call.own, Failing(down), call.quorum(3)) shouldBe Retryable
        check(call, states, down)
      }
    }

    "end with the own answer, final, once two cosigners gave it, although the third is unreachable" in {
      // The bound on Canton's retries: with two of three saying so, the one that is down could not
      // use the key alone. A key that exists nowhere is reported as such while a cosigner is down.
      val down = Status.UNAVAILABLE
      for (call <- calls.filter(_.counts); at <- 0 to 2) withClue(s"${call.name}, unreachable at $at: ") {
        val states = Seq.tabulate[State](3)(i => if (i == at) Failing(down) else call.own)
        expected(states, call.own, Failing(down), call.quorum(3)) shouldBe OwnAnswerFinal
        check(call, states, down)
      }
    }

    "stay retryable while a cosigner is unreachable when the answer is about the leader's state at the moment" in {
      // A ceremony holding the key, a session that is gone, an old release: two leaders saying so
      // does not mean the key cannot be used, so the count never makes it final.
      val down = Status.UNAVAILABLE
      calls.filterNot(_.counts).map(_.name) shouldBe
        Seq("sign, leader FAILED_PRECONDITION", "sign, leader ABORTED", "sign, leader UNIMPLEMENTED")
      for (call <- calls.filterNot(_.counts); at <- 0 to 2) withClue(s"${call.name}, unreachable at $at: ") {
        val states = Seq.tabulate[State](3)(i => if (i == at) Failing(down) else call.own)
        expected(states, call.own, Failing(down), call.quorum(3)) shouldBe Retryable
        check(call, states, down)
      }
    }

    "stay retryable call after call while two cosigners stay unreachable, and be served once one is back" in {
      val down = Status.UNAVAILABLE
      for (call <- calls) withClue(s"${call.name}: ") {
        withCluster(Seq(Failing(down), call.own, Failing(down)), call.pinFirst) { (backend, nodes) =>
          for (attempt <- 1 to 3) withClue(s"attempt $attempt: ") {
            val notes = new AuditNotes
            val thrown = intercept[StatusRuntimeException](await(backend.withAuditNotes(notes)(call.run(backend))))
            RutliDriver.transient(thrown.getStatus) shouldBe true
            notes.render should include("unconfirmed=")
          }
          nodes(2).state = Holds
          await(call.run(backend)) // Canton's retry
        }
      }
    }
  }

  "the same calls over five cosigners" should {

    def rotations(states: Seq[State]): Seq[Seq[State]] = states.indices.map(i => states.drop(i) ++ states.take(i))
    val down = Status.UNAVAILABLE

    /** `own` cosigners give the own answer, the other `5 - own` cannot be reached, interleaved. */
    def roster(call: Call, own: Int): Seq[State] = {
      val (answers, silent) = (Seq.fill[State](own)(call.own), Seq.fill[State](5 - own)(Failing(down)))
      answers.zipAll(silent, Internal, Internal).flatMap { case (a, b) => Seq(a, b) }.filterNot(_ == Internal)
    }

    "need four of five answers, so that a threshold below a majority is safe too" in {
      // 2-of-5: with three cosigners saying NOT_FOUND, the two that are unreachable could still
      // sign together. Only the fourth answer leaves too few.
      calls.filter(_.counts).map(_.quorum(5)).distinct shouldBe Seq(4)
    }

    "fail retryably while one answer short of the bound, the other cosigners unreachable, in every rotation" in {
      for (call <- calls.filter(_.counts); states <- rotations(roster(call, call.quorum(5) - 1)))
        withClue(s"${call.name}, ${states.mkString(" ")}: ") {
          expected(states, call.own, Failing(down), call.quorum(5)) shouldBe Retryable
          check(call, states, down)
        }
    }

    "end with the own answer, final, at the bound, although the other cosigners are unreachable" in {
      for (call <- calls.filter(_.counts); states <- rotations(roster(call, call.quorum(5))))
        withClue(s"${call.name}, ${states.mkString(" ")}: ") {
          expected(states, call.own, Failing(down), call.quorum(5)) shouldBe OwnAnswerFinal
          check(call, states, down)
        }
    }

    "be served by the one cosigner that holds the key, wherever it is" in {
      for (call <- calls; states <- rotations(Seq(call.own, Failing(down), call.own, Internal, Holds)))
        withClue(s"${call.name}, ${states.mkString(" ")}: ")(check(call, states, down))
    }
  }

  "a ciphertext that a cosigner's shared secret does not open" should {

    "end as an ECIES failure, final, although another cosigner is unreachable: a forged ciphertext buys no retries" in {
      // OtherKey: that cosigner holds another EC key under the id, so its secret is well formed and wrong.
      for (states <- sequences(Seq(OtherKey, Failing(Status.UNAVAILABLE)), 3) if states.contains(OtherKey))
        withClue(states.mkString(" ")) {
          withCluster(states) { (backend, _) =>
            val notes = new AuditNotes
            a[CantonEcies.EciesException] should be thrownBy
              await(backend.withAuditNotes(notes)(backend.decryptAsymmetric(Ciphertext, HostedKey, Ecies)))
            notes.render should include("ecies-failure=after-ecdh")
          }
        }
    }

    "still be opened by a cosigner that holds the right key" in {
      withCluster(Seq(OtherKey, Failing(Status.UNAVAILABLE), Holds)) { (backend, _) =>
        await(backend.decryptAsymmetric(Ciphertext, HostedKey, Ecies)) shouldBe Plaintext
      }
    }
  }

  "what the caller gets" should {

    "be the plaintext and the signature when a cosigner that holds the key is reached" in {
      withCluster(Seq(Missing, Failing(Status.UNAVAILABLE), Holds)) { (backend, _) =>
        await(backend.decryptAsymmetric(Ciphertext, HostedKey, Ecies)) shouldBe Plaintext
      }
      withCluster(Seq(OtherKey, Failing(Status.UNAVAILABLE), Holds), pinFirst = true) { (backend, _) =>
        await(backend.sign(Digest, FrostKey, SigningAlgoSpec.Ed25519)) shouldBe signWith(Group, Digest)
      }
    }

    "be a policy refusal at once, whatever was unreachable before it" in {
      val refusal = Status.PERMISSION_DENIED.withDescription("not on the signer_acl")
      withCluster(Seq(Failing(Status.UNAVAILABLE), Failing(refusal), Holds), pinFirst = true) { (backend, nodes) =>
        val thrown = intercept[StatusRuntimeException](await(signIt(backend)))
        thrown.getStatus.getCode shouldBe Status.Code.PERMISSION_DENIED
        nodes.map(_.asked.get) shouldBe Seq(1, 1, 0)
      }
    }
  }

  "getPublicKey for a FROST key that is not pinned, when nobody answers with a key" should {

    def outcome(states: Seq[State]): Throwable =
      withCluster(states)((backend, _) => intercept[Throwable](await(backend.getPublicKey(FrostKey))))
    val down: State = Failing(Status.UNAVAILABLE)

    "fail retryably for one NOT_FOUND and two unreachable cosigners, in every order" in {
      for (states <- Seq(Seq[State](Missing, down, down), Seq[State](down, Missing, down), Seq[State](down, down, Missing)))
        withClue(states.mkString(" "))(hasStatus(outcome(states), Status.Code.UNAVAILABLE) shouldBe true)
    }

    "end as NOT_FOUND once two of three cosigners say so" in {
      for (
        states <-
          Seq(Seq[State](Missing, Missing, down), Seq[State](down, Missing, Missing), Seq[State](Missing, Missing, Missing))
      )
        withClue(states.mkString(" "))(isNotFound(outcome(states)) shouldBe true)
    }

    "end as NOT_FOUND when one cosigner says so and the others answered an internal error: all were reached" in {
      for (states <- Seq(Seq[State](Missing, Internal, Internal), Seq[State](Internal, Internal, Missing)))
        withClue(states.mkString(" "))(isNotFound(outcome(states)) shouldBe true)
    }

    "end with the internal error when every cosigner answered that" in {
      hasStatus(outcome(Seq(Internal, Internal, Internal)), Status.Code.INTERNAL) shouldBe true
    }
  }
}

object FrostStaleVsUnreachableSpec {

  /** What a cosigner does with a key call. */
  sealed trait State

  /** It holds the key and answers. */
  case object Holds extends State

  /** It answers "not found" (`exists = false` for KeyInfo). */
  case object Missing extends State

  /** It holds other key material under the id: another group key, with which it also signs (FROST
    * keys), or another EC key, so its EcdhDerive secret is wrong (hosted key; KeyInfo and PublicKey
    * answer as [[Holds]]). */
  case object OtherKey extends State

  /** It fails every key call with this status. */
  final case class Failing(status: Status) extends State

  /** A call for which one cosigner's own answer is not the cluster's: the answer (`own`, the state
    * of a cosigner that gives it) and how the call fails when that answer is final. */
  final case class Call(
      name: String,
      own: State,
      pinFirst: Boolean,
      run: FrostBackend => Future[Any],
      isOwnFinal: Throwable => Boolean,
      // Whether the own answer says the cosigner cannot use the key, and so becomes final by count.
      counts: Boolean = true,
  ) {

    /** How many cosigners of `n` must give the own answer before it is final: all but one, or
      * never for an answer that is about the cosigner's state at the moment. */
    def quorum(n: Int): Int = if (counts) math.max(1, n - 1) else Int.MaxValue
  }

  /** How a call over a roster ends. */
  sealed trait Outcome
  case object Served extends Outcome
  case object OwnAnswerFinal extends Outcome
  case object Retryable extends Outcome
  case object InternalFinal extends Outcome
}
