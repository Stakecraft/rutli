// Copyright 2026 StakeCraft
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

/** "Not found" from one cosigner is not the cluster's answer while another cosigner could not be
  * reached: that one may hold the key. Canton never retries a final error, so the call must then
  * fail with the unreachable cosigner's status (retryable), in whatever order the endpoints were
  * asked; "not found" is final only when every endpoint answered.
  *
  * Three cosigners, each in one of these states per test: it holds the key, it does not ("not
  * found", or `exists = false`), it answers another group key, or it fails with a status.
  */
class FrostStaleVsUnreachableSpec extends AnyWordSpec with Matchers {

  import FrostStaleVsUnreachableSpec._

  private implicit val ec: ExecutionContext = ExecutionContext.global
  private val logger = LoggerFactory.getLogger(classOf[FrostStaleVsUnreachableSpec])
  private def await[T](f: Future[T]): T = Await.result(f, 10.seconds)

  private val FrostKey = "frost-ns"
  private val HostedKey = "rutli-enc-ec"
  private val Ecies = EncryptionAlgoSpec.EciesHkdfHmacSha256Aes128Cbc

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

  private val EcPair: KeyPair = {
    val g = KeyPairGenerator.getInstance("EC")
    g.initialize(new ECGenParameterSpec("secp256r1"))
    g.generateKeyPair()
  }
  private val Plaintext: Array[Byte] = "for the cosigner that holds the key".getBytes
  private val Ciphertext: Array[Byte] = {
    val iv = new Array[Byte](16)
    new SecureRandom().nextBytes(iv)
    val c = Cipher.getInstance("ECIESwithSHA256andAES-CBC", new org.bouncycastle.jce.provider.BouncyCastleProvider)
    c.init(Cipher.ENCRYPT_MODE, EcPair.getPublic, new IESParameterSpec(Array[Byte](), Array[Byte](), 512, 128, iv))
    iv ++ c.doFinal(Plaintext)
  }

  /** One cosigner in a switchable state. For the hosted key it answers as `holder` does while it
    * holds the key. Every key call is counted. */
  private final class Node(holder: CryptoFakeCluster) extends SignerGrpc.SignerImplBase {
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
    private def notFound[R](obs: StreamObserver[R]): Unit =
      obs.onError(Status.NOT_FOUND.withDescription("no such key").asRuntimeException())

    override def groupKey(req: GroupKeyRequest, obs: StreamObserver[GroupKeyReply]): Unit =
      serve(obs) {
        val key = if (state == OtherKey) raw(Other) else raw(Group)
        obs.onNext(GroupKeyReply.newBuilder().setGroupVerifyingKey(ByteString.copyFrom(key)).build())
        obs.onCompleted()
      }(notFound(obs))
    override def sign(req: SignRequest, obs: StreamObserver[SignReply]): Unit =
      serve(obs) {
        val signature = signWith(if (state == OtherKey) Other else Group, req.getMessage.toByteArray)
        obs.onNext(SignReply.newBuilder().setSignature(ByteString.copyFrom(signature)).build())
        obs.onCompleted()
      }(notFound(obs))
    override def keyInfo(req: KeyInfoRequest, obs: StreamObserver[KeyInfoReply]): Unit =
      serve(obs)(holder.keyInfo(req, obs)) {
        obs.onNext(KeyInfoReply.newBuilder().setExists(false).build())
        obs.onCompleted()
      }
    override def publicKey(req: PublicKeyRequest, obs: StreamObserver[PublicKeyReply]): Unit =
      serve(obs)(holder.publicKey(req, obs))(notFound(obs))
    override def ecdhDerive(req: EcdhDeriveRequest, obs: StreamObserver[EcdhDeriveReply]): Unit =
      serve(obs)(holder.ecdhDerive(req, obs))(notFound(obs))
  }

  /** Three cosigners in `states`, in roster order, and a backend over them. */
  private def withCluster[A](states: Seq[State])(body: (FrostBackend, IndexedSeq[Node]) => A): A = {
    val holder = new CryptoFakeCluster
    holder.putEcKey(HostedKey, EcPair)
    val nodes = states.toIndexedSeq.map { s =>
      val node = new Node(holder)
      node.state = s
      node
    }
    val servers = nodes.map(node => InProcessServerBuilder.forName(node.name).directExecutor().addService(node).build().start())
    val backend =
      new FrostBackend(nodes.map(_.name), new NoDelegateBackend, logger, None, 10.seconds, hostedKeys = true) {
        override protected def buildChannel(endpoint: String): io.grpc.ManagedChannel =
          InProcessChannelBuilder.forName(endpoint).directExecutor().build()
      }
    try body(backend, nodes)
    finally {
      backend.close()
      servers.foreach(_.shutdownNow())
    }
  }

  /** A call where one cosigner's "not found" is not the cluster's, and how its final "not found"
    * looks to the caller. */
  private final case class Call(name: String, run: FrostBackend => Future[Any], isNotFound: Throwable => Boolean)

  private def notFoundStatus(t: Throwable): Boolean = t match {
    case e: StatusRuntimeException => e.getStatus.getCode == Status.Code.NOT_FOUND
    case _                         => false
  }

  private val calls = Seq(
    Call("keyExistsAndIsActive (EC hosted key)", _.keyExistsAndIsActive(HostedKey), _.isInstanceOf[NoSuchElementException]),
    Call("getPublicKey (EC hosted key)", _.getPublicKey(HostedKey), notFoundStatus),
    Call("decryptAsymmetric (ECIES)", _.decryptAsymmetric(Ciphertext, HostedKey, Ecies), notFoundStatus),
    Call("keyExistsAndIsActive (FROST key, not pinned)", _.keyExistsAndIsActive(FrostKey), notFoundStatus),
  )

  private val unreachable = Seq(Status.UNAVAILABLE, Status.DEADLINE_EXCEEDED)

  /** Run `call` over `states` and return what it failed with, and its audit notes. */
  private def failure(call: Call, states: Seq[State]): (Throwable, String, Seq[Int]) =
    withCluster(states) { (backend, nodes) =>
      val notes = new AuditNotes
      val thrown = intercept[Throwable](await(backend.withAuditNotes(notes)(call.run(backend))))
      (thrown, notes.render, nodes.map(_.asked.get))
    }

  /** `thrown` is `status` as the cosigner sent it (the code), and Canton will retry it. */
  private def retryableAs(thrown: Throwable, status: Status): Unit = {
    thrown shouldBe a[StatusRuntimeException]
    val got = thrown.asInstanceOf[StatusRuntimeException].getStatus
    got.getCode shouldBe status.getCode
    RutliDriver.transient(got) shouldBe true
    ()
  }

  "a call that one cosigner answers with \"not found\"" should {

    "fail retryably when the cosigners asked after it could not be reached" in {
      for (call <- calls; down <- unreachable) withClue(s"${call.name}, ${down.getCode}: ") {
        val (thrown, _, asked) = failure(call, Seq(Missing, Failing(down), Failing(down)))
        retryableAs(thrown, down)
        asked shouldBe Seq(1, 1, 1)
      }
    }

    "fail retryably when the cosigners asked before it could not be reached, naming one in the audit entry" in {
      for (call <- calls; down <- unreachable) withClue(s"${call.name}, ${down.getCode}: ") {
        withCluster(Seq(Failing(down), Failing(down), Missing)) { (backend, nodes) =>
          val notes = new AuditNotes
          val thrown = intercept[Throwable](await(backend.withAuditNotes(notes)(call.run(backend))))
          retryableAs(thrown, down)
          nodes.map(_.asked.get) shouldBe Seq(1, 1, 1)
          notes.render should include(s"unconfirmed=${nodes(1).name} reason=${down.getCode}")
          thrown.getMessage should include("not a final answer")
        }
      }
    }

    "fail retryably when a single cosigner could not be reached, wherever it is in the order" in {
      for (call <- calls; down <- unreachable; at <- 0 to 2) withClue(s"${call.name}, ${down.getCode} at $at: ") {
        withCluster(Seq.tabulate[State](3)(i => if (i == at) Failing(down) else Missing)) { (backend, nodes) =>
          val notes = new AuditNotes
          val thrown = intercept[Throwable](await(backend.withAuditNotes(notes)(call.run(backend))))
          retryableAs(thrown, down)
          nodes.map(_.asked.get) shouldBe Seq(1, 1, 1)
          // Noted whenever the walk ended on a "not found"; when it ended on the unreachable
          // cosigner itself the error is that cosigner's own.
          if (at < 2) notes.render should include(s"unconfirmed=${nodes(at).name} reason=${down.getCode}")
        }
      }
    }

    "end as \"not found\", final, only when every cosigner answered it" in {
      for (call <- calls) withClue(s"${call.name}: ") {
        val (thrown, notes, asked) = failure(call, Seq(Missing, Missing, Missing))
        call.isNotFound(thrown) shouldBe true
        asked shouldBe Seq(1, 1, 1)
        notes should not include "unconfirmed="
        thrown match {
          case e: StatusRuntimeException => RutliDriver.transient(e.getStatus) shouldBe false
          case _                         => succeed
        }
      }
    }

    "end with the last cosigner's status when none of them answered at all" in {
      for (call <- calls; down <- unreachable) withClue(s"${call.name}, ${down.getCode}: ") {
        val (thrown, notes, asked) = failure(call, Seq(Failing(down), Failing(down), Failing(down)))
        retryableAs(thrown, down)
        asked shouldBe Seq(1, 1, 1)
        notes should not include "unconfirmed="
      }
    }

    "succeed through a cosigner that holds the key, asked before or after one that could not be reached" in {
      for (call <- calls; down <- unreachable) withClue(s"${call.name}, ${down.getCode}: ") {
        withCluster(Seq(Missing, Holds, Failing(down))) { (backend, nodes) =>
          await(call.run(backend))
          nodes.map(_.asked.get) shouldBe Seq(1, 1, 0)
        }
        withCluster(Seq(Failing(down), Missing, Holds)) { (backend, nodes) =>
          await(call.run(backend))
          nodes.map(_.asked.get) shouldBe Seq(1, 1, 1)
        }
      }
    }

    "succeed again once the unreachable cosigner is back" in {
      for (call <- calls) withClue(s"${call.name}: ") {
        withCluster(Seq(Missing, Failing(Status.UNAVAILABLE), Missing)) { (backend, nodes) =>
          retryableAs(intercept[Throwable](await(call.run(backend))), Status.UNAVAILABLE)
          nodes(1).state = Holds
          await(call.run(backend)) // Canton's retry
        }
      }
    }
  }

  "an EC hosted-key call that one cosigner answers with \"not found\"" should {

    "keep that answer when the others answered an internal error: they were reached, and their error is final too" in {
      for (call <- calls.take(3)) withClue(s"${call.name}: ") {
        val (thrown, notes, asked) = failure(call, Seq(Missing, Failing(Status.INTERNAL), Failing(Status.UNKNOWN)))
        call.isNotFound(thrown) shouldBe true
        asked shouldBe Seq(1, 1, 1)
        notes should not include "unconfirmed="
      }
    }

    "open the ciphertext through the cosigner that holds the key" in {
      withCluster(Seq(Missing, Holds, Failing(Status.UNAVAILABLE))) { (backend, _) =>
        await(backend.decryptAsymmetric(Ciphertext, HostedKey, Ecies)) shouldBe Plaintext
      }
    }
  }

  "keyExistsAndIsActive for a pinned FROST key" should {

    /** Pin the key while every cosigner holds it, then put the cosigners in `states`. */
    def pinnedThen[A](states: Seq[State])(body: (FrostBackend, IndexedSeq[Node]) => A): A =
      withCluster(Seq(Holds, Holds, Holds)) { (backend, nodes) =>
        await(backend.getPublicKey(FrostKey))
        nodes.zip(states).foreach { case (node, s) => node.state = s }
        nodes.foreach(_.asked.set(0))
        body(backend, nodes)
      }

    "fail retryably when one cosigner says \"not found\" or answers another key and the others could not be reached" in {
      for (answer <- Seq[State](Missing, OtherKey); down <- unreachable; at <- 0 to 2)
        withClue(s"$answer at $at, ${down.getCode}: ") {
          pinnedThen(Seq.tabulate[State](3)(i => if (i == at) answer else Failing(down))) { (backend, nodes) =>
            val notes = new AuditNotes
            val thrown = intercept[Throwable](await(backend.withAuditNotes(notes)(backend.keyExistsAndIsActive(FrostKey))))
            retryableAs(thrown, down)
            nodes.map(_.asked.get) shouldBe Seq(1, 1, 1)
            if (at == 2) notes.render should include(s"unconfirmed=${nodes(1).name} reason=${down.getCode}")

            // The cosigners are back: Canton's retry finds the key active.
            nodes.foreach(_.state = Holds)
            await(backend.keyExistsAndIsActive(FrostKey))
          }
        }
    }

    "end as \"not found\" when every cosigner says so, and as a final refusal when every cosigner answers another key" in {
      pinnedThen(Seq(Missing, Missing, Missing)) { (backend, nodes) =>
        val thrown = intercept[Throwable](await(backend.keyExistsAndIsActive(FrostKey)))
        notFoundStatus(thrown) shouldBe true
        nodes.map(_.asked.get) shouldBe Seq(1, 1, 1)
      }
      pinnedThen(Seq(OtherKey, OtherKey, OtherKey)) { (backend, nodes) =>
        val thrown = the[KmsDriverException] thrownBy await(backend.keyExistsAndIsActive(FrostKey))
        thrown.retryable shouldBe false
        nodes.map(_.asked.get) shouldBe Seq(1, 1, 1)
      }
    }
  }

  "a sign whose last leader cannot sign for a reason of its own" should {

    /** Pin the key while every cosigner holds it, then put the cosigners in `states`. */
    def pinnedThen[A](states: Seq[State])(body: (FrostBackend, IndexedSeq[Node]) => A): A =
      withCluster(Seq(Holds, Holds, Holds)) { (backend, nodes) =>
        await(backend.getPublicKey(FrostKey))
        nodes.zip(states).foreach { case (node, s) => node.state = s }
        nodes.foreach(_.asked.set(0))
        body(backend, nodes)
      }
    def sign(backend: FrostBackend, notes: AuditNotes = new AuditNotes): Array[Byte] =
      await(backend.withAuditNotes(notes)(backend.sign(Digest, FrostKey, SigningAlgoSpec.Ed25519)))

    // What one leader answers from its own state: it lacks the share, a ceremony holds the key, it
    // is too old, or it returns a signature the pinned group key does not verify.
    val leaderLocal = Seq[State](
      Missing,
      OtherKey,
      Failing(Status.FAILED_PRECONDITION),
      Failing(Status.ABORTED),
      Failing(Status.UNIMPLEMENTED),
    )

    "fail retryably when the other cosigners could not be reached, wherever that leader is in the order" in {
      for (answer <- leaderLocal; down <- unreachable; at <- 0 to 2) withClue(s"$answer at $at, ${down.getCode}: ") {
        pinnedThen(Seq.tabulate[State](3)(i => if (i == at) answer else Failing(down))) { (backend, nodes) =>
          val notes = new AuditNotes
          retryableAs(intercept[Throwable](sign(backend, notes)), down)
          nodes.map(_.asked.get) shouldBe Seq(1, 1, 1)
          if (at == 2) notes.render should include(s"unconfirmed=${nodes(1).name} reason=${down.getCode}")

          // The cosigners are back: Canton's retry of the same sign gets its signature.
          nodes.foreach(_.state = Holds)
          sign(backend) shouldBe signWith(Group, Digest)
        }
      }
    }

    "end as that leader's answer, final, when every cosigner gave it" in {
      pinnedThen(Seq(Missing, Missing, Missing)) { (backend, nodes) =>
        notFoundStatus(intercept[Throwable](sign(backend))) shouldBe true
        nodes.map(_.asked.get) shouldBe Seq(1, 1, 1)
      }
      pinnedThen(Seq(OtherKey, OtherKey, OtherKey)) { (backend, nodes) =>
        val thrown = the[KmsDriverException] thrownBy sign(backend)
        thrown.retryable shouldBe false
        thrown.getMessage should include("does not verify")
        nodes.map(_.asked.get) shouldBe Seq(1, 1, 1)
      }
    }

    "keep an internal error as the last error of the walk, as before" in {
      pinnedThen(Seq(Failing(Status.UNAVAILABLE), Failing(Status.UNAVAILABLE), Failing(Status.INTERNAL))) { (backend, _) =>
        val thrown = intercept[StatusRuntimeException](sign(backend))
        thrown.getStatus.getCode shouldBe Status.Code.INTERNAL
      }
    }

    "return a policy refusal at once, whatever was unreachable before it" in {
      val refusal = Status.PERMISSION_DENIED.withDescription("not on the signer_acl")
      pinnedThen(Seq(Failing(Status.UNAVAILABLE), Failing(refusal), Holds)) { (backend, nodes) =>
        val thrown = intercept[StatusRuntimeException](sign(backend))
        thrown.getStatus.getCode shouldBe Status.Code.PERMISSION_DENIED
        nodes.map(_.asked.get) shouldBe Seq(1, 1, 0)
      }
    }
  }

  "a key that no reachable cosigner has, while one cosigner stays unreachable" should {

    "be reported as retryable call after call, each time naming the unreachable cosigner: there is no time bound" in {
      // Deliberate: the driver cannot tell a key that exists nowhere from one whose only holder is
      // down, and "does not exist" for an authority key must not depend on how long an outage
      // lasted. The operator sees the endpoint in every attempt's audit entry and WARN line.
      for (call <- calls) withClue(s"${call.name}: ") {
        withCluster(Seq(Failing(Status.UNAVAILABLE), Missing, Missing)) { (backend, nodes) =>
          for (attempt <- 1 to 4) withClue(s"attempt $attempt: ") {
            val notes = new AuditNotes
            retryableAs(intercept[Throwable](await(backend.withAuditNotes(notes)(call.run(backend)))), Status.UNAVAILABLE)
            notes.render should include(s"unconfirmed=${nodes(0).name} reason=UNAVAILABLE")
          }
          // Once that cosigner answers too, the answer is final.
          nodes(0).state = Missing
          call.isNotFound(intercept[Throwable](await(call.run(backend)))) shouldBe true
        }
      }
    }
  }

  "getPublicKey for a FROST key that is not pinned" should {

    "fail retryably when nobody answered with a key and one cosigner could not be reached, wherever it is" in {
      for (down <- unreachable; at <- 0 to 2) withClue(s"${down.getCode} at $at: ") {
        withCluster(Seq.tabulate[State](3)(i => if (i == at) Failing(down) else Missing)) { (backend, _) =>
          retryableAs(intercept[Throwable](await(backend.getPublicKey(FrostKey))), down)
        }
      }
    }

    "end as \"not found\" when every cosigner says so" in {
      withCluster(Seq(Missing, Missing, Missing)) { (backend, _) =>
        notFoundStatus(intercept[Throwable](await(backend.getPublicKey(FrostKey)))) shouldBe true
      }
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

  /** It answers another group key than the cluster's (FROST keys; for a hosted key, as [[Holds]]). */
  case object OtherKey extends State

  /** It fails every key call with this status. */
  final case class Failing(status: Status) extends State
}
