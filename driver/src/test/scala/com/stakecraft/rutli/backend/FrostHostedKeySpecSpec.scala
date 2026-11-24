// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli.backend

import com.digitalasset.canton.crypto.kms.driver.api.v1._
import com.google.protobuf.ByteString
import com.stakecraft.rutli.audit.AuditNotes
import com.stakecraft.rutli.grpc._
import io.grpc.inprocess.{InProcessChannelBuilder, InProcessServerBuilder}
import io.grpc.stub.StreamObserver
import io.grpc.{Metadata, Status, StatusRuntimeException}
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import org.slf4j.LoggerFactory

import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import java.util.concurrent.atomic.AtomicInteger
import scala.concurrent.duration._
import scala.concurrent.{Await, ExecutionContext, Future}

/** The driver remembers the spec of a hosted key it has seen, and holds a metadata read
  * (`getPublicKey`, `keyExistsAndIsActive`) to it. A hosted key id is never used twice, so the
  * spec of an id does not change, and one cosigner's reply must not change what the driver knows:
  * a reply under another spec is that cosigner's own answer, passed over like "not found". When a
  * cosigner answers so, the driver asks every cosigner what it holds, and the remembered spec
  * changes only when all but one of them (and at least two) hold the key under one other spec.
  *
  * Three cosigners, asked in roster order. They do no cryptography: what matters is which one is
  * asked, what Canton is told the key is, and what the audit note says.
  */
class FrostHostedKeySpecSpec extends AnyWordSpec with Matchers {

  import FrostHostedKeySpecSpec._

  private implicit val ec: ExecutionContext = ExecutionContext.global
  private val logger = LoggerFactory.getLogger(classOf[FrostHostedKeySpecSpec])
  private def await[T](f: Future[T]): T = Await.result(f, 10.seconds)

  private val Key = "rutli-enc-0001"

  // A P-256 public key as the cluster sends it (X.509 SubjectPublicKeyInfo); the driver checks
  // its shape. The bytes of an RSA key are handed on as they are.
  private val EcDer: Array[Byte] = {
    val generator = KeyPairGenerator.getInstance("EC")
    generator.initialize(new ECGenParameterSpec("secp256r1"))
    generator.generateKeyPair().getPublic.getEncoded
  }
  private val RsaDer: Array[Byte] = Array[Byte](1, 2, 3)

  /** One cosigner, which answers the two metadata reads as `answers` says. `asked` counts the
    * reads; the driver's question to every cosigner about its own copy (`KeyInfo`, local only) is
    * answered the same way and not counted. */
  private final class Node extends SignerGrpc.SignerImplBase {
    val name: String = s"keyspec-${InProcessServerBuilder.generateName()}"
    @volatile var answers: Answer = Lacks
    val asked = new AtomicInteger

    private def answer[R](obs: StreamObserver[R], counted: Boolean = true)(under: String => R)(lacks: => Unit): Unit = {
      if (counted) asked.incrementAndGet()
      answers match {
        case Under(spec) =>
          obs.onNext(under(spec))
          obs.onCompleted()
        case Lacks        => lacks
        case Down(reason) =>
          val trailers = new Metadata
          trailers.put(ReasonTrailer, reason)
          obs.onError(Status.UNAVAILABLE.withDescription("test: down").asRuntimeException(trailers))
      }
    }

    override def publicKey(req: PublicKeyRequest, obs: StreamObserver[PublicKeyReply]): Unit =
      answer(obs) { spec =>
        val der = if (spec == Ec) EcDer else RsaDer
        PublicKeyReply.newBuilder().setSpec(spec).setPublicKeyDer(ByteString.copyFrom(der)).build()
      }(obs.onError(Status.NOT_FOUND.withDescription("no such key").asRuntimeException()))

    override def keyInfo(req: KeyInfoRequest, obs: StreamObserver[KeyInfoReply]): Unit =
      answer(obs, counted = !req.getLocalOnly)(spec => KeyInfoReply.newBuilder().setExists(true).setSpec(spec).build()) {
        obs.onNext(KeyInfoReply.newBuilder().setExists(false).build())
        obs.onCompleted()
      }
  }

  /** Three cosigners and a backend over them. With `known`, every cosigner first answers under
    * that spec and the backend reads the key once, so it knows the key by it. */
  private def withCluster[A](known: Option[String])(body: (FrostBackend, IndexedSeq[Node]) => A): A = {
    val nodes = (0 until 3).map(_ => new Node)
    val servers = nodes.map(node => InProcessServerBuilder.forName(node.name).directExecutor().addService(node).build().start())
    val backend =
      new FrostBackend(nodes.map(_.name), new NoDelegateBackend, logger, None, 10.seconds, hostedKeys = true) {
        override protected def buildChannel(endpoint: String): io.grpc.ManagedChannel =
          InProcessChannelBuilder.forName(endpoint).directExecutor().build()
      }
    try {
      known.foreach { spec =>
        nodes.foreach(_.answers = Under(spec))
        await(backend.keyExistsAndIsActive(Key))
      }
      nodes.foreach(_.asked.set(0))
      body(backend, nodes)
    } finally {
      backend.close()
      servers.foreach(_.shutdownNow())
    }
  }

  private def answering(nodes: IndexedSeq[Node], answers: Seq[Answer]): Unit =
    nodes.zip(answers).foreach { case (node, a) => node.answers = a }

  /** A metadata read of the key. */
  private final class Read(val name: String, val run: FrostBackend => Future[Any])
  private val reads: Seq[Read] = Seq(
    new Read("getPublicKey", _.getPublicKey(Key)),
    new Read("keyExistsAndIsActive", _.keyExistsAndIsActive(Key)),
  )
  private val specs: Seq[String] = Seq(Ec, Rsa)
  private def otherThan(spec: String): String = if (spec == Ec) Rsa else Ec

  /** What Canton is told a key of `spec` is. */
  private def atCanton(spec: String): EncryptionKeySpec =
    if (spec == Ec) EncryptionKeySpec.EcP256 else EncryptionKeySpec.Rsa2048

  /** The audit note's name for a hop: `ec-failover` on the path for a key known to be EC. */
  private def hop(known: String): String = if (known == Ec) "ec-failover" else "failover"

  private def read(backend: FrostBackend, r: Read, notes: AuditNotes = new AuditNotes): Any =
    await(backend.withAuditNotes(notes)(r.run(backend)))

  /** The key as a later read finds it, every cosigner answering under `spec` again: what Canton is
    * told it is, and whether that read changed what the driver knows. */
  private def laterRead(backend: FrostBackend, nodes: IndexedSeq[Node], spec: String): (Any, Boolean) = {
    nodes.foreach(_.answers = Under(spec))
    val notes = new AuditNotes
    val told: Any = await(backend.withAuditNotes(notes)(backend.getPublicKey(Key))).spec
    (told, notes.render.contains("hosted-spec="))
  }

  "a read of a hosted key the driver knows" should {

    "pass over a cosigner that answers under another spec, and take the lead from it" in {
      for (known <- specs; r <- reads) withClue(s"known as $known, ${r.name}: ") {
        withCluster(Some(known)) { (backend, nodes) =>
          nodes(0).answers = Under(otherThan(known))
          val notes = new AuditNotes
          read(backend, r, notes)
          notes.render shouldBe s"${hop(known)}=${nodes(0).name}→${nodes(1).name} reason=OTHER_SPEC"
          nodes.map(_.asked.get) shouldBe Seq(1, 1, 0)
          // The key is what it was, and the next read starts at the cosigner that served.
          await(backend.getPublicKey(Key)).spec shouldBe atCanton(known)
          nodes.map(_.asked.get) shouldBe Seq(1, 2, 0)
        }
      }
    }

    "not take another spec from the cosigner asked after one that lacks the key" in {
      for (known <- specs; r <- reads) withClue(s"known as $known, ${r.name}: ") {
        withCluster(Some(known)) { (backend, nodes) =>
          answering(nodes, Seq(Lacks, Under(otherThan(known)), Under(known)))
          read(backend, r)
          nodes.map(_.asked.get) shouldBe Seq(1, 1, 1)
          await(backend.getPublicKey(Key)).spec shouldBe atCanton(known)
          nodes.map(_.asked.get) shouldBe Seq(1, 1, 2)
        }
      }
    }

    "take another spec when all but one cosigner hold the key under it" in {
      for (known <- specs; r <- reads) {
        val other = Under(otherThan(known))
        val rosters: Seq[Seq[Answer]] =
          Seq(Seq(other, other, Down("")), Seq(Down(""), other, other), Seq(Lacks, other, other), Seq(other, Lacks, other))
        for (roster <- rosters) withClue(s"known as $known, ${r.name}, $roster: ") {
          withCluster(Some(known)) { (backend, nodes) =>
            answering(nodes, roster)
            val notes = new AuditNotes
            read(backend, r, notes)
            notes.render should include(s"hosted-spec=$known→${otherThan(known)}")
            // Known by the other spec from now on: a read under it changes nothing.
            laterRead(backend, nodes, otherThan(known)) shouldBe (atCanton(otherThan(known)) -> false)
          }
        }
      }
    }

    "fail retryable and keep the spec when one cosigner answers under another and the rest cannot be reached" in {
      for (known <- specs; r <- reads) withClue(s"known as $known, ${r.name}: ") {
        withCluster(Some(known)) { (backend, nodes) =>
          answering(nodes, Seq(Under(otherThan(known)), Down("hosted-unconfirmed"), Down("hosted-unconfirmed")))
          val notes = new AuditNotes
          val thrown = intercept[StatusRuntimeException](read(backend, r, notes))
          thrown.getStatus.getCode shouldBe Status.Code.UNAVAILABLE
          notes.render should include(s"unconfirmed=${nodes(2).name} reason=UNAVAILABLE")
          // The cosigner's reason for the status reaches the caller with it.
          Option(thrown.getTrailers).map(_.get(ReasonTrailer)) shouldBe Some("hosted-unconfirmed")
          laterRead(backend, nodes, known) shouldBe (atCanton(known) -> false)
        }
      }
    }

    "fail and keep the spec when one cosigner answers under another and the rest lack the key" in {
      for (known <- specs; r <- reads) withClue(s"known as $known, ${r.name}: ") {
        withCluster(Some(known)) { (backend, nodes) =>
          answering(nodes, Seq(Under(otherThan(known)), Lacks, Lacks))
          intercept[Exception](read(backend, r)) match {
            case e: StatusRuntimeException => e.getStatus.getCode shouldBe Status.Code.NOT_FOUND // not retryable
            case _                         => succeed
          }
          nodes.map(_.asked.get) shouldBe Seq(1, 1, 1)
          laterRead(backend, nodes, known) shouldBe (atCanton(known) -> false)
        }
      }
    }
  }

  "a read of a hosted key the driver has not seen" should {

    "learn the key from the first answer" in {
      withCluster(None) { (backend, nodes) =>
        answering(nodes, Seq(Under(Rsa), Under(Ec), Under(Ec)))
        await(backend.getPublicKey(Key)).spec shouldBe EncryptionKeySpec.Rsa2048
        nodes.map(_.asked.get) shouldBe Seq(1, 0, 0)
      }
    }
  }

  "a spec learned from one cosigner's first answer" should {

    "give way once the other cosigners are asked, also while a cosigner still answers under it" in {
      for (r <- reads) withClue(s"${r.name}: ") {
        withCluster(None) { (backend, nodes) =>
          answering(nodes, Seq(Under(Rsa), Under(Ec), Under(Ec)))
          await(backend.getPublicKey(Key)).spec shouldBe EncryptionKeySpec.Rsa2048
          // Now the two that hold the key as EC are asked first; the third still says RSA and
          // serves the read under the spec the driver knows. Two of three hold it as EC.
          answering(nodes, Seq(Under(Ec), Under(Ec), Under(Rsa)))
          val notes = new AuditNotes
          read(backend, r, notes)
          notes.render should include(s"hosted-spec=$Rsa→$Ec")
          laterRead(backend, nodes, Ec) shouldBe (EncryptionKeySpec.EcP256 -> false)
        }
      }
    }
  }
}

object FrostHostedKeySpecSpec {

  private val Ec = "ec-p256-ecies"
  private val Rsa = "rsa-2048-oaep-sha256"

  /** The trailer a cosigner names the reason of an error status in. */
  private val ReasonTrailer: Metadata.Key[String] = Metadata.Key.of("rutli-error", Metadata.ASCII_STRING_MARSHALLER)

  /** What a cosigner answers a metadata read of the key with. */
  sealed trait Answer

  /** It holds the key under this spec. */
  final case class Under(spec: String) extends Answer

  /** It does not hold the key: NOT_FOUND, `exists = false` for KeyInfo. */
  case object Lacks extends Answer

  /** It cannot be reached: UNAVAILABLE, with this reason in the trailer. */
  final case class Down(reason: String) extends Answer
}
