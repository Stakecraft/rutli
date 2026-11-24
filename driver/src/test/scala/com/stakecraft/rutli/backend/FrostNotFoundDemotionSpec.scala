// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli.backend

import com.digitalasset.canton.crypto.kms.driver.api.v1._
import com.google.protobuf.ByteString
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

/** A cosigner that says "I do not have this key" loses the lead only when another cosigner then
  * serves the call. A lookup of a key that exists nowhere must not take the lead from every
  * cosigner: with `frost.sign-leader = rotate` a cosigner that lost the lead is not a sign start for
  * `leader-recovery`, so that would switch the rotation off, and a caller repeating the lookup
  * would keep it off.
  *
  * What the tests look at is where the signs start afterwards: three cosigners, rotate, six signs.
  * Untouched, each cosigner starts two.
  */
class FrostNotFoundDemotionSpec extends AnyWordSpec with Matchers {

  import FrostStaleVsUnreachableSpec.{Failing, Holds, Missing, OtherKey, State}

  private implicit val ec: ExecutionContext = ExecutionContext.global
  private val logger = LoggerFactory.getLogger(classOf[FrostNotFoundDemotionSpec])
  private def await[T](f: Future[T]): T = Await.result(f, 10.seconds)

  private val FrostKey = "frost-ns"
  private val HostedKey = "rutli-enc-0001"
  private val Rsa = "rsa-2048-oaep-sha256"
  private val Data: Array[Byte] = "payload".getBytes
  private val Digest: Array[Byte] = Array.fill(34)(7.toByte)

  private val Group: KeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
  private def groupSign(msg: Array[Byte]): Array[Byte] = {
    val s = Signature.getInstance("Ed25519")
    s.initSign(Group.getPrivate)
    s.update(msg)
    s.sign()
  }

  /** One cosigner. It always signs; what it does with a hosted-key call is `hosted`, and whether it
    * knows the FROST key is `frostKeyMissing`. Signs are counted. */
  private final class Node extends SignerGrpc.SignerImplBase {
    val name: String = s"lead-${InProcessServerBuilder.generateName()}"
    val signs = new AtomicInteger
    val hostedCalls = new AtomicInteger
    @volatile var hosted: State = Missing
    @volatile var frostKeyMissing: Boolean = false

    private def noSuchKey[R](obs: StreamObserver[R]): Unit =
      obs.onError(Status.NOT_FOUND.withDescription("no such key").asRuntimeException())
    private def serve[R](obs: StreamObserver[R])(holds: => R)(missing: => Unit): Unit = {
      hostedCalls.incrementAndGet()
      hosted match {
        case Failing(status)  => obs.onError(status.asRuntimeException())
        case Missing          => missing
        case Holds | OtherKey =>
          obs.onNext(holds)
          obs.onCompleted()
      }
    }

    override def groupKey(req: GroupKeyRequest, obs: StreamObserver[GroupKeyReply]): Unit =
      if (frostKeyMissing) noSuchKey(obs)
      else {
        obs.onNext(
          GroupKeyReply.newBuilder().setGroupVerifyingKey(ByteString.copyFrom(Group.getPublic.getEncoded.takeRight(32))).build()
        )
        obs.onCompleted()
      }
    override def sign(req: SignRequest, obs: StreamObserver[SignReply]): Unit = {
      signs.incrementAndGet()
      obs.onNext(SignReply.newBuilder().setSignature(ByteString.copyFrom(groupSign(req.getMessage.toByteArray))).build())
      obs.onCompleted()
    }
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

  /** Three cosigners and a backend that rotates signs over them, with the FROST key pinned. With
    * `learnRsa` the backend has also read the hosted key's public key, so it knows the key is RSA
    * and uses the calls for a key that is not EC. Then the cosigners' hosted state is `hosted`. */
  private def withCluster[A](hosted: Seq[State], learnRsa: Boolean = false, pin: Boolean = true)(
      body: (FrostBackend, IndexedSeq[Node]) => A
  ): A = {
    val nodes = hosted.toIndexedSeq.map(_ => new Node)
    val servers = nodes.map(node => InProcessServerBuilder.forName(node.name).directExecutor().addService(node).build().start())
    val backend =
      new FrostBackend(
        nodes.map(_.name),
        new NoDelegateBackend,
        logger,
        None,
        10.seconds,
        hostedKeys = true,
        rotateSigns = true
      ) {
        override protected def buildChannel(endpoint: String): io.grpc.ManagedChannel =
          InProcessChannelBuilder.forName(endpoint).directExecutor().build()
      }
    try {
      if (pin) await(backend.getPublicKey(FrostKey)) // pins the group key; uses no sign turn
      if (learnRsa) {
        nodes.foreach(_.hosted = Holds)
        await(backend.getPublicKey(HostedKey)).spec shouldBe EncryptionKeySpec.Rsa2048
      }
      nodes.zip(hosted).foreach { case (node, s) => node.hosted = s }
      body(backend, nodes)
    } finally {
      backend.close()
      servers.foreach(_.shutdownNow())
    }
  }

  /** Sign `count` times and say how many signs each cosigner got since the last look. */
  private def signs(backend: FrostBackend, nodes: IndexedSeq[Node], count: Int): Seq[Int] = {
    val before = nodes.map(_.signs.get)
    (1 to count).foreach(_ => await(backend.sign(Digest, FrostKey, SigningAlgoSpec.Ed25519)) shouldBe groupSign(Digest))
    nodes.map(_.signs.get).zip(before).map { case (now, prev) => now - prev }
  }

  /** A hosted-key call, and whether it needs the backend to know the key is RSA first. */
  private final class Lookup(val name: String, val learnRsa: Boolean, val run: FrostBackend => Future[Any])

  private val lookups: Seq[Lookup] = Seq(
    new Lookup("decryptAsymmetric, RSA", false, _.decryptAsymmetric(Data, HostedKey, EncryptionAlgoSpec.RsaEsOaepSha256)),
    new Lookup("encryptSymmetric", false, _.encryptSymmetric(Data, HostedKey)),
    new Lookup("decryptSymmetric", false, _.decryptSymmetric(Data, HostedKey)),
    new Lookup("getPublicKey, type not known yet", false, _.getPublicKey(HostedKey)),
    new Lookup("keyExistsAndIsActive, type not known yet", false, _.keyExistsAndIsActive(HostedKey)),
    new Lookup("getPublicKey, key known to be RSA", true, _.getPublicKey(HostedKey)),
    new Lookup("keyExistsAndIsActive, key known to be RSA", true, _.keyExistsAndIsActive(HostedKey)),
  )

  private val Nowhere = Seq[State](Missing, Missing, Missing)

  "a lookup of a hosted key that no cosigner has" should {

    "leave the sign rotation as it was: each cosigner still starts every third sign" in {
      for (lookup <- lookups) withClue(s"${lookup.name}: ") {
        withCluster(Nowhere, lookup.learnRsa) { (backend, nodes) =>
          intercept[Exception](await(lookup.run(backend)))
          signs(backend, nodes, 6) shouldBe Seq(2, 2, 2)
        }
      }
    }

    "leave it so when the caller repeats the lookup between the signs" in {
      for (lookup <- lookups) withClue(s"${lookup.name}: ") {
        withCluster(Nowhere, lookup.learnRsa) { (backend, nodes) =>
          val perRound = (1 to 6).map { _ =>
            intercept[Exception](await(lookup.run(backend)))
            signs(backend, nodes, 1)
          }
          perRound.transpose.map(_.sum) shouldBe Seq(2, 2, 2)
        }
      }
    }
  }

  "keyExistsAndIsActive for a pinned FROST key that every cosigner answers with NOT_FOUND" should {

    "leave the sign rotation as it was" in {
      withCluster(Nowhere) { (backend, nodes) =>
        nodes.foreach(_.frostKeyMissing = true)
        val thrown = intercept[StatusRuntimeException](await(backend.keyExistsAndIsActive(FrostKey)))
        thrown.getStatus.getCode shouldBe Status.Code.NOT_FOUND
        signs(backend, nodes, 6) shouldBe Seq(2, 2, 2)
      }
    }
  }

  "keyExistsAndIsActive for a FROST key the driver has not pinned" should {

    "leave the sign rotation as it was when no cosigner has the key" in {
      withCluster(Nowhere, pin = false) { (backend, nodes) =>
        nodes.foreach(_.frostKeyMissing = true)
        val thrown = intercept[StatusRuntimeException](await(backend.keyExistsAndIsActive(FrostKey)))
        thrown.getStatus.getCode shouldBe Status.Code.NOT_FOUND
        nodes.foreach(_.frostKeyMissing = false)
        signs(backend, nodes, 6) shouldBe Seq(2, 2, 2)
      }
    }

    "change neither the lead nor any cosigner's standing when a cosigner answers after others said NOT_FOUND" in {
      // The answer for a key that is not pinned is not checked against anything, so it decides
      // nothing: one cosigner's lone answer, or two cosigners' after the first lacks the key.
      for (lacking <- Seq(Set(0, 1), Set(0))) withClue(s"cosigners $lacking answer NOT_FOUND: ") {
        withCluster(Seq(Holds, Holds, Holds), pin = false) { (backend, nodes) =>
          lacking.foreach(i => nodes(i).frostKeyMissing = true)
          await(backend.keyExistsAndIsActive(FrostKey))

          // The lead is where it was: the next call that starts at the preferred leader asks the
          // first cosigner.
          val before = nodes.map(_.hostedCalls.get)
          await(backend.encryptSymmetric(Data, HostedKey)) shouldBe Data
          nodes.map(_.hostedCalls.get).zip(before).map { case (now, prev) => now - prev } shouldBe Seq(1, 0, 0)

          // And no cosigner lost its place in the rotation.
          nodes.foreach(_.frostKeyMissing = false)
          signs(backend, nodes, 6) shouldBe Seq(2, 2, 2)
        }
      }
    }
  }

  "a cosigner that lacks a hosted key another cosigner serves" should {

    "lose the lead: it is not a sign start until leader-recovery has passed" in {
      for (lookup <- lookups) withClue(s"${lookup.name}: ") {
        withCluster(Seq(Missing, Holds, Holds), lookup.learnRsa) { (backend, nodes) =>
          await(lookup.run(backend))
          // Turns 0 and 3 would start at the first cosigner; they go to the next healthy one.
          signs(backend, nodes, 6) shouldBe Seq(0, 4, 2)
        }
      }
    }
  }

  "a lookup served after a cosigner without the key that sits between two sick ones (five cosigners)" should {

    "give the lead to the cosigner that served, not to the sick one after the cosigner without the key" in {
      val sick: State = Failing(Status.INTERNAL.withDescription("key store unreadable"))
      for (lookup <- lookups) withClue(s"${lookup.name}: ") {
        withCluster(Seq(sick, Missing, sick, Holds, Holds), lookup.learnRsa) { (backend, nodes) =>
          await(lookup.run(backend))
          // Everything is healthy again; the next call starts at the preferred leader.
          nodes.foreach(_.hosted = Holds)
          val before = nodes.map(_.hostedCalls.get)
          await(lookup.run(backend))
          nodes.map(_.hostedCalls.get).zip(before).map { case (now, prev) => now - prev } shouldBe Seq(0, 0, 0, 1, 0)
        }
      }
    }
  }

  "a lookup that ends retryable because two cosigners could not be reached" should {

    "take the lead from the unreachable cosigners only, not from the one that said \"not found\"" in {
      val down: State = Failing(Status.UNAVAILABLE)
      for (lookup <- lookups) withClue(s"${lookup.name}: ") {
        withCluster(Seq(Missing, down, down), lookup.learnRsa) { (backend, nodes) =>
          val thrown = intercept[StatusRuntimeException](await(lookup.run(backend)))
          thrown.getStatus.getCode shouldBe Status.Code.UNAVAILABLE
          // The first cosigner is the only one still healthy for the rotation: every sign starts there.
          signs(backend, nodes, 6) shouldBe Seq(6, 0, 0)
        }
      }
    }
  }
}
