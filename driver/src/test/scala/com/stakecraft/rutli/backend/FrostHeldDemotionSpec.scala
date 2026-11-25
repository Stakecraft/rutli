// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli.backend

import com.digitalasset.canton.crypto.kms.driver.api.v1._
import com.google.protobuf.ByteString
import com.stakecraft.rutli.grpc._
import io.grpc.Status
import io.grpc.inprocess.{InProcessChannelBuilder, InProcessServerBuilder}
import io.grpc.stub.StreamObserver
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import org.slf4j.LoggerFactory

import java.security.{KeyPair, KeyPairGenerator, Signature}
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.{CountDownLatch, TimeUnit}
import scala.concurrent.duration._
import scala.concurrent.{Await, ExecutionContext, Future}

/** A cosigner that says it lacks a key loses the lead only when a later cosigner serves the call.
  * That demotion is as old as the cosigner's answer, and the call may end much later. It must be
  * applied as what it is: it does not move a lead that another call has moved in the meantime, and
  * the time it records is the time of the answer.
  *
  * Three cosigners. A hosted-key call is held at one of them while something else happens.
  */
class FrostHeldDemotionSpec extends AnyWordSpec with Matchers {

  import FrostHeldDemotionSpec._

  private implicit val ec: ExecutionContext = ExecutionContext.global
  private val logger = LoggerFactory.getLogger(classOf[FrostHeldDemotionSpec])
  private def await[T](f: Future[T]): T = Await.result(f, 10.seconds)

  private val FrostKey = "frost-ns"
  private val HostedKey = "rutli-sym-0001"
  private val Digest: Array[Byte] = Array.fill(34)(7.toByte)
  private val Data: Array[Byte] = "payload".getBytes

  private val Group: KeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
  private def groupSign(msg: Array[Byte]): Array[Byte] = {
    val s = Signature.getInstance("Ed25519")
    s.initSign(Group.getPrivate)
    s.update(msg)
    s.sign()
  }

  /** One cosigner. It answers the group key always. A sign it serves, unless `signs` is off
    * (UNAVAILABLE). A hosted-key call it serves, or answers NOT_FOUND when it does not hold the
    * key; with a `pause` it first says that the call has arrived and waits to be let go. */
  private final class Node extends SignerGrpc.SignerImplBase {
    val name: String = s"held-${InProcessServerBuilder.generateName()}"
    val signCalls, hostedCalls = new AtomicInteger
    @volatile var holdsKey: Boolean = true
    @volatile var signs: Boolean = true
    @volatile var pause: Option[Pause] = None

    override def groupKey(req: GroupKeyRequest, obs: StreamObserver[GroupKeyReply]): Unit = {
      obs.onNext(
        GroupKeyReply.newBuilder().setGroupVerifyingKey(ByteString.copyFrom(Group.getPublic.getEncoded.takeRight(32))).build()
      )
      obs.onCompleted()
    }

    override def sign(req: SignRequest, obs: StreamObserver[SignReply]): Unit = {
      signCalls.incrementAndGet()
      if (signs) {
        obs.onNext(SignReply.newBuilder().setSignature(ByteString.copyFrom(groupSign(req.getMessage.toByteArray))).build())
        obs.onCompleted()
      } else obs.onError(Status.UNAVAILABLE.withDescription("test: down").asRuntimeException())
    }

    override def symmetricEncrypt(req: SymmetricRequest, obs: StreamObserver[SymmetricReply]): Unit = {
      hostedCalls.incrementAndGet()
      pause.foreach(_.hold())
      if (holdsKey) {
        obs.onNext(SymmetricReply.newBuilder().setData(req.getData).build())
        obs.onCompleted()
      } else obs.onError(Status.NOT_FOUND.withDescription("no such key").asRuntimeException())
    }
  }

  /** Three cosigners and a backend over them, with the FROST key pinned (no sign turn is used). */
  private def withCluster[A](rotate: Boolean, recovery: FiniteDuration = 60.seconds)(
      body: (FrostBackend, IndexedSeq[Node]) => A
  ): A = {
    val nodes = (0 until 3).map(_ => new Node)
    val servers = nodes.map(node => InProcessServerBuilder.forName(node.name).directExecutor().addService(node).build().start())
    val backend =
      new FrostBackend(
        nodes.map(_.name),
        new NoDelegateBackend,
        logger,
        None,
        10.seconds,
        hostedKeys = true,
        leaderRecovery = recovery,
        rotateSigns = rotate,
      ) {
        override protected def buildChannel(endpoint: String): io.grpc.ManagedChannel =
          InProcessChannelBuilder.forName(endpoint).directExecutor().build()
      }
    try {
      await(backend.getPublicKey(FrostKey))
      body(backend, nodes)
    } finally {
      nodes.foreach(_.pause.foreach(_.letGo())) // a call still held would keep its thread
      backend.close()
      servers.foreach(_.shutdownNow())
    }
  }

  private def lookup(backend: FrostBackend): Future[Array[Byte]] = backend.encryptSymmetric(Data, HostedKey)
  private def sign(backend: FrostBackend): Array[Byte] = await(backend.sign(Digest, FrostKey, SigningAlgoSpec.Ed25519))

  "a demotion held back until the call is served" should {

    "leave the lead where a newer call has put it" in {
      withCluster(rotate = false) { (backend, nodes) =>
        // A lookup: the first two cosigners lack the key, the third holds it and takes its time.
        nodes(0).holdsKey = false
        nodes(1).holdsKey = false
        val pause = new Pause
        nodes(2).pause = Some(pause)
        val held = lookup(backend)
        pause.arrived() shouldBe true

        // Meanwhile a sign finds the first cosigner unreachable and is signed by the second: the
        // lead is the second's, and that is newer than what the lookup heard from either.
        nodes(0).signs = false
        sign(backend) shouldBe groupSign(Digest)
        nodes.map(_.signCalls.get) shouldBe Seq(1, 1, 0)

        pause.letGo()
        await(held) shouldBe Data

        // The lookup's two demotions did not move it: the next hosted call starts at the second.
        nodes(2).pause = None
        nodes.foreach(_.holdsKey = true)
        val before = nodes.map(_.hostedCalls.get)
        await(lookup(backend)) shouldBe Data
        nodes.map(_.hostedCalls.get).zip(before).map { case (now, prev) => now - prev } shouldBe Seq(0, 1, 0)
      }
    }

    "be dated from the cosigner's answer, not from the end of the call" in {
      val recovery = 1.second
      withCluster(rotate = true, recovery = recovery) { (backend, nodes) =>
        // The first cosigner says "not found" at once; the second serves, but only after longer
        // than leader-recovery.
        nodes(0).holdsKey = false
        val pause = new Pause
        nodes(1).pause = Some(pause)
        val held = lookup(backend)
        pause.arrived() shouldBe true
        Thread.sleep(recovery.toMillis + 200)
        pause.letGo()
        await(held) shouldBe Data

        // The first lost the lead to the second. Its answer is older than leader-recovery by now,
        // so it is a sign start again: each cosigner starts one of three signs.
        (1 to 3).foreach(_ => sign(backend) shouldBe groupSign(Digest))
        nodes.map(_.signCalls.get) shouldBe Seq(1, 1, 1)
      }
    }
  }
}

object FrostHeldDemotionSpec {

  /** Where a test holds a cosigner's answer: the cosigner says the call has arrived and waits. */
  final class Pause {
    private val in = new CountDownLatch(1)
    private val out = new CountDownLatch(1)

    /** Called by the cosigner, in the call. */
    def hold(): Unit = {
      in.countDown()
      out.await(10, TimeUnit.SECONDS)
      ()
    }

    /** Whether the call has arrived at the cosigner (waits for it). */
    def arrived(): Boolean = in.await(10, TimeUnit.SECONDS)

    def letGo(): Unit = out.countDown()
  }
}
