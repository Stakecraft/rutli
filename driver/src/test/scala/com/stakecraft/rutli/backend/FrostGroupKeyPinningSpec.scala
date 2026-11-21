// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli.backend

import com.digitalasset.canton.crypto.kms.driver.api.v1._
import com.google.protobuf.ByteString
import com.stakecraft.rutli.audit.AuditNotes
import com.stakecraft.rutli.grpc._
import io.grpc.Status
import io.grpc.inprocess.{InProcessChannelBuilder, InProcessServerBuilder}
import io.grpc.stub.StreamObserver
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import org.slf4j.LoggerFactory

import java.security.{KeyPair, KeyPairGenerator, Signature}
import scala.concurrent.duration._
import scala.concurrent.{Await, ExecutionContext, Future}

/** Audit H2: the driver trusts no single cosigner for the group key, and releases no signature the
  * agreed key does not verify. Fake cosigners may lie about either. */
class FrostGroupKeyPinningSpec extends AnyWordSpec with Matchers {

  private implicit val ec: ExecutionContext = ExecutionContext.global
  private val logger = LoggerFactory.getLogger(classOf[FrostGroupKeyPinningSpec])
  private def await[T](f: Future[T]): T = Await.result(f, 10.seconds)

  private def keyPair(): KeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
  private def raw(kp: KeyPair): Array[Byte] = kp.getPublic.getEncoded.takeRight(32)
  private def signWith(kp: KeyPair, msg: Array[Byte]): Array[Byte] = {
    val s = Signature.getInstance("Ed25519")
    s.initSign(kp.getPrivate); s.update(msg); s.sign()
  }
  private def chain(t: Throwable): String =
    Iterator.iterate[Throwable](t)(_.getCause).takeWhile(_ != null).map(_.getMessage).mkString(" | ")

  private val Msg = Array.fill(34)(5.toByte)

  /** One fake cosigner that may lie: its group key, DKG reply and signatures are all switchable. */
  private final class Fake(var groupKey: Array[Byte], honest: KeyPair) extends SignerGrpc.SignerImplBase {
    val name: String = s"cosigner-${InProcessServerBuilder.generateName()}"
    @volatile var down = false
    @volatile var notFound = false
    val dkgCalls = new java.util.concurrent.atomic.AtomicInteger
    @volatile var dkgKey: Array[Byte] = groupKey
    @volatile var signer: Array[Byte] => Array[Byte] = signWith(honest, _)

    val groupKeyCalls = new java.util.concurrent.atomic.AtomicInteger
    override def groupKey(req: GroupKeyRequest, obs: StreamObserver[GroupKeyReply]): Unit = {
      groupKeyCalls.incrementAndGet()
      answerGroupKey(obs)
    }
    private def answerGroupKey(obs: StreamObserver[GroupKeyReply]): Unit =
      if (down) obs.onError(Status.UNAVAILABLE.asRuntimeException())
      else if (notFound) obs.onError(Status.NOT_FOUND.asRuntimeException())
      else { obs.onNext(GroupKeyReply.newBuilder().setGroupVerifyingKey(ByteString.copyFrom(groupKey)).build()); obs.onCompleted() }

    override def dkg(req: DkgRequest, obs: StreamObserver[DkgReply]): Unit = {
      dkgCalls.incrementAndGet()
      obs.onNext(DkgReply.newBuilder().setGroupVerifyingKey(ByteString.copyFrom(dkgKey)).build()); obs.onCompleted()
    }

    val signCalls = new java.util.concurrent.atomic.AtomicInteger
    override def sign(req: SignRequest, obs: StreamObserver[SignReply]): Unit = {
      signCalls.incrementAndGet()
      obs.onNext(SignReply.newBuilder().setSignature(ByteString.copyFrom(signer(req.getMessage.toByteArray))).build())
      obs.onCompleted()
    }
  }

  private def withCluster[A](
      fakes: Seq[Fake],
      pinDir: Option[java.nio.file.Path] = None,
      named: Boolean = false,
      expected: Map[String, String] = Map.empty,
      lostPins: Set[String] = Set.empty,
      pinned: GroupKeyPin => Unit = _ => (),
      rotate: Boolean = false,
  )(body: FrostBackend => A): A = {
    val servers = fakes.map(f => InProcessServerBuilder.forName(f.name).directExecutor().addService(f).build().start())
    val names: Map[String, String] = if (named) fakes.zipWithIndex.map { case (f, i) => f.name -> s"cosigner${i + 1}" }.toMap else Map.empty
    val store = pinDir.map(d => new GroupKeyPinStore(d, logger))
    val backend =
      try
        new FrostBackend(
          fakes.map(_.name),
          new NoDelegateBackend,
          logger,
          None,
          10.seconds,
          endpointTlsNames = names,
          pinStore = store,
          expectedGroupKeys = expected,
          lostPins = lostPins,
          onPin = pinned,
          rotateSigns = rotate,
        ) {
          override protected def buildChannel(endpoint: String): io.grpc.ManagedChannel =
            InProcessChannelBuilder.forName(endpoint).directExecutor().build()
        }
      catch { case e: Throwable => servers.foreach(_.shutdownNow()); throw e }
    try body(backend)
    finally { backend.close(); servers.foreach(_.shutdownNow()) }
  }

  private def tempDir(): java.nio.file.Path = java.nio.file.Files.createTempDirectory("rutli-pins")
  private def hex(b: Array[Byte]): String = b.map("%02x".format(_)).mkString

  private def honestCluster(n: Int, kp: KeyPair = keyPair()): Seq[Fake] = Seq.fill(n)(new Fake(raw(kp), kp))

  "FrostBackend.getPublicKey" should {

    "return the key when every cosigner agrees" in {
      val kp = keyPair()
      withCluster(honestCluster(3, kp)) { b =>
        val pk = await(b.getPublicKey("frost-ns"))
        pk.spec shouldBe SigningKeySpec.EcCurve25519
        pk.key.takeRight(32) shouldBe raw(kp)
      }
    }

    "fail hard, naming the endpoints, when endpoint 0 answers a different key than 1 and 2" in {
      val kp = keyPair()
      val fakes = honestCluster(3, kp)
      fakes.head.groupKey = raw(keyPair()) // a compromised cosigner swapping in its own key
      withCluster(fakes) { b =>
        val ex = the[KmsDriverException] thrownBy await(b.getPublicKey("frost-ns"))
        ex.retryable shouldBe false
        fakes.foreach(f => chain(ex) should include(f.name))
        chain(ex) should include("disagree")
      }
    }

    "treat a single dissenter as an error even when the majority agree" in {
      val kp = keyPair()
      val fakes = honestCluster(3, kp)
      fakes(2).groupKey = raw(keyPair())
      withCluster(fakes)(b => the[KmsDriverException] thrownBy await(b.getPublicKey("frost-ns")))
    }

    "need two identical answers: one lone answering cosigner of three is not believed" in {
      val fakes = honestCluster(3)
      fakes(1).down = true; fakes(2).down = true
      withCluster(fakes) { b =>
        val ex = the[KmsDriverException] thrownBy await(b.getPublicKey("frost-ns"))
        ex.retryable shouldBe true // availability, not trust
        chain(ex) should include("1 of 3")
      }
    }

    "accept two identical answers when the third cosigner is down" in {
      val fakes = honestCluster(3)
      fakes(2).down = true
      withCluster(fakes)(b => await(b.getPublicKey("frost-ns")).spec shouldBe SigningKeySpec.EcCurve25519)
    }

    "accept a single answer only for a single-endpoint (dev) roster" in {
      withCluster(honestCluster(1))(b => await(b.getPublicKey("frost-ns")).spec shouldBe SigningKeySpec.EcCurve25519)
    }

    "pin the key, serve the pin past one cosigner that later answers differently, and fail when all do" in {
      val fakes = honestCluster(3)
      withCluster(fakes) { b =>
        val first = await(b.getPublicKey("frost-ns"))
        fakes(1).groupKey = raw(keyPair()) // swapped after the pin: reported and routed around
        await(b.getPublicKey("frost-ns")).key shouldBe first.key
        val other = raw(keyPair())
        fakes.foreach(_.groupKey = other) // every answer differs from the pin: never re-pinned
        val ex = the[KmsDriverException] thrownBy await(b.getPublicKey("frost-ns"))
        ex.retryable shouldBe false
        chain(ex) should include("pinned")
        // ...and a restored cluster is served from the pin again.
        fakes.foreach(_.groupKey = first.key.takeRight(32))
        await(b.getPublicKey("frost-ns")).key shouldBe first.key
      }
    }

    "keep serving the pin while the cluster is unreachable" in {
      val fakes = honestCluster(3)
      withCluster(fakes) { b =>
        val first = await(b.getPublicKey("frost-ns"))
        fakes.foreach(_.down = true)
        await(b.getPublicKey("frost-ns")).key shouldBe first.key
      }
    }

    "refuse a group key that is not a valid Ed25519 point" in {
      val bad = Array.fill(32)(0.toByte) // the identity-adjacent small-order encoding family
      bad(0) = 1 // y = 1: the identity point, small order
      val fakes = Seq.fill(3)(new Fake(bad, keyPair()))
      withCluster(fakes)(b => the[KmsDriverException] thrownBy await(b.getPublicKey("frost-ns")))
    }
  }

  "FrostBackend.sign" should {

    "return a signature that verifies against the agreed key, pinning it first" in {
      val kp = keyPair()
      withCluster(honestCluster(3, kp)) { b =>
        val sig = await(b.sign(Msg, "frost-ns", SigningAlgoSpec.Ed25519))
        sig shouldBe signWith(kp, Msg)
      }
    }

    "refuse random 64 bytes from the leader, non-retryably" in {
      val fakes = honestCluster(3)
      fakes.foreach(_.signer = _ => Array.fill(64)(9.toByte))
      withCluster(fakes) { b =>
        val ex = the[KmsDriverException] thrownBy await(b.sign(Msg, "frost-ns", SigningAlgoSpec.Ed25519))
        ex.retryable shouldBe false
        chain(ex) should include("does not verify")
      }
    }

    "refuse a perfectly valid signature made by a different key" in {
      val fakes = honestCluster(3)
      val other = keyPair()
      fakes.foreach(_.signer = signWith(other, _))
      withCluster(fakes)(b => the[KmsDriverException] thrownBy await(b.sign(Msg, "frost-ns", SigningAlgoSpec.Ed25519)))
    }

    "refuse a valid signature over a different message" in {
      val kp = keyPair()
      val fakes = honestCluster(3, kp)
      fakes.foreach(_.signer = _ => signWith(kp, "something else".getBytes))
      withCluster(fakes)(b => the[KmsDriverException] thrownBy await(b.sign(Msg, "frost-ns", SigningAlgoSpec.Ed25519)))
    }

    "be strict: refuse a malleated signature whose S is not reduced mod L" in {
      val kp = keyPair()
      val fakes = honestCluster(3, kp)
      val L = BigInt("7237005577332262213973186563042994240857116359379907606001950938285454250989")
      fakes.foreach(_.signer = { msg =>
        val sig = signWith(kp, msg)
        val s = BigInt(1, sig.slice(32, 64).reverse) + L // same point equation, non-canonical S
        val sBytes = s.toByteArray.reverse.padTo(32, 0.toByte).take(32)
        sig.take(32) ++ sBytes
      })
      withCluster(fakes)(b => the[KmsDriverException] thrownBy await(b.sign(Msg, "frost-ns", SigningAlgoSpec.Ed25519)))
    }

    "refuse to sign for a key whose cosigners disagree, without asking anyone to sign" in {
      val fakes = honestCluster(3)
      fakes.head.groupKey = raw(keyPair())
      var signed = false
      fakes.foreach { f => val honestSigner = f.signer; f.signer = { m => signed = true; honestSigner(m) } }
      withCluster(fakes) { b =>
        the[KmsDriverException] thrownBy await(b.sign(Msg, "frost-ns", SigningAlgoSpec.Ed25519))
        signed shouldBe false
      }
    }
  }

  "FrostBackend DKG" should {

    "pin the agreed key, and then verify signatures against it" in {
      val kp = keyPair()
      withCluster(honestCluster(3, kp)) { b =>
        await(b.generateSigningKeyPair(SigningKeySpec.EcCurve25519, Some("ns"))) shouldBe "frost-ns"
        // A cosigner that turns rogue after DKG cannot change what the driver trusts.
        await(b.sign(Msg, "frost-ns", SigningAlgoSpec.Ed25519)) shouldBe signWith(kp, Msg)
      }
    }

    "fail when the leader's reply key is not the key the cosigners agree on" in {
      val fakes = honestCluster(3)
      fakes.foreach(_.dkgKey = raw(keyPair()))
      withCluster(fakes) { b =>
        val ex = the[KmsDriverException] thrownBy
          await(b.generateSigningKeyPair(SigningKeySpec.EcCurve25519, Some("ns")))
        ex.retryable shouldBe false
        chain(ex) should include("leader reported")
      }
    }

    "fail when the cosigners disagree on the new key" in {
      val fakes = honestCluster(3)
      fakes(2).groupKey = raw(keyPair())
      withCluster(fakes) { b =>
        the[KmsDriverException] thrownBy await(b.generateSigningKeyPair(SigningKeySpec.EcCurve25519, Some("ns")))
      }
    }
  }

  "a durable pin (frost.pin-dir)" should {

    "survive a restart: one cosigner answering another key cannot block the pin or signing" in {
      val kp = keyPair()
      val fakes = honestCluster(3, kp)
      val dir = tempDir()
      withCluster(fakes, pinDir = Some(dir))(b => await(b.getPublicKey("frost-ns")))
      java.nio.file.Files.exists(dir.resolve("frost-ns.pin")) shouldBe true
      fakes.head.groupKey = raw(keyPair()) // a compromised cosigner, after the restart
      withCluster(fakes, pinDir = Some(dir)) { b =>
        await(b.getPublicKey("frost-ns")).key.takeRight(32) shouldBe raw(kp)
        await(b.sign(Msg, "frost-ns", SigningAlgoSpec.Ed25519)) shouldBe signWith(kp, Msg)
      }
    }

    "adopt an existing key by a roster majority when every endpoint has its own TLS name, recording the dissenter" in {
      val kp = keyPair()
      val fakes = honestCluster(3, kp)
      fakes(2).groupKey = raw(keyPair())
      val dir = tempDir()
      var audited = List.empty[GroupKeyPin]
      withCluster(fakes, pinDir = Some(dir), named = true, pinned = p => audited ::= p) { b =>
        await(b.getPublicKey("frost-ns")).key.takeRight(32) shouldBe raw(kp)
      }
      val pin = new GroupKeyPinStore(dir, logger).get("frost-ns").get
      pin.groupKeyHex shouldBe hex(raw(kp))
      pin.source shouldBe "adopted"
      pin.dissent.map(_.takeWhile(_ != '=')) shouldBe List(fakes(2).name)
      audited.map(_.keyId) shouldBe List("frost-ns")
    }

    "stay strict for a DKG: a dissenter fails it and nothing is written" in {
      val fakes = honestCluster(3)
      fakes(2).groupKey = raw(keyPair())
      val dir = tempDir()
      withCluster(fakes, pinDir = Some(dir), named = true) { b =>
        val ex = the[KmsDriverException] thrownBy await(b.generateSigningKeyPair(SigningKeySpec.EcCurve25519, Some("ns")))
        chain(ex) should include("disagree")
      }
      java.nio.file.Files.exists(dir.resolve("frost-ns.pin")) shouldBe false
    }

    "refuse a first pin that is not the operator's expected key, and record operator-anchored pins as such" in {
      val kp = keyPair()
      withCluster(honestCluster(3, kp), pinDir = Some(tempDir()), expected = Map("frost-ns" -> hex(raw(keyPair())))) { b =>
        val ex = the[KmsDriverException] thrownBy await(b.getPublicKey("frost-ns"))
        ex.retryable shouldBe false
        chain(ex) should include("expected-group-keys")
      }
      val dir = tempDir()
      withCluster(honestCluster(3, kp), pinDir = Some(dir), expected = Map("frost-ns" -> hex(raw(kp)))) { b =>
        await(b.getPublicKey("frost-ns"))
      }
      new GroupKeyPinStore(dir, logger).get("frost-ns").map(_.source) shouldBe Some("operator")
    }

    "refuse to start when the expected key contradicts the pin on disk" in {
      val kp = keyPair()
      val dir = tempDir()
      withCluster(honestCluster(3, kp), pinDir = Some(dir))(b => await(b.getPublicKey("frost-ns")))
      an[IllegalArgumentException] should be thrownBy
        withCluster(honestCluster(3, kp), pinDir = Some(dir), expected = Map("frost-ns" -> hex(raw(keyPair())))) { _ => () }
    }

    "refuse a key whose pin file was lost, until the operator anchors it" in {
      val kp = keyPair()
      withCluster(honestCluster(3, kp), pinDir = Some(tempDir()), lostPins = Set("frost-ns")) { b =>
        val ex = the[KmsDriverException] thrownBy await(b.getPublicKey("frost-ns"))
        ex.retryable shouldBe false
        chain(ex) should include("pin file is missing")
      }
      withCluster(honestCluster(3, kp), pinDir = Some(tempDir()), lostPins = Set("frost-ns"), expected = Map("frost-ns" -> hex(raw(kp)))) { b =>
        await(b.getPublicKey("frost-ns")).key.takeRight(32) shouldBe raw(kp)
      }
    }

    "fail retryably, pinning nothing, when the pin cannot be written" in {
      val dir = tempDir()
      val kp = keyPair()
      withCluster(honestCluster(3, kp), pinDir = Some(dir)) { b =>
        dir.toFile.setWritable(false)
        try {
          // A runner with root ignores directory permissions: nothing to show there.
          assume(!java.nio.file.Files.isWritable(dir), "directory permissions are not enforced for this user")
          val ex = the[KmsDriverException] thrownBy await(b.getPublicKey("frost-ns"))
          ex.retryable shouldBe true
        } finally { dir.toFile.setWritable(true); () }
        // Nothing was pinned in memory: the next call pins (and writes) normally.
        await(b.getPublicKey("frost-ns")).key.takeRight(32) shouldBe raw(kp)
      }
      java.nio.file.Files.exists(dir.resolve("frost-ns.pin")) shouldBe true
    }
  }

  "FrostBackend.keyExistsAndIsActive with a pin" should {

    "route around a cosigner that answers another key, and fail when none answers the pin" in {
      val kp = keyPair()
      val fakes = honestCluster(3, kp)
      withCluster(fakes) { b =>
        await(b.getPublicKey("frost-ns"))
        fakes.head.groupKey = raw(keyPair())
        val notes = new AuditNotes
        await(b.withAuditNotes(notes)(b.keyExistsAndIsActive("frost-ns")))
        notes.render shouldBe
          s"groupkey-dissent=${fakes(0).name} failover=${fakes(0).name}→${fakes(1).name} reason=GROUP_KEY_MISMATCH"
        val other = raw(keyPair())
        fakes.foreach(_.groupKey = other)
        val ex = the[KmsDriverException] thrownBy await(b.keyExistsAndIsActive("frost-ns"))
        ex.retryable shouldBe false
      }
    }

    "ask the next cosigner when the leader answers NOT_FOUND, and keep the key active" in {
      // The leader here never answered another key, so it is not skipped as a dissenter: its
      // NOT_FOUND is what the call meets first.
      val fakes = honestCluster(3)
      withCluster(fakes) { b =>
        await(b.getPublicKey("frost-ns"))
        val asked = fakes.map(_.groupKeyCalls.get)
        fakes.head.notFound = true
        val notes = new AuditNotes
        await(b.withAuditNotes(notes)(b.keyExistsAndIsActive("frost-ns")))
        notes.render shouldBe s"failover=${fakes(0).name}→${fakes(1).name} reason=NOT_FOUND"
        fakes.map(_.groupKeyCalls.get).zip(asked).map { case (now, before) => now - before } shouldBe Seq(1, 1, 0)

        // That cosigner lost the lead: the next check starts at the one that answered.
        await(b.keyExistsAndIsActive("frost-ns"))
        fakes.map(_.groupKeyCalls.get).zip(asked).map { case (now, before) => now - before } shouldBe Seq(1, 2, 0)
      }
    }

    "end with NOT_FOUND once every cosigner was asked and none has the key" in {
      val fakes = honestCluster(3)
      withCluster(fakes) { b =>
        await(b.getPublicKey("frost-ns"))
        val asked = fakes.map(_.groupKeyCalls.get)
        fakes.foreach(_.notFound = true)
        val err = the[io.grpc.StatusRuntimeException] thrownBy await(b.keyExistsAndIsActive("frost-ns"))
        err.getStatus.getCode shouldBe Status.Code.NOT_FOUND
        fakes.map(_.groupKeyCalls.get).zip(asked).map { case (now, before) => now - before } shouldBe Seq(1, 1, 1)
      }
    }
  }

  "the first pin of an existing key" should {

    "tolerate one dissenter, never two, even with distinct TLS names" in {
      val kp = keyPair()
      val fakes = honestCluster(5, kp)
      fakes(3).groupKey = raw(keyPair()); fakes(4).groupKey = raw(keyPair())
      withCluster(fakes, named = true) { b =>
        val ex = the[KmsDriverException] thrownBy await(b.getPublicKey("frost-ns"))
        ex.retryable shouldBe false
        chain(ex) should include("disagree")
      }
    }

    "not be used when its audit entry cannot be written, and be recorded by the next call" in {
      val kp = keyPair()
      var fail = true
      var audited = 0
      withCluster(honestCluster(3, kp), pinDir = Some(tempDir()), pinned = _ => { if (fail) throw new java.io.IOException("disk full"); audited += 1 }) { b =>
        val ex = the[KmsDriverException] thrownBy await(b.getPublicKey("frost-ns"))
        ex.retryable shouldBe true
        b.pinnedGroupKeyHex("frost-ns") shouldBe None
        fail = false
        await(b.getPublicKey("frost-ns")).key.takeRight(32) shouldBe raw(kp)
        audited shouldBe 1
      }
    }

    "be refused before a DKG when the audit log records a pin whose file is gone" in {
      val fakes = honestCluster(3)
      withCluster(fakes, pinDir = Some(tempDir()), lostPins = Set("frost-ns")) { b =>
        val ex = the[KmsDriverException] thrownBy await(b.generateSigningKeyPair(SigningKeySpec.EcCurve25519, Some("ns")))
        chain(ex) should include("pin file is missing")
        an[KmsDriverException] should be thrownBy await(b.keyExistsAndIsActive("frost-ns"))
      }
      fakes.map(_.dkgCalls.get).sum shouldBe 0 // the ceremony was never started
    }
  }

  "frost.sign-leader = rotate" should {
    "never start a sign at a cosigner that answered another group key for that key" in {
      val kp = keyPair()
      val fakes = honestCluster(3, kp)
      withCluster(fakes, rotate = true) { b =>
        await(b.getPublicKey("frost-ns"))
        fakes(1).groupKey = raw(keyPair())
        await(b.getPublicKey("frost-ns")) // reported as a dissenter for frost-ns
        (1 to 6).foreach(_ => await(b.sign(Msg, "frost-ns", SigningAlgoSpec.Ed25519)) shouldBe signWith(kp, Msg))
        fakes(1).signCalls.get shouldBe 0
        (fakes(0).signCalls.get + fakes(2).signCalls.get) shouldBe 6
      }
    }
  }
}
