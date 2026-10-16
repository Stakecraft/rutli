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
    @volatile var dkgKey: Array[Byte] = groupKey
    @volatile var signer: Array[Byte] => Array[Byte] = signWith(honest, _)

    override def groupKey(req: GroupKeyRequest, obs: StreamObserver[GroupKeyReply]): Unit =
      if (down) obs.onError(Status.UNAVAILABLE.asRuntimeException())
      else { obs.onNext(GroupKeyReply.newBuilder().setGroupVerifyingKey(ByteString.copyFrom(groupKey)).build()); obs.onCompleted() }

    override def dkg(req: DkgRequest, obs: StreamObserver[DkgReply]): Unit = {
      obs.onNext(DkgReply.newBuilder().setGroupVerifyingKey(ByteString.copyFrom(dkgKey)).build()); obs.onCompleted()
    }

    override def sign(req: SignRequest, obs: StreamObserver[SignReply]): Unit = {
      obs.onNext(SignReply.newBuilder().setSignature(ByteString.copyFrom(signer(req.getMessage.toByteArray))).build())
      obs.onCompleted()
    }
  }

  private def withCluster[A](fakes: Seq[Fake])(body: FrostBackend => A): A = {
    val servers = fakes.map(f => InProcessServerBuilder.forName(f.name).directExecutor().addService(f).build().start())
    val backend = new FrostBackend(fakes.map(_.name), new NoDelegateBackend, logger, None, 10.seconds) {
      override protected def buildChannel(endpoint: String): io.grpc.ManagedChannel =
        InProcessChannelBuilder.forName(endpoint).directExecutor().build()
    }
    try body(backend)
    finally { backend.close(); servers.foreach(_.shutdownNow()) }
  }

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

    "pin the key, and fail if a cosigner later answers differently" in {
      val fakes = honestCluster(3)
      withCluster(fakes) { b =>
        val first = await(b.getPublicKey("frost-ns"))
        fakes(1).groupKey = raw(keyPair()) // swapped after the pin
        val ex = the[KmsDriverException] thrownBy await(b.getPublicKey("frost-ns"))
        ex.retryable shouldBe false
        chain(ex) should include(fakes(1).name)
        chain(ex) should include("pinned")
        // ...and a restored cluster is served from the pin again.
        fakes(1).groupKey = fakes.head.groupKey
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
}
