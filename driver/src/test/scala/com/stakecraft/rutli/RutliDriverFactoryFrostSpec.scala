// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli

import com.digitalasset.canton.crypto.kms.driver.api.v1._
import com.google.protobuf.ByteString
import com.stakecraft.rutli.audit.HashChainedAuditLog
import com.stakecraft.rutli.backend.{FrostBackend, GroupKeyPin, GroupKeyPinStore, PinAudit}
import com.stakecraft.rutli.grpc._
import io.grpc.Server
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder
import io.grpc.stub.StreamObserver
import io.opentelemetry.context.Context
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import org.slf4j.LoggerFactory
import pureconfig.ConfigSource

import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, Path}
import java.security.{KeyPair, KeyPairGenerator, Signature}
import java.util.concurrent.atomic.AtomicInteger
import scala.concurrent.duration._
import scala.concurrent.{Await, ExecutionContext, Future}
import scala.jdk.CollectionConverters._

/** A FROST driver built the way Canton builds it: the `config { ... }` text through the factory's
  * reader, then `create`. What the backend does with a pin store, a set of lost pins or a leader
  * mode is tested on the backend itself; here it is the factory's wiring of them — the pin store
  * checked against the audit log at start, every new pin written to the audit log, the config
  * values that reach the backend, and the configs the factory refuses.
  *
  * The cosigners are plaintext gRPC servers on localhost, since the factory dials real addresses.
  */
class RutliDriverFactoryFrostSpec extends AnyWordSpec with Matchers {

  private val ec: ExecutionContext = ExecutionContext.global
  private val logger = LoggerFactory.getLogger(classOf[RutliDriverFactoryFrostSpec])
  private val factory = new RutliDriverFactory
  private val ctx = Context.root()
  private def await[T](f: Future[T]): T = Await.result(f, 30.seconds)

  private def keyPair(): KeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
  private def raw(kp: KeyPair): Array[Byte] = kp.getPublic.getEncoded.takeRight(32)
  private def hex(b: Array[Byte]): String = b.map("%02x".format(_)).mkString
  private def chain(t: Throwable): String =
    Iterator.iterate[Throwable](t)(_.getCause).takeWhile(_ != null).map(_.getMessage).mkString(" | ")

  private val Key = "frost-ns"
  private val Digest: Array[Byte] = Array.fill(34)(3.toByte)

  /** One cosigner: answers the group key and signs with it, counting the signs it was asked for. */
  private final class Node(kp: KeyPair) extends SignerGrpc.SignerImplBase {
    val signCalls = new AtomicInteger
    override def groupKey(req: GroupKeyRequest, obs: StreamObserver[GroupKeyReply]): Unit = {
      obs.onNext(GroupKeyReply.newBuilder().setGroupVerifyingKey(ByteString.copyFrom(raw(kp))).build())
      obs.onCompleted()
    }
    override def sign(req: SignRequest, obs: StreamObserver[SignReply]): Unit = {
      signCalls.incrementAndGet()
      val s = Signature.getInstance("Ed25519")
      s.initSign(kp.getPrivate)
      s.update(req.getMessage.toByteArray)
      obs.onNext(SignReply.newBuilder().setSignature(ByteString.copyFrom(s.sign())).build())
      obs.onCompleted()
    }
  }

  /** Three cosigners holding `kp`, and their addresses in roster order. */
  private def withCluster[A](kp: KeyPair)(body: (IndexedSeq[Node], Seq[String]) => A): A = {
    val nodes = (0 until 3).map(_ => new Node(kp))
    val servers: Seq[Server] = nodes.map(n => NettyServerBuilder.forPort(0).addService(n).build().start())
    try body(nodes, servers.map(s => "localhost:" + s.getPort))
    finally servers.foreach(_.shutdownNow())
  }

  private def quoted(s: String): String = "\"" + s + "\""

  private def auditPath(dir: Path): String = dir.resolve("audit.jsonl").toString
  private def pinDir(dir: Path): Path = dir.resolve("pins")

  /** The driver config: FROST over `eps`, the software delegate, and under `dir` the audit log and
    * the pin directory. `frostExtra` is appended inside the frost block. */
  private def frostConfig(eps: Seq[String], dir: Path, frostExtra: String = ""): String =
    "backend = \"frost\"\n" +
      "audit-log-path = " + quoted(auditPath(dir)) + "\n" +
      "frost {\n" +
      "  endpoints = [" + eps.map(quoted).mkString(", ") + "]\n" +
      "  delegate = \"software\"\n" +
      "  pin-dir = " + quoted(pinDir(dir).toString) + "\n" +
      "  " + frostExtra + "\n" +
      "}\n"

  private def parse(hocon: String): RutliConfig = {
    implicit val reader: pureconfig.ConfigReader[RutliConfig] = factory.configReader
    ConfigSource.string(hocon).load[RutliConfig] match {
      case Right(c)  => c
      case Left(err) => fail(s"config did not parse: ${err.prettyPrint()}")
    }
  }

  private def create(hocon: String): RutliDriver =
    factory.create(parse(hocon), (c: Class[_]) => LoggerFactory.getLogger(c), ec)

  private def withDriver[A](hocon: String)(body: RutliDriver => A): A = {
    val driver = create(hocon)
    try body(driver)
    finally driver.close()
  }

  private def tempDir(): Path = Files.createTempDirectory("rutli-factory-frost")

  private def pinEntries(dir: Path): List[String] = HashChainedAuditLog.details(auditPath(dir), PinAudit.Op)

  /** The operations in the audit log, in file order. */
  private def auditOps(dir: Path): List[String] = {
    val op = "\"op\":\"([^\"]*)\"".r
    Files.readAllLines(dir.resolve("audit.jsonl")).asScala.toList.flatMap(l => op.findFirstMatchIn(l).map(_.group(1)))
  }

  "a FROST driver built by the factory" should {

    "write a first pin to the pin directory and to the audit log, before the key is served" in {
      val kp = keyPair()
      val dir = tempDir()
      withCluster(kp) { (_, eps) =>
        withDriver(frostConfig(eps, dir)) { driver =>
          val pk = await(driver.getPublicKey(Key)(ctx))
          pk.spec shouldBe SigningKeySpec.EcCurve25519
          pk.key.takeRight(32) shouldBe raw(kp)
        }
        val pin = new GroupKeyPinStore(pinDir(dir), logger).get(Key).get
        pin.groupKeyHex shouldBe hex(raw(kp))
        pin.source shouldBe "adopted"
        pin.agreedBy.toSet shouldBe eps.toSet

        val entry = pinEntries(dir) match {
          case List(one) => one
          case other     => fail(s"expected one group-key-pin entry, got $other")
        }
        entry should (include(s"keyId=$Key") and include(s"groupKey=${hex(raw(kp))}") and include("source=adopted"))
        entry should not include "recovered="
        // The pin's entry comes before the entry of the call that returned the key.
        auditOps(dir) shouldBe List(PinAudit.Op, "getPublicKey")
        HashChainedAuditLog.verify(auditPath(dir)) shouldBe Right(2L)
      }
    }

    "refuse a key after a restart when its pin file is gone, without asking any cosigner to sign" in {
      val kp = keyPair()
      val dir = tempDir()
      withCluster(kp) { (nodes, eps) =>
        withDriver(frostConfig(eps, dir))(driver => await(driver.getPublicKey(Key)(ctx)))
        Files.delete(pinDir(dir).resolve(Key + ".pin"))

        withDriver(frostConfig(eps, dir)) { driver =>
          val exists = the[KmsDriverException] thrownBy await(driver.keyExistsAndIsActive(Key)(ctx))
          exists.retryable shouldBe false
          chain(exists) should include("pin file is missing")

          val public = the[KmsDriverException] thrownBy await(driver.getPublicKey(Key)(ctx))
          public.retryable shouldBe false
          chain(public) should include("pin file is missing")

          val sign = the[KmsDriverException] thrownBy await(driver.sign(Digest, Key, SigningAlgoSpec.Ed25519)(ctx))
          sign.retryable shouldBe false
          chain(sign) should include("pin file is missing")
          nodes.map(_.signCalls.get).sum shouldBe 0
        }
        // Nothing was pinned again behind the operator's back.
        Files.exists(pinDir(dir).resolve(Key + ".pin")) shouldBe false
        pinEntries(dir).size shouldBe 1

        // The operator's anchor (frost.expected-group-keys) is the way back: the key is served
        // again, pinned as operator-anchored, and that pin is recorded too.
        val anchored = frostConfig(eps, dir, "expected-group-keys { " + quoted(Key) + " = " + quoted(hex(raw(kp))) + " }")
        withDriver(anchored) { driver =>
          await(driver.getPublicKey(Key)(ctx)).key.takeRight(32) shouldBe raw(kp)
        }
        new GroupKeyPinStore(pinDir(dir), logger).get(Key).map(_.source) shouldBe Some("operator")
        pinEntries(dir).size shouldBe 2
        pinEntries(dir).last should include("source=operator")
      }
    }

    "not treat a pin moved to retired/ as lost" in {
      val kp = keyPair()
      val dir = tempDir()
      withCluster(kp) { (_, eps) =>
        withDriver(frostConfig(eps, dir))(driver => await(driver.getPublicKey(Key)(ctx)))
        val retired = Files.createDirectories(pinDir(dir).resolve("retired"))
        Files.move(pinDir(dir).resolve(Key + ".pin"), retired.resolve(Key + ".pin"))

        withDriver(frostConfig(eps, dir)) { driver =>
          await(driver.getPublicKey(Key)(ctx)).key.takeRight(32) shouldBe raw(kp)
        }
        Files.exists(pinDir(dir).resolve(Key + ".pin")) shouldBe true
      }
    }

    "refuse to start when a pin file names another key than the audit log records" in {
      val kp = keyPair()
      val dir = tempDir()
      withCluster(kp) { (_, eps) =>
        withDriver(frostConfig(eps, dir))(driver => await(driver.getPublicKey(Key)(ctx)))
        // A well-formed pin file (its checksum is right) for another group key: only the audit log
        // can tell that it was rewritten.
        val forged = GroupKeyPin(Key, hex(raw(keyPair())), "adopted", eps.toList, Nil, "2026-11-20T12:00:00Z")
        Files.write(pinDir(dir).resolve(Key + ".pin"), GroupKeyPinStore.render(forged).getBytes(UTF_8))

        val ex = the[IllegalStateException] thrownBy create(frostConfig(eps, dir))
        ex.getMessage should (include(Key) and include("name another key") and include("refuses to start"))
      }
    }

    "record at start a pin the audit log lacks, once" in {
      val kp = keyPair()
      val dir = tempDir()
      // A crash between the pin file and its audit entry: the file is there, the entry is not.
      new GroupKeyPinStore(pinDir(dir), logger)
        .create(GroupKeyPin(Key, hex(raw(kp)), "dkg", List("c1:9101", "c2:9101"), Nil, "2026-11-20T12:00:00Z"))
      withCluster(kp) { (_, eps) =>
        withDriver(frostConfig(eps, dir))(_ => ())
        val entry = pinEntries(dir) match {
          case List(one) => one
          case other     => fail(s"expected one group-key-pin entry, got $other")
        }
        entry should (include(s"keyId=$Key") and include(s"groupKey=${hex(raw(kp))}") and include("source=dkg"))
        entry should include("recovered=startup")

        // The next start finds it recorded and adds nothing.
        withDriver(frostConfig(eps, dir))(_ => ())
        pinEntries(dir).size shouldBe 1
        HashChainedAuditLog.verify(auditPath(dir)) shouldBe Right(1L)
      }
    }
  }

  "frost.sign-leader, as configured" should {

    def signsPerNode(leader: String): Seq[Int] = {
      val kp = keyPair()
      withCluster(kp) { (nodes, eps) =>
        withDriver(frostConfig(eps, tempDir(), leader)) { driver =>
          (1 to 6).foreach(_ => await(driver.sign(Digest, Key, SigningAlgoSpec.Ed25519)(ctx)).length shouldBe 64)
        }
        nodes.map(_.signCalls.get)
      }
    }

    "keep every sign on the first cosigner for sticky" in {
      signsPerNode("sign-leader = \"sticky\"") shouldBe Seq(6, 0, 0)
    }

    "start each sign at the next cosigner in turn for rotate, whatever its case" in {
      signsPerNode("sign-leader = \"rotate\"") shouldBe Seq(2, 2, 2)
      signsPerNode("sign-leader = \" Rotate \"") shouldBe Seq(2, 2, 2)
    }

    "use the documented default when it is not set" in {
      signsPerNode("") shouldBe (if (FrostBackend.DefaultRotateSigns) Seq(2, 2, 2) else Seq(6, 0, 0))
    }
  }

  "the factory" should {

    /** `create` must refuse `hocon` with an IllegalArgumentException whose message has `expected`. */
    def refused(hocon: String, expected: String): Unit = {
      val ex = the[IllegalArgumentException] thrownBy create(hocon)
      ex.getMessage should include(expected)
      ()
    }
    def frost(body: String): String = "backend = \"frost\"\nfrost { " + body + " }\n"

    "refuse a frost backend without a frost block or without endpoints" in {
      refused("backend = \"frost\"\n", "requires a `frost { ... }` block")
      refused(frost("delegate = \"software\""), "requires `endpoint` or `endpoints`")
    }

    "refuse delegate = none without hosted keys, an hsm delegate without an hsm block, and an unknown delegate" in {
      refused(frost("endpoint = \"localhost:1\", delegate = \"none\""), "requires frost.hosted-keys = true")
      refused(frost("endpoint = \"localhost:1\""), "hsm backend requires an `hsm { ... }` config block")
      refused(frost("endpoint = \"localhost:1\", delegate = \"vault\""), "unsupported backend 'vault'")
    }

    "refuse an attempt deadline longer than the request timeout" in {
      val message = "must not exceed frost.request-timeout"
      refused(
        frost("endpoint = \"localhost:1\", delegate = \"software\", request-timeout = 12s, sign-attempt-timeout = 13s"),
        message
      )
      refused(frost("endpoint = \"localhost:1\", delegate = \"software\", request-timeout = 8s, attempt-timeout = 10s"), message)
    }

    "refuse a sign-leader or sign-intents value it does not know" in {
      refused(
        frost("endpoint = \"localhost:1\", delegate = \"software\", sign-leader = \"round-robin\""),
        "frost.sign-leader must be rotate or sticky",
      )
      refused(
        frost("endpoint = \"localhost:1\", delegate = \"software\", sign-intents = \"maybe\""),
        "frost.sign-intents must be on or off",
      )
    }
  }
}
