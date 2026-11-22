// Copyright 2026 StakeCraft LLC
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
import io.opentelemetry.context.Context
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import org.slf4j.LoggerFactory

import java.security.{KeyPair, KeyPairGenerator, Signature}
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.{ConcurrentHashMap, ConcurrentLinkedQueue}
import scala.concurrent.duration._
import scala.concurrent.{Await, ExecutionContext, Future}
import scala.jdk.CollectionConverters._

/** Failure paths of the FROST backend that no other spec reaches: the operations that had only ever
  * met a healthy leader (symmetric crypto, KeyInfo for an RSA key, DeleteKey), an EC hosted-key call
  * that meets a sick cosigner, sign-leader rotation with no healthy endpoint, the backend's health,
  * and what goes to the delegate. Each test says which cosigner was asked, in what order, and which
  * error reached the caller.
  */
class FrostFailoverPathsSpec extends AnyWordSpec with Matchers {

  private implicit val ec: ExecutionContext = ExecutionContext.global
  private val logger = LoggerFactory.getLogger(classOf[FrostFailoverPathsSpec])
  private val ctx = Context.root()
  private def await[T](f: Future[T]): T = Await.result(f, 10.seconds)

  private val Group: KeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
  private def groupSign(msg: Array[Byte]): Array[Byte] = {
    val s = Signature.getInstance("Ed25519")
    s.initSign(Group.getPrivate)
    s.update(msg)
    s.sign()
  }

  private val Rsa = "rsa-2048-oaep-sha256"
  private val Aes = "aes-256-gcm"
  private val Ec = "ec-p256-ecies"

  private val FrostKey = "frost-ns"
  private val HostedKey = "rutli-enc-0001"
  private val Digest: Array[Byte] = Array.fill(34)(7.toByte)
  private val Data: Array[Byte] = "payload".getBytes

  /** One cosigner. Every RPC is counted and can be made to answer a status instead of serving. */
  private final class Node extends SignerGrpc.SignerImplBase {
    val name: String = s"paths-${InProcessServerBuilder.generateName()}"
    private val counters = new ConcurrentHashMap[String, AtomicInteger]()
    def calls(rpc: String): Int = Option(counters.get(rpc)).fold(0)(_.get)
    def total: Int = counters.values.asScala.map(_.get).sum

    /** RPC name -> the status it answers instead of serving. */
    @volatile var failing: Map[String, Status] = Map.empty
    @volatile var keyExists: Boolean = true
    @volatile var keySpec: String = Ec
    @volatile var healthOk: Boolean = true

    private def serve[R](rpc: String, obs: StreamObserver[R])(reply: => R): Unit = {
      counters.computeIfAbsent(rpc, _ => new AtomicInteger).incrementAndGet()
      failing.get(rpc) match {
        case Some(status) => obs.onError(status.asRuntimeException())
        case None         =>
          obs.onNext(reply)
          obs.onCompleted()
      }
    }

    override def capabilities(req: CapabilitiesRequest, obs: StreamObserver[CapabilitiesReply]): Unit =
      serve("capabilities", obs)(
        CapabilitiesReply
          .newBuilder()
          .setHostedKeysEnabled(true)
          .addHostedKeySpecs(Rsa)
          .addHostedKeySpecs(Aes)
          .addHostedKeySpecs(Ec)
          .build()
      )
    override def health(req: HealthRequest, obs: StreamObserver[HealthReply]): Unit =
      serve("health", obs)(HealthReply.newBuilder().setOk(healthOk).build())
    override def groupKey(req: GroupKeyRequest, obs: StreamObserver[GroupKeyReply]): Unit =
      serve("groupKey", obs)(
        GroupKeyReply.newBuilder().setGroupVerifyingKey(ByteString.copyFrom(Group.getPublic.getEncoded.takeRight(32))).build()
      )
    override def sign(req: SignRequest, obs: StreamObserver[SignReply]): Unit =
      serve("sign", obs)(SignReply.newBuilder().setSignature(ByteString.copyFrom(groupSign(req.getMessage.toByteArray))).build())
    override def keyInfo(req: KeyInfoRequest, obs: StreamObserver[KeyInfoReply]): Unit =
      serve("keyInfo", obs)(KeyInfoReply.newBuilder().setExists(keyExists).setSpec(keySpec).build())
    override def publicKey(req: PublicKeyRequest, obs: StreamObserver[PublicKeyReply]): Unit =
      serve("publicKey", obs)(
        PublicKeyReply.newBuilder().setSpec(keySpec).setPublicKeyDer(ByteString.copyFrom(Array[Byte](1, 2, 3))).build()
      )
    override def symmetricEncrypt(req: SymmetricRequest, obs: StreamObserver[SymmetricReply]): Unit =
      serve("symmetricEncrypt", obs)(SymmetricReply.newBuilder().setData(req.getData).build())
    override def symmetricDecrypt(req: SymmetricRequest, obs: StreamObserver[SymmetricReply]): Unit =
      serve("symmetricDecrypt", obs)(SymmetricReply.newBuilder().setData(req.getData).build())
    override def deleteKey(req: DeleteKeyRequest, obs: StreamObserver[DeleteKeyReply]): Unit =
      serve("deleteKey", obs)(DeleteKeyReply.newBuilder().setDeleted(true).build())
  }

  /** A delegate that records what reaches it and answers with fixed values. */
  private final class RecordingDelegate(healthIs: KmsDriverHealth = KmsDriverHealth.Ok) extends KmsBackend {
    val seen = new ConcurrentLinkedQueue[String]()
    private def did[A](what: String, answer: A): Future[A] = {
      seen.add(what)
      Future.successful(answer)
    }
    override val supportedSigningKeySpecs: Set[SigningKeySpec] = Set(SigningKeySpec.EcP256)
    override val supportedSigningAlgoSpecs: Set[SigningAlgoSpec] = Set(SigningAlgoSpec.EcDsaSha256)
    override val supportedEncryptionKeySpecs: Set[EncryptionKeySpec] = Set(EncryptionKeySpec.Rsa2048)
    override val supportedEncryptionAlgoSpecs: Set[EncryptionAlgoSpec] = Set(EncryptionAlgoSpec.RsaEsOaepSha256)
    override def generateSigningKeyPair(s: SigningKeySpec, n: Option[String]): Future[String] =
      did("generateSigningKeyPair", "hsm-sig")
    override def generateEncryptionKeyPair(s: EncryptionKeySpec, n: Option[String]): Future[String] =
      did("generateEncryptionKeyPair", "hsm-enc")
    override def generateSymmetricKey(n: Option[String]): Future[String] = did("generateSymmetricKey", "hsm-sym")
    override def sign(d: Array[Byte], k: String, a: SigningAlgoSpec): Future[Array[Byte]] = did(s"sign $k", d)
    override def decryptAsymmetric(c: Array[Byte], k: String, a: EncryptionAlgoSpec): Future[Array[Byte]] =
      did(s"decryptAsymmetric $k", c)
    override def encryptSymmetric(d: Array[Byte], k: String): Future[Array[Byte]] = did(s"encryptSymmetric $k", d)
    override def decryptSymmetric(c: Array[Byte], k: String): Future[Array[Byte]] = did(s"decryptSymmetric $k", c)
    override def getPublicKey(k: String): Future[PublicKey] =
      did(s"getPublicKey $k", PublicKey(Array[Byte](9), EncryptionKeySpec.Rsa2048))
    override def keyExistsAndIsActive(k: String): Future[Unit] = did(s"keyExistsAndIsActive $k", ())
    override def deleteKey(k: String): Future[Unit] = did(s"deleteKey $k", ())
    override def health: Future[KmsDriverHealth] = Future.successful(healthIs)
  }

  /** `n` cosigners and a backend whose roster lists them in order. */
  private def withCluster[A](
      n: Int,
      hostedKeys: Boolean = false,
      rotate: Boolean = false,
      delegate: KmsBackend = new NoDelegateBackend,
  )(body: (FrostBackend, IndexedSeq[Node]) => A): A = {
    val nodes = (0 until n).map(_ => new Node)
    val servers = nodes.map(node => InProcessServerBuilder.forName(node.name).directExecutor().addService(node).build().start())
    val backend =
      new FrostBackend(nodes.map(_.name), delegate, logger, None, 10.seconds, hostedKeys, rotateSigns = rotate) {
        override protected def buildChannel(endpoint: String): io.grpc.ManagedChannel =
          InProcessChannelBuilder.forName(endpoint).directExecutor().build()
      }
    try body(backend, nodes)
    finally {
      backend.close()
      servers.foreach(_.shutdownNow())
    }
  }

  /** The driver over `backend`, as Canton calls it: what it throws is what Canton sees. */
  private def driverOf(backend: FrostBackend): RutliDriver =
    new RutliDriver(
      backend,
      logger,
      auditLogging = false,
      auditLog = None,
      com.stakecraft.rutli.policy.AutoApproveGate,
      signingJournal = None,
      backend.supportedSigningKeySpecs,
      backend.supportedSigningAlgoSpecs,
      backend.supportedEncryptionKeySpecs,
      backend.supportedEncryptionAlgoSpecs,
    )

  private def code(f: => Any): Status.Code = (the[StatusRuntimeException] thrownBy f).getStatus.getCode

  private def hop(from: Node, to: Node, reason: String): String = s"failover=${from.name}→${to.name} reason=$reason"

  "an EC hosted-key call that meets a sick cosigner" should {

    "ask the next cosigner, note the hop, and lead from the healthy one afterwards" in {
      withCluster(3, hostedKeys = true) { case (backend, Seq(a, b, c)) =>
        a.failing = Map("keyInfo" -> Status.UNAVAILABLE)
        val notes = new AuditNotes
        await(backend.withAuditNotes(notes)(backend.keyExistsAndIsActive(HostedKey)))
        notes.render shouldBe hop(a, b, "UNAVAILABLE")
        Seq(a, b, c).map(_.calls("keyInfo")) shouldBe Seq(1, 1, 0)

        // The sick node lost the lead: the next call does not pay an attempt against it.
        val later = new AuditNotes
        await(backend.withAuditNotes(later)(backend.keyExistsAndIsActive(HostedKey)))
        later.isEmpty shouldBe true
        Seq(a, b, c).map(_.calls("keyInfo")) shouldBe Seq(1, 2, 0)
      }
    }

    "end with the last cosigner's error once each was asked once, and reach Canton as retryable when that is a node down" in {
      withCluster(3, hostedKeys = true) { case (backend, Seq(a, b, c)) =>
        a.failing = Map("keyInfo" -> Status.INTERNAL.withDescription("io: Permission denied"))
        b.failing = Map("keyInfo" -> Status.UNKNOWN)
        c.failing = Map("keyInfo" -> Status.UNAVAILABLE.withDescription("connection refused"))
        val notes = new AuditNotes
        val err = the[StatusRuntimeException] thrownBy
          await(backend.withAuditNotes(notes)(backend.keyExistsAndIsActive(HostedKey)))
        err.getStatus.getCode shouldBe Status.Code.UNAVAILABLE
        err.getStatus.getDescription shouldBe "connection refused"
        notes.render shouldBe s"${hop(a, b, "INTERNAL")} ${hop(b, c, "UNKNOWN")}"
        Seq(a, b, c).map(_.calls("keyInfo")) shouldBe Seq(1, 1, 1)

        // Each node lost the lead in turn, so the ring is back at the first one; through the driver
        // the same outcome is an error Canton retries.
        val atCanton = the[KmsDriverException] thrownBy await(driverOf(backend).keyExistsAndIsActive(HostedKey)(ctx))
        atCanton.retryable shouldBe true
        Seq(a, b, c).map(_.calls("keyInfo")) shouldBe Seq(2, 2, 2)
      }
    }
  }

  "symmetric crypto on a hosted key" should {

    final case class Op(name: String, rpc: String, run: FrostBackend => Future[Array[Byte]])
    val ops = Seq(
      Op("encryptSymmetric", "symmetricEncrypt", _.encryptSymmetric(Data, HostedKey)),
      Op("decryptSymmetric", "symmetricDecrypt", _.decryptSymmetric(Data, HostedKey)),
    )

    "fail over on a leader that is down or sick, and lead from the next cosigner afterwards" in {
      for (op <- ops; status <- Seq(Status.UNAVAILABLE, Status.DEADLINE_EXCEEDED, Status.INTERNAL, Status.UNKNOWN))
        withClue(s"${op.name} ${status.getCode}: ") {
          withCluster(2, hostedKeys = true) { case (backend, Seq(a, b)) =>
            a.failing = Map(op.rpc -> status)
            val notes = new AuditNotes
            await(backend.withAuditNotes(notes)(op.run(backend))) shouldBe Data
            notes.render shouldBe hop(a, b, status.getCode.toString)
            await(op.run(backend)) shouldBe Data
            Seq(a, b).map(_.calls(op.rpc)) shouldBe Seq(1, 2)
          }
        }
    }

    "return a refusal at once, and keep the next call on the same cosigner" in {
      for (
        op <- ops;
        status <- Seq(Status.RESOURCE_EXHAUSTED, Status.PERMISSION_DENIED, Status.NOT_FOUND, Status.INVALID_ARGUMENT)
      )
        withClue(s"${op.name} ${status.getCode}: ") {
          withCluster(2, hostedKeys = true) { case (backend, Seq(a, b)) =>
            a.failing = Map(op.rpc -> status)
            val notes = new AuditNotes
            code(await(backend.withAuditNotes(notes)(op.run(backend)))) shouldBe status.getCode
            notes.isEmpty shouldBe true
            code(await(op.run(backend))) shouldBe status.getCode
            Seq(a, b).map(_.calls(op.rpc)) shouldBe Seq(2, 0)
          }
        }
    }
  }

  "KeyInfo for a hosted key the driver knows to be RSA" should {

    /** A cluster whose key is RSA, with the spec already learned from a public-key read. */
    def withRsaKey[A](body: (FrostBackend, Node, Node) => A): A =
      withCluster(2, hostedKeys = true) { case (backend, Seq(a, b)) =>
        Seq(a, b).foreach(_.keySpec = Rsa)
        await(backend.getPublicKey(HostedKey)).spec shouldBe EncryptionKeySpec.Rsa2048
        body(backend, a, b)
      }

    "fail over on a sick leader" in withRsaKey { (backend, leader, next) =>
      leader.failing = Map("keyInfo" -> Status.INTERNAL)
      val notes = new AuditNotes
      await(backend.withAuditNotes(notes)(backend.keyExistsAndIsActive(HostedKey)))
      notes.render shouldBe hop(leader, next, "INTERNAL")
      Seq(leader, next).map(_.calls("keyInfo")) shouldBe Seq(1, 1)
    }

    "take the leader's answer that the key does not exist, without asking another cosigner" in withRsaKey {
      (backend, leader, next) =>
        leader.keyExists = false
        an[NoSuchElementException] should be thrownBy await(backend.keyExistsAndIsActive(HostedKey))
        Seq(leader, next).map(_.calls("keyInfo")) shouldBe Seq(1, 0)
    }
  }

  "deleteKey for a hosted key" should {

    "fail over when the leader is down" in {
      for (status <- Seq(Status.UNAVAILABLE, Status.DEADLINE_EXCEEDED))
        withClue(s"${status.getCode}: ") {
          withCluster(2, hostedKeys = true) { case (backend, Seq(a, b)) =>
            a.failing = Map("deleteKey" -> status)
            val notes = new AuditNotes
            await(backend.withAuditNotes(notes)(backend.deleteKey(HostedKey)))
            notes.render shouldBe hop(a, b, status.getCode.toString)
            Seq(a, b).map(_.calls("deleteKey")) shouldBe Seq(1, 1)
          }
        }
    }

    "not send the delete to another cosigner after a leader-side error, but start the next call elsewhere" in {
      for (status <- Seq(Status.INTERNAL, Status.UNKNOWN))
        withClue(s"${status.getCode}: ") {
          withCluster(2, hostedKeys = true) { case (backend, Seq(a, b)) =>
            a.failing = Map("deleteKey" -> status)
            val notes = new AuditNotes
            code(await(backend.withAuditNotes(notes)(backend.deleteKey(HostedKey)))) shouldBe status.getCode
            notes.isEmpty shouldBe true
            Seq(a, b).map(_.calls("deleteKey")) shouldBe Seq(1, 0)

            a.failing = Map.empty
            await(backend.deleteKey(HostedKey))
            Seq(a, b).map(_.calls("deleteKey")) shouldBe Seq(1, 1)
          }
        }
    }

    "return a refusal at once and keep the lead where it is, so one node's delete allowlist is not shopped around" in {
      withCluster(2, hostedKeys = true) { case (backend, Seq(a, b)) =>
        a.failing = Map("deleteKey" -> Status.PERMISSION_DENIED.withDescription("not on the delete allowlist"))
        code(await(backend.deleteKey(HostedKey))) shouldBe Status.Code.PERMISSION_DENIED
        code(await(backend.deleteKey(HostedKey))) shouldBe Status.Code.PERMISSION_DENIED
        Seq(a, b).map(_.calls("deleteKey")) shouldBe Seq(2, 0)
        // And at Canton it is final.
        val atCanton = the[KmsDriverException] thrownBy await(driverOf(backend).deleteKey(HostedKey)(ctx))
        atCanton.retryable shouldBe false
      }
    }
  }

  "frost.sign-leader = rotate with no healthy endpoint" should {

    "start at the preferred leader, not at the endpoint whose turn it is" in {
      withCluster(3, rotate = true) { case (backend, Seq(a, b, c)) =>
        def sign(): Array[Byte] = await(backend.sign(Digest, FrostKey, SigningAlgoSpec.Ed25519))
        sign() shouldBe groupSign(Digest) // turn 0: a
        Seq(a, b, c).map(_.calls("sign")) shouldBe Seq(1, 0, 0)

        // Turn 1 starts at b; every cosigner fails, so each one is demoted. The last one asked is a,
        // and the lead moves off it to b.
        Seq(a, b, c).foreach(_.failing = Map("sign" -> Status.UNAVAILABLE))
        code(sign()) shouldBe Status.Code.UNAVAILABLE
        Seq(a, b, c).map(_.calls("sign")) shouldBe Seq(2, 1, 1)

        // All are back, but each was demoted a moment ago: nothing is healthy for the rotation.
        // Turn 2 would be c and turn 3 a; both signs start at the preferred leader b instead.
        Seq(a, b, c).foreach(_.failing = Map.empty)
        sign() shouldBe groupSign(Digest)
        sign() shouldBe groupSign(Digest)
        Seq(a, b, c).map(_.calls("sign")) shouldBe Seq(2, 3, 1)
      }
    }
  }

  "a FROST key asked to sign with another algorithm" should {

    "fail before any cosigner is asked, and reach Canton as final" in {
      withCluster(2) { case (backend, nodes) =>
        val err = the[IllegalArgumentException] thrownBy await(backend.sign(Digest, FrostKey, SigningAlgoSpec.EcDsaSha256))
        err.getMessage should include("FROST keys sign Ed25519 only")
        nodes.map(_.total).sum shouldBe 0
      }
      withCluster(2, hostedKeys = true) { case (backend, nodes) =>
        val driver = driverOf(backend)
        val before = nodes.map(n => n.calls("groupKey") + n.calls("sign")).sum
        val atCanton = the[KmsDriverException] thrownBy await(driver.sign(Digest, FrostKey, SigningAlgoSpec.EcDsaSha256)(ctx))
        atCanton.retryable shouldBe false
        nodes.map(n => n.calls("groupKey") + n.calls("sign")).sum shouldBe before
      }
    }
  }

  "FrostBackend.health" should {

    "be Ok while one cosigner answers ok, and Degraded when none does" in {
      withCluster(3) { case (backend, Seq(a, b, c)) =>
        await(backend.health) shouldBe KmsDriverHealth.Ok
        Seq(a, b, c).map(_.calls("health")) shouldBe Seq(1, 0, 0) // the first ok answer is enough

        a.failing = Map("health" -> Status.UNAVAILABLE)
        b.healthOk = false // answers, but says it is not ok
        await(backend.health) shouldBe KmsDriverHealth.Ok
        Seq(a, b, c).map(_.calls("health")) shouldBe Seq(2, 1, 1)

        c.failing = Map("health" -> Status.INTERNAL)
        await(backend.health) shouldBe KmsDriverHealth.Degraded("no FROST cosigner reachable")
      }
    }

    "be the delegate's state when that is worse than the cluster's" in {
      val delegate = new RecordingDelegate(KmsDriverHealth.Degraded("hsm session lost"))
      withCluster(2, delegate = delegate) { case (backend, _) =>
        await(backend.health) shouldBe KmsDriverHealth.Degraded("hsm session lost")
      }
    }
  }

  "a key id that is neither a FROST nor a hosted one" should {

    "go to the delegate for every operation, and never to a cosigner" in {
      val delegate = new RecordingDelegate()
      withCluster(2, delegate = delegate) { case (backend, nodes) =>
        backend.supportedSigningKeySpecs shouldBe Set(SigningKeySpec.EcP256, SigningKeySpec.EcCurve25519)
        backend.supportedEncryptionKeySpecs shouldBe Set(EncryptionKeySpec.Rsa2048)

        await(backend.generateSigningKeyPair(SigningKeySpec.EcP256, Some("p256"))) shouldBe "hsm-sig"
        await(backend.generateEncryptionKeyPair(EncryptionKeySpec.Rsa2048, Some("enc"))) shouldBe "hsm-enc"
        await(backend.generateSymmetricKey(Some("sym"))) shouldBe "hsm-sym"
        await(backend.sign(Digest, "hsm-sig", SigningAlgoSpec.EcDsaSha256)) shouldBe Digest
        await(backend.decryptAsymmetric(Data, "hsm-enc", EncryptionAlgoSpec.RsaEsOaepSha256)) shouldBe Data
        await(backend.encryptSymmetric(Data, "hsm-sym")) shouldBe Data
        await(backend.decryptSymmetric(Data, "hsm-sym")) shouldBe Data
        await(backend.getPublicKey("hsm-enc")).spec shouldBe EncryptionKeySpec.Rsa2048
        await(backend.keyExistsAndIsActive("hsm-enc"))
        await(backend.deleteKey("hsm-enc"))

        delegate.seen.asScala.toList shouldBe List(
          "generateSigningKeyPair",
          "generateEncryptionKeyPair",
          "generateSymmetricKey",
          "sign hsm-sig",
          "decryptAsymmetric hsm-enc",
          "encryptSymmetric hsm-sym",
          "decryptSymmetric hsm-sym",
          "getPublicKey hsm-enc",
          "keyExistsAndIsActive hsm-enc",
          "deleteKey hsm-enc",
        )
        nodes.map(_.total).sum shouldBe 0
      }
    }
  }

  "a hosted key whose spec has no Canton public key" should {

    "be refused, not mislabelled" in {
      val direct = the[IllegalStateException] thrownBy FrostBackend.hostedPublicKey(HostedKey, Aes, Array[Byte](1, 2, 3))
      direct.getMessage should (include(HostedKey) and include(Aes) and include("no Canton public key"))

      withCluster(2, hostedKeys = true) { case (backend, Seq(a, b)) =>
        Seq(a, b).foreach(_.keySpec = Aes)
        an[IllegalStateException] should be thrownBy await(backend.getPublicKey(HostedKey))
        val atCanton = the[KmsDriverException] thrownBy await(driverOf(backend).getPublicKey(HostedKey)(ctx))
        atCanton.retryable shouldBe false
      }
    }
  }

  "FrostBackend's constructor" should {

    def inProcess(endpoints: Seq[String], expected: Map[String, String]): FrostBackend =
      new FrostBackend(endpoints, new NoDelegateBackend, logger, None, 10.seconds, expectedGroupKeys = expected) {
        override protected def buildChannel(endpoint: String): io.grpc.ManagedChannel =
          InProcessChannelBuilder.forName(endpoint).directExecutor().build()
      }

    "refuse an empty roster" in {
      val err = the[IllegalArgumentException] thrownBy inProcess(Seq.empty, Map.empty)
      err.getMessage should include("at least one cosigner endpoint")
    }

    "refuse an expected group key that is not 64 hex characters" in {
      for (bad <- Seq("abc", "zz" * 32, "11" * 33)) withClue(s"'$bad': ") {
        val err = the[IllegalArgumentException] thrownBy inProcess(Seq("nowhere"), Map(FrostKey -> bad))
        err.getMessage should (include(s"frost.expected-group-keys.$FrostKey") and include("64 hex characters"))
      }
    }
  }
}
