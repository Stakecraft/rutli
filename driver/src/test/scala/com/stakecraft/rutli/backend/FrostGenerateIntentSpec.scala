// Copyright 2026 StakeCraft LLC
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli.backend

import com.digitalasset.canton.crypto.kms.driver.api.v1._
import com.google.protobuf.ByteString
import com.stakecraft.rutli.audit.AuditNotes
import com.stakecraft.rutli.grpc._
import com.stakecraft.rutli.FrostTlsConfig
import io.grpc.netty.shaded.io.grpc.netty.{GrpcSslContexts, NettyServerBuilder}
import io.grpc.netty.shaded.io.netty.handler.ssl.{ClientAuth, SslContextBuilder}
import io.grpc.stub.StreamObserver
import io.grpc.{CallOptions, ClientCall, ManagedChannel, MethodDescriptor, Server, Status, StatusRuntimeException}
import org.scalatest.{BeforeAndAfterAll, BeforeAndAfterEach}
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import org.slf4j.LoggerFactory

import java.nio.charset.StandardCharsets.US_ASCII
import java.nio.file.{Files, Path}
import java.security.cert.{CertificateFactory, X509Certificate}
import java.util.concurrent.ConcurrentLinkedQueue
import scala.concurrent.duration._
import scala.concurrent.{Await, ExecutionContext}
import scala.jdk.CollectionConverters._

/** Creating a hosted key (0.5.0): the driver signs a generate intent per endpoint it tries, naming
  * that endpoint as the leader, and believes the leader's reply only once the other cosigners'
  * own copies confirm it. Real mutual-TLS gRPC servers on localhost stand in for the cosigners;
  * the driver code is the production one.
  */
class FrostGenerateIntentSpec
    extends AnyWordSpec
    with Matchers
    with BeforeAndAfterAll
    with BeforeAndAfterEach
    with org.scalatest.LoneElement {

  import FrostSigningIntentSpec._

  private implicit val ec: ExecutionContext = ExecutionContext.global
  private val logger = LoggerFactory.getLogger(classOf[FrostGenerateIntentSpec])
  private val dir: Path = Files.createTempDirectory("rutli-genkey-intent")

  private val Cluster = "c2testcluster000"
  private val Aes = "aes-256-gcm"
  private val Rsa = "rsa-2048-oaep-sha256"
  private val CommitmentA = ByteString.copyFrom(Array.fill(32)(0x0a.toByte))
  private val CommitmentB = ByteString.copyFrom(Array.fill(32)(0x0b.toByte))

  private val ca = newCa()
  private val driver = issue(ca, "driver", None)
  private val caFile = write("ca.crt", pemOf("CERTIFICATE", ca.cert.getEncoded))
  private val tls = FrostTlsConfig(caFile, write("driver.crt", driver.certPem), write("driver.key", driver.keyPem))

  /** A copy a cosigner holds: commitment, spec, public key. */
  private final case class Copy(commitment: ByteString, spec: String, publicKey: ByteString)

  /** A cosigner stand-in for hosted-key generation: reports `nodeId` as its roster identifier,
    * answers GenerateKey with `reply` after `generateDelay` (or fails with `failGenerate`), records
    * every GenerateKey and when it arrived, and answers KeyInfo(local_only) with its own `copy`. */
  private final class HostedNode(@volatile var nodeId: Int) extends SignerGrpc.SignerImplBase {
    /** The address the backend dials for this node (set by [[cluster]]). */
    @volatile var endpoint: String = ""
    @volatile var copy: Option[Copy] = None
    @volatile var reply: Copy = Copy(CommitmentA, Aes, ByteString.EMPTY)
    @volatile var created: Boolean = true
    @volatile var failGenerate: Option[Status] = None
    @volatile var generateDelay: FiniteDuration = Duration.Zero
    /** KeyInfo answers UNAVAILABLE this many more times (then normally), or always. */
    @volatile var keyInfoFailures: Int = 0
    @volatile var keyInfoDown: Boolean = false
    val generates = new ConcurrentLinkedQueue[GenerateKeyRequest]()
    val generateTimes = new ConcurrentLinkedQueue[java.lang.Long]()
    val keyInfos = new ConcurrentLinkedQueue[KeyInfoRequest]()

    override def capabilities(req: CapabilitiesRequest, obs: StreamObserver[CapabilitiesReply]): Unit = {
      obs.onNext(
        CapabilitiesReply
          .newBuilder()
          .setClusterId(Cluster)
          .setNodeIdentifier(nodeId)
          .setHostedKeysEnabled(true)
          .addHostedKeySpecs(Rsa)
          .addHostedKeySpecs(Aes)
          .build()
      )
      obs.onCompleted()
    }
    override def generateKey(req: GenerateKeyRequest, obs: StreamObserver[GenerateKeyReply]): Unit = {
      generates.add(req)
      generateTimes.add(java.lang.Long.valueOf(System.nanoTime()))
      if (generateDelay > Duration.Zero) Thread.sleep(generateDelay.toMillis)
      failGenerate match {
        case Some(st) => obs.onError(st.withDescription("test: refused").asRuntimeException())
        case None =>
          obs.onNext(
            GenerateKeyReply
              .newBuilder()
              .setKeyId(req.getKeyId)
              .setSpec(reply.spec)
              .setPublicKeyDer(reply.publicKey)
              .setCreated(created)
              .setReplicas(3)
              .setCommitment(reply.commitment)
              .build()
          )
          obs.onCompleted()
      }
    }
    override def keyInfo(req: KeyInfoRequest, obs: StreamObserver[KeyInfoReply]): Unit = {
      keyInfos.add(req)
      val fail = synchronized {
        if (keyInfoFailures > 0) { keyInfoFailures -= 1; true }
        else keyInfoDown
      }
      if (fail) obs.onError(Status.UNAVAILABLE.withDescription("test: down").asRuntimeException())
      else {
        val b = KeyInfoReply.newBuilder()
        copy.foreach(c => b.setExists(true).setSpec(c.spec).setCommitment(c.commitment).setPublicKeyDer(c.publicKey))
        obs.onNext(b.build())
        obs.onCompleted()
      }
    }
  }

  private var servers: List[Server] = Nil
  override protected def afterAll(): Unit = { servers.foreach(_.shutdownNow()); super.afterAll() }
  // A "hang" outlives its test (the blocked probe thread sleeps on); its fault must not.
  override protected def afterEach(): Unit =
    try FrostGenerateIntentSpec.probeFaults.clear()
    finally super.afterEach()

  private def serve(name: String, svc: HostedNode): String = {
    val leaf = issue(ca, name, Some(name))
    val ssl = GrpcSslContexts
      .configure(
        SslContextBuilder
          .forServer(new java.io.File(write(s"$name.crt", leaf.certPem)), new java.io.File(write(s"$name.key", leaf.keyPem)))
          .trustManager(new java.io.File(caFile))
          .clientAuth(ClientAuth.REQUIRE)
      )
      .build()
    val s = NettyServerBuilder.forPort(0).sslContext(ssl).addService(svc).build().start()
    servers ::= s
    s"localhost:${s.getPort}"
  }

  /** `n` cosigners (roster identifiers 1..n) and a backend whose roster lists them in order, with
    * `timeout` as its request timeout and `attempt` as its attempt deadline. The backend's channels
    * go through [[FrostGenerateIntentSpec.FaultyChannel]], so a test can make the copy probe fail on
    * the client side ([[FrostGenerateIntentSpec.probeFaults]]). */
  private def cluster(
      n: Int,
      timeout: FiniteDuration = 10.seconds,
      attempt: FiniteDuration = 10.seconds,
  ): (FrostBackend, IndexedSeq[HostedNode]) = {
    val nodes = (1 to n).map(i => new HostedNode(i))
    val eps = nodes.zipWithIndex.map { case (node, i) =>
      val name = s"cosigner${i + 1}"
      node.endpoint = serve(name, node)
      node.endpoint -> name
    }
    val backend = new FrostBackend(
      eps.map(_._1),
      new NoDelegateBackend,
      logger,
      Some(tls),
      timeout,
      hostedKeys = true,
      capabilitiesRetryBudget = 2.seconds,
      endpointTlsNames = eps.toMap,
      attemptTimeout = attempt,
    ) {
      override protected def buildChannel(endpoint: String): ManagedChannel =
        new FrostGenerateIntentSpec.FaultyChannel(super.buildChannel(endpoint), endpoint)
    }
    (backend, nodes)
  }

  /** One generation with every copy in place, so the cluster id is learned and the connections are
    * up before a test times a call; then the nodes' records are cleared. Tried up to five times: with
    * a short attempt deadline the first can miss while connections are still being set up. */
  private def warmUp(backend: FrostBackend, nodes: IndexedSeq[HostedNode]): Unit = {
    nodes.foreach(_.copy = Some(AesCopy))
    def once(): Boolean =
      try { Await.result(backend.generateSymmetricKey(Some("warm")), 20.seconds); true }
      catch { case scala.util.control.NonFatal(_) => false }
    withClue("warm-up generation: ") { (1 to 5).exists(_ => once()) shouldBe true }
    nodes.foreach { n => n.generates.clear(); n.keyInfos.clear(); n.generateTimes.clear() }
  }

  /** Milliseconds since `t0` (a System.nanoTime). */
  private def msSince(t0: Long): Long = (System.nanoTime() - t0) / 1000000L

  private def decode(i: SignedIntent): SignIntent = SignIntent.parseFrom(i.getIntent)

  /** Every message down the cause chain (a KmsDriverException wraps its cause). */
  private def chain(t: Throwable): String =
    Iterator.iterate[Throwable](t)(_.getCause).takeWhile(_ != null).map(_.getMessage).mkString(" | ")

  /** The signature over the context and the intent bytes, by the driver's certificate. */
  private def verifies(i: SignedIntent): Boolean = {
    val leaf = CertificateFactory
      .getInstance("X.509")
      .generateCertificate(new java.io.ByteArrayInputStream(i.getSignerChain(0).toByteArray))
      .asInstanceOf[X509Certificate]
    val v = java.security.Signature.getInstance("SHA256withECDSA")
    v.initVerify(leaf.getPublicKey)
    v.update("rutli-intent-v1\n".getBytes(US_ASCII))
    v.update(i.getIntent.toByteArray)
    leaf.getEncoded.sameElements(driver.cert.getEncoded) && v.verify(i.getSignature.toByteArray)
  }

  private val AesCopy = Copy(CommitmentA, Aes, ByteString.EMPTY)

  "FrostBackend.generateSymmetricKey" should {

    "sign a fresh generate intent for every endpoint it tries, naming that endpoint as the leader" in {
      val (backend, nodes) = cluster(2)
      try {
        nodes.foreach(_.copy = Some(AesCopy))
        nodes(0).failGenerate = Some(Status.UNAVAILABLE)
        val notes = new AuditNotes
        val keyId = Await.result(backend.withAuditNotes(notes)(backend.generateSymmetricKey(Some("wrap"))), 20.seconds)
        val first = nodes(0).generates.asScala.toList.loneElement
        val second = nodes(1).generates.asScala.toList.loneElement
        Seq(first -> 1, second -> 2).foreach { case (req, leader) =>
          req.getKeyId shouldBe keyId
          req.getSpec shouldBe Aes
          req.hasIntent shouldBe true
          verifies(req.getIntent) shouldBe true
          val i = decode(req.getIntent)
          i.getPurpose shouldBe "generate-key"
          i.getClusterId shouldBe Cluster
          i.getKeyId shouldBe keyId
          i.getHostedSpec shouldBe Aes
          i.getLeader shouldBe leader
          i.getDigest.isEmpty shouldBe true
          i.getApprovalsCount shouldBe 0
          i.getRequestId.size shouldBe 16
        }
        decode(first.getIntent).getRequestId should not be decode(second.getIntent).getRequestId
        // Every endpoint was asked for its own copy.
        nodes.foreach(n => n.keyInfos.asScala.toList.loneElement.getLocalOnly shouldBe true)
        notes.render should include("hosted-check=ok copies=2")
      } finally backend.close()
    }

    "reject a reply no second cosigner confirms, without retrying, and not keep that leader preferred" in {
      val (backend, nodes) = cluster(3)
      try {
        nodes(0).copy = Some(AesCopy) // only the leader holds what it reported
        val ex = the[KmsDriverException] thrownBy Await.result(backend.generateSymmetricKey(Some("lonely")), 20.seconds)
        ex.retryable shouldBe false
        chain(ex) should include("only 1 cosigner(s) confirm")
        nodes.map(_.generates.size) shouldBe Seq(1, 0, 0)
        // The next generation starts at the next endpoint.
        nodes.foreach(_.copy = Some(AesCopy))
        Await.result(backend.generateSymmetricKey(Some("next")), 20.seconds)
        nodes.map(_.generates.size) shouldBe Seq(1, 1, 0)
      } finally backend.close()
    }

    "move on to the next endpoint when copies are short only because endpoints were silent" in {
      val (backend, nodes) = cluster(3)
      try {
        nodes.foreach(_.copy = Some(AesCopy))
        nodes(1).keyInfoFailures = 1
        nodes(2).keyInfoFailures = 1
        val notes = new AuditNotes
        val keyId = Await.result(backend.withAuditNotes(notes)(backend.generateSymmetricKey(Some("slow"))), 20.seconds)
        nodes.map(_.generates.size) shouldBe Seq(1, 1, 0)
        // The second attempt is a fresh intent naming the second endpoint, for the same id.
        val second = nodes(1).generates.asScala.toList.loneElement
        second.getKeyId shouldBe keyId
        decode(second.getIntent).getLeader shouldBe 2
        notes.render should include("hosted-check=unconfirmed")
        notes.render should include("reason=UNCONFIRMED")
        notes.render should include("hosted-check=ok copies=3")
      } finally backend.close()
    }

    "fail without retry by Canton, naming the silent endpoints, when no endpoint gets its copies confirmed" in {
      val (backend, nodes) = cluster(3)
      try {
        nodes.foreach(_.copy = Some(AesCopy))
        nodes(1).keyInfoDown = true
        nodes(2).keyInfoDown = true
        val ex = the[KmsDriverException] thrownBy Await.result(backend.generateSymmetricKey(Some("mute")), 30.seconds)
        ex.retryable shouldBe false
        chain(ex) should include("only 1 cosigner(s) confirm")
        chain(ex) should include(s"silent: ${nodes(1).endpoint}, ${nodes(2).endpoint}")
        // Every endpoint led once, none twice.
        nodes.map(_.generates.size) shouldBe Seq(1, 1, 1)
      } finally backend.close()
    }

    "count a probe that fails on the client side as silent, not fail the check" in {
      val (backend, nodes) = cluster(3)
      try {
        nodes.foreach(_.copy = Some(AesCopy))
        FrostGenerateIntentSpec.probeFaults.put(nodes(2).endpoint, "throw")
        val notes = new AuditNotes
        Await.result(backend.withAuditNotes(notes)(backend.generateSymmetricKey(Some("glitch"))), 20.seconds)
        notes.render should include("hosted-check=ok copies=2")
        nodes.map(_.generates.size) shouldBe Seq(1, 0, 0)
      } finally backend.close()
    }

    "keep the answers in hand when one probe never completes" in {
      val (backend, nodes) = cluster(3, timeout = 2.seconds)
      try {
        nodes.foreach(_.copy = Some(AesCopy))
        FrostGenerateIntentSpec.probeFaults.put(nodes(2).endpoint, "hang")
        val notes = new AuditNotes
        Await.result(backend.withAuditNotes(notes)(backend.generateSymmetricKey(Some("stuck"))), 20.seconds)
        notes.render should include("hosted-check=ok copies=2")
        nodes.map(_.generates.size) shouldBe Seq(1, 0, 0)
      } finally backend.close()
    }

    "finish within the request timeout when one copy probe hangs" in {
      val (backend, nodes) = cluster(3, timeout = 3.seconds)
      try {
        warmUp(backend, nodes)
        FrostGenerateIntentSpec.probeFaults.put(nodes(2).endpoint, "hang")
        val notes = new AuditNotes
        val t0 = System.nanoTime()
        Await.result(backend.withAuditNotes(notes)(backend.generateSymmetricKey(Some("bounded"))), 20.seconds)
        msSince(t0) should be <= 3500L
        notes.render should include("hosted-check=ok copies=2")
        nodes.map(_.generates.size) shouldBe Seq(1, 0, 0)
      } finally backend.close()
    }

    "fail with the unconfirmed error, not a spent request timeout, when no second attempt fits" in {
      val (backend, nodes) = cluster(3, timeout = 3.seconds)
      try {
        warmUp(backend, nodes)
        // The leader takes most of the budget; the copy check cannot leave room for another leader.
        nodes.foreach(_.generateDelay = 2.seconds)
        FrostGenerateIntentSpec.probeFaults.put(nodes(1).endpoint, "hang")
        FrostGenerateIntentSpec.probeFaults.put(nodes(2).endpoint, "hang")
        val t0 = System.nanoTime()
        val ex = the[KmsDriverException] thrownBy Await.result(backend.generateSymmetricKey(Some("late")), 20.seconds)
        msSince(t0) should be <= 3500L
        ex.retryable shouldBe false
        chain(ex) should include("only 1 cosigner(s) confirm")
        chain(ex) should include(s"silent: ${nodes(1).endpoint}, ${nodes(2).endpoint}")
        nodes.map(_.generates.size) shouldBe Seq(1, 0, 0)
      } finally backend.close()
    }

    "lead again under a fresh intent within the budget when the first check is short only by silence" in {
      val (backend, nodes) = cluster(3, timeout = 6.seconds)
      try {
        warmUp(backend, nodes)
        nodes(1).keyInfoFailures = 1
        FrostGenerateIntentSpec.probeFaults.put(nodes(2).endpoint, "hang")
        val notes = new AuditNotes
        val t0 = System.nanoTime()
        val keyId = Await.result(backend.withAuditNotes(notes)(backend.generateSymmetricKey(Some("again"))), 20.seconds)
        msSince(t0) should be <= 6500L
        nodes.map(_.generates.size) shouldBe Seq(1, 1, 0)
        val first = decode(nodes(0).generates.asScala.toList.loneElement.getIntent)
        val second = decode(nodes(1).generates.asScala.toList.loneElement.getIntent)
        Seq(first, second).foreach(_.getKeyId shouldBe keyId)
        (first.getLeader, second.getLeader) shouldBe ((1, 2))
        second.getRequestId should not be first.getRequestId
        notes.render should include("reason=UNCONFIRMED")
        notes.render should include("hosted-check=ok copies=2")
      } finally backend.close()
    }

    "send no second GenerateKey when the copy check leaves too little for another attempt" in {
      // A short attempt deadline: one attempt deadline in reserve cannot hold an attempt and a copy
      // check after it, so the check gets the whole remainder and a short result ends the call.
      val (backend, nodes) = cluster(3, timeout = 2.seconds, attempt = 250.millis)
      try {
        warmUp(backend, nodes)
        nodes.foreach(n => FrostGenerateIntentSpec.probeFaults.put(n.endpoint, "hang"))
        val t0 = System.nanoTime()
        val ex = the[KmsDriverException] thrownBy Await.result(backend.generateSymmetricKey(Some("cramped")), 20.seconds)
        msSince(t0) should be <= 2500L
        ex.retryable shouldBe false
        chain(ex) should include("only 0 cosigner(s) confirm")
        chain(ex) should include("silent:")
        // Leader-agnostic (a warm-up miss may have moved the lead): one GenerateKey in all.
        nodes.map(_.generates.size).sum shouldBe 1
      } finally backend.close()
    }

    "keep one attempt deadline in reserve and lead again in it after a check short only by silence" in {
      val (backend, nodes) = cluster(3, timeout = 3.seconds, attempt = 600.millis)
      try {
        warmUp(backend, nodes)
        // The first probe of every node fails, and one node's probe never completes: the first
        // check is short only by silence, whichever endpoint leads; the second confirms two copies.
        nodes.foreach(_.keyInfoFailures = 1)
        FrostGenerateIntentSpec.probeFaults.put(nodes(2).endpoint, "hang")
        val notes = new AuditNotes
        val t0 = System.nanoTime()
        Await.result(backend.withAuditNotes(notes)(backend.generateSymmetricKey(Some("reserve"))), 20.seconds)
        msSince(t0) should be <= 3500L
        val times = nodes.flatMap(_.generateTimes.asScala).map(_.longValue).sorted
        times should have size 2
        // The first check ran until one attempt deadline (600 ms) before the end of the budget, not
        // until half of it: the second leader was asked about 2.4 s in.
        val second = (times(1) - t0) / 1000000L
        second should (be >= 2000L and be <= 2800L)
        notes.render should include("reason=UNCONFIRMED")
        notes.render should include("hosted-check=ok copies=2")
      } finally backend.close()
    }

    "give the copy check the whole remainder when too little is left to keep a reserve" in {
      val (backend, nodes) = cluster(3, timeout = 3.seconds)
      try {
        warmUp(backend, nodes)
        // The first leader fails after 2.55 s and the second answers at once, with about 400 ms of
        // the budget left: too little to keep room for a third attempt and still probe.
        nodes(0).generateDelay = 2550.millis
        nodes(0).failGenerate = Some(Status.UNAVAILABLE)
        val notes = new AuditNotes
        val t0 = System.nanoTime()
        Await.result(backend.withAuditNotes(notes)(backend.generateSymmetricKey(Some("narrow"))), 20.seconds)
        msSince(t0) should be <= 3500L
        nodes.map(_.generates.size) shouldBe Seq(1, 1, 0)
        notes.render should include("hosted-check=ok copies=3")
        notes.render should not include ("reason=UNCONFIRMED")
      } finally backend.close()
    }

    "fail when any cosigner holds other material under the id" in {
      val (backend, nodes) = cluster(3)
      try {
        nodes(0).copy = Some(AesCopy)
        nodes(1).copy = Some(AesCopy)
        nodes(2).copy = Some(Copy(CommitmentB, Aes, ByteString.EMPTY))
        val ex = the[KmsDriverException] thrownBy Await.result(backend.generateSymmetricKey(Some("forked")), 20.seconds)
        ex.retryable shouldBe false
        chain(ex) should include("OTHER material")
        chain(ex) should include(nodes(2).endpoint)
        chain(ex) should include("may be false")
        nodes.map(_.generates.size) shouldBe Seq(1, 0, 0)
      } finally backend.close()
    }

    "refuse a reply without a commitment when the request carried an intent" in {
      val (backend, nodes) = cluster(2)
      try {
        nodes.foreach(_.copy = Some(AesCopy))
        nodes(0).reply = Copy(ByteString.EMPTY, Aes, ByteString.EMPTY)
        val ex = the[KmsDriverException] thrownBy Await.result(backend.generateSymmetricKey(Some("bare")), 20.seconds)
        chain(ex) should include("no commitment")
      } finally backend.close()
    }

    "refuse to generate through an endpoint that does not report its roster identifier" in {
      val (backend, nodes) = cluster(2)
      try {
        nodes.foreach(_.copy = Some(AesCopy))
        nodes(0).nodeId = 0
        val ex = the[StatusRuntimeException] thrownBy Await.result(backend.generateSymmetricKey(Some("old")), 20.seconds)
        ex.getStatus.getCode shouldBe Status.Code.FAILED_PRECONDITION
        nodes.map(_.generates.size) shouldBe Seq(0, 0)
        // Not failed over within the call, but that endpoint lost the lead: the next generation
        // starts at the other one.
        Await.result(backend.generateSymmetricKey(Some("next")), 20.seconds)
        nodes.map(_.generates.size) shouldBe Seq(0, 1)
      } finally backend.close()
    }
  }

  "FrostBackend.generateEncryptionKeyPair" should {

    "check an existing key the leader returns the same way, public key included" in {
      val (backend, nodes) = cluster(2)
      val spki = ByteString.copyFrom(Array[Byte](1, 2, 3))
      try {
        val existing = Copy(CommitmentA, Rsa, spki)
        nodes.foreach { n => n.reply = existing; n.created = false; n.copy = Some(existing) }
        Await.result(backend.generateEncryptionKeyPair(EncryptionKeySpec.Rsa2048, Some("enc")), 20.seconds) should startWith("rutli-enc")
        // A cosigner whose copy derives another public key: other material.
        nodes(1).copy = Some(Copy(CommitmentA, Rsa, ByteString.copyFrom(Array[Byte](9, 9, 9))))
        val ex = the[KmsDriverException] thrownBy
          Await.result(backend.generateEncryptionKeyPair(EncryptionKeySpec.Rsa2048, Some("enc")), 20.seconds)
        ex.retryable shouldBe false
        chain(ex) should include("OTHER material")
      } finally backend.close()
    }
  }

  "FrostIntentSigner generate intents" should {
    val rid = Array.fill(16)(1.toByte)

    "serialize exactly as the cosigners do (golden vector shared with intent.rs)" in {
      hex(
        FrostIntentSigner
          .generateIntent("c2testcluster000", "participant1-rutli-enc-golden", Rsa, 2, rid, 1700000000000L, 120000L)
          .toByteArray
      ) shouldBe
        "08011210633274657374636c75737465723030301a0c67656e65726174652d6b6579221d7061727469636970616e74312d7275746c692d656e632d676f6c64656e3210010101010101010101010101010101013880d095ffbc3140c0f99cffbc315a147273612d323034382d6f6165702d7368613235366002"
      FrostIntentSigner.generateCeremonyId(rid) shouldBe "genkey-01010101010101010101010101010101"
    }

    "refuse a missing leader, a missing spec and a short request id" in {
      an[IllegalArgumentException] should be thrownBy FrostIntentSigner.generateIntent(Cluster, "rutli-x", Aes, 0, rid, 1L, 1L)
      an[IllegalArgumentException] should be thrownBy FrostIntentSigner.generateIntent(Cluster, "rutli-x", "", 1, rid, 1L, 1L)
      an[IllegalArgumentException] should be thrownBy
        FrostIntentSigner.generateIntent(Cluster, "rutli-x", Aes, 1, Array.fill(8)(1.toByte), 1L, 1L)
    }

    "be signed by signGenerate with the driver's key" in {
      val signer = FrostIntentSigner.load(tls.cert, tls.key)
      val signed = signer.signGenerate(Cluster, "rutli-x", Aes, 3, rid, 1700000000000L, 120000L)
      verifies(signed) shouldBe true
      decode(signed) shouldBe FrostIntentSigner.generateIntent(Cluster, "rutli-x", Aes, 3, rid, 1700000000000L, 120000L)
    }
  }

  private def write(name: String, content: String): String = {
    val p = dir.resolve(name); Files.write(p, content.getBytes(US_ASCII)); p.toString
  }
}

object FrostGenerateIntentSpec {

  /** Client-side faults of the copy probe (`KeyInfo`) by endpoint: "throw" makes the call fail
    * with an exception that is not a gRPC status, "hang" blocks it past every deadline. */
  val probeFaults = new java.util.concurrent.ConcurrentHashMap[String, String]()

  /** A channel that applies [[probeFaults]] to `KeyInfo` calls and passes everything else on. */
  final class FaultyChannel(underlying: ManagedChannel, endpoint: String) extends ManagedChannel {
    override def newCall[Q, R](method: MethodDescriptor[Q, R], options: CallOptions): ClientCall[Q, R] = {
      if (method.getFullMethodName.endsWith("/KeyInfo"))
        probeFaults.get(endpoint) match {
          case "throw" => throw new IllegalStateException("test: client-side failure")
          case "hang"  => Thread.sleep(8000)
          case _       => ()
        }
      underlying.newCall(method, options)
    }
    override def authority(): String = underlying.authority()
    override def shutdown(): ManagedChannel = { underlying.shutdown(); this }
    override def shutdownNow(): ManagedChannel = { underlying.shutdownNow(); this }
    override def isShutdown: Boolean = underlying.isShutdown
    override def isTerminated: Boolean = underlying.isTerminated
    override def awaitTermination(timeout: Long, unit: java.util.concurrent.TimeUnit): Boolean =
      underlying.awaitTermination(timeout, unit)
  }
}
