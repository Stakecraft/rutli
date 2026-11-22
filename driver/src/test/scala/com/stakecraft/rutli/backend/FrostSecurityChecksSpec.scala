// Copyright 2026 StakeCraft LLC
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli.backend

import com.digitalasset.canton.crypto.kms.driver.api.v1._
import com.google.protobuf.ByteString
import com.stakecraft.rutli.FrostTlsConfig
import com.stakecraft.rutli.audit.AuditNotes
import com.stakecraft.rutli.grpc._
import io.grpc.inprocess.{InProcessChannelBuilder, InProcessServerBuilder}
import io.grpc.netty.shaded.io.grpc.netty.{GrpcSslContexts, NettyServerBuilder}
import io.grpc.netty.shaded.io.netty.handler.ssl.{ClientAuth, SslContextBuilder}
import io.grpc.stub.StreamObserver
import io.grpc.Server
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.{JcaX509CertificateConverter, JcaX509v3CertificateBuilder}
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.scalatest.BeforeAndAfterAll
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import org.slf4j.LoggerFactory

import java.math.BigInteger
import java.nio.charset.StandardCharsets.{US_ASCII, UTF_8}
import java.nio.file.{Files, Path}
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.security.{KeyPair, KeyPairGenerator, Signature}
import java.util.Date
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicInteger
import scala.concurrent.duration._
import scala.concurrent.{Await, ExecutionContext, Future}
import scala.jdk.CollectionConverters._

/** Refusals of the FROST backend that no other spec reaches: a pin the store already holds for
  * another key, a DKG whose ceremony id cannot be recorded, another client's key with a pin
  * directory configured, a hosted-key reply for another spec, hosted keys generated without an
  * intent, the cluster-id lookup while no cosigner reports one, the key and certificate types the
  * intent signer loads, and trust-file errors. Where an intent is involved the cosigners are real
  * mutual-TLS servers on localhost, as in FrostSigningIntentSpec.
  */
class FrostSecurityChecksSpec extends AnyWordSpec with Matchers with BeforeAndAfterAll with org.scalatest.LoneElement {

  import FrostSigningIntentSpec.{issue, newCa, pemOf}

  private implicit val ec: ExecutionContext = ExecutionContext.global
  private val logger = LoggerFactory.getLogger(classOf[FrostSecurityChecksSpec])
  private val dir: Path = Files.createTempDirectory("rutli-security-checks")
  private def await[T](f: Future[T]): T = Await.result(f, 20.seconds)

  private val Cluster = "c2testcluster000"
  private val Key = "frost-ns"
  private val Rsa = "rsa-2048-oaep-sha256"
  private val Aes = "aes-256-gcm"
  private val Msg: Array[Byte] = Array.fill(34)(5.toByte)

  private def keyPair(): KeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
  private def raw(kp: KeyPair): Array[Byte] = kp.getPublic.getEncoded.takeRight(32)
  private def hex(b: Array[Byte]): String = b.map("%02x".format(_)).mkString
  private def signWith(kp: KeyPair, msg: Array[Byte]): Array[Byte] = {
    val s = Signature.getInstance("Ed25519")
    s.initSign(kp.getPrivate)
    s.update(msg)
    s.sign()
  }
  private def chain(t: Throwable): String =
    Iterator.iterate[Throwable](t)(_.getCause).takeWhile(_ != null).map(_.getMessage).mkString(" | ")
  private def tempDir(): Path = Files.createTempDirectory("rutli-security-pins")
  private def write(name: String, content: String): String = {
    val p = dir.resolve(name)
    Files.write(p, content.getBytes(US_ASCII))
    p.toString
  }

  private val Group = keyPair()

  // -- in-process cosigners (no TLS, so no intents) --

  private final class Plain extends SignerGrpc.SignerImplBase {
    val name: String = s"checks-${InProcessServerBuilder.generateName()}"
    val signCalls, generateCalls = new AtomicInteger

    /** The spec a GenerateKey reply names; None: the requested one. */
    @volatile var generateSpec: Option[String] = None

    override def capabilities(req: CapabilitiesRequest, obs: StreamObserver[CapabilitiesReply]): Unit = {
      obs.onNext(CapabilitiesReply.newBuilder().setHostedKeysEnabled(true).addHostedKeySpecs(Rsa).addHostedKeySpecs(Aes).build())
      obs.onCompleted()
    }
    override def groupKey(req: GroupKeyRequest, obs: StreamObserver[GroupKeyReply]): Unit = {
      obs.onNext(GroupKeyReply.newBuilder().setGroupVerifyingKey(ByteString.copyFrom(raw(Group))).build())
      obs.onCompleted()
    }
    override def sign(req: SignRequest, obs: StreamObserver[SignReply]): Unit = {
      signCalls.incrementAndGet()
      obs.onNext(SignReply.newBuilder().setSignature(ByteString.copyFrom(signWith(Group, req.getMessage.toByteArray))).build())
      obs.onCompleted()
    }
    override def generateKey(req: GenerateKeyRequest, obs: StreamObserver[GenerateKeyReply]): Unit = {
      generateCalls.incrementAndGet()
      obs.onNext(
        GenerateKeyReply.newBuilder().setKeyId(req.getKeyId).setSpec(generateSpec.getOrElse(req.getSpec)).setCreated(true).build()
      )
      obs.onCompleted()
    }
  }

  private def inProcess[A](n: Int, pinDir: Option[Path] = None, hostedKeys: Boolean = false)(
      body: (FrostBackend, IndexedSeq[Plain]) => A
  ): A = {
    val nodes = (0 until n).map(_ => new Plain)
    val servers = nodes.map(node => InProcessServerBuilder.forName(node.name).directExecutor().addService(node).build().start())
    val backend =
      new FrostBackend(
        nodes.map(_.name),
        new NoDelegateBackend,
        logger,
        None,
        10.seconds,
        hostedKeys,
        pinStore = pinDir.map(d => new GroupKeyPinStore(d, logger)),
      ) {
        override protected def buildChannel(endpoint: String): io.grpc.ManagedChannel =
          InProcessChannelBuilder.forName(endpoint).directExecutor().build()
      }
    try body(backend, nodes)
    finally {
      backend.close()
      servers.foreach(_.shutdownNow())
    }
  }

  // -- mutual-TLS cosigners (the driver signs intents) --

  private val ca = newCa()
  private val driverLeaf = issue(ca, "driver", None)
  private val caFile = write("ca.crt", pemOf("CERTIFICATE", ca.cert.getEncoded))
  private val tls = FrostTlsConfig(caFile, write("driver.crt", driverLeaf.certPem), write("driver.key", driverLeaf.keyPem))

  /** A cosigner that reports `clusterId` and records what it is asked. */
  private final class Cosigner(@volatile var clusterId: String) extends SignerGrpc.SignerImplBase {
    val capabilityCalls = new AtomicInteger
    val dkgs = new ConcurrentLinkedQueue[DkgRequest]()
    val signs = new ConcurrentLinkedQueue[SignRequest]()
    val generates = new ConcurrentLinkedQueue[GenerateKeyRequest]()

    /** `DkgReply.existing` and the origin ceremony id to report. */
    @volatile var existing: Option[Boolean] = None
    @volatile var origin: String = ""

    override def capabilities(req: CapabilitiesRequest, obs: StreamObserver[CapabilitiesReply]): Unit = {
      capabilityCalls.incrementAndGet()
      obs.onNext(
        CapabilitiesReply
          .newBuilder()
          .setClusterId(clusterId)
          .setNodeIdentifier(1)
          .setHostedKeysEnabled(true)
          .addHostedKeySpecs(Rsa)
          .addHostedKeySpecs(Aes)
          .build()
      )
      obs.onCompleted()
    }
    override def groupKey(req: GroupKeyRequest, obs: StreamObserver[GroupKeyReply]): Unit = {
      obs.onNext(GroupKeyReply.newBuilder().setGroupVerifyingKey(ByteString.copyFrom(raw(Group))).build())
      obs.onCompleted()
    }
    override def dkg(req: DkgRequest, obs: StreamObserver[DkgReply]): Unit = {
      dkgs.add(req)
      val b = DkgReply.newBuilder().setGroupVerifyingKey(ByteString.copyFrom(raw(Group))).setOriginCeremonyId(origin)
      existing.foreach(e => b.setExisting(e))
      obs.onNext(b.build())
      obs.onCompleted()
    }
    override def sign(req: SignRequest, obs: StreamObserver[SignReply]): Unit = {
      signs.add(req)
      obs.onNext(SignReply.newBuilder().setSignature(ByteString.copyFrom(signWith(Group, req.getMessage.toByteArray))).build())
      obs.onCompleted()
    }
    override def generateKey(req: GenerateKeyRequest, obs: StreamObserver[GenerateKeyReply]): Unit = {
      generates.add(req)
      obs.onNext(GenerateKeyReply.newBuilder().setKeyId(req.getKeyId).setSpec(req.getSpec).setCreated(true).build())
      obs.onCompleted()
    }
  }

  private var servers: List[Server] = Nil
  override protected def afterAll(): Unit = {
    servers.foreach(_.shutdownNow())
    super.afterAll()
  }

  /** Serve `svc` over mutual TLS as `name`; returns its address. */
  private def serve(name: String, svc: Cosigner): String = {
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

  /** A backend with the driver's mTLS identity over one cosigner served as `name`. */
  private def tlsBackend(
      name: String,
      svc: Cosigner,
      signIntents: Boolean = true,
      pinDir: Option[Path] = None,
      hostedKeys: Boolean = false,
  ): FrostBackend = {
    val endpoint = serve(name, svc)
    new FrostBackend(
      Seq(endpoint),
      new NoDelegateBackend,
      logger,
      Some(tls),
      10.seconds,
      hostedKeys,
      capabilitiesRetryBudget = 2.seconds,
      endpointTlsNames = Map(endpoint -> name),
      signIntents = signIntents,
      pinStore = pinDir.map(d => new GroupKeyPinStore(d, logger)),
    )
  }

  /** The DKG ceremony id a request's intent names, as the cosigners derive it. */
  private def ceremonyOf(req: DkgRequest): String =
    FrostIntentSigner.ceremonyId(
      FrostIntentSigner.PurposeDkg,
      SignIntent.parseFrom(req.getIntent.getIntent).getRequestId.toByteArray
    )

  "a group-key pin the store already holds for another key" should {

    "refuse the key, non-retryably, and leave the stored pin as it is" in {
      val pins = tempDir()
      inProcess(3, pinDir = Some(pins)) { case (backend, nodes) =>
        // Written after this backend loaded the directory: another process on the same volume, or a
        // file put there by hand.
        val other = hex(raw(keyPair()))
        new GroupKeyPinStore(pins, logger)
          .create(GroupKeyPin(Key, other, "dkg", List("elsewhere:9101"), Nil, "2026-11-20T12:00:00Z"))

        val public = the[KmsDriverException] thrownBy await(backend.getPublicKey(Key))
        public.retryable shouldBe false
        chain(public) should (include("already holds group key") and include(other))
        backend.pinnedGroupKeyHex(Key) shouldBe None

        val sign = the[KmsDriverException] thrownBy await(backend.sign(Msg, Key, SigningAlgoSpec.Ed25519))
        sign.retryable shouldBe false
        nodes.map(_.signCalls.get).sum shouldBe 0

        new GroupKeyPinStore(pins, logger).get(Key).map(_.groupKeyHex) shouldBe Some(other)
      }
    }
  }

  "a hosted-key reply that names another spec than the request" should {

    "be refused without asking another cosigner to generate, and cost that leader the lead" in {
      inProcess(2, hostedKeys = true) { case (backend, Seq(first, second)) =>
        first.generateSpec = Some(Rsa)
        val notes = new AuditNotes
        val ex = the[KmsDriverException] thrownBy
          await(backend.withAuditNotes(notes)(backend.generateSymmetricKey(Some("wrap"))))
        ex.retryable shouldBe false
        chain(ex) should (include(s"reports spec '$Rsa'") and include(s"the request was for '$Aes'"))
        notes.render should include("hosted-check=failed")
        (first.generateCalls.get, second.generateCalls.get) shouldBe ((1, 0))

        // The next generation starts at the other cosigner.
        first.generateSpec = None
        await(backend.generateSymmetricKey(Some("wrap"))) should startWith("rutli-sym")
        (first.generateCalls.get, second.generateCalls.get) shouldBe ((1, 1))
      }
    }
  }

  "a DKG whose ceremony id cannot be recorded in the pin directory" should {

    "fail retryably without sending the ceremony, and send it once the id can be recorded" in {
      val pins = tempDir()
      val node = new Cosigner(Cluster)
      val backend = tlsBackend("record1", node, pinDir = Some(pins))
      try {
        // A directory where the ceremony file belongs: it cannot be opened for append.
        val blocker = Files.createDirectory(pins.resolve(Key + GroupKeyPinStore.CeremonySuffix))
        val ex = the[KmsDriverException] thrownBy
          await(backend.generateSigningKeyPair(SigningKeySpec.EcCurve25519, Some("ns")))
        ex.retryable shouldBe true
        chain(ex) should include("cannot record DKG ceremony")
        node.dkgs.size shouldBe 0

        Files.delete(blocker)
        await(backend.generateSigningKeyPair(SigningKeySpec.EcCurve25519, Some("ns"))) shouldBe Key
        val sent = node.dkgs.asScala.toList.loneElement
        sent.hasIntent shouldBe true
        new GroupKeyPinStore(pins, logger).ceremonies(Key) shouldBe Set(ceremonyOf(sent))
      } finally backend.close()
    }
  }

  "a key another client's ceremony created, with a pin directory configured" should {

    "be refused, naming the pin directory, and pin nothing" in {
      val pins = tempDir()
      val node = new Cosigner(Cluster)
      node.existing = Some(true)
      node.origin = "dkg-" + "0" * 32
      val backend = tlsBackend("foreign1", node, pinDir = Some(pins))
      try {
        val ex = the[KmsDriverException] thrownBy
          await(backend.generateSigningKeyPair(SigningKeySpec.EcCurve25519, Some("ns")))
        ex.retryable shouldBe false
        chain(ex) should (include("already exists") and include(s"no ceremony id recorded for it in $pins"))
        backend.pinnedGroupKeyHex(Key) shouldBe None
        Files.exists(pins.resolve(Key + GroupKeyPinStore.Suffix)) shouldBe false
        // The driver's own ceremony id was recorded before the request went out; the foreign one
        // was not added by the refusal.
        val store = new GroupKeyPinStore(pins, logger)
        store.ceremonies(Key) shouldBe Set(ceremonyOf(node.dkgs.asScala.toList.loneElement))
        store.ceremonies(Key) should not contain node.origin
      } finally backend.close()
    }
  }

  "a hosted key generated while the driver signs no intent" should {

    def generated(name: String, node: Cosigner, signIntents: Boolean): (GenerateKeyRequest, String) = {
      val backend = tlsBackend(name, node, signIntents = signIntents, hostedKeys = true)
      try {
        val notes = new AuditNotes
        await(backend.withAuditNotes(notes)(backend.generateSymmetricKey(Some("wrap")))) should startWith("rutli-sym")
        (node.generates.asScala.toList.loneElement, notes.render)
      } finally backend.close()
    }

    "carry no generate intent with frost.sign-intents = off, and say the copies were not checked" in {
      val (request, notes) = generated("nointent1", new Cosigner(Cluster), signIntents = false)
      request.hasIntent shouldBe false
      notes should include("hosted-check=skipped")
    }

    "carry no generate intent while no cosigner reports a cluster id" in {
      val (request, notes) = generated("nointent2", new Cosigner(""), signIntents = true)
      request.hasIntent shouldBe false
      notes should include("hosted-check=skipped")
    }
  }

  "the cluster-id lookup while no cosigner reports one" should {

    "be made once, not for every sign, and the signs go without an intent meanwhile" in {
      val node = new Cosigner("")
      val backend = tlsBackend("lookup1", node)
      try {
        def sign(): String = {
          val notes = new AuditNotes
          await(backend.withAuditNotes(notes)(backend.sign(Msg, Key, SigningAlgoSpec.Ed25519))) shouldBe signWith(Group, Msg)
          notes.render
        }
        sign() shouldBe "intent=none"
        sign() shouldBe "intent=none"
        node.capabilityCalls.get shouldBe 1

        // A cosigner that starts reporting an id is asked again a minute after the last lookup at
        // the earliest, not by the next sign.
        node.clusterId = Cluster
        sign() shouldBe "intent=none"
        node.capabilityCalls.get shouldBe 1
        node.signs.asScala.toList.map(_.hasIntent) shouldBe List(false, false, false)
      } finally backend.close()
    }
  }

  "FrostIntentSigner.load" should {

    val notBefore = new Date(System.currentTimeMillis() - 3600 * 1000L)
    val notAfter = new Date(System.currentTimeMillis() + 24 * 3600 * 1000L)

    def selfSigned(keys: KeyPair, signatureAlg: String): X509Certificate = {
      val name = new X500Name("CN=driver")
      val builder = new JcaX509v3CertificateBuilder(name, BigInteger.ONE, notBefore, notAfter, name, keys.getPublic)
      new JcaX509CertificateConverter().getCertificate(
        builder.build(new JcaContentSignerBuilder(signatureAlg).build(keys.getPrivate))
      )
    }
    def generate(algorithm: String, init: KeyPairGenerator => Unit): KeyPair = {
      val g = KeyPairGenerator.getInstance(algorithm)
      init(g)
      g.generateKeyPair()
    }
    def pkcs8(keys: KeyPair): String = pemOf("PRIVATE KEY", keys.getPrivate.getEncoded)

    /** The traditional `RSA PRIVATE KEY` (PKCS#1) form of an RSA key. */
    def pkcs1(keys: KeyPair): String =
      pemOf(
        "RSA PRIVATE KEY",
        PrivateKeyInfo.getInstance(keys.getPrivate.getEncoded).parsePrivateKey().toASN1Primitive.getEncoded
      )

    /** Load the identity, sign an intent with it, and check what a cosigner checks: the algorithm
      * label, the leaf of the chain, and the signature over the context and the intent bytes. */
    def loadsAndSigns(tag: String, keys: KeyPair, certAlg: String, keyPem: String, label: String, jcaAlg: String): Unit = {
      val cert = selfSigned(keys, certAlg)
      val signer = FrostIntentSigner.load(write(s"$tag.crt", pemOf("CERTIFICATE", cert.getEncoded)), write(s"$tag.key", keyPem))
      signer.signatureAlg shouldBe label
      val signed =
        signer.signCeremony(Cluster, FrostIntentSigner.PurposeDkg, Key, Array.fill(16)(1.toByte), 1700000000000L, 120000L)
      signed.getSignatureAlg shouldBe label
      signed.getSignerChain(0).toByteArray shouldBe cert.getEncoded
      val v = Signature.getInstance(jcaAlg)
      v.initVerify(cert.getPublicKey)
      v.update(FrostIntentSigner.Context)
      v.update(signed.getIntent.toByteArray)
      v.verify(signed.getSignature.toByteArray) shouldBe true
      ()
    }

    "sign with ECDSA P-384 and SHA-384 for a P-384 certificate" in {
      val keys = generate("EC", _.initialize(new ECGenParameterSpec("secp384r1")))
      loadsAndSigns("p384", keys, "SHA384withECDSA", pkcs8(keys), "ecdsa-p384-sha384", "SHA384withECDSA")
    }

    "sign with RSA PKCS#1 v1.5 and SHA-256 for an RSA certificate, from a PKCS#8 or a PKCS#1 key file" in {
      val keys = generate("RSA", _.initialize(2048))
      loadsAndSigns("rsa8", keys, "SHA256withRSA", pkcs8(keys), "rsa-pkcs1-sha256", "SHA256withRSA")
      loadsAndSigns("rsa1", keys, "SHA256withRSA", pkcs1(keys), "rsa-pkcs1-sha256", "SHA256withRSA")
    }

    "sign with Ed25519 for an Ed25519 certificate" in {
      val keys = generate("Ed25519", _ => ())
      loadsAndSigns("ed25519", keys, "Ed25519", pkcs8(keys), "ed25519", "Ed25519")
    }

    "refuse a certificate whose key type the cosigners do not verify" in {
      val keys = generate("DSA", _.initialize(2048))
      val cert = write("dsa.crt", pemOf("CERTIFICATE", selfSigned(keys, "SHA256withDSA").getEncoded))
      val err = the[IllegalArgumentException] thrownBy FrostIntentSigner.load(cert, write("dsa.key", pkcs8(keys)))
      err.getMessage should (include("unsupported key") and include("for signing intents"))
    }

    "refuse a key file that holds no private key" in {
      val notAKey = the[IllegalArgumentException] thrownBy FrostIntentSigner.load(tls.cert, tls.cert)
      notAKey.getMessage should include("not a private key")
      val empty = the[IllegalArgumentException] thrownBy FrostIntentSigner.load(tls.cert, write("empty.key", ""))
      empty.getMessage should include("not a private key (empty)")
    }
  }

  "the trust file (frost.tls.ca-cert)" should {

    def refusal(bytes: Array[Byte]): String = FrostTrustFile.validate(bytes, allowExpired = false) match {
      case Left(why)      => why
      case Right(anchors) => fail(s"accepted with ${anchors.size} anchor(s)")
    }

    "be refused for a PEM header that never ends, a body that is not base64, and bytes that are not UTF-8" in {
      refusal("-----BEGIN CERTIFICATE\nMIIB".getBytes(UTF_8)) shouldBe "malformed PEM header"
      refusal("-----BEGIN CERTIFICATE-----\n!!not base64!!\n-----END CERTIFICATE-----\n".getBytes(UTF_8)) shouldBe
        "PEM body is not base64"
      refusal(Array(0xff.toByte, 0xfe.toByte, 0x2d.toByte)) shouldBe "PEM file is not UTF-8"
    }

    "be refused for a certificate followed by other bytes inside its block" in {
      refusal(pemOf("CERTIFICATE", ca.cert.getEncoded ++ Array[Byte](0, 0, 0)).getBytes(UTF_8)) shouldBe
        "certificate 0: malformed certificate"
    }

    "be refused, naming the path, when it cannot be read" in {
      val missing = dir.resolve("no-such-ca.crt").toString
      val err = the[IllegalArgumentException] thrownBy FrostTrustFile.load(missing, allowExpired = false)
      err.getMessage should (include(missing) and include("cannot read it"))
    }
  }
}
