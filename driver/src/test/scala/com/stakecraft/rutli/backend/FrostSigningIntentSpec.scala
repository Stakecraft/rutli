// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli.backend

import com.digitalasset.canton.crypto.kms.driver.api.v1._
import com.google.protobuf.ByteString
import com.stakecraft.rutli.audit.AuditNotes
import com.stakecraft.rutli.policy.ApprovalProof
import com.stakecraft.rutli.grpc._
import com.stakecraft.rutli.FrostTlsConfig
import io.grpc.netty.shaded.io.grpc.netty.{GrpcSslContexts, NettyServerBuilder}
import io.grpc.netty.shaded.io.netty.handler.ssl.{ClientAuth, SslContextBuilder}
import io.grpc.stub.StreamObserver
import io.grpc.{Server, Status}
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509._
import org.bouncycastle.cert.jcajce.{JcaX509CertificateConverter, JcaX509v3CertificateBuilder}
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.scalatest.BeforeAndAfterAll
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import org.slf4j.LoggerFactory

import java.math.BigInteger
import java.nio.charset.StandardCharsets.US_ASCII
import java.nio.file.{Files, Path}
import java.security.cert.{CertificateFactory, X509Certificate}
import java.security.spec.ECGenParameterSpec
import java.security.{KeyPair, KeyPairGenerator}
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicInteger
import java.util.{Base64, Date}
import scala.concurrent.duration._
import scala.concurrent.{Await, ExecutionContext}
import scala.jdk.CollectionConverters._

/** Audit C2, driver side: every FROST sign carries a signing intent the driver signed with its own
  * mTLS key, which the cosigners verify independently. Real mutual-TLS gRPC servers on localhost
  * stand in for the cosigners and record what they receive; the driver code is the production one.
  */
class FrostSigningIntentSpec extends AnyWordSpec with Matchers with BeforeAndAfterAll with org.scalatest.LoneElement {

  import FrostSigningIntentSpec._

  private implicit val ec: ExecutionContext = ExecutionContext.global
  private val logger = LoggerFactory.getLogger(classOf[FrostSigningIntentSpec])
  private val dir: Path = Files.createTempDirectory("rutli-intent")

  private val Cluster = "c2testcluster000"
  private val Key = "frost-participant1-namespace"
  private val Digest: Array[Byte] = Array[Byte](0x12, 0x20) ++ Array.fill(32)(0x5a.toByte)
  private val Group = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
  private val GroupRaw: Array[Byte] = Group.getPublic.getEncoded.takeRight(32)
  private def ed25519(msg: Array[Byte]): Array[Byte] = {
    val s = java.security.Signature.getInstance("Ed25519"); s.initSign(Group.getPrivate); s.update(msg); s.sign()
  }

  private val ca = newCa()
  private val driver = issue(ca, "driver", None)
  private val caFile = write("ca.crt", pemOf("CERTIFICATE", ca.cert.getEncoded))
  private val tls = FrostTlsConfig(caFile, write("driver.crt", driver.certPem), write("driver.key", driver.keyPem))

  /** A cosigner stand-in: reports `clusterId`, answers the group key, records every Sign request,
    * and fails the first `failSigns` of them with UNAVAILABLE. */
  private final class Recorder(@volatile var clusterId: String, failSigns: Int = 0) extends SignerGrpc.SignerImplBase {
    /** Refuse an intent for any other cluster, as a cosigner does (intent.rs, reason "cluster"). */
    @volatile var accept: Option[String] = None
    val signs = new ConcurrentLinkedQueue[SignRequest]()
    val deletes = new ConcurrentLinkedQueue[DeleteKeyRequest]()
    override def deleteKey(req: DeleteKeyRequest, obs: StreamObserver[DeleteKeyReply]): Unit = {
      deletes.add(req)
      obs.onNext(DeleteKeyReply.newBuilder().setDeleted(true).setTombstones(3).build()); obs.onCompleted()
    }
    private val failed = new AtomicInteger(0)
    override def capabilities(req: CapabilitiesRequest, obs: StreamObserver[CapabilitiesReply]): Unit = {
      obs.onNext(CapabilitiesReply.newBuilder().setClusterId(clusterId).build()); obs.onCompleted()
    }
    override def groupKey(req: GroupKeyRequest, obs: StreamObserver[GroupKeyReply]): Unit = {
      obs.onNext(GroupKeyReply.newBuilder().setGroupVerifyingKey(ByteString.copyFrom(GroupRaw)).build()); obs.onCompleted()
    }
    override def sign(req: SignRequest, obs: StreamObserver[SignReply]): Unit = {
      signs.add(req)
      val named = if (req.hasIntent) Some(SignIntent.parseFrom(req.getIntent.getIntent).getClusterId) else None
      if (accept.isDefined && named.isDefined && named != accept)
        obs.onError(
          Status.PERMISSION_DENIED
            .withDescription(s"signing intent refused: intent is for cluster \"${named.get}\", this is ${accept.get}")
            .asRuntimeException()
        )
      else if (failed.getAndIncrement() < failSigns) obs.onError(Status.UNAVAILABLE.withDescription("test: down").asRuntimeException())
      else {
        obs.onNext(SignReply.newBuilder().setSignature(ByteString.copyFrom(ed25519(req.getMessage.toByteArray))).build())
        obs.onCompleted()
      }
    }
  }

  private var servers: List[Server] = Nil
  override protected def afterAll(): Unit = { servers.foreach(_.shutdownNow()); super.afterAll() }

  private def serve(name: String, svc: Recorder): String = {
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

  private def backend(eps: Seq[(String, String)], clusterId: Option[String] = None, signIntents: Boolean = true) =
    new FrostBackend(eps.map(_._1), new NoDelegateBackend, logger, Some(tls), 10.seconds,
      endpointTlsNames = eps.toMap, clusterId = clusterId, signIntents = signIntents)

  private def decode(i: SignedIntent): SignIntent = SignIntent.parseFrom(i.getIntent)

  /** What a cosigner checks first: the signature over the context and the intent bytes, by the
    * leaf of the chain, and that the leaf is the driver's certificate. */
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

  "FrostBackend.sign" should {

    "carry a signing intent, signed with the driver's mTLS key, for exactly this sign" in {
      val rec = new Recorder(Cluster)
      val b = backend(Seq(serve("cosigner1", rec) -> "cosigner1"))
      try {
        val notes = new AuditNotes
        val sig = Await.result(b.withAuditNotes(notes)(b.sign(Digest, Key, SigningAlgoSpec.Ed25519)), 20.seconds)
        sig shouldBe ed25519(Digest)
        val req = rec.signs.asScala.toList.loneElement
        req.hasIntent shouldBe true
        verifies(req.getIntent) shouldBe true
        req.getIntent.getSignatureAlg shouldBe "ecdsa-p256-sha256"
        val i = decode(req.getIntent)
        i.getVersion shouldBe 1
        i.getClusterId shouldBe Cluster
        i.getPurpose shouldBe "sign"
        i.getKeyId shouldBe Key
        i.getDigest.toByteArray shouldBe Digest
        i.getRequestId.size shouldBe 16
        (i.getNotAfterMs - i.getIssuedAtMs) shouldBe 180000L
        math.abs(i.getIssuedAtMs - System.currentTimeMillis()) should be < 60000L
        i.getApprovalsCount shouldBe 0
        // The audit entry names the request the cosigners journal.
        notes.render should include(s"intent=${hex(i.getRequestId.toByteArray)}")
      } finally b.close()
    }

    "send the SAME intent to every leader it fails over to (one charge, one journal request)" in {
      val (down, up) = (new Recorder(Cluster, failSigns = 1), new Recorder(Cluster))
      val b = backend(Seq(serve("cosigner1", down) -> "cosigner1", serve("cosigner2", up) -> "cosigner2"))
      try {
        Await.result(b.sign(Digest, Key, SigningAlgoSpec.Ed25519), 20.seconds) shouldBe ed25519(Digest)
        val first = down.signs.asScala.toList.loneElement.getIntent
        val second = up.signs.asScala.toList.loneElement.getIntent
        first shouldBe second
        // ...and a new sign is a new request.
        Await.result(b.sign(Digest, Key, SigningAlgoSpec.Ed25519), 20.seconds)
        val third = up.signs.asScala.toList.last.getIntent
        decode(third).getRequestId should not be decode(first).getRequestId
      } finally b.close()
    }

    "carry the approvals the approval gate collected" in {
      val rec = new Recorder(Cluster)
      val b = backend(Seq(serve("cosigner1", rec) -> "cosigner1"))
      try {
        val proof = ApprovalProof(Array.fill(16)(9.toByte), Seq("alice" -> Array.fill(64)(1.toByte), "bob" -> Array.fill(64)(2.toByte)))
        Await.result(b.sign(Digest, Key, SigningAlgoSpec.Ed25519, proof), 20.seconds)
        val i = decode(rec.signs.asScala.toList.loneElement.getIntent)
        i.getApprovalNonce.toByteArray shouldBe Array.fill(16)(9.toByte)
        i.getApprovalsList.asScala.map(a => a.getApproverId -> a.getSignature.toByteArray.head).toList shouldBe
          List("alice" -> 1.toByte, "bob" -> 2.toByte)
      } finally b.close()
    }

    "use a configured cluster id over the cluster's, and sign without an intent while none is known" in {
      val rec = new Recorder("")
      val b = backend(Seq(serve("cosigner1", rec) -> "cosigner1"))
      try {
        val notes = new AuditNotes
        Await.result(b.withAuditNotes(notes)(b.sign(Digest, Key, SigningAlgoSpec.Ed25519)), 20.seconds)
        rec.signs.asScala.toList.loneElement.hasIntent shouldBe false
        notes.render should include("intent=none")
      } finally b.close()
      val rec2 = new Recorder("")
      val pinned = backend(Seq(serve("cosigner2", rec2) -> "cosigner2"), clusterId = Some("pinnedcluster000"))
      try {
        Await.result(pinned.sign(Digest, Key, SigningAlgoSpec.Ed25519), 20.seconds)
        decode(rec2.signs.asScala.toList.loneElement.getIntent).getClusterId shouldBe "pinnedcluster000"
      } finally pinned.close()
    }
  }

  "FrostBackend's cluster id (audit F5)" should {

    "be what a majority of the cosigners report, never one cosigner's word" in {
      val recs = Seq(new Recorder(Cluster), new Recorder("liarcluster00000"), new Recorder(Cluster))
      val b = backend(recs.zipWithIndex.map { case (r, i) => serve(s"cosigner${i + 1}", r) -> s"cosigner${i + 1}" })
      try {
        Await.result(b.sign(Digest, Key, SigningAlgoSpec.Ed25519), 20.seconds)
        val sent = recs.flatMap(_.signs.asScala).loneElement
        decode(sent.getIntent).getClusterId shouldBe Cluster
      } finally b.close()
      // Two endpoints that disagree: no majority, no intent (and a loud error) — not the first one's.
      val split = Seq(new Recorder("liarcluster00000"), new Recorder(Cluster))
      val b2 = backend(split.zipWithIndex.map { case (r, i) => serve(s"cosigner${i + 1}", r) -> s"cosigner${i + 1}" })
      try {
        val notes = new AuditNotes
        Await.result(b2.withAuditNotes(notes)(b2.sign(Digest, Key, SigningAlgoSpec.Ed25519)), 20.seconds)
        split.flatMap(_.signs.asScala).loneElement.hasIntent shouldBe false
        notes.render should include("intent=none")
      } finally b2.close()
    }

    "be learned again when a cosigner refuses the intent for its cluster" in {
      val recs = Seq(new Recorder("oldcluster000000"), new Recorder("oldcluster000000"))
      val b = backend(recs.zipWithIndex.map { case (r, i) => serve(s"cosigner${i + 1}", r) -> s"cosigner${i + 1}" })
      try {
        Await.result(b.sign(Digest, Key, SigningAlgoSpec.Ed25519), 20.seconds)
        // The cluster's id changes (or the learned one was wrong): the cosigners refuse the old one.
        recs.foreach { r => r.clusterId = Cluster; r.accept = Some(Cluster) }
        val notes = new AuditNotes
        Await.result(b.withAuditNotes(notes)(b.sign(Digest, Key, SigningAlgoSpec.Ed25519)), 20.seconds) shouldBe ed25519(Digest)
        decode(recs.flatMap(_.signs.asScala).last.getIntent).getClusterId shouldBe Cluster
        notes.render should include("intent-cluster=relearned")
      } finally b.close()
      // A configured id is never "re-learned": the refusal is the answer.
      val rec = new Recorder(Cluster)
      rec.accept = Some(Cluster)
      val pinned = backend(Seq(serve("cosigner3", rec) -> "cosigner3"), clusterId = Some("pinnedcluster000"))
      try {
        val e = intercept[Exception](Await.result(pinned.sign(Digest, Key, SigningAlgoSpec.Ed25519), 20.seconds))
        e.getMessage should include("intent is for cluster")
        rec.signs.size shouldBe 1
      } finally pinned.close()
    }

    "not be attached at all with frost.sign-intents = off" in {
      val rec = new Recorder(Cluster)
      val b = backend(Seq(serve("cosigner1", rec) -> "cosigner1"), signIntents = false)
      try {
        val notes = new AuditNotes
        Await.result(b.withAuditNotes(notes)(b.sign(Digest, Key, SigningAlgoSpec.Ed25519)), 20.seconds)
        rec.signs.asScala.toList.loneElement.hasIntent shouldBe false
        notes.render should include("intent=off")
      } finally b.close()
      com.stakecraft.rutli.FrostConfig(signIntents = "off").signIntentsEnabled shouldBe false
      com.stakecraft.rutli.FrostConfig().signIntentsEnabled shouldBe true
      an[IllegalArgumentException] should be thrownBy com.stakecraft.rutli.FrostConfig(signIntents = "maybe").signIntentsEnabled
    }
  }

  "FrostBackend.deleteKey" should {
    "carry a delete intent (purpose delete-key, the delete digest), signed with the driver's mTLS key" in {
      val rec = new Recorder(Cluster)
      val b = backend(Seq(serve("cosigner1", rec) -> "cosigner1"))
      try {
        Await.result(b.deleteKey("rutli-enc-1"), 20.seconds)
        val req = rec.deletes.asScala.toList.loneElement
        req.getKeyId shouldBe "rutli-enc-1"
        verifies(req.getIntent) shouldBe true
        val i = decode(req.getIntent)
        i.getPurpose shouldBe "delete-key"
        i.getClusterId shouldBe Cluster
        i.getKeyId shouldBe "rutli-enc-1"
        i.getDigest.toByteArray shouldBe FrostIntentSigner.deleteDigest("rutli-enc-1")
        i.getRequestId.size shouldBe 16
      } finally b.close()
    }

    "compute the delete digest exactly as the cosigners do (golden vector shared with intent.rs)" in {
      hex(FrostIntentSigner.deleteDigest("participant1-rutli-enc-golden")) shouldBe
        "10e118018ec6f17f27279a2c5030ae03c65ade57a2174b5f097cb4a5d00c3877"
    }
  }

  "FrostIntentSigner.load" should {
    "refuse a key that does not belong to the certificate" in {
      val other = issue(ca, "driver", None)
      val err = intercept[IllegalArgumentException](FrostIntentSigner.load(tls.cert, write("other.key", other.keyPem)))
      err.getMessage should include("does not belong")
    }
  }

  private def write(name: String, content: String): String = {
    val p = dir.resolve(name); Files.write(p, content.getBytes(US_ASCII)); p.toString
  }
}

object FrostSigningIntentSpec {
  final case class Ca(name: X500Name, keys: KeyPair, cert: X509Certificate)
  final case class Leaf(cert: X509Certificate, certPem: String, keyPem: String)

  def hex(b: Array[Byte]): String = b.map("%02x".format(_)).mkString

  private def ecKeys(): KeyPair = {
    val g = KeyPairGenerator.getInstance("EC"); g.initialize(new ECGenParameterSpec("secp256r1")); g.generateKeyPair()
  }
  private val notBefore = new Date(System.currentTimeMillis() - 3600 * 1000L)
  private val notAfter = new Date(System.currentTimeMillis() + 24 * 3600 * 1000L)

  def newCa(): Ca = {
    val name = new X500Name("CN=rutli-test-ca")
    val keys = ecKeys()
    val b = new JcaX509v3CertificateBuilder(name, BigInteger.ONE, notBefore, notAfter, name, keys.getPublic)
    b.addExtension(Extension.basicConstraints, true, new BasicConstraints(true))
    b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign))
    val cert = new JcaX509CertificateConverter().getCertificate(b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(keys.getPrivate)))
    Ca(name, keys, cert)
  }

  def issue(ca: Ca, cn: String, sanDns: Option[String]): Leaf = {
    val keys = ecKeys()
    val b = new JcaX509v3CertificateBuilder(
      ca.name, new BigInteger(64, new java.security.SecureRandom()), notBefore, notAfter, new X500Name(s"CN=$cn"), keys.getPublic
    )
    b.addExtension(Extension.basicConstraints, true, new BasicConstraints(false))
    b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature))
    b.addExtension(Extension.extendedKeyUsage, false,
      new ExtendedKeyUsage(Array(KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth)))
    sanDns.foreach(d => b.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(new GeneralName(GeneralName.dNSName, d))))
    val cert = new JcaX509CertificateConverter().getCertificate(b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(ca.keys.getPrivate)))
    Leaf(cert, pemOf("CERTIFICATE", cert.getEncoded), pemOf("PRIVATE KEY", keys.getPrivate.getEncoded))
  }

  def pemOf(label: String, der: Array[Byte]): String =
    s"-----BEGIN $label-----\n" + Base64.getMimeEncoder(64, "\n".getBytes(US_ASCII)).encodeToString(der) + s"\n-----END $label-----\n"
}
