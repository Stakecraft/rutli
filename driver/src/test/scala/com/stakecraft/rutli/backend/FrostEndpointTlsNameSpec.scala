// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli.backend

import com.stakecraft.rutli.FrostTlsConfig
import com.stakecraft.rutli.grpc._
import io.grpc.Server
import io.grpc.netty.shaded.io.grpc.netty.{GrpcSslContexts, NettyServerBuilder}
import io.grpc.netty.shaded.io.netty.handler.ssl.ClientAuth
import io.grpc.stub.StreamObserver
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.{BasicConstraints, Extension, GeneralName, GeneralNames}
import org.bouncycastle.cert.jcajce.{JcaX509CertificateConverter, JcaX509v3CertificateBuilder}
import org.bouncycastle.openssl.jcajce.{JcaPEMWriter, JcaPKCS8Generator}
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import org.slf4j.LoggerFactory

import java.io.{File, FileWriter}
import java.math.BigInteger
import java.net.InetSocketAddress
import java.nio.file.Files
import java.security.cert.X509Certificate
import java.security.{KeyPair, KeyPairGenerator}
import java.util.Date
import scala.concurrent.ExecutionContext
import scala.concurrent.duration._
import scala.util.Try

/** Audit M3, driver side: each endpoint is verified under its own TLS server name, so a cosigner's
  * certificate cannot answer at another cosigner's address. Real mTLS over loopback. */
class FrostEndpointTlsNameSpec extends AnyWordSpec with Matchers {

  private implicit val ec: ExecutionContext = ExecutionContext.global
  private val logger = LoggerFactory.getLogger(classOf[FrostEndpointTlsNameSpec])
  private val dir = Files.createTempDirectory("rutli-tls-names").toFile

  private def ecKey(): KeyPair = {
    val g = KeyPairGenerator.getInstance("EC"); g.initialize(256); g.generateKeyPair()
  }

  private def cert(subject: String, kp: KeyPair, issuer: String, issuerKey: KeyPair, sans: Seq[String], ca: Boolean): X509Certificate = {
    val now = System.currentTimeMillis()
    val b = new JcaX509v3CertificateBuilder(
      new X500Name(s"CN=$issuer"), BigInteger.valueOf(now), new Date(now - 60000), new Date(now + 86400000L),
      new X500Name(s"CN=$subject"), kp.getPublic,
    )
    b.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca))
    if (sans.nonEmpty)
      b.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(sans.map(n => new GeneralName(GeneralName.dNSName, n)).toArray))
    new JcaX509CertificateConverter().getCertificate(b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(issuerKey.getPrivate)))
  }

  private def pem(name: String, obj: AnyRef): File = {
    val f = new File(dir, name)
    val w = new JcaPEMWriter(new FileWriter(f)); w.writeObject(obj); w.close(); f
  }

  private val caKey = ecKey()
  private val caFile = pem("ca.crt", cert("test-ca", caKey, "test-ca", caKey, Nil, ca = true))

  /** A cosigner cert as gen-frost-certs.sh now issues it: CN and SAN `name`, no shared SAN. */
  private def leaf(name: String): (File, File) = {
    val kp = ecKey()
    (pem(s"$name.crt", cert(name, kp, "test-ca", caKey, Seq(name, "localhost"), ca = false)),
     pem(s"$name.key", new JcaPKCS8Generator(kp.getPrivate, null))) // PKCS#8, as gRPC wants
  }

  private object Healthy extends SignerGrpc.SignerImplBase {
    override def health(req: HealthRequest, obs: StreamObserver[HealthReply]): Unit = {
      obs.onNext(HealthReply.newBuilder().setOk(true).build()); obs.onCompleted()
    }
  }

  private def serve(name: String): Server = {
    val (c, k) = leaf(name)
    val ssl = GrpcSslContexts.forServer(c, k).trustManager(caFile).clientAuth(ClientAuth.REQUIRE).build()
    NettyServerBuilder.forAddress(new InetSocketAddress("127.0.0.1", 0)).sslContext(ssl).addService(Healthy).build().start()
  }

  private val (driverCrt, driverKey) = leaf("driver")
  private def tls(domain: Option[String]) = FrostTlsConfig(caFile.getPath, driverCrt.getPath, driverKey.getPath, domain)

  /** Exposes the real channel builder; Health over each endpoint's channel says whether its
    * handshake (server-name check included) succeeded. */
  private final class Probe(eps: Seq[String], names: Map[String, String], domain: Option[String])
      extends FrostBackend(eps, new NoDelegateBackend, logger, Some(tls(domain)), 5.seconds, endpointTlsNames = names) {
    def ok(ep: String): Boolean = {
      val ch = buildChannel(ep)
      try Try(SignerGrpc.newBlockingStub(ch).withDeadlineAfter(5, java.util.concurrent.TimeUnit.SECONDS)
        .health(HealthRequest.newBuilder().build()).getOk).getOrElse(false)
      finally ch.shutdownNow()
    }
  }

  "the driver's TLS channels" should {
    "verify each endpoint under its own tls-name and refuse another cosigner's certificate" in {
      val s1 = serve("cosigner1")
      val s2 = serve("cosigner2")
      try {
        val (e1, e2) = (s"127.0.0.1:${s1.getPort}", s"127.0.0.1:${s2.getPort}")
        val right = new Probe(Seq(e1, e2), Map(e1 -> "cosigner1", e2 -> "cosigner2"), None)
        try { right.ok(e1) shouldBe true; right.ok(e2) shouldBe true }
        finally right.close()
        // Endpoint 2 is answered by cosigner2's certificate, but this driver expects cosigner1
        // there (as if cosigner2 squatted on cosigner1's address): the handshake must fail.
        val swapped = new Probe(Seq(e1, e2), Map(e1 -> "cosigner1", e2 -> "cosigner1"), None)
        try { swapped.ok(e1) shouldBe true; swapped.ok(e2) shouldBe false }
        finally swapped.close()
      } finally { s1.shutdownNow(); s2.shutdownNow() }
    }

    "fall back to tls.domain for a bare endpoint, as before" in {
      val s1 = serve("cosigner1")
      try {
        val e1 = s"127.0.0.1:${s1.getPort}"
        val legacy = new Probe(Seq(e1), Map.empty, Some("cosigner1"))
        try { legacy.tlsServerName(e1) shouldBe Some("cosigner1"); legacy.ok(e1) shouldBe true }
        finally legacy.close()
        // A per-endpoint name wins over the shared domain.
        val both = new Probe(Seq(e1), Map(e1 -> "cosigner1"), Some("rutli-cosigner"))
        try { both.tlsServerName(e1) shouldBe Some("cosigner1"); both.ok(e1) shouldBe true }
        finally both.close()
        // A shared domain the new cert does not carry fails, which is why rc.2 configs name each endpoint.
        val stale = new Probe(Seq(e1), Map.empty, Some("rutli-cosigner"))
        try stale.ok(e1) shouldBe false
        finally stale.close()
      } finally s1.shutdownNow()
    }
  }
}
