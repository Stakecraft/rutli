// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli

import com.digitalasset.canton.crypto.kms.driver.api.v1._
import com.google.protobuf.ByteString
import com.stakecraft.rutli.backend.{FrostBackend, NoDelegateBackend}
import com.stakecraft.rutli.grpc._
import io.grpc.netty.shaded.io.grpc.netty.{GrpcSslContexts, NettyServerBuilder}
import io.grpc.netty.shaded.io.netty.handler.ssl.{ClientAuth, SslContextBuilder}
import io.grpc.stub.StreamObserver
import io.grpc.{Server, Status, StatusRuntimeException}
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509._
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.{JcaX509CertificateConverter, JcaX509ExtensionUtils, JcaX509v3CertificateBuilder}
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.scalatest.BeforeAndAfterAll
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import org.slf4j.LoggerFactory
import FrostTlsTrustBundleSpec._

import java.math.BigInteger
import java.nio.charset.StandardCharsets.US_ASCII
import java.nio.file.{Files, Path}
import java.security.spec.ECGenParameterSpec
import java.security.{KeyPair, KeyPairGenerator}
import java.util.Base64
import java.util.Date
import scala.concurrent.duration._
import scala.concurrent.{Await, ExecutionContext}

/** The driver's TLS channel accepts a multi-CA trust bundle: a `ca.crt` holding the old CA and the
  * new CA concatenated, which is what a zero-downtime cluster-CA rotation relies on.
  *
  * Real mutual-TLS gRPC server on localhost, driven through [[FrostBackend]]'s production
  * `buildChannel` (`GrpcSslContexts.forClient().trustManager(caCert).keyManager(cert, key)` with
  * `overrideAuthority`). No driver code is substituted; only the cosigner behind the listener is a
  * fake answering `Sign`.
  */
class FrostTlsTrustBundleSpec extends AnyWordSpec with Matchers with BeforeAndAfterAll {

  private implicit val ec: ExecutionContext = ExecutionContext.global
  private val logger = LoggerFactory.getLogger(classOf[FrostTlsTrustBundleSpec])

  private val Domain = "rutli-cosigner"
  private val Digest = Array.fill(34)(7.toByte)
  private val Signature = Array.fill(64)(9.toByte)

  private val dir: Path = Files.createTempDirectory("rutli-tls-bundle")

  // --- certificate material -------------------------------------------------------------------


  private def ecKeys(): KeyPair = {
    val g = KeyPairGenerator.getInstance("EC")
    g.initialize(new ECGenParameterSpec("secp256r1"))
    g.generateKeyPair()
  }

  private val notBefore = new Date(System.currentTimeMillis() - 3600 * 1000L)
  private val notAfter = new Date(System.currentTimeMillis() + 24 * 3600 * 1000L)
  private val extUtils = new JcaX509ExtensionUtils()

  private def newCa(
      cn: String,
      from: Date = notBefore,
      to: Date = notAfter,
      usage: Int = KeyUsage.keyCertSign | KeyUsage.cRLSign,
  ): Ca = {
    val name = new X500Name(s"CN=$cn")
    val keys = ecKeys()
    val b = new JcaX509v3CertificateBuilder(
      name, new BigInteger(64, new java.security.SecureRandom()), from, to, name, keys.getPublic
    )
    b.addExtension(Extension.basicConstraints, true, new BasicConstraints(true))
    b.addExtension(Extension.keyUsage, true, new KeyUsage(usage))
    b.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(keys.getPublic))
    val signer = new JcaContentSignerBuilder("SHA256withECDSA").build(keys.getPrivate)
    Ca(name, keys, b.build(signer))
  }

  private def issue(ca: Ca, cn: String, sanDns: Option[String], serverAuth: Boolean): Leaf = {
    val keys = ecKeys()
    val b = new JcaX509v3CertificateBuilder(
      ca.name, new BigInteger(64, new java.security.SecureRandom()), notBefore, notAfter, new X500Name(s"CN=$cn"),
      keys.getPublic
    )
    b.addExtension(Extension.basicConstraints, true, new BasicConstraints(false))
    b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature))
    val usages =
      (if (serverAuth) Seq(KeyPurposeId.id_kp_serverAuth) else Seq.empty) :+ KeyPurposeId.id_kp_clientAuth
    b.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(usages.toArray))
    sanDns.foreach { d =>
      b.addExtension(
        Extension.subjectAlternativeName, false, new GeneralNames(new GeneralName(GeneralName.dNSName, d))
      )
    }
    b.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(keys.getPublic))
    b.addExtension(
      Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(ca.keys.getPublic)
    )
    val signer = new JcaContentSignerBuilder("SHA256withECDSA").build(ca.keys.getPrivate)
    val cert = new JcaX509CertificateConverter().getCertificate(b.build(signer))
    // PKCS#8 ("BEGIN PRIVATE KEY") is what the driver and Netty expect; JCA's EC getEncoded is PKCS#8.
    Leaf(pemOf("CERTIFICATE", cert.getEncoded), pemOf("PRIVATE KEY", keys.getPrivate.getEncoded))
  }

  private def write(name: String, content: String): String = {
    val p = dir.resolve(name)
    Files.write(p, content.getBytes(US_ASCII))
    p.toString
  }

  private lazy val oldCa = newCa("rutli-frost-cluster-ca")
  private lazy val newerCa = newCa("rutli-frost-cluster-ca-2026-10")

  // --- the fake cosigner behind a real TLS listener -------------------------------------------

  private final class Signer extends SignerGrpc.SignerImplBase {
    override def sign(req: SignRequest, obs: StreamObserver[SignReply]): Unit = {
      obs.onNext(SignReply.newBuilder().setSignature(ByteString.copyFrom(Signature)).build())
      obs.onCompleted()
    }
  }

  private var servers: List[Server] = Nil

  override protected def afterAll(): Unit = {
    servers.foreach(_.shutdownNow())
    scala.util.Try {
      Files.walk(dir).sorted(java.util.Comparator.reverseOrder[Path]()).forEach(p => { Files.deleteIfExists(p); () })
    }
    super.afterAll()
  }

  /** Start an mTLS gRPC server (client auth REQUIRED) and return its port. */
  private def startServer(tag: String, leaf: Leaf, trustBundle: Seq[Ca]): Int = {
    val cert = write(s"$tag-server.crt", leaf.certPem)
    val key = write(s"$tag-server.key", leaf.keyPem)
    val trust = write(s"$tag-server-trust.crt", trustBundle.map(_.pem).mkString)
    val ssl = GrpcSslContexts
      .configure(
        SslContextBuilder
          .forServer(new java.io.File(cert), new java.io.File(key))
          .trustManager(new java.io.File(trust))
          .clientAuth(ClientAuth.REQUIRE)
      )
      .build()
    val server = NettyServerBuilder.forPort(0).sslContext(ssl).addService(new Signer).build().start()
    servers ::= server
    server.getPort
  }

  /** A cosigner leaf (CA=false) issued by `ca`, wrapped as a [[Ca]] so its key can issue in turn —
    * what whoever holds a leaf's key can do once that leaf sits in a trust file. */
  private def leafAsIssuer(ca: Ca, cn: String): Ca = {
    val name = new X500Name(s"CN=$cn")
    val keys = ecKeys()
    val b = new JcaX509v3CertificateBuilder(
      ca.name, new BigInteger(64, new java.security.SecureRandom()), notBefore, notAfter, name, keys.getPublic
    )
    b.addExtension(Extension.basicConstraints, true, new BasicConstraints(false))
    b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature))
    b.addExtension(
      Extension.subjectAlternativeName, false, new GeneralNames(new GeneralName(GeneralName.dNSName, Domain))
    )
    Ca(name, keys, b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(ca.keys.getPrivate)))
  }

  /** Drive one `Sign` through a production-built [[FrostBackend]] whose TLS config is the given files. */
  private def signVia(tag: String, port: Int, clientTrust: Seq[Ca], clientLeaf: Leaf): Array[Byte] =
    signViaTrust(tag, port, clientTrust.map(_.pem).mkString, clientLeaf)

  private def signViaTrust(
      tag: String,
      port: Int,
      trustPem: String,
      clientLeaf: Leaf,
      allowExpiredCa: Boolean = false,
  ): Array[Byte] = {
    val tls = FrostTlsConfig(
      caCert = write(s"$tag-client-ca.crt", trustPem),
      cert = write(s"$tag-client.crt", clientLeaf.certPem),
      key = write(s"$tag-client.key", clientLeaf.keyPem),
      domain = Some(Domain),
      allowExpiredCa = allowExpiredCa,
    )
    val backend = new FrostBackend(Seq(s"localhost:$port"), new NoDelegateBackend, logger, Some(tls), 10.seconds)
    try Await.result(backend.sign(Digest, "frost-ns", SigningAlgoSpec.Ed25519), 20.seconds)
    finally backend.close()
  }

  "FrostBackend's TLS channel with a multi-CA trust bundle" should {

    "accept a server issued by the NEW CA, and present a client cert issued by the OLD CA (old,new order)" in {
      val port = startServer("a", issue(newerCa, "cosigner1", Some(Domain), serverAuth = true), Seq(oldCa, newerCa))
      val client = issue(oldCa, "driver", None, serverAuth = false)
      signVia("a", port, Seq(oldCa, newerCa), client) shouldBe Signature
    }

    "accept a server issued by the OLD CA with the bundle in reverse order (new,old), client cert by the NEW CA" in {
      val port = startServer("b", issue(oldCa, "cosigner1", Some(Domain), serverAuth = true), Seq(newerCa, oldCa))
      val client = issue(newerCa, "driver", None, serverAuth = false)
      signVia("b", port, Seq(newerCa, oldCa), client) shouldBe Signature
    }

    "reject a server issued by the NEW CA when the client trusts only the OLD CA (negative control)" in {
      val port = startServer("c", issue(newerCa, "cosigner1", Some(Domain), serverAuth = true), Seq(oldCa, newerCa))
      val client = issue(oldCa, "driver", None, serverAuth = false)
      val err = intercept[StatusRuntimeException](signVia("c", port, Seq(oldCa), client))
      err.getStatus.getCode shouldBe Status.Code.UNAVAILABLE
    }
  }

  "FrostBackend's trust file (review M1)" should {

    "be refused at driver init when it holds a cosigner leaf, whose key could otherwise pose as any cosigner" in {
      // `cat ca.crt cosigner1.crt > ca.crt`: the cosigner1 key holder mints a "cosigner2" server
      // certificate issued by that leaf. rustls (the cosigners) trusted such an anchor; the JDK's
      // PKIX validator happens to refuse a non-CA anchor at the handshake (allowNonCaAnchor is off
      // by default), as an opaque UNAVAILABLE. The driver now refuses the file at init, by name.
      val leaf = leafAsIssuer(oldCa, "cosigner1")
      val port = startServer("m1", issue(leaf, "cosigner2", Some(Domain), serverAuth = true), Seq(oldCa))
      val client = issue(oldCa, "driver", None, serverAuth = false)
      val err = intercept[IllegalArgumentException](signViaTrust("m1", port, oldCa.pem + leaf.pem, client))
      err.getMessage should (include("certificate 1") and include("not a CA") and include("m1-client-ca.crt"))
      // With the trust file as it should be, the forged server is refused at the handshake.
      intercept[StatusRuntimeException](signVia("m1ok", port, Seq(oldCa), client)).getStatus.getCode shouldBe
        Status.Code.UNAVAILABLE
    }

    "be refused when a CA in it is expired or not yet valid, unless allow-expired-ca is set" in {
      val day = 24 * 3600 * 1000L
      val expired = newCa("expired-ca", new Date(System.currentTimeMillis() - 400 * day), new Date(System.currentTimeMillis() - day))
      val future = newCa("future-ca", new Date(System.currentTimeMillis() + 300 * day), new Date(System.currentTimeMillis() + 400 * day))
      val port = startServer("m1e", issue(newerCa, "cosigner1", Some(Domain), serverAuth = true), Seq(newerCa))
      val client = issue(newerCa, "driver", None, serverAuth = false)
      for ((tag, bad) <- Seq("m1x" -> expired, "m1f" -> future)) {
        val err = intercept[IllegalArgumentException](signViaTrust(tag, port, bad.pem + newerCa.pem, client))
        err.getMessage should (include("certificate 0") and include("expired or not yet valid") and include("allow-expired-ca"))
      }
      // The emergency override: the expired CA is accepted, the channel works.
      signViaTrust("m1xo", port, expired.pem + newerCa.pem, client, allowExpiredCa = true) shouldBe Signature
      // ...but never a non-CA.
      val leaf = leafAsIssuer(newerCa, "cosigner3")
      intercept[IllegalArgumentException](
        signViaTrust("m1lo", port, newerCa.pem + leaf.pem, client, allowExpiredCa = true)
      ).getMessage should include("not a CA")
    }

    "be refused when it holds a private key (never echoed), no certificate, or a malformed block" in {
      val port = startServer("m1k", issue(newerCa, "cosigner1", Some(Domain), serverAuth = true), Seq(newerCa))
      val client = issue(newerCa, "driver", None, serverAuth = false)
      val keyBody = client.keyPem.linesIterator.drop(1).next()
      val err = intercept[IllegalArgumentException](signViaTrust("m1k", port, newerCa.pem + client.keyPem, client))
      err.getMessage should (include("PEM block 1") and include("PRIVATE KEY") and not include keyBody)
      for (
        (tag, junk, needle) <- Seq(
          ("m1z", "", "no CERTIFICATE"),
          ("m1t", "not a pem\n", "no CERTIFICATE"),
          ("m1g", "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", "malformed"),
          ("m1u", "-----BEGIN CERTIFICATE-----\nAAAA\n", "unterminated"),
        )
      ) intercept[IllegalArgumentException](signViaTrust(tag, port, junk, client)).getMessage should include(needle)
      // A CA whose keyUsage does not allow certificate signing.
      val noSign = newCa("no-keycertsign-ca", usage = KeyUsage.digitalSignature)
      intercept[IllegalArgumentException](signViaTrust("m1n", port, newerCa.pem + noSign.pem, client)).getMessage should
        include("keyCertSign")
    }
  }
}

object FrostTlsTrustBundleSpec {

  final case class Ca(name: X500Name, keys: KeyPair, holder: X509CertificateHolder) {
    def pem: String = pemOf("CERTIFICATE", holder.getEncoded)
  }
  final case class Leaf(certPem: String, keyPem: String)

  def pemOf(label: String, der: Array[Byte]): String =
    s"-----BEGIN $label-----\n" +
      Base64.getMimeEncoder(64, "\n".getBytes(US_ASCII)).encodeToString(der) +
      s"\n-----END $label-----\n"
}
