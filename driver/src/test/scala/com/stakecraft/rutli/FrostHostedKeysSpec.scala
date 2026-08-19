// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli

import com.digitalasset.canton.crypto.kms.driver.api.v1._
import com.stakecraft.rutli.backend.{FrostBackend, KmsBackend, NoDelegateBackend}
import com.stakecraft.rutli.grpc._
import io.grpc.inprocess.{InProcessChannelBuilder, InProcessServerBuilder}
import io.grpc.stub.StreamObserver
import io.grpc.Status
import com.google.protobuf.ByteString
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import org.slf4j.LoggerFactory

import scala.collection.mutable
import scala.concurrent.duration._
import scala.concurrent.{Await, ExecutionContext, Future}

/** Driver-side routing for cluster-hosted (non-FROST) keys, against an in-process fake cosigner.
  *
  * The Rust side has its own end-to-end coverage; what matters here is that the driver sends the
  * right RPC for the right key id, never leaks a hosted-key operation to the delegate, and does not
  * fall back to the delegate when the cluster says a key is missing (that would silently split
  * custody — the failure mode the whole feature exists to prevent).
  */
class FrostHostedKeysSpec extends AnyWordSpec with Matchers {

  private implicit val ec: ExecutionContext = ExecutionContext.global
  private val logger = LoggerFactory.getLogger(classOf[FrostHostedKeysSpec])
  private def await[T](f: scala.concurrent.Future[T]): T = Await.result(f, 10.seconds)

  /** Minimal in-process Signer: records calls and serves hosted-key ops from a map. */
  private class FakeCluster(hostedEnabled: Boolean = true, specs: Seq[String] = Seq("rsa-2048-oaep-sha256", "aes-256-gcm"))
      extends SignerGrpc.SignerImplBase {
    val calls: mutable.Buffer[String] = mutable.Buffer.empty
    private val keys = mutable.Map.empty[String, String] // key id -> spec

    override def capabilities(
        req: CapabilitiesRequest,
        obs: StreamObserver[CapabilitiesReply],
    ): Unit = {
      calls += "capabilities"
      val b = CapabilitiesReply.newBuilder().setHostedKeysEnabled(hostedEnabled)
      specs.foreach(b.addHostedKeySpecs)
      obs.onNext(b.build()); obs.onCompleted()
    }

    override def generateKey(req: GenerateKeyRequest, obs: StreamObserver[GenerateKeyReply]): Unit = {
      calls += s"generateKey:${req.getSpec}"
      val created = !keys.contains(req.getKeyId)
      keys(req.getKeyId) = req.getSpec
      obs.onNext(
        GenerateKeyReply
          .newBuilder()
          .setKeyId(req.getKeyId)
          .setSpec(req.getSpec)
          .setPublicKeyDer(ByteString.copyFrom(Array[Byte](1, 2, 3)))
          .setCreated(created)
          .setReplicas(3)
          .build()
      )
      obs.onCompleted()
    }

    override def decrypt(req: DecryptRequest, obs: StreamObserver[DecryptReply]): Unit = {
      calls += "decrypt"
      if (!keys.contains(req.getKeyId)) obs.onError(Status.NOT_FOUND.asRuntimeException())
      else {
        obs.onNext(DecryptReply.newBuilder().setPlaintext(ByteString.copyFromUtf8("plaintext")).build())
        obs.onCompleted()
      }
    }

    override def symmetricEncrypt(req: SymmetricRequest, obs: StreamObserver[SymmetricReply]): Unit = {
      calls += "symmetricEncrypt"
      obs.onNext(SymmetricReply.newBuilder().setData(ByteString.copyFromUtf8("sealed")).build())
      obs.onCompleted()
    }

    override def symmetricDecrypt(req: SymmetricRequest, obs: StreamObserver[SymmetricReply]): Unit = {
      calls += "symmetricDecrypt"
      obs.onNext(SymmetricReply.newBuilder().setData(ByteString.copyFromUtf8("opened")).build())
      obs.onCompleted()
    }

    override def publicKey(req: PublicKeyRequest, obs: StreamObserver[PublicKeyReply]): Unit = {
      calls += "publicKey"
      obs.onNext(
        PublicKeyReply
          .newBuilder()
          .setSpec("rsa-2048-oaep-sha256")
          .setPublicKeyDer(ByteString.copyFrom(Array[Byte](4, 5, 6)))
          .build()
      )
      obs.onCompleted()
    }

    override def keyInfo(req: KeyInfoRequest, obs: StreamObserver[KeyInfoReply]): Unit = {
      calls += "keyInfo"
      obs.onNext(KeyInfoReply.newBuilder().setExists(keys.contains(req.getKeyId)).setReplicas(3).build())
      obs.onCompleted()
    }

    override def deleteKey(req: DeleteKeyRequest, obs: StreamObserver[DeleteKeyReply]): Unit = {
      calls += "deleteKey"
      val existed = keys.remove(req.getKeyId).isDefined
      obs.onNext(DeleteKeyReply.newBuilder().setDeleted(existed).build())
      obs.onCompleted()
    }
  }

  /** A delegate that fails on every call — proves an op reached the cluster, not the delegate. */
  private class TripwireDelegate extends KmsBackend {
    override val supportedSigningKeySpecs: Set[SigningKeySpec] = Set.empty
    override val supportedSigningAlgoSpecs: Set[SigningAlgoSpec] = Set.empty
    override val supportedEncryptionKeySpecs: Set[EncryptionKeySpec] = Set.empty
    override val supportedEncryptionAlgoSpecs: Set[EncryptionAlgoSpec] = Set.empty
    protected def boom[A](op: String): Future[A] =
      Future.failed(new AssertionError(s"$op must not reach the delegate"))
    // Explicit return types: subclasses below override some of these with real answers, which is
    // impossible if the inferred type is Future[Nothing].
    override def generateSigningKeyPair(s: SigningKeySpec, n: Option[String]): Future[String] =
      boom("generateSigningKeyPair")
    override def generateEncryptionKeyPair(s: EncryptionKeySpec, n: Option[String]): Future[String] =
      boom("generateEncryptionKeyPair")
    override def generateSymmetricKey(n: Option[String]): Future[String] = boom("generateSymmetricKey")
    override def sign(d: Array[Byte], k: String, a: SigningAlgoSpec): Future[Array[Byte]] = boom("sign")
    override def decryptAsymmetric(c: Array[Byte], k: String, a: EncryptionAlgoSpec): Future[Array[Byte]] =
      boom("decryptAsymmetric")
    override def encryptSymmetric(d: Array[Byte], k: String): Future[Array[Byte]] = boom("encryptSymmetric")
    override def decryptSymmetric(c: Array[Byte], k: String): Future[Array[Byte]] = boom("decryptSymmetric")
    override def getPublicKey(k: String): Future[PublicKey] = boom("getPublicKey")
    override def keyExistsAndIsActive(k: String): Future[Unit] = boom("keyExistsAndIsActive")
    override def deleteKey(k: String): Future[Unit] = boom("deleteKey")
    override def health: Future[KmsDriverHealth] = Future.successful(KmsDriverHealth.Ok)
  }

  private def withCluster[A](fake: FakeCluster, delegate: KmsBackend = new TripwireDelegate)(
      body: FrostBackend => A
  ): A = {
    val serverName = InProcessServerBuilder.generateName()
    val srv = InProcessServerBuilder.forName(serverName).directExecutor().addService(fake).build().start()
    // FrostBackend builds its own channel from the endpoint string, so point it at the in-process
    // name via the same plaintext path a dev deployment uses.
    val backend = new FrostBackend(Seq(serverName), delegate, logger, None, 10.seconds, hostedKeys = true) {
      override protected def buildChannel(endpoint: String): io.grpc.ManagedChannel =
        InProcessChannelBuilder.forName(endpoint).directExecutor().build()
    }
    try body(backend)
    finally {
      backend.close()
      srv.shutdownNow()
    }
  }

  "FrostBackend with hosted keys" should {

    "generate an RSA encryption key on the cluster, not the delegate" in {
      val fake = new FakeCluster()
      withCluster(fake) { backend =>
        val keyId = await(backend.generateEncryptionKeyPair(EncryptionKeySpec.Rsa2048, Some("enc")))
        keyId should startWith("rutli-enc")
        fake.calls should contain("generateKey:rsa-2048-oaep-sha256")
      }
    }

    "generate a symmetric key on the cluster" in {
      val fake = new FakeCluster()
      withCluster(fake) { backend =>
        val keyId = await(backend.generateSymmetricKey(Some("wrap")))
        keyId should startWith("rutli-sym")
        fake.calls should contain("generateKey:aes-256-gcm")
      }
    }

    "route decrypt, symmetric crypto, public key and delete for rutli- keys to the cluster" in {
      val fake = new FakeCluster()
      withCluster(fake) { backend =>
        val keyId = await(backend.generateEncryptionKeyPair(EncryptionKeySpec.Rsa2048, None))
        await(backend.decryptAsymmetric(Array[Byte](1), keyId, EncryptionAlgoSpec.RsaEsOaepSha256)) shouldBe
          "plaintext".getBytes
        await(backend.getPublicKey(keyId)).key shouldBe Array[Byte](4, 5, 6)
        await(backend.keyExistsAndIsActive(keyId))

        val symId = await(backend.generateSymmetricKey(None))
        await(backend.encryptSymmetric(Array[Byte](1), symId)) shouldBe "sealed".getBytes
        await(backend.decryptSymmetric(Array[Byte](1), symId)) shouldBe "opened".getBytes

        // Unlike the non-rotatable namespace key, hosted keys are deletable.
        await(backend.deleteKey(keyId))
        fake.calls should contain("deleteKey")
      }
    }

    "advertise the encryption specs the cluster reports" in {
      val fake = new FakeCluster()
      withCluster(fake) { backend =>
        backend.supportedEncryptionKeySpecs should contain(EncryptionKeySpec.Rsa2048)
        backend.supportedEncryptionAlgoSpecs should contain(EncryptionAlgoSpec.RsaEsOaepSha256)
        // Ed25519 signing is still the cluster's, via FROST.
        backend.supportedSigningKeySpecs should contain(SigningKeySpec.EcCurve25519)
      }
    }

    "fall back to the delegate when the cluster reports hosted keys disabled" in {
      // A driver configured for hosted keys against a cluster that has them off must not pretend to
      // serve them — it must keep using the delegate, and say so.
      val fake = new FakeCluster(hostedEnabled = false)
      val delegate = new SoftwareBackendProbe
      withCluster(fake, delegate) { backend =>
        val keyId = await(backend.generateEncryptionKeyPair(EncryptionKeySpec.Rsa2048, None))
        keyId shouldBe "delegate-key"
        fake.calls should not contain "generateKey:rsa-2048-oaep-sha256"
      }
    }

    "never fall back to the delegate when the cluster says a hosted key is missing" in {
      // Falling back here would silently create split custody: Canton would get a *different* key
      // under the same logical role, exactly the class of failure hosted keys exist to prevent.
      val fake = new FakeCluster()
      withCluster(fake) { backend =>
        val err = intercept[Exception] {
          await(backend.decryptAsymmetric(Array[Byte](1), "rutli-enc-unknown", EncryptionAlgoSpec.RsaEsOaepSha256))
        }
        err.getMessage should include("NOT_FOUND")
      }
    }

    "leave non-rutli keys to the delegate" in {
      val fake = new FakeCluster()
      val delegate = new SoftwareBackendProbe
      withCluster(fake, delegate) { backend =>
        await(backend.decryptAsymmetric(Array[Byte](1), "enc-legacy-hsm-key", EncryptionAlgoSpec.RsaEsOaepSha256))
        delegate.decrypted shouldBe true
        fake.calls should not contain "decrypt"
      }
    }
  }

  "NoDelegateBackend" should {
    "refuse every operation with an actionable message" in {
      val nd = new NoDelegateBackend
      nd.supportedEncryptionKeySpecs shouldBe empty
      val err = intercept[UnsupportedOperationException] {
        await(nd.decryptAsymmetric(Array[Byte](1), "stray-key", EncryptionAlgoSpec.RsaEsOaepSha256))
      }
      err.getMessage should include("delegate = \"none\"")
      err.getMessage should include("stray-key")
    }
  }

  /** A delegate that answers instead of exploding, for the fallback cases. */
  private class SoftwareBackendProbe extends TripwireDelegate {
    var decrypted = false
    override val supportedEncryptionKeySpecs: Set[EncryptionKeySpec] = Set(EncryptionKeySpec.Rsa2048)
    override val supportedEncryptionAlgoSpecs: Set[EncryptionAlgoSpec] = Set(EncryptionAlgoSpec.RsaEsOaepSha256)
    override def generateEncryptionKeyPair(
        s: EncryptionKeySpec,
        n: Option[String],
    ): Future[String] = Future.successful("delegate-key")
    override def decryptAsymmetric(
        c: Array[Byte],
        k: String,
        a: EncryptionAlgoSpec,
    ): Future[Array[Byte]] = {
      decrypted = true
      Future.successful(Array[Byte](9))
    }
  }
}
