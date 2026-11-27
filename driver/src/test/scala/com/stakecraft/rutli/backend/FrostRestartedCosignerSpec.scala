// Copyright 2026 StakeCraft LLC
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli.backend

import com.digitalasset.canton.crypto.kms.driver.api.v1._
import com.google.protobuf.ByteString
import com.stakecraft.rutli.audit.AuditNotes
import com.stakecraft.rutli.grpc._
import io.grpc.inprocess.{InProcessChannelBuilder, InProcessServerBuilder, InProcessSocketAddress}
import io.grpc.stub.StreamObserver
import io.grpc.{
  EquivalentAddressGroup,
  ManagedChannel,
  NameResolver,
  NameResolverProvider,
  NameResolverRegistry,
  Server,
  Status,
  StatusOr,
  StatusRuntimeException,
}
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import org.slf4j.LoggerFactory

import java.net.{ConnectException, SocketAddress, URI}
import java.security.{KeyPair, KeyPairGenerator, Signature}
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import scala.concurrent.duration._
import scala.concurrent.{Await, ExecutionContext, Future}
import scala.util.Try

/** A cosigner that restarts while another one leads comes back under another address (a pod under
  * a new IP), and nothing is sent over its channel until the leader fails: gRPC then still holds
  * the address it resolved when the connection closed. The first call over such a channel fails
  * before anything is sent, and only that failure makes the channel resolve the name again. A sign
  * that fails over at that moment must not end with "no cosigner left to try" while cosigners are
  * up: the walk asks again the endpoints its request was never sent to.
  *
  * The cosigners here are real gRPC servers behind a name the test resolves itself, so the channel,
  * its load balancer and its reconnect logic are gRPC's own; the transport is the in-process one.
  */
class FrostRestartedCosignerSpec extends AnyWordSpec with Matchers {

  import FrostRestartedCosignerSpec._

  private implicit val ec: ExecutionContext = ExecutionContext.global
  private val logger = LoggerFactory.getLogger(classOf[FrostRestartedCosignerSpec])
  private def await[T](f: Future[T]): T = Await.result(f, 20.seconds)

  private val FrostKey = "frost-ns"
  private val Digest: Array[Byte] = Array.fill(34)(7.toByte)
  private val AttemptDeadline = 2.seconds

  /** Three cosigners behind resolved names, a backend over them with the key pinned and one sign
    * served by the first endpoint, which therefore leads. */
  private def withCluster[A](transport: Transport)(body: (FrostBackend, IndexedSeq[Cosigner]) => A): A = {
    val cosigners = (0 until 3).map(_ => new Cosigner(transport))
    val backend =
      new FrostBackend(
        cosigners.map(_.target),
        new NoDelegateBackend,
        logger,
        None,
        10.seconds,
        signAttemptTimeout = AttemptDeadline,
      ) {
        override protected def buildChannel(endpoint: String): ManagedChannel = transport.channel(endpoint)
      }
    try {
      cosigners.foreach(_.start())
      await(backend.getPublicKey(FrostKey))
      await(backend.sign(Digest, FrostKey, SigningAlgoSpec.Ed25519))
      cosigners.map(_.signs.get) shouldBe Seq(1, 0, 0)
      body(backend, cosigners)
    } finally
      try backend.close()
      finally cosigners.foreach(_.close())
  }

  private def sign(backend: FrostBackend): (Try[Array[Byte]], String) = {
    val notes = new AuditNotes
    val result = Try(await(backend.withAuditNotes(notes)(backend.sign(Digest, FrostKey, SigningAlgoSpec.Ed25519))))
    (result, notes.render)
  }

  private def verifies(signature: Array[Byte]): Boolean = {
    val v = Signature.getInstance("Ed25519")
    v.initVerify(Group.getPublic)
    v.update(Digest)
    v.verify(signature)
  }

  "a sign" should {

    "be served by a cosigner that restarted under another address while another one led, when the leader goes down" in {
      withCluster(InProcess) { (backend, cosigners) =>
        // The two that do not lead restart, one after the other, and are up again.
        cosigners(1).restart()
        cosigners(2).restart()
        // Now the leader goes down: the sign fails over to channels that were not used meanwhile.
        cosigners(0).stop()

        val (result, notes) = sign(backend)

        withClue(s"notes: $notes; ") {
          result.isSuccess shouldBe true
          verifies(result.get) shouldBe true
        }
        // One of the two served it, and no cosigner saw the request twice.
        cosigners.map(_.signs.get).sorted shouldBe Seq(0, 1, 1)
        cosigners(0).signs.get shouldBe 1
        // The first pass went round the roster; the second asked one endpoint again.
        notes should include(s"failover=${cosigners(0).target}→${cosigners(1).target} reason=UNAVAILABLE")
        notes should include(s"failover=${cosigners(1).target}→${cosigners(2).target} reason=UNAVAILABLE")
        val served = cosigners.indexWhere(c => c.signs.get == 1 && (c ne cosigners(0)))
        notes should include(s"failover=${cosigners(2).target}→${cosigners(served).target} reason=UNAVAILABLE")

        // The next sign is served too, by one of the two that are up.
        val (next, nextNotes) = sign(backend)
        withClue(s"notes: $nextNotes; ")(next.isSuccess shouldBe true)
        cosigners(1).signs.get + cosigners(2).signs.get shouldBe 2
      }
    }

    "end with the unreachable cosigners' status, after one attempt deadline, when no cosigner comes back" in {
      withCluster(InProcess) { (backend, cosigners) =>
        cosigners.foreach(_.stop())

        val started = System.nanoTime()
        val (result, notes) = sign(backend)
        val took = (System.nanoTime() - started).nanos

        val thrown = result.failed.get
        thrown shouldBe a[StatusRuntimeException]
        thrown.asInstanceOf[StatusRuntimeException].getStatus.getCode shouldBe Status.Code.UNAVAILABLE
        // It waited for a connection for one attempt deadline, and did not spend the request
        // budget: the error is the one the first pass ended with.
        took should be >= AttemptDeadline
        notes should not include "request-timeout=spent"
        cosigners.map(_.signs.get) shouldBe Seq(1, 0, 0)
      }
    }

    "not be repeated at a cosigner that answered UNAVAILABLE itself: the request reached it" in {
      withCluster(InProcess) { (backend, cosigners) =>
        cosigners.foreach(_.answer = Some(Status.UNAVAILABLE.withDescription("shutting down")))
        cosigners.foreach(_.asked.set(0))

        val (result, notes) = sign(backend)

        result.failed.get.asInstanceOf[StatusRuntimeException].getStatus.getCode shouldBe Status.Code.UNAVAILABLE
        cosigners.map(_.asked.get) shouldBe Seq(1, 1, 1)
        // Two hops, and no third: nobody was asked again.
        "failover=".r.findAllIn(notes).size shouldBe 2
      }
    }

    "ask again only the cosigners its request was not sent to" in {
      withCluster(InProcess) { (backend, cosigners) =>
        // The second cosigner restarted under another address; the third is up and refuses to
        // sign for now, which is an answer. The leader goes down.
        cosigners(1).restart()
        cosigners(2).answer = Some(Status.FAILED_PRECONDITION.withDescription("a ceremony holds the key"))
        cosigners.foreach(_.asked.set(0))
        cosigners(0).stop()

        val (result, notes) = sign(backend)

        withClue(s"notes: $notes; ")(result.isSuccess shouldBe true)
        cosigners.map(_.asked.get) shouldBe Seq(0, 1, 1)
        cosigners(1).signs.get shouldBe 1
        notes should include(s"failover=${cosigners(2).target}→${cosigners(1).target} reason=FAILED_PRECONDITION")
      }
    }
  }

  "the log line of a failed attempt" should {

    "name the exception under a transport failure" in {
      val refused = Status.UNAVAILABLE
        .withDescription("io exception")
        .withCause(new ConnectException("Connection refused: cosigner-1/192.0.2.7:7443"))
        .asRuntimeException()
      FrostBackend.describe(refused) shouldBe
        "UNAVAILABLE: io exception; cause: ConnectException: Connection refused: cosigner-1/192.0.2.7:7443"
    }

    "be the status alone when there is nothing under it" in {
      FrostBackend.describe(Status.NOT_FOUND.withDescription("no such key").asRuntimeException()) shouldBe
        "NOT_FOUND: no such key"
      FrostBackend.describe(Status.INTERNAL.asRuntimeException()) shouldBe "INTERNAL"
    }
  }
}

object FrostRestartedCosignerSpec {

  private val Group: KeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()

  /** name -> the address the name resolves to now. A channel learns of a change only when it asks
    * again, as with DNS. */
  private val addresses = new ConcurrentHashMap[String, SocketAddress]()
  private val names = new AtomicInteger

  /** name -> how often a channel has resolved it. */
  private val lookups = new ConcurrentHashMap[String, AtomicInteger]()

  /** How the cosigners listen and how the driver's channel reaches a resolved name. */
  sealed trait Transport {
    def name: String
    def scheme: String
    def addressType: Class[_ <: SocketAddress]

    /** Start `service` at a new address. */
    def serve(service: SignerGrpc.SignerImplBase): (Server, SocketAddress)
    def channel(target: String): ManagedChannel
  }

  object InProcess extends Transport {
    val name = "the in-process transport"
    val scheme = "restarted-inprocess"
    val addressType: Class[_ <: SocketAddress] = classOf[InProcessSocketAddress]
    def serve(service: SignerGrpc.SignerImplBase): (Server, SocketAddress) = {
      val at = InProcessServerBuilder.generateName()
      (InProcessServerBuilder.forName(at).addService(service).build().start(), new InProcessSocketAddress(at))
    }
    def channel(target: String): ManagedChannel = InProcessChannelBuilder.forTarget(target).build()
  }

  /** Resolves `<scheme>:///<name>` to the address in [[addresses]], once at the start and again
    * whenever the channel asks. */
  private final class Resolver(transport: Transport) extends NameResolverProvider {
    override protected def isAvailable: Boolean = true
    override protected def priority: Int = 5
    override def getDefaultScheme: String = transport.scheme
    override def getProducedSocketAddressTypes: java.util.Collection[Class[_ <: SocketAddress]] =
      java.util.Collections.singleton(transport.addressType)
    override def newNameResolver(target: URI, args: NameResolver.Args): NameResolver =
      if (target.getScheme != transport.scheme) null
      else
        new NameResolver {
          private val name = target.getPath.stripPrefix("/")
          @volatile private var listener: Option[NameResolver.Listener2] = None
          private def resolve(): Unit = listener.foreach { l =>
            Option(addresses.get(name)) match {
              case Some(address) =>
                val resolved = StatusOr.fromValue(java.util.List.of(new EquivalentAddressGroup(address)))
                l.onResult(NameResolver.ResolutionResult.newBuilder().setAddressesOrError(resolved).build())
              case None => l.onError(Status.UNAVAILABLE.withDescription(s"$name does not resolve"))
            }
            // Counted once the channel has its answer: a test that waits for a lookup then knows
            // which address that lookup gave.
            lookups.computeIfAbsent(name, _ => new AtomicInteger).incrementAndGet()
            ()
          }
          override def getServiceAuthority: String = name
          override def start(l: NameResolver.Listener2): Unit = { listener = Some(l); resolve() }
          override def refresh(): Unit = resolve()
          override def shutdown(): Unit = listener = None
        }
  }
  NameResolverRegistry.getDefaultRegistry.register(new Resolver(InProcess))

  /** One cosigner: it signs with the group key unless told to answer with a status. `restart()`
    * brings it back at another address, as a pod comes back under another IP. */
  final class Cosigner(transport: Transport) extends SignerGrpc.SignerImplBase {
    private val name = s"cosigner-${names.incrementAndGet()}"
    val target: String = s"${transport.scheme}:///$name"
    @volatile var answer: Option[Status] = None
    val asked = new AtomicInteger
    val signs = new AtomicInteger
    // Every server of this cosigner that may still listen, the current one last.
    private val servers = new java.util.concurrent.ConcurrentLinkedDeque[Server]()

    def start(): Unit = {
      val (started, address) = transport.serve(this)
      servers.add(started)
      addresses.put(name, address)
      ()
    }
    def stop(): Unit = {
      var next = servers.poll()
      while (next != null) {
        next.shutdownNow().awaitTermination()
        next = servers.poll()
      }
    }

    /** Stop for good and forget the name. */
    def close(): Unit = {
      stop()
      addresses.remove(name)
      lookups.remove(name)
      ()
    }

    /** Come back at another address. The new server listens before the old one stops, so the
      * addresses differ. The name keeps the old address until the driver's channel has seen its
      * connection close and resolved the name once more, as it does at that moment: so the channel
      * is left with the old address, whichever of the two happens first on the wire. */
    def restart(): Unit = {
      val before = Option(lookups.get(name)).fold(0)(_.get)
      val old = servers.peekLast()
      val (started, address) = transport.serve(this)
      servers.add(started)
      require(address != addresses.get(name), s"$name came back at the address it had")
      if (old != null) {
        old.shutdownNow().awaitTermination()
        servers.remove(old)
      }
      val giveUp = System.nanoTime() + 10.seconds.toNanos
      while (Option(lookups.get(name)).fold(0)(_.get) == before && System.nanoTime() < giveUp) Thread.sleep(10)
      require(
        Option(lookups.get(name)).fold(0)(_.get) > before,
        s"the channel to $name did not resolve it again after the restart"
      )
      addresses.put(name, address)
      ()
    }

    override def groupKey(req: GroupKeyRequest, obs: StreamObserver[GroupKeyReply]): Unit = {
      val raw = Group.getPublic.getEncoded.takeRight(32)
      obs.onNext(GroupKeyReply.newBuilder().setGroupVerifyingKey(ByteString.copyFrom(raw)).build())
      obs.onCompleted()
    }
    override def sign(req: SignRequest, obs: StreamObserver[SignReply]): Unit = {
      asked.incrementAndGet()
      answer match {
        case Some(status) => obs.onError(status.asRuntimeException())
        case None         =>
          signs.incrementAndGet()
          val s = Signature.getInstance("Ed25519")
          s.initSign(Group.getPrivate)
          s.update(req.getMessage.toByteArray)
          obs.onNext(SignReply.newBuilder().setSignature(ByteString.copyFrom(s.sign())).build())
          obs.onCompleted()
      }
    }
  }
}
