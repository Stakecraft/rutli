// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli.backend

import com.digitalasset.canton.crypto.kms.driver.api.v1._
import com.google.protobuf.ByteString
import com.stakecraft.rutli.FrostTlsConfig
import com.stakecraft.rutli.grpc.{
  CapabilitiesRequest,
  DecryptRequest,
  DeleteKeyRequest,
  DkgRequest,
  EcdhDeriveReply,
  EcdhDeriveRequest,
  GenerateKeyRequest,
  GroupKeyRequest,
  HealthRequest,
  KeyInfoReply,
  KeyInfoRequest,
  PublicKeyReply,
  PublicKeyRequest,
  SignRequest,
  SignerGrpc,
  SymmetricRequest,
}
import com.stakecraft.rutli.audit.AuditNotes
import io.grpc.netty.shaded.io.grpc.netty.{GrpcSslContexts, NettyChannelBuilder}
import io.grpc.{ManagedChannel, ManagedChannelBuilder, Status, StatusRuntimeException}
import org.slf4j.Logger

import java.io.File
import java.security.KeyFactory
import java.security.interfaces.ECPublicKey
import java.security.spec.X509EncodedKeySpec
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import scala.annotation.tailrec
import scala.jdk.CollectionConverters._
import scala.concurrent.duration._
import scala.concurrent.{ExecutionContext, Future, blocking}

/** Phase 2 backend: routes the Ed25519 namespace/identity key to the external FROST cosigner
  * cluster (threshold signing, no node ever holds the whole key). Every other operation — ECDSA
  * signing, RSA/ECIES decryption, symmetric crypto — is delegated to a co-located [[KmsBackend]]
  * (the HSM in production), because threshold-izing those is out of scope (see docs/architecture.md).
  * With `hosted-keys = true` the cluster also serves the encryption and symmetric keys as replicated
  * whole keys (docs/hosted-keys.md): RSA-OAEP decryption entirely, ECIES as the ECDH only, completed
  * here by [[CantonEcies]].
  *
  * The driver thus presents a single KMS to Canton while, underneath, the highest-value key lives
  * in MPC and the rest live in the HSM.
  *
  * Routing is by key-id prefix, and every id is minted and recognised through one helper,
  * [[FrostKeyIds]]: keys this backend creates on the cluster are tagged `frost-` (threshold) or
  * `rutli-` (cluster-hosted), optionally behind a per-participant `keyPrefix` so several
  * participants can share one cluster. `generateSigningKeyPair(EcCurve25519)` runs a distributed
  * key generation on the cluster and returns the cluster key id; `sign` with that id calls the
  * cluster's threshold Sign.
  *
  * '''Availability:''' the backend is configured with the full cosigner roster and fails over
  * across endpoints — any live cosigner can lead a request (the cluster orchestrates the rest).
  * Which statuses move a request to the next endpoint depends on whether the operation is safe to
  * re-issue through another leader (the predicates on the companion say why):
  *   - Re-issuable operations — sign, group/public key, key info, decrypt, symmetric crypto,
  *     capabilities — fail over on transport failures (UNAVAILABLE / DEADLINE_EXCEEDED) AND on a
  *     leader that answered but could not do its job (INTERNAL / UNKNOWN, e.g. its key store became
  *     unreadable). One sick node must not be a signing outage while a quorum is healthy.
  *   - Writes (hosted GenerateKey, DeleteKey) fail over only when the node is down, and a DKG
  *     ceremony only on a refused connection (UNAVAILABLE): a ceremony is never blindly re-run
  *     against another leader.
  *   - Any other status (NOT_FOUND, RESOURCE_EXHAUSTED, ...) is a real answer from a live node and
  *     is returned immediately, never masked by trying another node.
  * Every hop is logged at WARN and recorded in the operation's own audit entry
  * (`failover=<from>→<to> reason=<CODE>`, see [[withAuditNotes]]). The leader is sticky: whichever
  * endpoint last served a request leads the next one, so once a node is found sick later calls do
  * not each pay a failed attempt against it. This removes the single-leader availability gap
  * without any cross-node consensus — FROST sessions are independent, so no Raft log is needed.
  */
class FrostBackend(
    endpoints: Seq[String],
    delegate: KmsBackend,
    logger: Logger,
    tls: Option[FrostTlsConfig] = None,
    requestTimeout: FiniteDuration = 60.seconds,
    hostedKeys: Boolean = false,
    keyPrefix: String = "",
    // How long the first Capabilities probe keeps retrying endpoints that do not answer before it
    // settles for an unconfirmed result, and how soon an unconfirmed result is asked again.
    capabilitiesRetryBudget: FiniteDuration = 30.seconds,
    capabilitiesRequery: FiniteDuration = 60.seconds,
    // Once a majority has answered, how much longer the first probe waits for the silent rest, so
    // a cosigner that is down delays participant startup by this much, not the whole budget.
    capabilitiesSilentGrace: FiniteDuration = 5.seconds,
)(implicit ec: ExecutionContext)
    extends KmsBackend {

  import FrostBackend._

  require(endpoints.nonEmpty, "FrostBackend needs at least one cosigner endpoint")

  /** The single source of every key id this backend mints or routes on. Validates `keyPrefix`. */
  private val ids: FrostKeyIds = FrostKeyIds(keyPrefix)
  if (keyPrefix.nonEmpty) logger.info(s"FROST: key ids carry the per-participant prefix '$keyPrefix'")

  /** The validated anchors of `tls.caCert`, once, before any channel is built: a trust file with
    * anything but valid CA certificates fails driver init here ([[FrostTrustFile]], review M1). */
  private val trustAnchors: Option[Seq[FrostTrustFile.Anchor]] = tls.map { t =>
    val anchors = FrostTrustFile.load(t.caCert, t.allowExpiredCa)
    logger.info(s"FROST: ${anchors.size} trust anchor(s) in ${t.caCert}")
    anchors.zipWithIndex.foreach { case (a, i) =>
      logger.info(s"FROST: trust anchor $i: ${a.describe}")
      if (!a.validNow)
        logger.warn(
          s"FROST: trust anchor $i (${a.subject}) is expired or not yet valid, accepted because " +
            "allow-expired-ca is set — finish the CA rotation and remove it"
        )
    }
    anchors
  }

  private val channels: Vector[ManagedChannel] = endpoints.toVector.map(buildChannel)

  /** Build the gRPC channel for one endpoint. Overridable so tests can substitute an in-process
    * channel without standing up a TLS listener. */
  protected def buildChannel(endpoint: String): ManagedChannel = tls match {
    case Some(t) =>
      // Exactly the certificates FrostTrustFile validated, not the file: nothing else is trusted.
      val anchors = trustAnchors.getOrElse(FrostTrustFile.load(t.caCert, t.allowExpiredCa)).map(_.cert)
      val ssl = GrpcSslContexts
        .forClient()
        .trustManager(anchors: _*)
        .keyManager(new File(t.cert), new File(t.key))
        .build()
      val b = NettyChannelBuilder.forTarget(endpoint).sslContext(ssl)
      t.domain.foreach(b.overrideAuthority)
      logger.info(s"FROST: mutual TLS channel to $endpoint")
      b.build()
    case None =>
      logger.warn(s"FROST: plaintext channel to $endpoint (no TLS) — do not use in production")
      ManagedChannelBuilder.forTarget(endpoint).usePlaintext().build()
  }

  private def stubFor(ch: ManagedChannel): SignerGrpc.SignerBlockingStub =
    SignerGrpc.newBlockingStub(ch).withDeadlineAfter(requestTimeout.toMillis, TimeUnit.MILLISECONDS)

  /** Index into `endpoints` of the preferred leader: the cosigner that last served a request. */
  private val preferred = new AtomicInteger(0)

  /** Run `op` against the cosigners in ring order, starting from the preferred leader, moving to
    * the next only when `retryOn` says the contacted node could not serve it (see the predicates on
    * the companion — each call site picks the one its operation is safe under). Any other gRPC
    * status is a real answer and is rethrown immediately; when every endpoint fails over, the last
    * error is thrown. Each hop is logged at WARN and noted in `notes` for the operation's audit
    * entry.
    *
    * Sticky leader ("last healthy first"): when endpoint i gives a real answer — success, or an
    * application error such as NOT_FOUND, since the node is serving either way — it becomes the
    * preferred leader. Once a node is found sick, later calls lead from the healthy one directly
    * instead of each paying a failed attempt (and a WARN) against the sick node, and a recovered
    * node is simply reached again when the ring next wraps to it. A leader-sick or transport status
    * never makes its node preferred, even when this op does not fail over on it (a DKG that hits
    * INTERNAL), so one ceremony error cannot steer every later sign back to the sick node.
    * Deterministic: no probing, no randomness; concurrent calls race benignly, since every write is
    * the index of a node that just served. */
  private def withFailover[A](what: String, retryOn: Status => Boolean, notes: AuditNotes)(
      op: SignerGrpc.SignerBlockingStub => A
  ): A = {
    val n = channels.size
    val start = preferred.get
    @tailrec def attempt(k: Int): A = {
      val i = (start + k) % n
      val outcome =
        try Right(op(stubFor(channels(i))))
        catch { case e: StatusRuntimeException => Left(e) }
      outcome match {
        case Right(answer) =>
          preferred.set(i)
          answer
        case Left(e) =>
          val status = e.getStatus
          if (!isLeaderSick(status)) preferred.set(i)
          if (!retryOn(status)) throw e
          val reason = Option(status.getDescription).fold(status.getCode.toString)(d => s"${status.getCode}: $d")
          if (k + 1 < n) {
            val next = endpoints((i + 1) % n)
            logger.warn(s"FROST: $what via ${endpoints(i)} failed ($reason); failing over to $next")
            notes.add(s"failover=${endpoints(i)}→$next reason=${status.getCode}")
            attempt(k + 1)
          } else {
            logger.warn(s"FROST: $what via ${endpoints(i)} failed ($reason); no cosigner left to try")
            throw e
          }
      }
    }
    attempt(0)
  }

  /** Hosted-key specs learned in this process (`GenerateKey`, `PublicKey`, `KeyInfo` replies), so
    * that EC-only failover applies only to keys that are, or may be, EC. */
  private val hostedSpecOf = new java.util.concurrent.ConcurrentHashMap[String, String]()
  private def learnSpec(keyId: String, spec: String): Unit = if (spec.nonEmpty) { hostedSpecOf.put(keyId, spec); () }

  /** [[withFailover]] for an operation on a hosted key that is, or may be, `ec-p256-ecies`.
    *
    * A cosigner older than that spec cannot hold the key, and says so in ways that are normally
    * authoritative: NOT_FOUND (read-repair skips what it cannot parse), `KeyInfo.exists = false`,
    * UNIMPLEMENTED for `EcdhDerive`. While the driver no longer refuses ECIES because a silent
    * cosigner might be old, such an answer is treated here as "this node may be old or missing the
    * key": the next cosigner is asked, and the answering node does **not** become the preferred
    * leader (review M1, 2026-10-09 decision). `stale` recognises such an answer; leader-sick
    * statuses fail over as usual.
    *
    * `acceptAfterStale` decides whether an answer found after a stale one is used. For a key the
    * driver has not seen yet it is "only if the answer says the key is EC": for any other key type,
    * the first node's NOT_FOUND / does-not-exist stays the answer, exactly as without this path, so
    * FROST/RSA/AES semantics are unchanged. If every node is stale, the first stale answer stands. */
  private def withEcFailover[A](
      what: String,
      notes: AuditNotes,
      stale: Either[StatusRuntimeException, A] => Boolean,
      acceptAfterStale: A => Boolean,
  )(op: SignerGrpc.SignerBlockingStub => A): A = {
    val n = channels.size
    val start = preferred.get
    @tailrec def attempt(k: Int, firstStale: Option[Either[StatusRuntimeException, A]]): A = {
      val i = (start + k) % n
      val outcome =
        try Right(op(stubFor(channels(i))))
        catch { case e: StatusRuntimeException => Left(e) }
      def settle(o: Either[StatusRuntimeException, A]): A = o.fold(e => throw e, identity)
      val next = if (k + 1 < n) Some(endpoints((i + 1) % n)) else None
      outcome match {
        case Left(e) if isLeaderSick(e.getStatus) =>
          next match {
            case Some(to) =>
              logger.warn(s"FROST: $what via ${endpoints(i)} failed (${e.getStatus.getCode}); failing over to $to")
              notes.add(s"failover=${endpoints(i)}→$to reason=${e.getStatus.getCode}")
              attempt(k + 1, firstStale)
            case None => settle(firstStale.getOrElse(outcome))
          }
        case o if stale(o) =>
          val reason = o.fold(_.getStatus.getCode.toString, _ => "NOT_FOUND")
          val first = firstStale.orElse(Some(o))
          next match {
            case Some(to) =>
              logger.warn(
                s"FROST: $what via ${endpoints(i)} answered $reason for an EC hosted key — that cosigner may " +
                  s"predate ec-p256-ecies or lack the key; asking $to"
              )
              notes.add(s"ec-failover=${endpoints(i)}→$to reason=$reason")
              attempt(k + 1, first)
            case None => settle(first.get)
          }
        case Right(answer) if firstStale.nonEmpty && !acceptAfterStale(answer) =>
          settle(firstStale.get) // not an EC key after all: the first answer stands, as before
        case o =>
          preferred.set(i)
          settle(o)
      }
    }
    attempt(0, None)
  }

  /** [[clusterCall]] for [[withEcFailover]]. */
  private def clusterCallEc[A](
      what: String,
      stale: Either[StatusRuntimeException, A] => Boolean,
      acceptAfterStale: A => Boolean,
  )(op: SignerGrpc.SignerBlockingStub => A): Future[A] = {
    val notes = currentNotes.get
    Future(blocking(withEcFailover(what, notes, stale, acceptAfterStale)(op)))
  }

  /** Whether `keyId` is, or for all the driver knows may be, an EC hosted key. */
  private def mayBeEc(keyId: String): Boolean =
    Option(hostedSpecOf.get(keyId)).forall(_ == EcSpec)

  /** The audit notes of the operation being issued on this thread: bound by [[withAuditNotes]],
    * [[AuditNotes.discard]] outside it.
    *
    * A plain `ThreadLocal`, deliberately not `scala.util.DynamicVariable`: that one is an
    * `InheritableThreadLocal`, so a pool thread spawned while an operation's notes are bound would
    * inherit them as its permanent default — and could pin a later, unrelated call's failover onto
    * that operation's audit entry. */
  private val currentNotes: ThreadLocal[AuditNotes] = ThreadLocal.withInitial(() => AuditNotes.discard)

  override def withAuditNotes[A](notes: AuditNotes)(op: => Future[A]): Future[A] = {
    val outer = currentNotes.get
    currentNotes.set(notes)
    try op
    finally currentNotes.set(outer)
  }

  /** Issue one cluster RPC, with failover, on the (blocking) execution context.
    *
    * The audit notes are captured HERE, synchronously on the calling thread, before `Future.apply`.
    * The binding is thread-local and does not follow a `Future` onto an ExecutionContext thread:
    * read inside the Future body it would yield the default (discard) and the failover would
    * silently vanish from the audit entry. So every cluster call goes through this helper from the
    * synchronous part of the public method, and reply post-processing (signature length, SPKI
    * wrapping, existence checks) is chained with `.map`. */
  private def clusterCall[A](what: String, retryOn: Status => Boolean)(
      op: SignerGrpc.SignerBlockingStub => A
  ): Future[A] = {
    val notes = currentNotes.get
    Future(blocking(withFailover(what, retryOn, notes)(op)))
  }

  /** Fail the returned Future — rather than throw — when a caller-side precondition does not hold,
    * keeping the backend's "failures arrive in the Future" contract while the cluster call itself is
    * still issued synchronously (see [[clusterCall]]). Same exception as `require`. */
  private def precondition[A](ok: Boolean, msg: => String)(call: => Future[A]): Future[A] =
    if (ok) call else Future.failed(new IllegalArgumentException(s"requirement failed: $msg"))

  /** Which hosted-key specs the cluster serves: the specs **every answering cosigner** reports.
    *
    * Queried rather than hardcoded so a cluster can add a key type without a driver release. Every
    * endpoint is asked, not just the leader, and the answers are intersected: a cosigner that
    * predates a spec cannot serve it — read-repair skips the key, `KeyInfo` says it does not exist —
    * so a spec that an answering node lacks is never advertised (review M1). An answer of
    * UNIMPLEMENTED (a cosigner older than `Capabilities`) counts as RSA + AES, and so vetoes ECIES.
    *
    * A cosigner that does not answer at all (down, unreachable, deadline) does **not** veto: one node
    * down must not stop a participant from restarting (decided 2026-10-09; restart availability over
    * the residual risk). That risk — a silent node that is old and comes back — is covered at run
    * time instead: an EC operation that meets "not found" or UNIMPLEMENTED fails over to the next
    * cosigner ([[withEcFailover]]), and a leader never creates an EC key unless every cosigner
    * supports it (cosigner side). But a spec newer than v1 needs a **majority** of the roster to
    * have answered: the driver does not know the cluster's threshold, and for the deployed shapes
    * (2-of-3, 3-of-5) a majority is the threshold; one lone answering node is not allowed to speak
    * for a cluster whose majority is silent.
    *
    * Silent endpoints are retried with backoff — for up to `capabilitiesRetryBudget` on the first
    * probe, cut to `capabilitiesSilentGrace` once a majority has answered — and logged at WARN. A
    * result with silent endpoints is unconfirmed and asked again on the next use after
    * `capabilitiesRequery`, so a later answer (including an old node's veto) changes routing. What
    * Canton is told at startup is fixed then (`RutliDriver` captures the supported specs once).
    */
  private val specsLock = new Object
  @volatile private var specsProbe: Option[SpecsProbe] = None

  private def clusterSpecs: Set[String] =
    if (!hostedKeys) Set.empty
    else
      specsProbe match {
        case Some(p) if p.confirmed => p.specs
        case Some(p) if System.nanoTime() - p.atNanos < capabilitiesRequery.toNanos => p.specs
        case _ =>
          specsLock.synchronized {
            specsProbe match {
              case Some(p) if p.confirmed || System.nanoTime() - p.atNanos < capabilitiesRequery.toNanos => p.specs
              case previous =>
                // Only the very first probe waits out the retry budget; a re-query is one round.
                val probe = blocking(probeCapabilities(if (previous.isEmpty) capabilitiesRetryBudget else Duration.Zero))
                specsProbe = Some(probe)
                probe.specs
            }
          }
      }

  /** The answers needed before a spec newer than v1 is advertised: a majority of the roster. */
  private val capabilitiesQuorum: Int = channels.size / 2 + 1

  /** Ask every endpoint for its capabilities, retrying silent ones until `budget` is spent. */
  private def probeCapabilities(budget: FiniteDuration): SpecsProbe = {
    val started = System.nanoTime()
    var deadline = started + budget.toNanos
    val probeTimeout = requestTimeout.min(5.seconds)
    val answers = scala.collection.mutable.Map.empty[Int, Set[String]]
    var lastError = Map.empty[Int, String]
    var backoff = 250.millis
    var graceApplied = false
    @tailrec def round(): Unit = {
      channels.indices.filterNot(answers.contains).foreach { i =>
        try {
          val reply = SignerGrpc
            .newBlockingStub(channels(i))
            .withDeadlineAfter(probeTimeout.toMillis, TimeUnit.MILLISECONDS)
            .capabilities(CapabilitiesRequest.newBuilder().build())
          answers(i) = if (reply.getHostedKeysEnabled) reply.getHostedKeySpecsList.asScala.toSet else Set.empty
          if (!reply.getHostedKeysEnabled)
            logger.warn(
              s"FROST: cosigner ${endpoints(i)} reports hosted keys disabled — non-FROST keys will fall " +
                "back to the delegate. Set hosted_keys.enabled on every cosigner."
            )
        } catch {
          case e: StatusRuntimeException if e.getStatus.getCode == Status.Code.UNIMPLEMENTED =>
            answers(i) = DefaultHostedSpecs // older than Capabilities: RSA + AES, nothing newer
          case e: StatusRuntimeException =>
            lastError += i -> e.getStatus.getCode.toString
        }
      }
      if (!graceApplied && answers.size >= capabilitiesQuorum && answers.size < channels.size) {
        graceApplied = true
        deadline = deadline.min(System.nanoTime() + capabilitiesSilentGrace.toNanos)
      }
      val remaining = deadline - System.nanoTime()
      if (answers.size < channels.size && remaining > 0) {
        Thread.sleep(backoff.toMillis.min(remaining / 1000000L).max(1L))
        backoff = (backoff * 2).min(4.seconds)
        round()
      }
    }
    round()
    val agreed = answers.values.reduceOption(_ intersect _)
    val vetoes = channels.indices.filter(i => answers.get(i).exists(a => !a.contains(EcSpec))).map(endpoints)
    if (answers.size == channels.size) {
      val specs = agreed.getOrElse(Set.empty)
      logger.info(s"FROST: every cosigner hosts non-FROST keys (${specs.toSeq.sorted.mkString(", ")})")
      if (vetoes.nonEmpty && answers.values.exists(_.contains(EcSpec)))
        logger.warn(s"FROST: ec-p256-ecies not advertised: ${vetoes.mkString(", ")} do(es) not serve it — upgrade every cosigner")
      SpecsProbe(specs, confirmed = true, System.nanoTime())
    } else {
      val silent = channels.indices.filterNot(answers.contains).map(i => s"${endpoints(i)} (${lastError.getOrElse(i, "?")})")
      val (specs, why) =
        if (answers.size >= capabilitiesQuorum)
          (agreed.getOrElse(Set.empty), s"${answers.size} of ${channels.size} answered, a majority")
        else
          (
            agreed.fold(DefaultHostedSpecs)(_ intersect DefaultHostedSpecs),
            s"only ${answers.size} of ${channels.size} answered, fewer than the majority ($capabilitiesQuorum) " +
              "needed to advertise a spec newer than RSA/AES",
          )
      logger.warn(
        s"FROST: no capabilities answer from ${silent.mkString(", ")}; $why. Advertising what every answering " +
          s"cosigner serves: ${specs.toSeq.sorted.mkString(", ")}" +
          (if (vetoes.nonEmpty) s" (ec-p256-ecies vetoed by ${vetoes.mkString(", ")})" else "") +
          ". A silent cosigner does not veto; EC operations fail over past a node that turns out not to serve " +
          "the key. Will ask again."
      )
      SpecsProbe(specs, confirmed = false, System.nanoTime())
    }
  }

  private def hostsRsa: Boolean = clusterSpecs.contains(RsaSpec)
  private def hostsAes: Boolean = clusterSpecs.contains(AesSpec)
  private def hostsEc: Boolean = clusterSpecs.contains(EcSpec)

  // Advertise Ed25519 (threshold-signed by the cluster) plus, when hosted keys are on, the
  // encryption specs the cluster serves — and whatever the delegate still supports on top.
  // EcP256/ECIES appears only when the cluster itself reports `ec-p256-ecies`: never from the
  // fallback for an older or unreachable cluster, which could not serve EcdhDerive.
  override def supportedSigningKeySpecs: Set[SigningKeySpec] =
    delegate.supportedSigningKeySpecs + SigningKeySpec.EcCurve25519
  override def supportedSigningAlgoSpecs: Set[SigningAlgoSpec] =
    delegate.supportedSigningAlgoSpecs + SigningAlgoSpec.Ed25519
  override def supportedEncryptionKeySpecs: Set[EncryptionKeySpec] =
    delegate.supportedEncryptionKeySpecs ++
      (if (hostsRsa) Set(EncryptionKeySpec.Rsa2048) else Set.empty) ++
      (if (hostsEc) Set(EncryptionKeySpec.EcP256) else Set.empty)
  override def supportedEncryptionAlgoSpecs: Set[EncryptionAlgoSpec] =
    delegate.supportedEncryptionAlgoSpecs ++
      (if (hostsRsa) Set(EncryptionAlgoSpec.RsaEsOaepSha256) else Set.empty) ++
      (if (hostsEc) Set(EncryptionAlgoSpec.EciesHkdfHmacSha256Aes128Cbc) else Set.empty)

  override def generateSigningKeyPair(
      spec: SigningKeySpec,
      keyName: Option[String],
  ): Future[String] = spec match {
    case SigningKeySpec.EcCurve25519 =>
      val keyId = ids.frost(keyName)
      logger.info(s"FROST: initiating distributed key generation for $keyId")
      // DKG is a one-shot ceremony: only fail over if the endpoint is unreachable at the
      // connection level (no ceremony started). Never retry on DEADLINE_EXCEEDED — a slow but
      // in-flight DKG must not be run a second time against another leader — nor on a leader-side
      // INTERNAL, which may have failed part-way through the ceremony.
      clusterCall("dkg", connectionRefused)(_.dkg(DkgRequest.newBuilder().setKeyId(keyId).build()))
        .map(_ => keyId)
    case other => delegate.generateSigningKeyPair(other, keyName)
  }

  override def generateEncryptionKeyPair(
      spec: EncryptionKeySpec,
      keyName: Option[String],
  ): Future[String] = spec match {
    // The spec is Canton's choice (`crypto.encryption.keys.default`, RSA-2048 for a KMS unless
    // configured otherwise); the driver mints exactly what was asked for.
    case EncryptionKeySpec.Rsa2048 if hostsRsa =>
      val keyId = ids.hosted("enc", keyName)
      logger.info(s"FROST: generating cluster-hosted $RsaSpec key $keyId")
      generateHosted(keyId, RsaSpec)
    case EncryptionKeySpec.EcP256 if hostsEc =>
      val keyId = ids.hosted("enc", keyName)
      logger.info(s"FROST: generating cluster-hosted $EcSpec key $keyId")
      generateHosted(keyId, EcSpec)
    case other => delegate.generateEncryptionKeyPair(other, keyName)
  }

  override def generateSymmetricKey(keyName: Option[String]): Future[String] =
    if (hostsAes) {
      val keyId = ids.hosted("sym", keyName)
      logger.info(s"FROST: generating cluster-hosted $AesSpec key $keyId")
      generateHosted(keyId, AesSpec)
    } else delegate.generateSymmetricKey(keyName)

  /** Generate a hosted key on the cluster; completes with `keyId`.
    *
    * `key_id` is caller-supplied and the cluster treats a repeat as a no-op, so this is idempotent
    * and may fail over on a timeout as well as a refused connection — unlike DKG, where a retry
    * could run a second ceremony. It is still a write, so a leader-side INTERNAL is surfaced, not
    * routed around (see [[FrostBackend.isNodeDown]]).
    */
  private def generateHosted(keyId: String, spec: String): Future[String] = {
    val req = GenerateKeyRequest.newBuilder().setKeyId(keyId).setSpec(spec).build()
    clusterCall("generateKey", isNodeDown)(_.generateKey(req)).map { reply =>
      learnSpec(keyId, spec)
      logger.info(
        s"FROST: hosted key $keyId ready (created=${reply.getCreated}, replicas=${reply.getReplicas})"
      )
      keyId
    }
  }

  override def sign(data: Array[Byte], keyId: String, algo: SigningAlgoSpec): Future[Array[Byte]] =
    if (ids.isFrost(keyId))
      precondition(algo == SigningAlgoSpec.Ed25519, s"FROST keys sign Ed25519 only, got $algo") {
        val req = SignRequest.newBuilder().setKeyId(keyId).setMessage(ByteString.copyFrom(data)).build()
        // Re-issuing through another leader opens a fresh session with fresh nonces; the sick
        // leader's session is abandoned and its nonces are burnt by the cosigners (AbortSign, or the
        // pending-session TTL), never reused — see isLeaderSick.
        clusterCall("sign", isLeaderSick)(_.sign(req)).map { reply =>
          val sig = reply.getSignature.toByteArray
          require(sig.length == 64, s"expected 64-byte Ed25519 signature, got ${sig.length}")
          sig
        }
      }
    else delegate.sign(data, keyId, algo)

  override def decryptAsymmetric(
      ciphertext: Array[Byte],
      keyId: String,
      algo: EncryptionAlgoSpec,
  ): Future[Array[Byte]] =
    if (ids.isHosted(keyId)) algo match {
      case EncryptionAlgoSpec.RsaEsOaepSha256 =>
        val req = DecryptRequest
          .newBuilder()
          .setKeyId(keyId)
          .setCiphertext(ByteString.copyFrom(ciphertext))
          .build()
        clusterCall("decrypt", isLeaderSick)(_.decrypt(req)).map(_.getPlaintext.toByteArray)
      case EncryptionAlgoSpec.EciesHkdfHmacSha256Aes128Cbc =>
        decryptEcies(ciphertext, keyId)
    }
    else delegate.decryptAsymmetric(ciphertext, keyId, algo)

  /** ECIES for a hosted P-256 key: the cluster does the ECDH, BouncyCastle's `IESEngine` the rest
    * ([[CantonEcies]]). The blob is checked against Canton's exact shape before anything is sent, so
    * a malformed ciphertext costs no cluster call and no decryption budget. `EcdhDerive` is
    * re-issuable like `Decrypt` (it is a pure function of key and point), hence [[isLeaderSick]]. */
  private def decryptEcies(ciphertext: Array[Byte], keyId: String): Future[Array[Byte]] = {
    // The cluster cannot see the MAC/padding outcome — its metrics count every EcdhDerive that
    // produced a Z as ok. So a failure here is noted in this operation's audit entry
    // (`ecies-failure=shape|after-ecdh`) and logged at WARN, which is what to alert on
    // (docs/observability.md).
    val notes = currentNotes.get
    scala.util.Try(CantonEcies.parse(ciphertext)) match {
      case scala.util.Failure(e) =>
        notes.add("ecies-failure=shape")
        Future.failed(e)
      case scala.util.Success(parsed) =>
        val req = EcdhDeriveRequest
          .newBuilder()
          .setKeyId(keyId)
          .setPeerPoint(ByteString.copyFrom(parsed.ephemeralPoint))
          .build()
        // A cosigner that predates EcdhDerive answers UNIMPLEMENTED, one that lacks the key NOT_FOUND:
        // ask the next one (withEcFailover). Every other status behaves as for Decrypt.
        clusterCallEc[EcdhDeriveReply](
          "ecdhDerive",
          {
            case Left(e) => e.getStatus.getCode == Status.Code.UNIMPLEMENTED || e.getStatus.getCode == Status.Code.NOT_FOUND
            case Right(_) => false
          },
          _ => true,
        )(_.ecdhDerive(req)).map { reply =>
          // The JVM cannot promise this is the only copy of Z: the protobuf ByteString holds one
          // that cannot be wiped, and the GC may have moved either. Wiping ours is best-effort.
          val z = reply.getSharedSecret.toByteArray
          try CantonEcies.decrypt(parsed, z)
          catch {
            case e: CantonEcies.EciesException =>
              notes.add("ecies-failure=after-ecdh")
              logger.warn(
                s"FROST: ECIES decryption failed after a successful EcdhDerive for $keyId (MAC, padding or a " +
                  "wrong shared secret) — a forged or corrupted ciphertext, or a cosigner answering with the wrong key"
              )
              throw e
          } finally java.util.Arrays.fill(z, 0.toByte)
        }
    }
  }

  override def encryptSymmetric(data: Array[Byte], keyId: String): Future[Array[Byte]] =
    if (ids.isHosted(keyId)) {
      val req =
        SymmetricRequest.newBuilder().setKeyId(keyId).setData(ByteString.copyFrom(data)).build()
      clusterCall("symmetricEncrypt", isLeaderSick)(_.symmetricEncrypt(req)).map(_.getData.toByteArray)
    } else delegate.encryptSymmetric(data, keyId)

  override def decryptSymmetric(ciphertext: Array[Byte], keyId: String): Future[Array[Byte]] =
    if (ids.isHosted(keyId)) {
      val req = SymmetricRequest
        .newBuilder()
        .setKeyId(keyId)
        .setData(ByteString.copyFrom(ciphertext))
        .build()
      clusterCall("symmetricDecrypt", isLeaderSick)(_.symmetricDecrypt(req)).map(_.getData.toByteArray)
    } else delegate.decryptSymmetric(ciphertext, keyId)

  override def getPublicKey(keyId: String): Future[PublicKey] =
    if (ids.isFrost(keyId)) {
      val req = GroupKeyRequest.newBuilder().setKeyId(keyId).build()
      clusterCall("groupKey", isLeaderSick)(_.groupKey(req)).map { reply =>
        val raw = reply.getGroupVerifyingKey.toByteArray
        require(raw.length == 32, s"expected 32-byte Ed25519 group key, got ${raw.length}")
        PublicKey(ed25519Spki(raw), SigningKeySpec.EcCurve25519)
      }
    } else if (ids.isHosted(keyId)) {
      val req = PublicKeyRequest.newBuilder().setKeyId(keyId).build()
      // The cluster returns X.509 SubjectPublicKeyInfo DER — exactly what Canton's PublicKey wants —
      // and the spec it holds the key under, which decides what Canton is told it is.
      // For a key that is (or may be) EC, a NOT_FOUND may come from a cosigner that predates the
      // spec: confirm it with the others (withEcFailover). A key known to be RSA keeps the plain path.
      val call =
        if (mayBeEc(keyId))
          clusterCallEc[PublicKeyReply](
            "publicKey",
            { case Left(e) => e.getStatus.getCode == Status.Code.NOT_FOUND; case Right(_) => false },
            _.getSpec == EcSpec,
          )(_.publicKey(req))
        else clusterCall("publicKey", isLeaderSick)(_.publicKey(req))
      call.map { reply =>
        learnSpec(keyId, reply.getSpec)
        hostedPublicKey(keyId, reply.getSpec, reply.getPublicKeyDer.toByteArray)
      }
    } else delegate.getPublicKey(keyId)

  override def keyExistsAndIsActive(keyId: String): Future[Unit] =
    if (ids.isFrost(keyId))
      // groupKey returns NOT_FOUND if the cluster has no such key.
      clusterCall("groupKey", isLeaderSick)(_.groupKey(GroupKeyRequest.newBuilder().setKeyId(keyId).build()))
        .map(_ => ())
    else if (ids.isHosted(keyId)) {
      val req = KeyInfoRequest.newBuilder().setKeyId(keyId).build()
      // As for getPublicKey: `exists = false` for a key that is (or may be) EC is confirmed with the
      // other cosigners before it is believed.
      val call =
        if (mayBeEc(keyId))
          clusterCallEc[KeyInfoReply](
            "keyInfo",
            {
              case Left(e)      => e.getStatus.getCode == Status.Code.NOT_FOUND
              case Right(reply) => !reply.getExists
            },
            _.getSpec == EcSpec,
          )(_.keyInfo(req))
        else clusterCall("keyInfo", isLeaderSick)(_.keyInfo(req))
      call.map { reply =>
        if (!reply.getExists) throw new NoSuchElementException(s"key not found or inactive: $keyId")
        learnSpec(keyId, reply.getSpec)
      }
    }
    else delegate.keyExistsAndIsActive(keyId)

  override def deleteKey(keyId: String): Future[Unit] =
    if (ids.isFrost(keyId))
      // The cluster intentionally has no delete — the namespace key is non-rotatable and deleting
      // it would be catastrophic. Deletion is an operator ceremony, not an API call.
      Future.failed(new UnsupportedOperationException("FROST namespace keys cannot be deleted via the API"))
    else if (ids.isHosted(keyId))
      // Unlike the namespace key, Canton CAN rotate encryption keys, so hosted keys are deletable.
      // A write: fail over only when the node is down, never on a leader-side error.
      clusterCall("deleteKey", isNodeDown)(_.deleteKey(DeleteKeyRequest.newBuilder().setKeyId(keyId).build()))
        .map(_ => ())
    else delegate.deleteKey(keyId)

  override def health: Future[KmsDriverHealth] = {
    val cluster = Future {
      // Healthy if ANY cosigner answers — the cluster leads from whichever node is reachable.
      val anyUp = channels.iterator.exists { ch =>
        try stubFor(ch).health(HealthRequest.newBuilder().build()).getOk
        catch { case _: Throwable => false }
      }
      if (anyUp) KmsDriverHealth.Ok
      else KmsDriverHealth.Degraded("no FROST cosigner reachable")
    }
    // Overall health is the worse of cluster + delegate.
    cluster.flatMap(c =>
      delegate.health.map {
        case KmsDriverHealth.Ok => c
        case worse              => worse
      }
    )
  }

  override def close(): Unit = {
    try
      channels.foreach { ch =>
        ch.shutdown()
        ch.awaitTermination(5, TimeUnit.SECONDS)
      }
    finally delegate.close()
  }
}

object FrostBackend {
  // Key-id construction and routing live in FrostKeyIds — nothing here builds or parses an id.

  private val RsaSpec = "rsa-2048-oaep-sha256"
  private val AesSpec = "aes-256-gcm"
  private val EcSpec = "ec-p256-ecies"

  /** DER prefix of a named-curve P-256 SPKI with an uncompressed point, up to and including the
    * point's 0x04 tag; the full SPKI is 91 bytes. */
  private[backend] val P256SpkiPrefix: Array[Byte] = Array(
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
  ).map(_.toByte)
  private[backend] val P256SpkiLength = 91

  /** The P-256 group order, to recognise the curve of an EC public key without trusting names. */
  private val P256Order = new java.math.BigInteger(
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    16,
  )

  /** Canton's view of a hosted public key: the spec comes from what the cluster holds the key as,
    * never from a guess. An EC key is checked to be a P-256 SPKI before Canton sees it; Canton
    * validates the key again itself (`KmsEncryptionPublicKey.create`). A spec the driver does not
    * know (a symmetric key, a newer cluster's type) is refused rather than mislabelled. */
  private[backend] def hostedPublicKey(keyId: String, spec: String, spki: Array[Byte]): PublicKey =
    spec match {
      case RsaSpec => PublicKey(spki, EncryptionKeySpec.Rsa2048)
      case EcSpec =>
        // The exact DER Canton/BouncyCastle write for a P-256 key: SEQUENCE { SEQUENCE {
        // id-ecPublicKey, prime256v1 }, BIT STRING 0x00 ‖ 0x04 ‖ X ‖ Y } — 91 bytes. Anything else
        // (another curve, explicit parameters, a compressed point) is refused, then the point is
        // parsed as a sanity check; Canton validates it again (`KmsEncryptionPublicKey.create`).
        val ok =
          spki.length == P256SpkiLength && spki.startsWith(P256SpkiPrefix) &&
            (try
              KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(spki)) match {
                case k: ECPublicKey => k.getParams.getOrder == P256Order && k.getParams.getCofactor == 1
                case _              => false
              }
            catch { case _: java.security.GeneralSecurityException => false })
        if (!ok) throw new IllegalStateException(s"cluster returned a public key for $keyId that is not EC P-256")
        PublicKey(spki, EncryptionKeySpec.EcP256)
      case other =>
        throw new IllegalStateException(s"hosted key $keyId has spec '$other', which has no Canton public key")
    }

  /** Assumed cluster capability when the Capabilities RPC is unavailable (older cosigner, or the
    * cluster was unreachable at startup) but the operator configured hosted keys. */
  private val DefaultHostedSpecs = Set(RsaSpec, AesSpec)

  /** One Capabilities probe of the whole roster: the agreed specs, and whether every endpoint answered. */
  private final case class SpecsProbe(specs: Set[String], confirmed: Boolean, atNanos: Long)

  // -- Failover predicates: which statuses move a request to the next cosigner. --
  //
  // Each call site picks the widest predicate its operation is safe under. Every status none of
  // them names — NOT_FOUND, INVALID_ARGUMENT, ALREADY_EXISTS, FAILED_PRECONDITION,
  // RESOURCE_EXHAUSTED, PERMISSION_DENIED, UNAUTHENTICATED, UNIMPLEMENTED, ... — is a real answer
  // from a live node and is surfaced immediately: trying another node would only mask it.
  //
  // Note in particular that RESOURCE_EXHAUSTED (the cluster's per-key decryption rate limit) is
  // NOT retried elsewhere. Every cosigner enforces the same ceiling, so failing over would merely
  // spread the load an attacker is generating across the cluster. It surfaces to Canton, which
  // backs off.

  /** The contacted node isn't serving at all: unreachable (UNAVAILABLE) or too slow to answer
    * (DEADLINE_EXCEEDED).
    *
    * For writes that are idempotent by key — hosted GenerateKey (a repeated `key_id` is a no-op)
    * and DeleteKey — so re-sending one after a timeout is harmless. They deliberately do NOT fail
    * over on a leader-side INTERNAL: that leader may have half-applied the write (e.g. replicated
    * to some peers before failing), and an operator should see that error rather than have it
    * papered over by a second leader. */
  private def isNodeDown(status: Status): Boolean =
    status.getCode == Status.Code.UNAVAILABLE || status.getCode == Status.Code.DEADLINE_EXCEEDED

  /** [[isNodeDown]], or the node answered but could not do its job — INTERNAL / UNKNOWN, e.g. its
    * key store is unreadable (the 2026-10-07 DevNet incident: a remounted volume left cosigner-0
    * "ready" but answering every request with `INTERNAL: io: Permission denied`; with cosigner-0
    * first in the roster, one sick node was a total signing outage while a quorum was healthy).
    *
    * Only for operations safe to re-issue through another leader: reads (group/public key, key
    * info, capabilities), decryption, symmetric crypto — and sign. A sign re-issued elsewhere
    * opens a FRESH FROST session with fresh nonces; the first leader's session is abandoned and its
    * round-1 nonces are burnt by the cosigners' own abort/TTL logic (AbortSign, the pending-session
    * TTL), never reused. At worst two valid signatures over the same message exist, which leaks
    * nothing. */
  private def isLeaderSick(status: Status): Boolean =
    isNodeDown(status) || status.getCode == Status.Code.INTERNAL || status.getCode == Status.Code.UNKNOWN

  /** Strictest predicate, for the non-idempotent DKG ceremony: only the endpoint being unreachable
    * at the connection level (no ceremony started) — never a timeout, which may mean the ceremony is
    * still running, and never a leader-side error, which may have struck mid-ceremony. A blind
    * re-run against another leader is exactly what the ceremony guard exists to refuse. */
  private def connectionRefused(status: Status): Boolean =
    status.getCode == Status.Code.UNAVAILABLE

  /** Wrap a raw 32-byte Ed25519 public key in DER X.509 SubjectPublicKeyInfo — what Canton expects
    * from getPublicKey. The 12-byte prefix is the fixed Ed25519 SPKI header (SEQUENCE, alg OID
    * 1.3.101.112, BIT STRING); we re-parse to normalize to exactly the verifier's encoding. */
  private def ed25519Spki(raw: Array[Byte]): Array[Byte] = {
    val header = Array[Byte](0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00)
    val spki = header ++ raw
    KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(spki)).getEncoded
  }
}
