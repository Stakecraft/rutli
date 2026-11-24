// Copyright 2026 StakeCraft LLC
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli.backend

import com.digitalasset.canton.crypto.kms.driver.api.v1._
import com.google.protobuf.ByteString
import com.stakecraft.rutli.FrostTlsConfig
import com.stakecraft.rutli.grpc.{
  CapabilitiesRequest,
  DecryptRequest,
  DeleteKeyRequest,
  DkgReply,
  DkgRequest,
  EcdhDeriveReply,
  EcdhDeriveRequest,
  GenerateKeyReply,
  GenerateKeyRequest,
  GroupKeyReply,
  GroupKeyRequest,
  HealthRequest,
  KeyInfoReply,
  KeyInfoRequest,
  PublicKeyReply,
  PublicKeyRequest,
  SignIntent,
  SignReply,
  SignRequest,
  SignerGrpc,
  SymmetricRequest,
}
import com.stakecraft.rutli.audit.AuditNotes
import io.grpc.netty.shaded.io.grpc.netty.{GrpcSslContexts, NettyChannelBuilder}
import io.grpc.{ManagedChannel, ManagedChannelBuilder, Status, StatusRuntimeException}
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
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
import scala.util.control.NonFatal

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
  *   - Sign fails over on every status except PERMISSION_DENIED, UNAUTHENTICATED,
  *     RESOURCE_EXHAUSTED and INVALID_ARGUMENT (policy, configuration, rate limit, a malformed
  *     request), and on a signature the pinned group key does not verify (`reason=BAD_SIGNATURE`):
  *     a leader that answers wrongly is routed around within the call ([[signFailsOver]]).
  *   - Other re-issuable operations — group/public key, key info, decrypt, symmetric crypto —
  *     fail over on transport failures (UNAVAILABLE / DEADLINE_EXCEEDED) AND on a leader that
  *     answered but could not do its job (INTERNAL / UNKNOWN, e.g. its key store became
  *     unreadable). One sick node must not be a signing outage while a quorum is healthy.
  *   - Writes (hosted GenerateKey, DeleteKey) fail over only when the node is down, and a DKG
  *     ceremony only on a refused connection (UNAVAILABLE): a ceremony is never blindly re-run
  *     against another leader.
  *   - For the operations other than sign, a refusal (RESOURCE_EXHAUSTED, PERMISSION_DENIED,
  *     INVALID_ARGUMENT, ...) is a real answer from a live node and is returned immediately, never
  *     masked by trying another node. NOT_FOUND is one cosigner's answer about its own store: for
  *     a write (DeleteKey) it is returned as it is, for everything else the next point applies.
  *   - Where one cosigner's own answer is not the cluster's — "not found" in
  *     `keyExistsAndIsActive` for a FROST key, in a group-key read and in every call on a hosted
  *     key ([[withEcFailover]], [[clusterCallWholeRoster]]); a sign leader's NOT_FOUND,
  *     FAILED_PRECONDITION, ABORTED, UNIMPLEMENTED or unverifiable signature — the other cosigners
  *     are asked, and the outcome is decided over the whole roster, whatever the order
  *     ([[rosterVerdict]]): the answer is final once enough endpoints gave it that the rest could
  *     not use the key ([[ownAnswerQuorum]]: all but one, 2 of 3, 4 of 5); short of that, while
  *     an endpoint could not be reached (UNAVAILABLE or DEADLINE_EXCEEDED) the call fails with
  *     that endpoint's status. That is retryable: Canton never retries a final error, and the
  *     unreachable cosigner may hold the key.
  * Every hop is logged at WARN and recorded in the operation's own audit entry
  * (`failover=<from>→<to> reason=<CODE>`, see [[withAuditNotes]]). The leader is sticky: the
  * endpoint that last served a request successfully leads the next one, so once a node is found
  * sick later calls do not each pay a failed attempt against it. For sign, success means a verified
  * signature, and every error takes the lead from the node (see [[signDemotes]] for the
  * exceptions); for the other operations, only a leader-sick status does (for DKG, only
  * UNAVAILABLE), and a refusal leaves the lead where it is. This removes the single-leader
  * availability gap without any cross-node consensus — FROST sessions are independent, so no Raft
  * log is needed.
  *
  * '''Trust in the group key (audit H2):''' no single cosigner is believed about the namespace key.
  * `getPublicKey` (and the DKG reply) asks EVERY configured endpoint for the group key and needs at
  * least a roster majority of identical answers. A DKG's new key also needs no disagreeing one; the
  * first pin of an existing key (a first use after an upgrade) tolerates a dissenter, reported and
  * demoted, when every endpoint has its own TLS name. The agreed key is pinned per key id, durably
  * when `frost.pin-dir` is set ([[GroupKeyPinStore]]), before it is used, and never replaced. Later
  * `getPublicKey` calls re-ask and serve the pin, reporting any cosigner that answers differently;
  * every signature a leader returns is verified (Ed25519, strict) against the pinned key before it
  * leaves the driver, and one that does not verify is withheld and the next leader is asked. A
  * roster of exactly one endpoint (a dev setup) cannot agree with anyone, so there one answer
  * suffices — production rosters have several cosigners.
  */
class FrostBackend(
    endpoints: Seq[String],
    delegate: KmsBackend,
    logger: Logger,
    tls: Option[FrostTlsConfig] = None,
    // The budget of one driver call across every cosigner it tries (`frost.request-timeout`). A
    // DKG gets all of it in one attempt; every other call one attempt deadline per cosigner.
    requestTimeout: FiniteDuration = 30.seconds,
    hostedKeys: Boolean = false,
    keyPrefix: String = "",
    // How long the first Capabilities probe keeps retrying endpoints that do not answer before it
    // settles for an unconfirmed result, and how soon an unconfirmed result is asked again.
    capabilitiesRetryBudget: FiniteDuration = 30.seconds,
    capabilitiesRequery: FiniteDuration = 60.seconds,
    // Once a majority has answered, how much longer the first probe waits for the silent rest, so
    // a cosigner that is down delays participant startup by this much, not the whole budget.
    capabilitiesSilentGrace: FiniteDuration = 5.seconds,
    // The TLS server name each endpoint must present (url -> name, normally `cosigner<id>`). An
    // endpoint missing here falls back to `tls.domain`, then to its own host.
    endpointTlsNames: Map[String, String] = Map.empty,
    // The cosigners' cluster id for signing intents; None = learn it from Capabilities (a majority
    // of the endpoints must agree).
    clusterId: Option[String] = None,
    // How long a signing intent is valid: room for a sign through every endpoint's deadline (the
    // cosigners accept at most `intent_max_lifetime_secs`, 300 s by default).
    intentLifetime: FiniteDuration = 180.seconds,
    // `frost.sign-intents`: false stops attaching signing intents to signs — an emergency switch
    // for a cluster-id or intent problem while the cosigners do not require intents (audit F5).
    signIntents: Boolean = true,
    // The deadline of one attempt at one cosigner: signs (`frost.sign-attempt-timeout`), and every
    // other call that fails over (`frost.attempt-timeout`). Shorter than `requestTimeout`, so a
    // cosigner that stops answering costs one attempt deadline, not the whole budget.
    attemptTimeout: FiniteDuration = 10.seconds,
    signAttemptTimeout: FiniteDuration = 5.seconds,
    // HTTP/2 keepalive on every channel (`frost.keepalive-time` / `-timeout`), also while idle: a
    // connection to a cosigner that vanished (powered off, cut off) is torn down within about
    // keepaliveTime + keepaliveTimeout, and the next call fails over at once.
    keepaliveTime: FiniteDuration = 10.seconds,
    keepaliveTimeout: FiniteDuration = 5.seconds,
    // After this long, a configured-first cosigner that lost the lead gets it back (it is asked
    // first again; if it still fails it loses the lead again at the cost of one attempt).
    leaderRecovery: FiniteDuration = 60.seconds,
    // `frost.sign-leader`: true = rotate (each sign starts at the next healthy endpoint in turn),
    // false = sticky (every sign starts at the preferred leader, as every other call does).
    rotateSigns: Boolean = FrostBackend.DefaultRotateSigns,
    // `frost.pin-dir`: the durable group-key pins; None keeps them in memory only (a WARN).
    pinStore: Option[GroupKeyPinStore] = None,
    // `frost.expected-group-keys`: key id -> 64 hex, the operator's anchor for a key's first pin.
    expectedGroupKeys: Map[String, String] = Map.empty,
    // Key ids the audit log records as pinned whose pin file is gone: refused until re-anchored.
    lostPins: Set[String] = Set.empty,
    // Told about every new pin (the factory writes it to the audit log as `group-key-pin`).
    onPin: GroupKeyPin => Unit = (_: GroupKeyPin) => (),
    // `frost.adopt-existing-keys`: FROST key ids a DKG may return although the cluster already held
    // them from a ceremony this driver did not ask for (a deliberate adoption, after checking the key).
    adoptExistingKeys: Set[String] = Set.empty,
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

  /** Signs every FROST sign's intent with the mTLS identity (audit C2). None without TLS: a
    * plaintext (dev) cluster has no CA to verify intents against, and gets none. */
  private val intentSigner: Option[FrostIntentSigner] = tls.map { t =>
    val signer = FrostIntentSigner.load(t.cert, t.key)
    logger.info(s"FROST: signing intents are signed by ${signer.subject} (${signer.signatureAlg})")
    signer
  }
  if (tls.isEmpty) logger.warn("FROST: no TLS — signs carry no signing intent (a cosigner with require_intent refuses them)")

  /** The cluster id intents name: configured, or learned from the cluster (a majority of the
    * endpoints agreeing), and learned again after a cosigner refuses an intent for its cluster. */
  private val configuredClusterId: Option[String] = clusterId.filter(_.nonEmpty)
  @volatile private var intentClusterId: Option[String] = configuredClusterId
  if (!signIntents)
    logger.warn(
      "FROST: frost.sign-intents = off — signs carry NO signing intent; cosigners that require intents " +
        "refuse them. An emergency setting: turn it back on once the incident is over."
    )
  /** The DKG ceremony ids this driver's own intents named, per FROST key id, in this process (and,
    * with `frost.pin-dir`, durably in the pin store, which survives a restart). A
    * DKG reply for a key that already existed is accepted only when it names one of them: a retry
    * of this driver's own ceremony, never another client's key under the same id. */
  private val ownDkgCeremonies = new java.util.concurrent.ConcurrentHashMap[String, java.util.Set[String]]()

  private val lastIntentWarning = new java.util.concurrent.atomic.AtomicLong(0L)
  private val lastClusterProbe = new java.util.concurrent.atomic.AtomicLong(0L)

  /** Group keys (raw 32-byte Ed25519) pinned per key id: loaded from the pin store at startup and
    * written there before they are used. A pinned key never changes: the group key survives
    * refreshes, a new key id gets a new pin, and nothing here re-pins. */
  private val pinnedKeys = new java.util.concurrent.ConcurrentHashMap[String, ByteString]()

  /** `frost.expected-group-keys`, parsed. */
  private val expectedKeys: Map[String, ByteString] = expectedGroupKeys.map { case (k, h) =>
    if (!h.matches("[0-9a-fA-F]{64}"))
      throw new IllegalArgumentException(s"frost.expected-group-keys.$k must be 64 hex characters (a 32-byte Ed25519 key)")
    k -> ByteString.copyFrom(GroupKeyPinStore.unhex(h.toLowerCase))
  }

  pinStore.foreach { store =>
    store.all.foreach { case (k, p) => pinnedKeys.put(k, ByteString.copyFrom(p.groupKeyBytes)) }
    logger.info(s"FROST: ${store.all.size} pinned group key(s) loaded from ${store.dir}")
  }
  expectedKeys.foreach { case (k, e) =>
    Option(pinnedKeys.get(k)).filter(_ != e).foreach { p =>
      throw new IllegalArgumentException(
        s"frost.expected-group-keys.$k is ${hexOf(e)} but the pin store holds ${hexOf(p)} for it. The pin is never " +
          "replaced silently: check the key ceremony record (docs/production-profile.md)"
      )
    }
  }
  if (pinStore.isEmpty && channels.size > 1)
    logger.warn(
      "FROST: frost.pin-dir is not set: group-key pins live in memory only and are agreed again after every restart"
    )
  lostPins.filterNot(expectedKeys.contains).foreach { k =>
    logger.error(
      s"FROST: the audit log records a pin for $k but the pin store has no file for it: $k is refused until " +
        "the file is restored or frost.expected-group-keys names its key"
    )
  }

  /** Identical answers needed to believe a group key: a majority of the roster, or the lone
    * endpoint of a single-endpoint (dev) roster, which has nobody to agree with. */
  private val groupKeyAgreement: Int = if (channels.size == 1) 1 else channels.size / 2 + 1

  /** Answers needed to believe a cluster id (signing intents): two identical ones, or the lone
    * endpoint of a single-endpoint (dev) roster. */
  private val requiredAgreement: Int = if (channels.size == 1) 1 else 2

  /** A dissenter may be outvoted at the first pin of an existing key only when every endpoint has a
    * TLS name of its own: otherwise one cosigner could answer at two addresses and count twice. */
  private val distinctCosigners: Boolean = {
    val names = endpoints.flatMap(e => endpointTlsNames.get(e))
    names.size == endpoints.size && names.distinct.size == names.size
  }

  /** Endpoint indices that answered another group key than the pin (or the majority), per key id:
    * reported, demoted, and asked last for that key's signs. */
  private val dissenters = new java.util.concurrent.ConcurrentHashMap[String, java.util.Set[Integer]]()

  /** A group-key query's outcome: the key, the endpoints that answered it, and those that answered
    * another one. */
  private final case class Agreed(key: ByteString, agreedBy: Seq[String], dissent: Seq[(String, ByteString)])

  /** Ask every endpoint (in parallel) for `keyId`'s group key and settle on it ([[agreeOnGroupKey]]).
    * `fresh`: the key a DKG just made, which no answering cosigner may contradict. `notes` are the
    * calling operation's audit notes, captured on the calling thread. */
  private def queryGroupKey(keyId: String, fresh: Boolean, notes: AuditNotes): Future[Agreed] = {
    val req = GroupKeyRequest.newBuilder().setKeyId(keyId).build()
    Future
      .traverse(channels.indices.toVector) { i =>
        Future(blocking {
          try Right(endpoints(i) -> stubFor(channels(i)).groupKey(req).getGroupVerifyingKey)
          catch { case e: StatusRuntimeException => Left(endpoints(i) -> e) }
        })
      }
      .map { results =>
        val answers = results.collect { case Right(a) => a }
        val errors = results.collect { case Left(e) => e }
        errors.foreach { case (ep, e) =>
          logger.warn(s"FROST: groupKey for $keyId via $ep did not answer (${e.getStatus.getCode}); not counted")
        }
        agreeOnGroupKey(keyId, answers, errors.map(_._2), fresh, notes)
      }
  }

  /** Settle `keyId`'s group key from the endpoints' answers.
    *
    * Pinned: the pin is the answer. A cosigner that answers another key is reported and demoted;
    * the call fails, non-retryably, only when every endpoint answered and each differs from the pin,
    * and is served from the pin otherwise, also when nobody answers (availability is not trust).
    *
    * Not pinned: a roster majority of identical answers ([[groupKeyAgreement]]). For a DKG's new
    * key (`fresh`) any disagreeing answer fails the call; for an existing key one dissenter (never
    * more) is tolerated, reported and demoted, when [[distinctCosigners]]. A configured
    * `frost.expected-group-keys` value must be the agreed key. Too few answers is retryable; when
    * none came, an endpoint's own error is rethrown: NOT_FOUND (an unknown key) once
    * [[ownAnswerQuorum]] endpoints said so; short of that an unreachable endpoint's (UNAVAILABLE or
    * DEADLINE_EXCEEDED, retryable) when there is one, else NOT_FOUND if any endpoint said so, else
    * the last error. */
  private def agreeOnGroupKey(
      keyId: String,
      answers: Seq[(String, ByteString)],
      errors: Seq[StatusRuntimeException],
      fresh: Boolean,
      notes: AuditNotes,
  ): Agreed = {
    def detail(as: Seq[(String, ByteString)]): String = as.map { case (ep, k) => s"$ep=${hexOf(k)}" }.mkString(", ")
    Option(pinnedKeys.get(keyId)) match {
      case Some(p) =>
        val (matching, wrong) = answers.partition(_._2 == p)
        // Only when every endpoint answered, and each answered another key: some endpoints silent
        // and the rest wrong is served from the pin (with the dissent reported), not a final error.
        if (answers.nonEmpty && matching.isEmpty && errors.isEmpty) {
          logger.error(s"FROST: every answering cosigner differs from the pinned group key ${hexOf(p)} of $keyId: ${detail(wrong)}")
          throw KmsDriverException(
            new SecurityException(s"group key for $keyId differs from the pinned ${hexOf(p)} at every answering cosigner: ${detail(wrong)}"),
            retryable = false,
          )
        }
        wrong.foreach(w => reportDissent(keyId, w, s"the pinned ${hexOf(p)}", notes))
        Agreed(p, matching.map(_._1), wrong)
      case None =>
        if (lostPin(keyId)) throw lostPinError(keyId)
        // Nobody answered with a key. NOT_FOUND is the answer once enough cosigners said so that the
        // rest could not use the key (ownAnswerQuorum); short of that, a cosigner that could not be
        // reached may hold it, and its error (which Canton retries) comes first.
        if (answers.isEmpty && errors.nonEmpty) {
          val (notFound, rest) = errors.partition(_.getStatus.getCode == Status.Code.NOT_FOUND)
          throw (
            if (notFound.size >= ownAnswerQuorum) notFound.last
            else rest.find(e => isNodeDown(e.getStatus)).orElse(notFound.lastOption).getOrElse(errors.last)
          )
        }
        val byKey = answers.groupBy(_._2).toSeq.sortBy { case (_, as) => -as.size }
        val (top, topAnswers) = byKey.headOption.getOrElse(
          throw KmsDriverException(new IllegalStateException(s"no cosigner answered for the group key of $keyId"), retryable = true)
        )
        val dissent = answers.filter(_._2 != top)
        val tolerated = !fresh && distinctCosigners && dissent.size <= 1 && topAnswers.size >= groupKeyAgreement
        if (dissent.nonEmpty && !tolerated) {
          logger.error(s"FROST: cosigners DISAGREE on the group key of $keyId: ${detail(answers)}")
          throw KmsDriverException(
            new SecurityException(s"cosigners disagree on the group key of $keyId: ${detail(answers)}"),
            retryable = false,
          )
        }
        if (topAnswers.size < groupKeyAgreement)
          throw KmsDriverException(
            new IllegalStateException(
              s"only ${answers.size} of ${channels.size} cosigners answered for the group key of $keyId; " +
                s"$groupKeyAgreement identical answers are needed before it is trusted"
            ),
            retryable = true,
          )
        expectedKeys.get(keyId).filter(_ != top).foreach { e =>
          throw KmsDriverException(
            new SecurityException(
              s"the cosigners agree on group key ${hexOf(top)} for $keyId, but frost.expected-group-keys says ${hexOf(e)}"
            ),
            retryable = false,
          )
        }
        require(top.size == 32, s"expected 32-byte Ed25519 group key, got ${top.size}")
        dissent.foreach(d => reportDissent(keyId, d, s"the majority's ${hexOf(top)}", notes))
        Agreed(top, topAnswers.map(_._1), dissent)
    }
  }

  /** One endpoint answered `keyId`'s group key differently from `against`: an ERROR, an audit note,
    * the lead taken from it, and it is asked last for this key's signs. */
  private def reportDissent(keyId: String, answer: (String, ByteString), against: String, notes: AuditNotes): Unit = {
    val (ep, key) = answer
    logger.error(s"FROST: cosigner $ep answers group key ${hexOf(key)} for $keyId, not $against; routed around")
    notes.add(s"groupkey-dissent=$ep")
    val i = endpoints.indexOf(ep)
    if (i >= 0) {
      dissenters.computeIfAbsent(keyId, _ => java.util.concurrent.ConcurrentHashMap.newKeySet[Integer]()).add(Integer.valueOf(i))
      demote(i)
    }
  }

  /** Where the next sign for `keyId` starts.
    *
    * Sticky: the preferred leader, past this key's group-key dissenters ([[leaderFor]]).
    * Rotate: the next endpoint in turn (one shared counter, so concurrent signs spread too) that is
    * healthy: not demoted within [[leaderRecovery]] and not a dissenter for this key. Only when no
    * endpoint is healthy does it fall back to the sticky choice (a call has to start somewhere).
    * This picks the start only: failover then walks the ring from it, as in sticky mode.
    * Ceremonies and hosted-key calls never come here: they stay on the preferred leader. */
  private[backend] def signStart(keyId: String): Int =
    if (!rotateSigns) leaderFor(keyId, startIndex())
    else {
      val n = channels.size
      val now = System.nanoTime()
      val bad = Option(dissenters.get(keyId))
      def healthy(i: Int): Boolean = {
        val d = demotedAt.get(i)
        !(d != 0L && now - d <= leaderRecovery.toNanos) && !bad.exists(_.contains(Integer.valueOf(i)))
      }
      val first = Math.floorMod(signCursor.getAndIncrement(), n)
      (0 until n).map(k => (first + k) % n).find(healthy).getOrElse(leaderFor(keyId, startIndex()))
    }

  /** The rotation counter of [[signStart]]. */
  private val signCursor = new AtomicInteger(0)

  /** Where a sign for `keyId` starts: `start`, or the first endpoint after it in ring order that has
    * not dissented about this key's group key. */
  private def leaderFor(keyId: String, start: Int): Int =
    Option(dissenters.get(keyId)).fold(start) { bad =>
      (0 until channels.size).map(k => (start + k) % channels.size).find(i => !bad.contains(Integer.valueOf(i))).getOrElse(start)
    }

  /** The audit log records a pin for `keyId` whose file is gone, and no operator anchor replaces it. */
  private def lostPin(keyId: String): Boolean =
    lostPins.contains(keyId) && !expectedKeys.contains(keyId) && !pinnedKeys.containsKey(keyId)

  private def lostPinError(keyId: String): KmsDriverException =
    KmsDriverException(
      new SecurityException(
        s"the audit log records a group-key pin for $keyId but its pin file is missing; restore it, or set " +
          s"frost.expected-group-keys.$keyId from the key ceremony record (docs/disaster-recovery.md §3i)"
      ),
      retryable = false,
    )

  /** How a first pin of `keyId` came about, when it is not a DKG. */
  private def adoptSource(keyId: String): String = if (expectedKeys.contains(keyId)) "operator" else "adopted"

  /** Pin `agreed` as `keyId`'s group key: durably first (when a pin store is configured), then in
    * memory. Returns the pinned key. A pin that already exists must be the same key; any other is a
    * non-retryable error, and nothing is replaced. A pin that cannot be made durable fails the call
    * (retryable) and is not used. */
  private def pin(keyId: String, agreed: Agreed, source: String): ByteString = {
    val key = agreed.key
    if (!isValidEd25519Key(key.toByteArray))
      throw KmsDriverException(
        new SecurityException(s"group key for $keyId is not a valid Ed25519 public key (${hexOf(key)})"),
        retryable = false,
      )
    def changed(prior: ByteString): Nothing =
      throw KmsDriverException(
        new SecurityException(s"group key for $keyId changed: pinned ${hexOf(prior)}, the cosigners now answer ${hexOf(key)}"),
        retryable = false,
      )
    Option(pinnedKeys.get(keyId)) match {
      case Some(prior) if prior == key => prior
      case Some(prior)                 => changed(prior)
      case None =>
        val record = GroupKeyPin(
          keyId,
          hexOf(key),
          source,
          agreed.agreedBy.toList,
          agreed.dissent.map { case (ep, k) => s"$ep=${hexOf(k)}" }.toList,
          java.time.Instant.now().toString,
        )
        val stored = pinStore match {
          case None => record
          case Some(store) =>
            try store.create(record)
            catch {
              case c: GroupKeyPinStore.Conflict =>
                throw KmsDriverException(new SecurityException(c.getMessage), retryable = false)
              case e: java.io.IOException =>
                throw KmsDriverException(
                  new IllegalStateException(s"cannot write the group-key pin for $keyId to ${store.dir}: ${e.getMessage}", e),
                  retryable = true,
                )
            }
        }
        // The audit entry before the pin is used: an append that fails leaves the pin out of memory
        // (the call fails, retryably, and the next one records it); a crash between the pin file and
        // this entry is recorded at the next start (PinAudit.reconcile).
        try onPin(stored)
        catch {
          case e: Exception =>
            throw KmsDriverException(
              new IllegalStateException(s"cannot record the group-key pin for $keyId in the audit log: ${e.getMessage}", e),
              retryable = true,
            )
        }
        val prior = pinnedKeys.putIfAbsent(keyId, key)
        if (prior != null && prior != key) changed(prior)
        if (prior == null)
          logger.info(s"FROST: pinned group key for $keyId = ${hexOf(key)} (${stored.source}, agreed by ${stored.agreedBy.mkString(", ")})")
        key
    }
  }

  /** The pinned group key of `keyId`: the pin if there is one, otherwise a first pin by agreement. */
  private def pinnedGroupKey(keyId: String, notes: AuditNotes): Future[ByteString] =
    Option(pinnedKeys.get(keyId)).fold(
      queryGroupKey(keyId, fresh = false, notes).map(a => pin(keyId, a, adoptSource(keyId)))
    )(Future.successful)

  /** The pinned group key of `keyId`, for the production-profile and state checks. */
  private[rutli] def pinnedGroupKeyHex(keyId: String): Option[String] = Option(pinnedKeys.get(keyId)).map(hexOf)

  /** The TLS server name `endpoint` must present: its own `tls-name`, else `tls.domain`, else None
    * (the host in the target). */
  private[backend] def tlsServerName(endpoint: String): Option[String] =
    endpointTlsNames.get(endpoint).orElse(tls.flatMap(_.domain))

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
      val b = NettyChannelBuilder
        .forTarget(endpoint)
        .sslContext(ssl)
        .keepAliveTime(keepaliveTime.toMillis, TimeUnit.MILLISECONDS)
        .keepAliveTimeout(keepaliveTimeout.toMillis, TimeUnit.MILLISECONDS)
        .keepAliveWithoutCalls(true)
      // Per endpoint (audit M3): with one shared name for every endpoint, a certificate issued to
      // any cosigner would verify at every address.
      val serverName = tlsServerName(endpoint)
      serverName.foreach(b.overrideAuthority)
      logger.info(s"FROST: mutual TLS channel to $endpoint (server name ${serverName.getOrElse("<host>")})")
      b.build()
    case None =>
      logger.warn(s"FROST: plaintext channel to $endpoint (no TLS) — do not use in production")
      ManagedChannelBuilder
        .forTarget(endpoint)
        .usePlaintext()
        .keepAliveTime(keepaliveTime.toMillis, TimeUnit.MILLISECONDS)
        .keepAliveTimeout(keepaliveTimeout.toMillis, TimeUnit.MILLISECONDS)
        .keepAliveWithoutCalls(true)
        .build()
  }

  /** A stub for one attempt at one cosigner, with its own deadline: [[attemptTimeout]] unless the
    * caller says otherwise (a sign, a ceremony, the time left of a call's budget). */
  private def stubFor(ch: ManagedChannel, deadline: FiniteDuration = attemptTimeout): SignerGrpc.SignerBlockingStub =
    SignerGrpc.newBlockingStub(ch).withDeadlineAfter(math.max(deadline.toMillis, 1L), TimeUnit.MILLISECONDS)

  /** Index into `endpoints` of the preferred leader: the cosigner that last served a request. */
  private val preferred = new AtomicInteger(0)

  /** Endpoint `i` failed in a way that should cost it the lead: if it is still the preferred leader,
    * the next endpoint in ring order is, so the next call starts elsewhere. A compare-and-set, so it
    * never overrides a newer value another call wrote. */
  private def demote(i: Int): Unit = demote(i, (i + 1) % channels.size)

  /** [[demote]] with the endpoint that takes the lead named: `to`, the one that served the call,
    * for an endpoint whose demotion was held back until the call was served (it said it lacks the
    * key). The next endpoint in the ring is not known to be good then: it may be one that failed
    * later in the same walk. */
  private def demote(i: Int, to: Int): Unit = {
    // Recorded even when another call already moved the lead: it is still evidence that this node
    // failed just now, and it only delays the first endpoint's recovery. Before the lead moves, so
    // that startIndex never sees the lead off endpoint 0 without its demotion time.
    demotedAt.set(i, System.nanoTime())
    if (preferred.compareAndSet(i, to) && to != i)
      logger.info(s"FROST: leader is now ${endpoints(to)} (was ${endpoints(i)}); leader order ${leaderOrder(to)}")
  }

  /** When each endpoint last lost the lead (System.nanoTime; 0 = never). */
  private val demotedAt = new java.util.concurrent.atomic.AtomicLongArray(channels.size)

  /** The order in which a call starting at `start` asks the endpoints, as logged on every change of
    * leader (the driver has no metrics endpoint: this log line and the `failover=` notes in the
    * audit log are where the leader order shows). */
  private def leaderOrder(start: Int): String =
    (0 until channels.size).map(k => endpoints((start + k) % channels.size)).mkString(" > ")

  /** The endpoint a call starts at: the preferred leader, except that the configured-first endpoint
    * gets the lead back once [[leaderRecovery]] has passed since it lost it (at once if it never
    * failed: the lead then moved for another reason, such as another node answering first). A transient blip (one
    * missed deadline, a restart) therefore does not keep the lead elsewhere for good. */
  private def startIndex(): Int = {
    val p = preferred.get
    if (p != 0 && System.nanoTime() - demotedAt.get(0) > leaderRecovery.toNanos && preferred.compareAndSet(p, 0)) {
      logger.info(
        s"FROST: leader back to ${endpoints(0)} (lost the lead more than $leaderRecovery ago); leader order ${leaderOrder(0)}"
      )
      0
    } else preferred.get
  }

  /** Run `op` against the cosigners in ring order, starting from the preferred leader, moving to
    * the next only when `retryOn` says the contacted node could not serve it (see the predicates on
    * the companion — each call site picks the one its operation is safe under). Any other gRPC
    * status is a real answer and is rethrown immediately; when every endpoint fails over, the last
    * error is thrown. Each hop is logged at WARN and noted in `notes` for the operation's audit
    * entry.
    *
    * Sticky leader ("last healthy first"): a successful answer makes its node the preferred leader,
    * and an error status for which `demoteOn` holds takes the lead from its node ([[demote]]). Each
    * call site picks `demoteOn`: for the operations one node serves alone and the driver cannot
    * check (decrypt, symmetric crypto, hosted keys, key reads) it is [[isLeaderSick]], so a refusal
    * such as RESOURCE_EXHAUSTED or PERMISSION_DENIED leaves the lead where it is (the per-node
    * decrypt limit must not become n times the budget, and one node's delete allowlist must not be
    * shopped around); for a DKG it is only the status it also fails over on. Sign uses
    * [[withCheckedFailover]] with its own rule. Once a node is found sick, later calls lead from the
    * healthy one directly instead of each paying a failed attempt (and a WARN) against the sick
    * node, and a recovered node is simply reached again when the ring next wraps to it.
    *
    * Concurrent calls: a success writes its node only if the preference is still the value this call
    * started from (a compare-and-set), so a slow success cannot undo a demotion a newer call made
    * meanwhile; a demotion only moves the lead off the node that failed. Deterministic: no probing,
    * no randomness. */
  private def withFailover[A](
      what: String,
      retryOn: Status => Boolean,
      demoteOn: Status => Boolean,
      notes: AuditNotes,
      attempt: FiniteDuration = attemptTimeout,
  )(op: SignerGrpc.SignerBlockingStub => A): A = {
    val start = startIndex()
    val budgetEnd = System.nanoTime() + requestTimeout.toNanos
    withCheckedFailover[A](what, retryOn, demoteOn, notes, (_: String, _: A) => None, start, start, (_: Int) => (), attempt, budgetEnd)(op)
  }

  /** [[withFailover]] where the driver also checks each answer: `check(endpoint, answer)` returns
    * a [[Rejected]] for an answer that must not be used (a signature the pinned group key does not
    * verify). A rejected answer is that leader failing: it is not returned, its node is demoted, and
    * the next endpoint is tried within this call, noted as `failover=<from>→<to> reason=<code>`.
    * When it is the last endpoint's answer, the call fails with the rejection's error.
    *
    * `observed` is the preference this call read when it began (a success replaces only that
    * value), `from` the endpoint it tries first (normally the same), and `tried` is told each
    * endpoint index just before it is asked.
    *
    * `wholeRoster` is set by the calls where one cosigner's failure is not the cluster's answer: it
    * names the failures that are that cosigner's own (a NOT_FOUND for a key the others may hold) —
    * `Some(true)` for one that says the cosigner cannot use the key, which counts towards
    * [[ownAnswerQuorum]], `Some(false)` for one that is about the cosigner's state at the moment (a
    * ceremony in progress), which never becomes final by count, `None` for any other failure.
    * For such a call, what it fails with once every endpoint has failed is decided over the whole
    * walk, not by the endpoint that happened to be asked last ([[rosterVerdict]]). Without it the
    * last endpoint's error is thrown, as before. A failure for which `retryOn` does not hold is
    * thrown at once either way.
    *
    * `lacksKey` names the failures that say only "I do not have this key" (NOT_FOUND). Such an
    * endpoint is not at fault unless the cluster has the key: it loses the lead only when a later
    * endpoint serves the call, and not at all when the call ends with the roster's "not found" or
    * with the retryable [[unconfirmed]]. Otherwise a lookup of a key that exists nowhere would
    * take the lead from every endpoint, and with it the sign rotation ([[signStart]]) for
    * [[leaderRecovery]]. A failure it does not name costs the lead at once, as `demoteOn` says. */
  private def withCheckedFailover[A](
      what: String,
      retryOn: Status => Boolean,
      demoteOn: Status => Boolean,
      notes: AuditNotes,
      check: (String, A) => Option[Rejected],
      observed: Int,
      from: Int,
      tried: Int => Unit,
      attemptDeadline: FiniteDuration,
      // When the whole call's budget ends (System.nanoTime). A caller that runs this loop more
      // than once for one call (a sign that learns the cluster id again) passes the same value.
      budgetEnd: Long,
      wholeRoster: Option[Either[StatusRuntimeException, Rejected] => Option[Boolean]] = None,
      lacksKey: Either[StatusRuntimeException, Rejected] => Boolean = (_: Either[StatusRuntimeException, Rejected]) => false,
  )(op: SignerGrpc.SignerBlockingStub => A): A = {
    val n = channels.size
    // One attempt in flight at a time: the next cosigner is asked only once this attempt has failed
    // or hit its deadline, which cancels it (the RPC is reset). Each attempt's deadline is capped
    // by what is left of the budget, and no attempt starts once less than MinAttempt is left.
    def left: Long = budgetEnd - System.nanoTime()
    // `seen`: what the endpoints asked so far in this call failed with (for `wholeRoster`).
    @tailrec def attempt(k: Int, lastReason: String, seen: Seen): A = {
      if (k > 0 && left < MinAttempt.toNanos) {
        logger.warn(s"FROST: $what: request-timeout $requestTimeout spent after $k cosigner(s); last: $lastReason")
        notes.add("request-timeout=spent")
        throw Status.DEADLINE_EXCEEDED
          .withDescription(s"$what: request-timeout $requestTimeout spent after $k cosigner(s); last: $lastReason")
          .asRuntimeException()
      }
      val i = (from + k) % n
      tried(i)
      val deadline: FiniteDuration = FiniteDuration(math.min(attemptDeadline.toNanos, math.max(left, 0L)), NANOSECONDS)
      val outcome: Either[Either[StatusRuntimeException, Rejected], A] =
        try {
          val answer = op(stubFor(channels(i), deadline))
          check(endpoints(i), answer) match {
            case Some(rejected) => Left(Right(rejected))
            case None           => Right(answer)
          }
        } catch { case e: StatusRuntimeException => Left(Left(e)) }
      outcome match {
        case Right(answer) =>
          // After this call's own demotions the preference is normally `i` already; if another call
          // changed it meanwhile, its value stands.
          // The cluster has the key: the endpoints that said they lack it lose the lead now, to
          // the endpoint that served — not to the next one in the ring, which may be one that
          // failed later in this walk.
          seen.lackedKeyAt.reverse.foreach(j => demote(j, i))
          preferred.compareAndSet(observed, i)
          answer
        case Left(failure) =>
          val error: Exception = failure match {
            case Left(e)  => e
            case Right(r) => r.error
          }
          val retry: Boolean = failure match {
            case Left(e)  => retryOn(e.getStatus)
            case Right(_) => true
          }
          val loseLead: Boolean = failure match {
            case Left(e)  => demoteOn(e.getStatus)
            case Right(_) => true
          }
          val code: String = failure match {
            case Left(e)  => e.getStatus.getCode.toString
            case Right(r) => r.code
          }
          val reason: String = failure match {
            case Left(e)  => Option(e.getStatus.getDescription).fold(code)(d => s"$code: $d")
            case Right(r) => s"$code: ${r.error.getMessage}"
          }
          val deferred: Boolean = lacksKey(failure)
          val counted: Seen = failure match {
            case Left(e) if isNodeDown(e.getStatus)      => seen.copy(unreachable = Some(endpoints(i) -> e))
            case f =>
              wholeRoster.flatMap(own => own(f)) match {
                case Some(counts) => seen.copy(own = seen.own + (if (counts) 1 else 0), lastOwn = Some(code -> error))
                case None         => seen.copy(other = Some(error))
              }
          }
          val seenNow: Seen = if (deferred) counted.copy(lackedKeyAt = i :: counted.lackedKeyAt) else counted
          if (loseLead && !deferred) demote(i)
          if (!retry) throw error
          if (k + 1 < n) {
            val next = endpoints((i + 1) % n)
            logger.warn(s"FROST: $what via ${endpoints(i)} failed ($reason); failing over to $next")
            notes.add(s"failover=${endpoints(i)}→$next reason=$code")
            attempt(k + 1, reason, seenNow)
          } else {
            logger.warn(s"FROST: $what via ${endpoints(i)} failed ($reason); no cosigner left to try")
            throw (if (wholeRoster.isDefined) rosterVerdict(what, notes, seenNow, error) else error)
          }
      }
    }
    attempt(0, "", Seen())
  }

  /** How many endpoints must give a cosigner's own "I do not have it" before it is the cluster's
    * answer: all but one (2 of 3, 4 of 5; the lone endpoint of a dev roster). Then at most one
    * cosigner is left that could hold the key, and that is too few to use it:
    *   - a FROST key needs t holders to sign. The driver does not know t, and a cosigner accepts
    *     any threshold up to n, also one below a majority (2-of-5), so n - t + 1 cannot be used; a
    *     threshold key has t >= 2, for which all but one is always enough;
    *   - a hosted key is a whole key on every cosigner that holds it, and the driver saw
    *     [[requiredCopies]] (two) of them before it gave the key id to Canton
    *     ([[confirmHostedCopies]]), so a key only one cosigner holds is one whose generation was
    *     never confirmed. */
  private val ownAnswerQuorum: Int = math.max(1, channels.size - 1)

  /** What a call fails with once every endpoint has failed, for a call where one cosigner's own
    * answer ("not found", "another key", "I cannot sign") is not the cluster's. Decided over the
    * whole walk, so the outcome is the same in whatever order the endpoints were asked:
    *   1. at least [[ownAnswerQuorum]] endpoints gave such an answer of the kind that counts (the
    *      cosigner cannot use the key): it is final, and the last own answer is thrown. The cosigners that did not answer are then too few to use the key, so
    *      waiting for them cannot help; this also bounds what Canton retries for a key that exists
    *      nowhere while a cosigner is down;
    *   2. otherwise, an endpoint could not be reached (UNAVAILABLE, or DEADLINE_EXCEEDED, which
    *      includes the driver's own attempt deadline passing): its status is thrown, which the
    *      driver reports to Canton as retryable — as [[unconfirmed]], with an audit note, when some
    *      endpoint did give such an answer. The unreachable cosigners may hold the key, and Canton
    *      never retries a final error;
    *   3. otherwise every endpoint answered: the last such answer stands, also next to INTERNAL or
    *      UNKNOWN answers; with none, the last of those errors (`last` when there is neither). */
  private def rosterVerdict(what: String, notes: AuditNotes, seen: Seen, last: Exception): Exception =
    seen.lastOwn match {
      case Some((_, error)) if seen.own >= ownAnswerQuorum => error
      case own =>
        seen.unreachable match {
          case Some((endpoint, down)) =>
            own.fold[Exception](down) { case (answer, _) => unconfirmed(what, notes, endpoint, down, answer) }
          case None => own.map(_._2).orElse(seen.other).getOrElse(last)
        }
    }

  /** The error of a call whose cosigners answered `answer` (NOT_FOUND, say), fewer of them than
    * [[ownAnswerQuorum]], while `endpoint` could not be reached: that cosigner may hold the key, so
    * the answer is not the cluster's. The call fails with the unreachable endpoint's own status —
    * UNAVAILABLE or DEADLINE_EXCEEDED, which the driver reports to Canton as retryable — and the
    * audit entry gets `unconfirmed=<endpoint> reason=<CODE>`. `reason=DEADLINE_EXCEEDED` is also
    * what an endpoint that did not answer within the driver's own attempt deadline gets. */
  private def unconfirmed(
      what: String,
      notes: AuditNotes,
      endpoint: String,
      down: StatusRuntimeException,
      answer: String,
  ): StatusRuntimeException = {
    val code = down.getStatus.getCode
    logger.warn(
      s"FROST: $what: the cosigners that answered said $answer, but $endpoint did not serve the call ($code) and may " +
        "hold the key; not a final answer"
    )
    notes.add(s"unconfirmed=$endpoint reason=$code")
    down.getStatus
      .augmentDescription(s"$what: $answer from the cosigners that answered, but $endpoint did not serve the call; not a final answer")
      .asRuntimeException()
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
    * leader (review M1, 2026-10-09 decision; if it was the preferred one it loses that, once
    * another cosigner has served the call — when none does, nobody is demoted for it). `stale`
    * recognises such an answer; leader-sick statuses fail over and demote as usual, and any other
    * status is returned at once and leaves the lead where it is (see [[withFailover]]).
    *
    * An answer found after a stale one is used whatever the key's type turns out to be: a
    * cosigner that lacks a key the others hold is routed around for an RSA or AES key as well
    * ([[clusterCallWholeRoster]] is the same rule for a key known not to be EC).
    *
    * How the walk ends when no answer was used is decided over the whole roster, whatever the order
    * the endpoints were asked in (the rule of [[rosterVerdict]]):
    *   1. at least [[ownAnswerQuorum]] endpoints gave a stale answer: the first stale answer
    *      stands (the key is not there, or no cosigner's secret opens the blob);
    *   2. otherwise, an endpoint could not be reached (UNAVAILABLE or DEADLINE_EXCEEDED, the
    *      driver's own attempt deadline included): the call fails with that endpoint's status, which
    *      is retryable — as [[unconfirmed]] when some endpoint gave a stale answer. The unreachable
    *      cosigner may hold the key, and a final "not found" would tell Canton the key does not
    *      exist; Canton never retries a final error;
    *   3. otherwise every endpoint answered: the first stale answer stands, also next to INTERNAL
    *      or UNKNOWN answers (those nodes were reached); with no stale answer, the last such error.
    * One exception, in [[decryptEcies]]: a shared secret that did not open the ciphertext ends the
    * decrypt as an ECIES failure even when another cosigner was unreachable, because the
    * ciphertext is the counterparty's and must not be able to buy retries.
    *
    * `staleAnswer` names a stale *answer* (a `Right`) for the WARN and the `ec-failover` note
    * (`failover` when the key's type is not known yet, `knownEc = false`): its
    * reason code and what it may mean. A stale status is named by its gRPC code. Each endpoint is
    * asked at most once, so one call costs at most n cosigner round trips. */
  private def withEcFailover[A](
      what: String,
      notes: AuditNotes,
      stale: Either[StatusRuntimeException, A] => Boolean,
      staleAnswer: A => (String, String),
      // False for a call on a key whose type the driver does not know yet (PublicKey, KeyInfo): the
      // key may turn out to be RSA or AES, so the hop is noted as a plain `failover=`.
      knownEc: Boolean,
  )(op: SignerGrpc.SignerBlockingStub => A): A = {
    val n = channels.size
    val start = startIndex()
    // `stales`: how many endpoints gave a stale answer so far, `firstStale` the first of them;
    // `unreachable`: the endpoint asked most recently that could not be reached; `sick`: the last
    // INTERNAL or UNKNOWN error.
    @tailrec def attempt(
        k: Int,
        firstStale: Option[Either[StatusRuntimeException, A]],
        stales: Int,
        unreachable: Option[(String, StatusRuntimeException)],
        sick: Option[StatusRuntimeException],
        // Endpoint indices that gave a stale answer, latest first: demoted only if the call is served.
        staleAt: List[Int],
    ): A = {
      val i = (start + k) % n
      val outcome: Either[StatusRuntimeException, A] =
        try Right(op(stubFor(channels(i))))
        catch { case e: StatusRuntimeException => Left(e) }
      def settle(o: Either[StatusRuntimeException, A]): A = o.fold(e => throw e, identity)
      // The roster is exhausted without an answer to use (see the three cases above).
      def exhausted(
          first: Option[Either[StatusRuntimeException, A]],
          staleCount: Int,
          down: Option[(String, StatusRuntimeException)],
          lastSick: Option[StatusRuntimeException],
      ): A =
        (first, down, lastSick) match {
          case (Some(f), _, _) if staleCount >= ownAnswerQuorum => settle(f)
          case (Some(f), Some((endpoint, e)), _) =>
            throw unconfirmed(what, notes, endpoint, e, f.fold(_.getStatus.getCode.toString, a => staleAnswer(a)._1))
          case (None, Some((_, e)), _) => throw e
          case (Some(f), None, _)      => settle(f)
          case (None, None, Some(e))   => throw e
          case (None, None, None)      => throw new IllegalStateException(s"$what: no cosigner was asked")
        }
      val next = if (k + 1 < n) Some(endpoints((i + 1) % n)) else None
      outcome match {
        case Left(e) if isLeaderSick(e.getStatus) =>
          demote(i)
          val down = if (isNodeDown(e.getStatus)) Some(endpoints(i) -> e) else unreachable
          val lastSick = if (isNodeDown(e.getStatus)) sick else Some(e)
          next match {
            case Some(to) =>
              logger.warn(s"FROST: $what via ${endpoints(i)} failed (${e.getStatus.getCode}); failing over to $to")
              notes.add(s"failover=${endpoints(i)}→$to reason=${e.getStatus.getCode}")
              attempt(k + 1, firstStale, stales, down, lastSick, staleAt)
            case None => exhausted(firstStale, stales, down, lastSick)
          }
        case o if stale(o) =>
          // Not demoted here: a stale answer costs the lead only when another cosigner then serves
          // the call (below). A key that is nowhere, or a blob no cosigner's secret opens, is not
          // these cosigners' fault, and demoting all of them would switch the sign rotation off.
          val (reason, meaning) = o.fold(e => (e.getStatus.getCode.toString, MayBeOld), staleAnswer)
          val first = firstStale.getOrElse(o)
          next match {
            case Some(to) =>
              val key = if (knownEc) "an EC hosted key" else "a hosted key that may be EC"
              val note = if (knownEc) "ec-failover" else "failover"
              logger.warn(s"FROST: $what via ${endpoints(i)} answered $reason for $key — $meaning; asking $to")
              notes.add(s"$note=${endpoints(i)}→$to reason=$reason")
              attempt(k + 1, Some(first), stales + 1, unreachable, sick, i :: staleAt)
            case None => exhausted(Some(first), stales + 1, unreachable, sick)
          }
        case Right(answer) =>
          // The cluster serves the key: the cosigners that answered stale lose the lead, to the
          // one that served (see withCheckedFailover).
          staleAt.reverse.foreach(j => demote(j, i))
          preferred.compareAndSet(start, i)
          answer
        case Left(e) =>
          // A real answer (RESOURCE_EXHAUSTED, INVALID_ARGUMENT, ...), returned at once as before.
          // It leaves the lead where it is: the per-node decrypt limit must not become n times the
          // budget by moving the next call to another node.
          throw e
      }
    }
    attempt(0, None, 0, None, None, Nil)
  }

  /** [[clusterCall]] for [[withEcFailover]]. */
  private def clusterCallEc[A](
      what: String,
      stale: Either[StatusRuntimeException, A] => Boolean,
      staleAnswer: A => (String, String) = (_: A) => ("NOT_FOUND", MayBeOld),
      knownEc: Boolean = false,
  )(op: SignerGrpc.SignerBlockingStub => A): Future[A] = {
    val notes = currentNotes.get
    Future(blocking(withEcFailover(what, notes, stale, staleAnswer, knownEc)(op)))
  }

  /** [[clusterCall]] for a call on a hosted key the driver knows not to be EC (RSA decrypt,
    * symmetric crypto, PublicKey, KeyInfo), where one cosigner's "not found" is not the cluster's
    * answer either.
    *
    * A cosigner answers NOT_FOUND from its own store after asking its peers (read-repair). That
    * makes the answer the cluster's only while the cosigner can reach those peers and read what
    * they hold: one with a missing or unreadable replica that is cut off from the others answers
    * NOT_FOUND for a key the cluster has. So the next cosigner is asked, the one that lacks the key
    * loses the lead once another cosigner has served the call (not when no cosigner has the key:
    * `lacksKey` of [[withCheckedFailover]]), and what the call ends with when none serves it is decided over the
    * whole roster ([[rosterVerdict]]): NOT_FOUND once all but one cosigner said so
    * ([[ownAnswerQuorum]]), retryable while one that may hold the key could not be reached.
    *
    * `absent` recognises an answer that says the key is not there (`KeyInfo.exists = false`); it
    * ends the call as a [[NoSuchElementException]] when it is the roster's verdict. Every other
    * status keeps its meaning: a leader-sick one fails over, and a refusal — RESOURCE_EXHAUSTED
    * above all, the per-node decrypt limit — is returned at once and leaves the lead where it is.
    * One attempt deadline per cosigner, inside the call's request timeout, as for [[clusterCall]]. */
  private def clusterCallWholeRoster[A](what: String, keyId: String, absent: A => Boolean = (_: A) => false)(
      op: SignerGrpc.SignerBlockingStub => A
  ): Future[A] = {
    val notes = currentNotes.get
    val notFoundOrSick = (s: Status) => isLeaderSick(s) || s.getCode == Status.Code.NOT_FOUND
    Future(blocking {
      val start = startIndex()
      withCheckedFailover[A](
        what,
        notFoundOrSick,
        notFoundOrSick,
        notes,
        (_: String, answer: A) =>
          if (absent(answer)) Some(Rejected(KeyAbsent, new NoSuchElementException(s"key not found or inactive: $keyId")))
          else None,
        start,
        start,
        (_: Int) => (),
        attemptTimeout,
        System.nanoTime() + requestTimeout.toNanos,
        Some(hostedKeyIsNotThere _),
        // A cosigner without the key loses the lead only if another one has it.
        (failure: Either[StatusRuntimeException, Rejected]) => hostedKeyIsNotThere(failure).isDefined,
      )(op)
    })
  }

  private final val MayBeOld = "that cosigner may predate ec-p256-ecies or lack the key"

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
  private def clusterCall[A](
      what: String,
      retryOn: Status => Boolean,
      demoteOn: Status => Boolean,
      attempt: FiniteDuration = attemptTimeout,
  )(
      op: SignerGrpc.SignerBlockingStub => A
  ): Future[A] = {
    val notes = currentNotes.get
    Future(blocking(withFailover(what, retryOn, demoteOn, notes, attempt)(op)))
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
      // INTERNAL, which may have failed part-way through the ceremony. Only the status it fails
      // over on (UNAVAILABLE) takes the lead from the node: after a timeout or an INTERNAL the
      // ceremony may still be running there, and the next call must not start elsewhere because of it.
      // The request carries a ceremony intent (purpose "dkg") signed with the mTLS identity, which
      // every cosigner verifies before it opens the ceremony. A FRESH intent per attempt: the
      // ceremony id is derived from the intent and a ceremony that failed (even at the fence) burns
      // its id on every node, so a failover leader must not present the same one — and a fresh id
      // cannot join a ceremony a reached-but-silent leader may still be running (its guard refuses
      // it; a later retry adopts that key, M5).
      val cluster: Option[String] =
        if (!signIntents) None
        else
          intentSigner.flatMap { _ =>
            val c = learnClusterId()
            if (c.isEmpty)
              logger.warn(
                s"FROST: DKG for $keyId goes WITHOUT a ceremony intent: no cosigner reports a cluster id " +
                  "(frost.cluster-id unset); cosigners with signing_policy.require_ceremony_intent will refuse it."
              )
            c
          }
      def dkgRequest(): DkgRequest = {
        val b = DkgRequest.newBuilder().setKeyId(keyId)
        for (signer <- intentSigner; c <- cluster) {
          val requestId = FrostIntentSigner.newRequestId()
          val ceremony = FrostIntentSigner.ceremonyId(FrostIntentSigner.PurposeDkg, requestId)
          // Durable BEFORE the request goes out: a driver that dies between the request and the
          // reply still knows the ceremony as its own after the restart. If it cannot be recorded,
          // nothing is sent.
          pinStore.foreach { store =>
            try store.recordCeremony(keyId, ceremony)
            catch {
              case e: Exception =>
                throw KmsDriverException(
                  new IllegalStateException(s"cannot record DKG ceremony $ceremony for $keyId in ${store.dir}: ${e.getMessage}", e),
                  retryable = true,
                )
            }
          }
          b.setIntent(
            signer.signCeremony(c, FrostIntentSigner.PurposeDkg, keyId, requestId, System.currentTimeMillis(), intentLifetime.toMillis)
          )
          ownDkgCeremonies
            .computeIfAbsent(keyId, _ => java.util.concurrent.ConcurrentHashMap.newKeySet[String]())
            .add(ceremony)
          logger.info(
            s"FROST: DKG for $keyId carries ceremony intent " +
              s"(ceremony ${FrostIntentSigner.ceremonyId(FrostIntentSigner.PurposeDkg, requestId)})"
          )
        }
        b.build()
      }
      val notes = currentNotes.get
      // A key id whose pin the audit log records but whose file is gone is refused before the
      // ceremony, which cannot be undone (a deliberate re-use moves the pin to retired/ first).
      // Stricter than lostPin: an operator anchor re-establishes an existing key's pin, never a DKG.
      if (lostPins.contains(keyId) && !pinnedKeys.containsKey(keyId)) return Future.failed(lostPinError(keyId))
      // A ceremony's attempt gets the whole budget (what is left of it) and is never re-run on a
      // deadline; it fails over only on a refused connection, where no ceremony started.
      clusterCall("dkg", connectionRefused, connectionRefused, attempt = requestTimeout)(_.dkg(dkgRequest()))
        .map(reply =>
          acceptDkgReply(keyId, reply, withIntent = cluster.nonEmpty && intentSigner.nonEmpty, intentExpected = signIntents && intentSigner.nonEmpty)
        )
        .flatMap { reply =>
          // The leader's reply is one cosigner's word: the new key is believed only once a roster
          // majority agrees on it and no answering cosigner contradicts it, and it must be the key
          // the leader reported. It is pinned (durably) before its id goes back to Canton.
          queryGroupKey(keyId, fresh = true, notes).map { result =>
            val agreed = result.key
            if (reply.getGroupVerifyingKey != agreed)
              throw KmsDriverException(
                new SecurityException(
                  s"DKG for $keyId: the leader reported group key ${hexOf(reply.getGroupVerifyingKey)} but the " +
                    s"cosigners agree on ${hexOf(agreed)}"
                ),
                retryable = false,
              )
            pin(keyId, result, "dkg")
            keyId
          }
        }
    case other => delegate.generateSigningKeyPair(other, keyName)
  }

  /** A DKG reply for `keyId`, checked: a key the cluster already held is accepted only when the
    * reply names a ceremony this driver asked for itself (a retry, e.g. after a timeout), or when
    * the operator listed the id in `frost.adopt-existing-keys`. Otherwise it is another client's
    * key under the same id (two participants on one cluster without `frost.key-prefix`), or a DKG
    * this driver started before a restart, and is refused, non-retryably. A leader older than
    * 0.5.0 cannot say whether the key existed: accepted with a warning, as before. A DKG sent
    * without an intent by choice (no TLS, or `frost.sign-intents = off`) cannot be matched either:
    * accepted with a warning; one that lacked an intent only because no cluster id was known is
    * retried. A new key must come from one of this driver's own ceremonies.
    *
    * A ceremony id is remembered when its intent is sent, before the outcome is known: a leader
    * names it as the origin only when that ceremony committed, so a match still means this driver
    * started the ceremony that created the key. */
  private def acceptDkgReply(keyId: String, reply: DkgReply, withIntent: Boolean, intentExpected: Boolean): DkgReply = {
    val origin = reply.getOriginCeremonyId
    def ours: Boolean =
      origin.nonEmpty &&
        (Option(ownDkgCeremonies.get(keyId)).exists(_.contains(origin)) || pinStore.exists(_.ceremonies(keyId).contains(origin)))
    if (!reply.hasExisting)
      logger.warn(
        s"FROST: the DKG leader for $keyId is older than 0.5.0 and cannot say whether the key already existed; " +
          "finish the cosigner upgrade before bootstrapping another participant on this cluster"
      )
    else if (!reply.getExisting) {
      // A new key: the leader must name one of this driver's own ceremonies (a leader bug otherwise).
      if (withIntent && !ours)
        throw KmsDriverException(
          new SecurityException(
            s"DKG for $keyId: the leader reports a new key from ceremony '$origin', which is not one this driver started"
          ),
          retryable = false,
        )
    } else if (reply.getExisting) {
      if (ours) logger.info(s"FROST: DKG for $keyId returned the key of this driver's own ceremony $origin (a retry)")
      else if (adoptExistingKeys.contains(keyId))
        logger.warn(
          s"FROST: DKG for $keyId returned a key the cluster already held (ceremony ${if (origin.isEmpty) "unknown" else origin}); " +
            "adopted because frost.adopt-existing-keys lists it"
        )
      else if (!withIntent && intentExpected)
        // TLS is on and intents are not switched off, but no cluster id was known for this DKG (a slow
        // or failed probe): the reply cannot be matched now. Retry rather than take the key.
        throw KmsDriverException(
          new IllegalStateException(
            s"DKG for $keyId returned a key the cluster already held, and this DKG went without a ceremony intent " +
              "because no cluster id was known; retrying (set frost.cluster-id to avoid the probe)"
          ),
          retryable = true,
        )
      else if (!withIntent)
        logger.warn(
          s"FROST: DKG for $keyId returned a key the cluster already held, and this DKG carried no ceremony intent " +
            "(no TLS, or frost.sign-intents = off), so it cannot be matched to this driver; accepted. A production driver " +
            "signs its intents (docs/production-profile.md)"
        )
      else {
        val originText = if (origin.isEmpty) "an unknown ceremony" else s"ceremony $origin"
        val scope =
          if (pinStore.isEmpty) " in this process (frost.pin-dir is not set, so its ceremony ids do not survive a restart)"
          else s" (no ceremony id recorded for it in ${pinStore.get.dir})"
        logger.error(s"FROST: DKG for $keyId: the cluster already holds this key from $originText, not from this driver")
        throw KmsDriverException(
          new SecurityException(
            s"FROST key $keyId already exists on the cosigner cluster, created by $originText, which this driver did not " +
              s"start$scope. What to do: (1) if any other participant uses this cluster with the same " +
              "frost.key-prefix, do NOT adopt it: it is that participant's key; give this participant its own " +
              "frost.key-prefix (and driver certificate) and start again. (2) Otherwise the key is the one an earlier " +
              s"DKG of this participant created before the driver restarted: set frost.adopt-existing-keys = [\"$keyId\"], " +
              "restart the participant, and remove the entry once Canton has registered the key. " +
              "(docs/architecture.md, \"One cluster, several participants\")"
          ),
          retryable = false,
        )
      }
    }
    reply
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
    *
    * The request carries a generate intent (purpose `generate-key`) signed with the mTLS identity,
    * naming the key, its spec and the cosigner asked to lead: every cosigner verifies it at the
    * generation's fence. A FRESH intent per endpoint tried, as for a DKG: the intent names its
    * leader, and its request id is spent on every node the previous attempt fenced. Before each
    * attempt the endpoint is asked which roster slot it serves (`Capabilities.node_identifier`, on
    * the same channel); an endpoint that cannot say (a cosigner older than 0.5.0) is refused, not
    * failed over, and loses the lead, so the next generation starts at another endpoint.
    *
    * The leader's reply is one cosigner's word. Before the key id goes back to Canton every endpoint
    * is asked for its own copy ([[confirmHostedCopies]]), inside the failover: a reply the other
    * nodes contradict (absent copies, other material, a wrong spec) fails the call without retry; a
    * reply short of confirmations only because endpoints were silent moves on to the next endpoint,
    * which leads the same id under a fresh intent (it holds the key, adopts it from agreeing peers or
    * refuses; it never mints over a copy) and is checked again. Each endpoint is tried at most once.
    * A leader whose reply fails the check loses the lead and does not become the preferred one.
    * The call's `requestTimeout` covers the cluster-id lookup, every attempt and every check. The
    * check uses what is left of it, keeping room for one more attempt when one fits (an endpoint left
    * to lead, and time for an attempt as long as the last one plus a minimal check); when none fits,
    * a reply short only because endpoints were silent ends the call with that (non-retryable)
    * error, not a spent request timeout.
    */
  private def generateHosted(keyId: String, spec: String): Future[String] = {
    val notes = currentNotes.get
    Future(blocking {
      val start = preferred.get
      // One budget for the whole call: the cluster-id lookup, every attempt and every copy check
      // come out of it.
      val budgetEnd = System.nanoTime() + requestTimeout.toNanos
      val cluster: Option[String] =
        if (!signIntents) None
        else
          intentSigner.flatMap { _ =>
            val c = learnClusterId(FiniteDuration(math.max(budgetEnd - System.nanoTime(), 0L), NANOSECONDS))
            if (c.isEmpty)
              logger.warn(
                s"FROST: hosted key $keyId is generated WITHOUT a generate intent: no cosigner reports a cluster id " +
                  "(frost.cluster-id unset); cosigners with signing_policy.require_ceremony_intent will refuse it."
              )
            c
          }
      val withIntent = intentSigner.isDefined && cluster.isDefined
      // The endpoint asked last (`tried` sets it before each attempt). Read by the request and the
      // check for that attempt, and after withCheckedFailover returned: the leader whose reply passed.
      val lastTried = new AtomicInteger(-1)
      val attempts = new AtomicInteger(0)
      val attemptStarted = new java.util.concurrent.atomic.AtomicLong(0L)
      def request(stub: SignerGrpc.SignerBlockingStub): GenerateKeyRequest = {
        val b = GenerateKeyRequest.newBuilder().setKeyId(keyId).setSpec(spec)
        for (signer <- intentSigner; c <- cluster) {
          val leader = stub.capabilities(CapabilitiesRequest.newBuilder().build()).getNodeIdentifier
          if (leader <= 0) {
            // Not failed over (a 0.5.0 leader refuses while an older peer is reachable anyway), but
            // the endpoint loses the lead, so the next generation does not start here again.
            demote(lastTried.get)
            throw Status.FAILED_PRECONDITION
              .withDescription(
                s"cannot generate hosted key $keyId through this cosigner: it does not report its roster identifier " +
                  "(a cosigner older than 0.5.0) — upgrade the cosigners; a generate intent must name its leader"
              )
              .asRuntimeException()
          }
          val requestId = FrostIntentSigner.newRequestId()
          b.setIntent(signer.signGenerate(c, keyId, spec, leader, requestId, System.currentTimeMillis(), intentLifetime.toMillis))
          logger.info(
            s"FROST: hosted key $keyId: generate intent for cosigner $leader " +
              s"(ceremony ${FrostIntentSigner.generateCeremonyId(requestId)})"
          )
        }
        b.build()
      }
      // A refusal (thrown) fails the call at once and costs the leader the lead here; a rejection
      // (returned) is demoted and failed over by withCheckedFailover.
      val check = (endpoint: String, reply: GenerateKeyReply) => {
        val leader = lastTried.get
        val now = System.nanoTime()
        val attemptTook = now - attemptStarted.get
        // The one rule for "another attempt fits", before and after the copy check: an endpoint is
        // left to lead, and `remaining` (nanoseconds of the budget) covers an attempt as long as the
        // one that just answered (at least MinAttempt) plus the shortest copy check after it.
        def nextAttemptFits(remaining: Long): Boolean =
          attempts.get < channels.size &&
            remaining >= math.max(MinAttempt.toNanos, attemptTook) + (ProbeSlack + MinAttempt).toNanos
        val left = budgetEnd - now
        // The copy check keeps a reserve (up to one attempt deadline, at most half of what is left)
        // only when the next attempt fits in it and the check still gets time to probe; otherwise it
        // gets all of what is left.
        val reserve = math.min(attemptTimeout.toNanos, left / 2)
        val keep = nextAttemptFits(reserve) && left - reserve >= (ProbeSlack + MinAttempt).toNanos
        val probeBudget = FiniteDuration(math.max(left - (if (keep) reserve else 0L), 0L), NANOSECONDS)
        try {
          val outcome: Option[Rejected] = confirmHostedCopies(keyId, spec, reply, withIntent, endpoint, notes, probeBudget)
          // A rejection is failed over only if the next attempt fits in what is left now; otherwise
          // it ends the call with its own (non-retryable) error, not with "request-timeout spent".
          outcome match {
            case Some(rejected) if !nextAttemptFits(budgetEnd - System.nanoTime()) =>
              logger.warn(s"FROST: generateKey via $endpoint not confirmed; no attempt left in this call")
              throw rejected.error
            case _ => outcome
          }
        } catch {
          case e: KmsDriverException =>
            demote(leader)
            throw e
        }
      }
      // NoPreference: answering does not make the leader preferred here; only a reply that passes
      // the check does.
      val reply = withCheckedFailover[GenerateKeyReply](
        "generateKey",
        isNodeDown,
        isLeaderSick,
        notes,
        check,
        NoPreference,
        start,
        (i: Int) => {
          lastTried.set(i)
          attempts.incrementAndGet()
          attemptStarted.set(System.nanoTime())
        },
        // One attempt covers Capabilities and GenerateKey at that cosigner; the copy check after
        // it takes its time from the same budget (above).
        attemptTimeout,
        budgetEnd,
      )(stub => stub.generateKey(request(stub)))
      preferred.compareAndSet(start, lastTried.get)
      reply
    }).map { reply =>
      learnSpec(keyId, spec)
      logger.info(
        s"FROST: hosted key $keyId ready (created=${reply.getCreated}, replicas=${reply.getReplicas})"
      )
      keyId
    }
  }

  /** Copies of a new hosted key the driver needs to see before it believes the leader: two, or the
    * lone endpoint of a single-endpoint (dev) roster, as for a group key. A constant: the driver
    * does not know the cluster's write quorum, and a cosigner could lie about it. */
  private val requiredCopies: Int = if (channels.size == 1) 1 else 2

  /** The check of a `GenerateKey` reply from `leaderEndpoint` (a new key or an existing one): every
    * endpoint is asked for its OWN copy (`KeyInfo` with `local_only`, no read-repair), in parallel.
    * Accepted (None) only when at least [[requiredCopies]] nodes hold a copy with the reply's
    * commitment, spec and public key, and no node reports other material under the id. Silent
    * endpoints, nodes without a copy and nodes too old to report a commitment count neither way.
    *
    * Two outcomes when it is not accepted:
    *  - a [[Rejected]] (code `UNCONFIRMED`) when too few copies confirm only because endpoints were
    *    silent: the silent ones could have confirmed. The caller fails over to the next endpoint,
    *    and when none is left (or the call's budget cannot fit another attempt) the rejection's
    *    error (non-retryable, naming the silent endpoints) ends the call;
    *  - a thrown non-retryable [[KmsDriverException]] for everything else (a wrong spec, no
    *    commitment where one is due, a node reporting other material, too few copies although the
    *    nodes answered). The key id never reaches Canton: a leader whose reply the cluster does not
    *    confirm may have chosen material only it holds, and the id is left to an operator
    *    (docs/hosted-keys.md).
    *
    * A reply without a commitment is from a cosigner older than 0.5.0: refused when the request
    * carried an intent (only a 0.5.0 leader accepts one, and it always sends a commitment), else the
    * check is skipped with a WARN — the cosigners then accept generations without an intent anyway
    * (`require_ceremony_intent: false`, or no TLS). */
  private def confirmHostedCopies(
      keyId: String,
      spec: String,
      reply: GenerateKeyReply,
      withIntent: Boolean,
      leaderEndpoint: String,
      notes: AuditNotes,
      probeBudget: FiniteDuration,
  ): Option[Rejected] = {
    def refuse(why: String): Nothing = {
      notes.add("hosted-check=failed")
      logger.error(s"FROST: hosted key $keyId from $leaderEndpoint REFUSED: $why")
      throw KmsDriverException(new SecurityException(s"hosted key $keyId: $why"), retryable = false)
    }
    if (reply.getSpec != spec) refuse(s"the leader reports spec '${reply.getSpec}', the request was for '$spec'")
    if (reply.getCommitment.isEmpty) {
      if (withIntent) refuse("the leader's reply carries no commitment, which every cosigner that accepts a generate intent sends")
      notes.add("hosted-check=skipped")
      logger.warn(
        s"FROST: hosted key $keyId: the leader $leaderEndpoint sent no commitment (a cosigner older than 0.5.0); " +
          "its copies are not checked"
      )
      None
    } else checkCopies(keyId, reply, leaderEndpoint, notes, refuse, probeBudget)
  }

  /** One endpoint's answer to the copy probe: its `KeyInfo`, or why it gave none (`Left`, silent).
    * The whole probe ends within `budget` (what the call can spend on it): each `KeyInfo` gets that
    * less [[ProbeSlack]], at most 10 s. When that leaves less than [[MinAttempt]], no endpoint is
    * asked and every one counts as silent (`NO_TIME`). */
  private def probeCopies(keyId: String, budget: FiniteDuration): Vector[(String, Either[String, KeyInfoReply])] = {
    val deadline = requestTimeout.min(10.seconds).min(budget - ProbeSlack)
    if (deadline < MinAttempt) channels.indices.toVector.map(i => endpoints(i) -> (Left("NO_TIME"): Either[String, KeyInfoReply]))
    else probeCopiesWithin(keyId, deadline)
  }

  private def probeCopiesWithin(keyId: String, deadline: FiniteDuration): Vector[(String, Either[String, KeyInfoReply])] = {
    val req = KeyInfoRequest.newBuilder().setKeyId(keyId).setLocalOnly(true).build()
    val probes: Vector[Future[(String, Either[String, KeyInfoReply])]] = channels.indices.toVector.map { i =>
      Future(blocking {
        val answer: Either[String, KeyInfoReply] =
          try
            Right(
              SignerGrpc
                .newBlockingStub(channels(i))
                .withDeadlineAfter(deadline.toMillis, TimeUnit.MILLISECONDS)
                .keyInfo(req)
            )
          catch {
            case e: StatusRuntimeException => Left(e.getStatus.getCode.toString)
            case NonFatal(e)               => Left(e.getClass.getSimpleName)
          }
        endpoints(i) -> answer
      })
    }
    // Each call has its own deadline, so this wait normally ends with every probe complete. If it
    // fires anyway (a starved pool, a call stuck before its deadline applies), the answers already
    // in hand are kept and the rest are silent.
    try scala.concurrent.Await.ready(Future.sequence(probes), deadline + ProbeSlack)
    catch { case _: java.util.concurrent.TimeoutException => () }
    probes.zipWithIndex.map { case (f, i) =>
      f.value match {
        case Some(scala.util.Success(answer)) => answer
        case Some(scala.util.Failure(e))      => endpoints(i) -> Left(e.getClass.getSimpleName)
        case None                             => endpoints(i) -> Left("NO_ANSWER")
      }
    }
  }

  /** The copies part of [[confirmHostedCopies]], for a reply that carries a commitment. */
  private def checkCopies(
      keyId: String,
      reply: GenerateKeyReply,
      leaderEndpoint: String,
      notes: AuditNotes,
      refuse: String => Nothing,
      probeBudget: FiniteDuration,
  ): Option[Rejected] = {
    val answers = probeCopies(keyId, probeBudget)
    def same(r: KeyInfoReply): Boolean =
      r.getCommitment == reply.getCommitment && r.getSpec == reply.getSpec && r.getPublicKeyDer == reply.getPublicKeyDer
    val confirming = answers.collect { case (e, Right(r)) if r.getExists && !r.getCommitment.isEmpty && same(r) => e }
    val other = answers.collect { case (e, Right(r)) if r.getExists && !r.getCommitment.isEmpty && !same(r) => e }
    val silent = answers.collect { case (e, Left(_)) => e }
    def describe: String =
      answers
        .map {
          case (e, Left(code))                          => s"$e=$code"
          case (e, Right(r)) if !r.getExists            => s"$e=absent"
          case (e, Right(r)) if r.getCommitment.isEmpty => s"$e=unknown"
          case (e, Right(r)) if same(r)                 => s"$e=confirms"
          case (e, Right(r))                            => s"$e=other(${hexOf(r.getCommitment).take(16)}…, ${r.getSpec})"
        }
        .mkString(", ")
    // Fail closed, as a cosigner aborts a generation on a conflict. The claim is the endpoint's own
    // and is not verified here: a faulty or compromised node can make it falsely, and so veto this
    // generation (availability only; it could refuse the generation at the cosigner level anyway).
    if (other.nonEmpty)
      refuse(
        s"${other.mkString(", ")} report(s) holding OTHER material under the id than the leader reported " +
          s"(${hexOf(reply.getCommitment).take(16)}…). This is that endpoint's own statement and may be false " +
          "(a faulty or compromised node can make it); either way one of the cosigners is not consistent. " +
          s"Not given to Canton. Answers: $describe"
      )
    if (confirming.size >= requiredCopies) {
      notes.add(s"hosted-check=ok copies=${confirming.size}")
      None
    } else if (confirming.size + silent.size >= requiredCopies) {
      // Short only because endpoints were silent: they could have confirmed. Retried on the next
      // endpoint by the caller; the error ends the call when none is left.
      val why =
        s"only ${confirming.size} cosigner(s) confirm the material the leader $leaderEndpoint reported, " +
          s"$requiredCopies needed; silent: ${silent.mkString(", ")}. Not given to Canton. Answers: $describe"
      notes.add("hosted-check=unconfirmed")
      logger.warn(s"FROST: hosted key $keyId from $leaderEndpoint not confirmed: $why")
      Some(Rejected(Unconfirmed, KmsDriverException(new SecurityException(s"hosted key $keyId: $why"), retryable = false)))
    } else
      refuse(
        s"only ${confirming.size} cosigner(s) confirm the material the leader reported, $requiredCopies needed — " +
          s"not given to Canton. Answers: $describe"
      )
  }

  override def sign(data: Array[Byte], keyId: String, algo: SigningAlgoSpec): Future[Array[Byte]] =
    sign(data, keyId, algo, com.stakecraft.rutli.policy.ApprovalProof.None)

  override def sign(
      data: Array[Byte],
      keyId: String,
      algo: SigningAlgoSpec,
      approval: com.stakecraft.rutli.policy.ApprovalProof,
  ): Future[Array[Byte]] =
    if (ids.isFrost(keyId))
      precondition(algo == SigningAlgoSpec.Ed25519, s"FROST keys sign Ed25519 only, got $algo") {
        // Captured here, synchronously: the binding is thread-local and the flatMap below runs on a
        // pool thread (see clusterCall).
        val notes = currentNotes.get
        // One request id per driver call, and one intent per attempt below (not per leader): every
        // leader the sign fails over to gets the same intent bytes. Each cosigner charges its rate
        // limit once per intent request id, so trying more leaders charges no more. But each leader
        // tried can make a node release one more signature share for that id, up to that node's
        // `max_shares_per_request`; in 3-of-5 a call that fails over more than once can reach that
        // bound, and the node then refuses (RESOURCE_EXHAUSTED). Learning the cluster id again
        // builds a new intent with the same request id.
        val requestId = FrostIntentSigner.newRequestId()
        // Pin the group key first (no-op once pinned), so a signature is never produced for a key
        // the cluster has not agreed on.
        pinnedGroupKey(keyId, notes).flatMap { groupKey =>
          // Re-issuing through another leader opens a fresh session with fresh nonces; the sick
          // leader's session is abandoned and its nonces are burnt by the cosigners (AbortSign, or the
          // pending-session TTL), never reused — see isLeaderSick.
          Future(blocking {
            val lastTried = new AtomicInteger(-1)
            // One budget for the whole driver call, the cluster-id relearn included.
            val budgetEnd = System.nanoTime() + requestTimeout.toNanos
            def attempt(relearned: Boolean, from: Option[Int]): SignReply = {
              val req = SignRequest.newBuilder().setKeyId(keyId).setMessage(ByteString.copyFrom(data))
              val intent = signingIntent(keyId, data, requestId, approval, notes)
              intent.foreach(req.setIntent)
              val built = req.build()
              // A signature the pinned group key does not verify is that leader failing, like a
              // leader-sick status: withheld, the node demoted, the next leader tried with the same
              // intent. Only a verified signature makes a node the preferred leader.
              val check = (endpoint: String, reply: SignReply) => unverified(keyId, data, groupKey, notes)(endpoint, reply)
              // Sticky: a verified answer makes its node the preferred leader (compare-and-set
              // from the value read here). Rotate: signs leave the preference to the sticky calls
              // (-1 never matches), and only a failure moves it (demote).
              val observed = if (rotateSigns) -1 else startIndex()
              try
                withCheckedFailover[SignReply](
                  "sign",
                  signFailsOver,
                  signDemotes(intent.nonEmpty),
                  notes,
                  check,
                  observed,
                  from.getOrElse(signStart(keyId)),
                  (i: Int) => lastTried.set(i),
                  signAttemptTimeout,
                  budgetEnd,
                  // A leader's own "cannot sign" is not the cluster's while a cosigner was unreachable.
                  Some(signAnswerIsLeaderLocal _),
                  // And it costs that leader the lead only when another leader then signs: when
                  // every leader answers so (the shares are gone, a ceremony holds the key on all of
                  // them), none is at fault and none leaves the rotation.
                  signLeaderCannotSignNow _,
                )(_.sign(built))
              catch {
                // A cosigner says the intent names another cluster: the learned id is wrong (one
                // endpoint lied, or the cluster id changed). Learn it again and retry once, on the
                // same node first: the stale id was the driver's, so that node keeps the lead.
                case e: StatusRuntimeException
                    if !relearned && intent.nonEmpty && isClusterRefusal(e.getStatus) && forgetLearnedClusterId() =>
                  logger.warn(
                    s"FROST: a cosigner refused the signing intent for ${intent.map(i => SignIntent.parseFrom(i.getIntent).getClusterId).getOrElse("")} " +
                      s"(${e.getStatus.getDescription}); learning the cluster id again"
                  )
                  notes.add("intent-cluster=relearned")
                  attempt(relearned = true, Some(lastTried.get).filter(_ >= 0))
              }
            }
            attempt(relearned = false, None)
          }).map(_.getSignature.toByteArray) // verified in withCheckedFailover
        }
      }
    else delegate.sign(data, keyId, algo)

  /** The check of a sign reply from `endpoint`: None when its signature verifies (Ed25519, strict)
    * against the pinned `groupKey` over `data`, else the rejection. Never release a signature the
    * pinned group key does not verify — a wrong-key, wrong-length or garbage signature from a faulty
    * or malicious leader stops here, not at Canton. The error, thrown when no leader is left, is
    * non-retryable: every cosigner was asked and none produced a valid signature. */
  private def unverified(
      keyId: String,
      data: Array[Byte],
      groupKey: ByteString,
      notes: AuditNotes,
  )(endpoint: String, reply: SignReply): Option[Rejected] = {
    val sig = reply.getSignature.toByteArray
    if (verifyEd25519(groupKey.toByteArray, data, sig)) None
    else {
      logger.error(
        s"FROST: signature for $keyId from $endpoint (${sig.length} bytes) did NOT verify against the pinned " +
          "group key; withheld"
      )
      notes.add("sig-verify=failed")
      Some(
        Rejected(
          BadSignature,
          KmsDriverException(
            new SecurityException(s"FROST signature for $keyId does not verify against the pinned group key; withheld"),
            retryable = false,
          ),
        )
      )
    }
  }

  /** The signing intent for one sign (audit C2): signed with the mTLS identity, naming the
    * cluster, the key, the exact digest, `requestId`, a validity of `intentLifetime` and the
    * approvals. None — the sign goes without one, which only a cosigner that does not require
    * intents accepts — without TLS, or while the cluster id is unknown (configured nowhere and no
    * cosigner reports one: an older cluster, which ignores intents anyway). The request id is noted
    * in the sign's audit entry (`intent=<hex>`), the key `rutli-cosigner audit-cross-check` matches
    * the cosigners' sign journals on. */
  private def signingIntent(
      keyId: String,
      data: Array[Byte],
      requestId: Array[Byte],
      approval: com.stakecraft.rutli.policy.ApprovalProof,
      notes: AuditNotes,
  ): Option[com.stakecraft.rutli.grpc.SignedIntent] =
    if (!signIntents) { notes.add("intent=off"); None }
    else intentSigner.flatMap { signer =>
      learnClusterId() match {
        case Some(cluster) =>
          notes.add(s"intent=${requestId.map("%02x".format(_)).mkString}")
          Some(signer.sign(cluster, keyId, data, requestId, approval, System.currentTimeMillis(), intentLifetime.toMillis))
        case None =>
          val now = System.nanoTime()
          val last = lastIntentWarning.get
          if (now - last > 60.seconds.toNanos && lastIntentWarning.compareAndSet(last, now))
            logger.warn(
              "FROST: no cosigner reports a cluster id (frost.cluster-id unset) — signing WITHOUT an intent; " +
                "cosigners that require intents will refuse. Upgrade the cosigners or set frost.cluster-id."
            )
          notes.add("intent=none")
          None
      }
    }

  /** The cluster id for intents: configured, else the `Capabilities.cluster_id` a majority of the
    * endpoints agree on — at least `requiredAgreement` of them (two, or the lone endpoint of a dev
    * roster) and more than report any other value (audit F5: one compromised or misconfigured
    * cosigner cannot set the id every honest cosigner then refuses). Cached once found; asked again
    * at most once a minute while unknown, and again at once after a cluster refusal
    * ([[forgetLearnedClusterId]]).
    *
    * The lookup ends within `within` (a caller's remaining budget; by default up to 2 s past one
    * `Capabilities` deadline of at most 5 s). With too little of it left to ask, nothing is asked
    * and the next caller may ask at once. */
  private def learnClusterId(within: FiniteDuration = requestTimeout.min(5.seconds) + 2.seconds): Option[String] =
    intentClusterId.orElse {
      val now = System.nanoTime()
      val last = lastClusterProbe.get
      val lookupWait = within.min(requestTimeout.min(5.seconds) + 2.seconds)
      val deadline = requestTimeout.min(5.seconds).min(lookupWait - ProbeSlack)
      if (last != 0L && now - last < 60.seconds.toNanos) None
      else if (deadline < MinAttempt) None
      else {
        lastClusterProbe.set(now)
        val probes = Future.traverse(channels.indices.toVector) { i =>
          Future(blocking {
            try {
              val id = SignerGrpc
                .newBlockingStub(channels(i))
                .withDeadlineAfter(deadline.toMillis, TimeUnit.MILLISECONDS)
                .capabilities(CapabilitiesRequest.newBuilder().build())
                .getClusterId
              Option(id).filter(_.nonEmpty).map(endpoints(i) -> _)
            } catch { case _: StatusRuntimeException => None }
          })
        }
        val answers =
          try scala.concurrent.Await.result(probes, lookupWait).flatten
          catch { case _: java.util.concurrent.TimeoutException => Vector.empty }
        val found = agreeOnClusterId(answers)
        found.foreach { id =>
          logger.info(s"FROST: cluster id $id (agreed by ${answers.count(_._2 == id)} of ${channels.size} cosigners) for signing intents")
          intentClusterId = Some(id)
        }
        found
      }
    }

  /** The majority cluster id among `answers` (endpoint -> id), if one has enough agreement. */
  private[backend] def agreeOnClusterId(answers: Seq[(String, String)]): Option[String] = {
    val counts = answers.groupBy(_._2).view.mapValues(_.size).toVector.sortBy(-_._2)
    if (counts.map(_._1).distinct.size > 1)
      logger.error(
        s"FROST: the cosigners report DIFFERENT cluster ids: ${answers.map { case (e, id) => s"$e=$id" }.mkString(", ")} — " +
          "a misconfigured or compromised cosigner; using the majority value if there is one (set frost.cluster-id to pin it)"
      )
    counts match {
      case (id, n) +: rest if n >= requiredAgreement && rest.forall(_._2 < n) => Some(id)
      case _ => None
    }
  }

  /** Forget a learned (never a configured) cluster id so the next sign learns it again. False when
    * the id is configured: there is nothing to learn, the refusal is the answer. */
  private def forgetLearnedClusterId(): Boolean =
    configuredClusterId.isEmpty && {
      intentClusterId = None
      lastClusterProbe.set(0L)
      true
    }

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
        clusterCallWholeRoster[com.stakecraft.rutli.grpc.DecryptReply]("decrypt", keyId)(_.decrypt(req)).map(_.getPlaintext.toByteArray)
      case EncryptionAlgoSpec.EciesHkdfHmacSha256Aes128Cbc =>
        decryptEcies(ciphertext, keyId)
    }
    else delegate.decryptAsymmetric(ciphertext, keyId, algo)

  /** ECIES for a hosted P-256 key: the cluster does the ECDH, BouncyCastle's `IESEngine` the rest
    * ([[CantonEcies]]). The blob is checked against Canton's exact shape before anything is sent, so
    * a malformed ciphertext costs no cluster call and no decryption budget. `EcdhDerive` is
    * re-issuable like `Decrypt` (it is a pure function of key and point), hence [[isLeaderSick]].
    *
    * A cosigner's `EcdhDerive` only counts as served once its Z has opened the ciphertext (MAC and
    * padding). One holding stale or corrupt EC material under the right id answers a well-formed,
    * wrong Z; it must not become the preferred leader on that answer, or every later decrypt would
    * lead from it and fail (second review of C2). So the ECDH *and* the local decrypt run per
    * cosigner inside [[withEcFailover]], and a Z that does not open the blob is a stale answer: the
    * next cosigner is asked (`ec-failover=… reason=ECIES_AFTER_ECDH`), the node that gave it is not
    * preferred, and the failure surfaces only when no cosigner's Z opens the blob. A forged
    * ciphertext therefore costs at most one `EcdhDerive` per roster entry, each charged to that
    * node's rate limit — n calls, never unbounded. `RESOURCE_EXHAUSTED` (the rate limit) is a real
    * answer and is surfaced at once, never routed around. */
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
        def oldOrMissing(e: StatusRuntimeException) =
          e.getStatus.getCode == Status.Code.UNIMPLEMENTED || e.getStatus.getCode == Status.Code.NOT_FOUND
        // The first Z that did not open the blob. If the call then settles on an older node's "not
        // found", some cosigner did hold the key, and the ECIES failure is the truer answer.
        val badZ = new java.util.concurrent.atomic.AtomicReference[CantonEcies.EciesException]()
        def failedAfterEcdh(e: CantonEcies.EciesException): scala.util.Failure[Array[Byte]] = {
          notes.add("ecies-failure=after-ecdh")
          logger.warn(
            s"FROST: ECIES decryption failed after a successful EcdhDerive for $keyId, with the shared secret of " +
              "every cosigner that produced one (MAC, padding or a wrong shared secret) — a forged or corrupted " +
              "ciphertext, or cosigners answering with the wrong key"
          )
          scala.util.Failure(e)
        }
        // A cosigner that predates EcdhDerive answers UNIMPLEMENTED, one that lacks the key NOT_FOUND,
        // one with the wrong key a Z that does not open the blob: ask the next one (withEcFailover).
        // Every other status behaves as for Decrypt — RESOURCE_EXHAUSTED included.
        clusterCallEc[Either[CantonEcies.EciesException, Array[Byte]]](
          "ecdhDerive",
          {
            case Left(e)       => oldOrMissing(e)
            case Right(opened) => opened.isLeft
          },
          _ => ("ECIES_AFTER_ECDH", "its shared secret did not open the ciphertext (wrong key material, or a forged blob)"),
          knownEc = true,
        ) { stub =>
          val reply = stub.ecdhDerive(req)
          // The JVM cannot promise this is the only copy of Z: the protobuf ByteString holds one
          // that cannot be wiped, and the GC may have moved either. Wiping ours is best-effort, and
          // done here, for every cosigner's Z, whatever the outcome.
          val z = reply.getSharedSecret.toByteArray
          try Right(CantonEcies.decrypt(parsed, z))
          catch {
            case e: CantonEcies.EciesException =>
              badZ.compareAndSet(null, e)
              Left(e)
          } finally java.util.Arrays.fill(z, 0.toByte)
        }.transform {
          case scala.util.Success(Right(plaintext)) => scala.util.Success(plaintext)
          case scala.util.Success(Left(e))          => failedAfterEcdh(e)
          case scala.util.Failure(e: StatusRuntimeException) if oldOrMissing(e) && badZ.get != null =>
            failedAfterEcdh(badZ.get)
          // A cosigner's secret did not open the blob and another cosigner could not be reached.
          // The ciphertext comes from a counterparty: a forged one must end here, as an ECIES
          // failure, and not be retried by Canton for as long as a cosigner is down (each retry
          // costs an EcdhDerive per reachable cosigner). Final, as before this rule existed.
          case scala.util.Failure(e: StatusRuntimeException) if isNodeDown(e.getStatus) && badZ.get != null =>
            failedAfterEcdh(badZ.get)
          case scala.util.Failure(e) => scala.util.Failure(e)
        }
    }
  }

  override def encryptSymmetric(data: Array[Byte], keyId: String): Future[Array[Byte]] =
    if (ids.isHosted(keyId)) {
      val req =
        SymmetricRequest.newBuilder().setKeyId(keyId).setData(ByteString.copyFrom(data)).build()
      clusterCallWholeRoster[com.stakecraft.rutli.grpc.SymmetricReply]("symmetricEncrypt", keyId)(_.symmetricEncrypt(req)).map(_.getData.toByteArray)
    } else delegate.encryptSymmetric(data, keyId)

  override def decryptSymmetric(ciphertext: Array[Byte], keyId: String): Future[Array[Byte]] =
    if (ids.isHosted(keyId)) {
      val req = SymmetricRequest
        .newBuilder()
        .setKeyId(keyId)
        .setData(ByteString.copyFrom(ciphertext))
        .build()
      clusterCallWholeRoster[com.stakecraft.rutli.grpc.SymmetricReply]("symmetricDecrypt", keyId)(_.symmetricDecrypt(req)).map(_.getData.toByteArray)
    } else delegate.decryptSymmetric(ciphertext, keyId)

  override def getPublicKey(keyId: String): Future[PublicKey] =
    if (ids.isFrost(keyId)) {
      // Always asks the whole roster, even once pinned: a cosigner that now answers differently
      // from the pin is reported and routed around (and the call fails if every answer differs).
      queryGroupKey(keyId, fresh = false, currentNotes.get).map(agreed =>
        PublicKey(ed25519Spki(pin(keyId, agreed, adoptSource(keyId)).toByteArray), SigningKeySpec.EcCurve25519)
      )
    } else if (ids.isHosted(keyId)) {
      val req = PublicKeyRequest.newBuilder().setKeyId(keyId).build()
      // The cluster returns X.509 SubjectPublicKeyInfo DER — exactly what Canton's PublicKey wants —
      // and the spec it holds the key under, which decides what Canton is told it is.
      // One cosigner's NOT_FOUND is confirmed with the others before it is believed, whatever the
      // key's type: for a key that is (or may be) EC it may come from a cosigner that predates the
      // spec (withEcFailover), for any key from one with a missing replica (clusterCallWholeRoster).
      val call =
        if (mayBeEc(keyId))
          clusterCallEc[PublicKeyReply](
            "publicKey",
            { case Left(e) => e.getStatus.getCode == Status.Code.NOT_FOUND; case Right(_) => false },
          )(_.publicKey(req))
        else clusterCallWholeRoster[PublicKeyReply]("publicKey", keyId)(_.publicKey(req))
      call.map { reply =>
        learnSpec(keyId, reply.getSpec)
        hostedPublicKey(keyId, reply.getSpec, reply.getPublicKeyDer.toByteArray)
      }
    } else delegate.getPublicKey(keyId)

  override def keyExistsAndIsActive(keyId: String): Future[Unit] =
    if (ids.isFrost(keyId)) {
      val req = GroupKeyRequest.newBuilder().setKeyId(keyId).build()
      // One cosigner's NOT_FOUND is that cosigner's answer, not the cluster's: the next one is
      // asked, and the key is active when one of them has it. NOT_FOUND (or, for a pinned key,
      // "another key") is the call's answer only when the whole roster could be asked: while an
      // endpoint was unreachable the call fails with that endpoint's status, which Canton retries
      // (see withCheckedFailover, `wholeRoster`, and rosterVerdict).
      val notFoundOrSick = (s: Status) => isLeaderSick(s) || s.getCode == Status.Code.NOT_FOUND
      val ownAnswer = (failure: Either[StatusRuntimeException, Rejected]) =>
        failure match {
          case Left(e)         => if (e.getStatus.getCode == Status.Code.NOT_FOUND) Some(true) else None
          case Right(rejected) => if (rejected.code == GroupKeyMismatch) Some(true) else None
        }
      // NOT_FOUND says only that this cosigner lacks the key (`lacksKey` of withCheckedFailover).
      val lacksFrostKey = (failure: Either[StatusRuntimeException, Rejected]) =>
        failure match {
          case Left(e)  => e.getStatus.getCode == Status.Code.NOT_FOUND
          case Right(_) => false
        }
      Option(pinnedKeys.get(keyId)) match {
        case None if lostPin(keyId) => Future.failed(lostPinError(keyId))
        case None =>
          // Not pinned: any cosigner's group key answers the question. Nothing here pins. A
          // cosigner that answers NOT_FOUND loses the lead only when another one then answers with
          // a key (`lacksKey`), and that one becomes the preferred leader.
          val notes = currentNotes.get
          Future(blocking {
            val start = startIndex()
            withCheckedFailover[GroupKeyReply](
              "groupKey",
              notFoundOrSick,
              notFoundOrSick,
              notes,
              (_: String, _: GroupKeyReply) => None,
              start,
              start,
              (_: Int) => (),
              attemptTimeout,
              System.nanoTime() + requestTimeout.toNanos,
              Some(ownAnswer),
              lacksFrostKey,
            )(_.groupKey(req))
          }).map(_ => ())
        case Some(p) =>
          // Pinned: a cosigner's answer is checked against the pin and routed around; the key is
          // active when a cosigner answers the pinned key. Nothing here pins.
          val notes = currentNotes.get
          Future(blocking {
            val start = startIndex()
            withCheckedFailover[GroupKeyReply](
              "groupKey",
              notFoundOrSick,
              notFoundOrSick,
              notes,
              (ep: String, r: GroupKeyReply) =>
                if (r.getGroupVerifyingKey == p) None
                else {
                  reportDissent(keyId, ep -> r.getGroupVerifyingKey, s"the pinned ${hexOf(p)}", notes)
                  Some(
                    Rejected(
                      GroupKeyMismatch,
                      KmsDriverException(
                        new SecurityException(s"no cosigner answers the pinned group key ${hexOf(p)} for $keyId"),
                        retryable = false,
                      ),
                    )
                  )
                },
              start,
              leaderFor(keyId, start),
              (_: Int) => (),
              attemptTimeout,
              System.nanoTime() + requestTimeout.toNanos,
              Some(ownAnswer),
              // NOT_FOUND costs a cosigner the lead only if another one then answers the pinned
              // key. Another key than the pin is reported and demoted at once (reportDissent).
              lacksFrostKey,
            )(_.groupKey(req))
          }).map(_ => ())
      }
    }
    else if (ids.isHosted(keyId)) {
      val req = KeyInfoRequest.newBuilder().setKeyId(keyId).build()
      // As for getPublicKey: `exists = false` from one cosigner is confirmed with the others before
      // it is believed.
      val call =
        if (mayBeEc(keyId))
          clusterCallEc[KeyInfoReply](
            "keyInfo",
            {
              case Left(e)      => e.getStatus.getCode == Status.Code.NOT_FOUND
              case Right(reply) => !reply.getExists
            },
          )(_.keyInfo(req))
        else clusterCallWholeRoster[KeyInfoReply]("keyInfo", keyId, !_.getExists)(_.keyInfo(req))
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
    else if (ids.isHosted(keyId)) {
      // Unlike the namespace key, Canton CAN rotate encryption keys, so hosted keys are deletable —
      // by a signed delete intent (audit M2), which every cosigner verifies and honours only if
      // this certificate holds the delete role (hosted_keys.delete_allowlist; by default it does
      // not, and the delete fails PERMISSION_DENIED). The key becomes a tombstone on every node,
      // recoverable for the cluster's grace period. A write: fail over only when the node is down.
      val req = DeleteKeyRequest.newBuilder().setKeyId(keyId)
      intentSigner.foreach { signer =>
        learnClusterId().foreach { cluster =>
          req.setIntent(
            signer.signDelete(cluster, keyId, FrostIntentSigner.newRequestId(), System.currentTimeMillis(), intentLifetime.toMillis)
          )
        }
      }
      val built = req.build()
      clusterCall("deleteKey", isNodeDown, isLeaderSick)(_.deleteKey(built)).map(_ => ())
    }
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
  // Each call site picks the widest predicate its operation is safe under. Apart from sign
  // ([[signFailsOver]], which also fails over on NOT_FOUND, FAILED_PRECONDITION, ABORTED,
  // UNIMPLEMENTED and the like), every status none of them names — NOT_FOUND, INVALID_ARGUMENT,
  // ALREADY_EXISTS, FAILED_PRECONDITION, RESOURCE_EXHAUSTED, PERMISSION_DENIED, UNAUTHENTICATED,
  // UNIMPLEMENTED, ... — is a real answer from a live node and is surfaced immediately: trying
  // another node would only mask it.
  //
  // Note in particular that RESOURCE_EXHAUSTED (the cluster's per-key decryption rate limit, or a
  // sign rate limit) is NOT retried elsewhere, for any operation. Every cosigner enforces the same ceiling, so failing over would merely
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
    * info, capabilities), decryption, symmetric crypto — and sign, which fails over on more
    * ([[signFailsOver]]). A sign re-issued elsewhere
    * opens a FRESH FROST session with fresh nonces; the first leader's session is abandoned and its
    * round-1 nonces are burnt by the cosigners' own abort/TTL logic (AbortSign, the pending-session
    * TTL), never reused. At worst two valid signatures over the same message exist, which leaks
    * nothing. */
  private def isLeaderSick(status: Status): Boolean =
    isNodeDown(status) || status.getCode == Status.Code.INTERNAL || status.getCode == Status.Code.UNKNOWN

  /** Which statuses move a SIGN to the next leader within one call: every status except the four
    * that are about the request or the signing policy, which are returned to Canton at once.
    *
    * A sign is safe to re-issue through another leader (see [[isLeaderSick]]: a fresh session with
    * fresh nonces), and costs no extra rate-limit charge, because every leader gets the same signed
    * intent and the cosigners charge once per request id and intent. And for a sign the driver has
    * already pinned the group key, so the cluster agreed the key exists: NOT_FOUND,
    * FAILED_PRECONDITION, ABORTED, UNIMPLEMENTED and the like come from that leader's own state (a
    * missing or stale share, a ceremony holding the key, an old or lying node), not from the
    * request, and another leader may well sign. One compromised cosigner that answers every sign
    * with one of them is routed around within the call. The cosigner sends every signing-policy
    * refusal as PERMISSION_DENIED and a rate limit as RESOURCE_EXHAUSTED (`error.rs`); the retried
    * codes carry no policy decision.
    *
    * Returned at once, never tried on another leader:
    *   - PERMISSION_DENIED: a signing-policy refusal (an intent this node will not accept, missing
    *     approvals under its rules, the caller's ACL). Each cosigner enforces its own policy, and
    *     retrying a strict node's refusal through a lenient one would defeat the strict one. The
    *     cluster-id refusal is still handled by the caller (learn the id again, retry once);
    *   - UNAUTHENTICATED: the driver's certificate is not accepted — configuration, not the node;
    *   - RESOURCE_EXHAUSTED: a rate limit. Every cosigner enforces the same one, so going elsewhere
    *     would only spread the load; Canton backs off;
    *   - INVALID_ARGUMENT: the request itself is malformed (the digest length), the same everywhere.
    * A leader that answers one of these loses the lead when the sign carried an intent (see
    * [[signDemotes]]), so a lying node costs at most that one call before the next starts
    * elsewhere. */
  private def signFailsOver(status: Status): Boolean =
    status.getCode match {
      case Status.Code.PERMISSION_DENIED | Status.Code.UNAUTHENTICATED | Status.Code.RESOURCE_EXHAUSTED |
          Status.Code.INVALID_ARGUMENT =>
        false
      case _ => true
    }

  /** The sign failures that are one leader's own and so do not end a sign as final while another
    * cosigner could not be reached (`wholeRoster` of [[withCheckedFailover]]). With two cosigners
    * down and the third answering one of these, the sign fails with an unreachable cosigner's
    * status, which Canton retries: a final error would be a signature Canton never asks for again,
    * although the cosigners that were down can produce it.
    *   - NOT_FOUND (the leader has no share) and a signature the pinned group key does not verify
    *     say that this cosigner cannot sign with the key: `Some(true)`, they count towards the
    *     bound at which the answer is final.
    *   - FAILED_PRECONDITION, ABORTED and UNIMPLEMENTED are about the leader's state at the moment
    *     (a ceremony holds the key, a session is gone, an old release): `Some(false)`, never final
    *     by count while a cosigner is unreachable.
    * INTERNAL and UNKNOWN are not a leader's own answer in this sense (`None`), and the refusals
    * that are returned at once never get here. */
  private def signAnswerIsLeaderLocal(failure: Either[StatusRuntimeException, Rejected]): Option[Boolean] =
    failure match {
      case Left(e) =>
        e.getStatus.getCode match {
          case Status.Code.NOT_FOUND                                                              => Some(true)
          case Status.Code.FAILED_PRECONDITION | Status.Code.ABORTED | Status.Code.UNIMPLEMENTED => Some(false)
          case _                                                                                  => None
        }
      case Right(rejected) => if (rejected.code == BadSignature) Some(true) else None
    }

  /** `lacksKey` of [[withCheckedFailover]] for a sign: the leader's own status that says it cannot
    * sign this key now ([[signAnswerIsLeaderLocal]]: NOT_FOUND, FAILED_PRECONDITION, ABORTED,
    * UNIMPLEMENTED). Such a leader loses the lead once another leader has signed, and the signature
    * has verified against the pinned group key — then the cluster can sign and this leader cannot.
    * When every leader answers so, nobody is demoted: otherwise a sign for a key whose shares are
    * gone, or one that arrives while a ceremony holds the key everywhere, would take every
    * cosigner out of the sign rotation for [[leaderRecovery]], for every key.
    *
    * A signature that does not verify is not in this set: a leader that returns one is demoted at
    * once, whether or not another leader signs. So are INTERNAL, UNKNOWN and an unreachable leader. */
  private def signLeaderCannotSignNow(failure: Either[StatusRuntimeException, Rejected]): Boolean =
    failure.isLeft && signAnswerIsLeaderLocal(failure).isDefined

  /** Which error statuses take the lead from a SIGN leader (see [[withCheckedFailover]]): every
    * status the sign fails over on, and also the refusals returned at once — with an intent.
    *
    * Why a refusal demotes: a signature needs a quorum of cosigners, and with an intent each one
    * checks it on its own share in round 1 and again before release (signer allowlist, SPKI pin,
    * cluster, key ACL, validity, approvals) and charges its own rate limit. So which node leads does
    * not change what can be signed. Keeping the lead on a refusing node would let one compromised
    * cosigner stop every sign by answering with a refusal while it leads, from process start when
    * it is endpoint 0.
    *
    * A leader's own "cannot sign now" loses it the lead only once another leader has signed
    * ([[signLeaderCannotSignNow]]).
    *
    * Not demoted:
    *   - a cluster-id refusal that makes the driver learn the id again: the stale id was the
    *     driver's, and the retry goes to the same node first;
    *   - a refusal of a sign WITHOUT an intent (`frost.sign-intents = off`, no TLS, or no cluster
    *   id known): the other cosigners then cannot see who asks, so the Signer allowlist, the pin and
    *     the key ACL are checked by the leader alone, and moving the next call to another node could
    *     move it past a stricter node's check. */
  private def signDemotes(withIntent: Boolean): Status => Boolean =
    (status: Status) => !isClusterRefusal(status) && (signFailsOver(status) || withIntent)

  /** A cosigner's refusal of an intent naming another cluster (`intent.rs` reason "cluster"). */
  private def isClusterRefusal(s: Status): Boolean =
    s.getCode == Status.Code.PERMISSION_DENIED && Option(s.getDescription).exists(_.contains("intent is for cluster"))

  /** `frost.sign-leader`'s default, in one place: rotate. Whether it stays the 0.5.0 default
    * depends on the stands' evidence before the freeze (docs/architecture.md); `sticky` is the
    * alternative. */
  val DefaultRotateSigns: Boolean = true

  /** No attempt starts with less of the call's budget left than this: it could not succeed. */
  private val MinAttempt: FiniteDuration = 50.millis
  /** How much longer than its calls' deadline the hosted-key copy probe waits for them. */
  private val ProbeSlack: FiniteDuration = 200.millis
  /** `observed` for a [[withCheckedFailover]] call whose answer must not make its node the
    * preferred leader by itself (no endpoint has this index, so the compare-and-set never hits). */
  private val NoPreference = -1

  /** The failover note's reason for a signature the pinned group key does not verify. */
  private val BadSignature = "BAD_SIGNATURE"

  /** The failover note's reason for a hosted-key reply too few cosigners confirmed because some
    * were silent. */
  private val Unconfirmed = "UNCONFIRMED"
  /** The failover note's reason for a hosted-key answer that says the key is not there. */
  private val KeyAbsent = "NOT_FOUND"

  /** `wholeRoster` of [[FrostBackend.clusterCallWholeRoster]]: a cosigner's NOT_FOUND, or its answer
    * that the key does not exist, is its own and counts towards the bound at which it is final. */
  private def hostedKeyIsNotThere(failure: Either[StatusRuntimeException, Rejected]): Option[Boolean] =
    failure match {
      case Left(e)         => if (e.getStatus.getCode == Status.Code.NOT_FOUND) Some(true) else None
      case Right(rejected) => if (rejected.code == KeyAbsent) Some(true) else None
    }

  /** The failover note's reason for a group key that is not the pin. */
  private val GroupKeyMismatch = "GROUP_KEY_MISMATCH"

  /** What a whole-roster walk has seen ([[FrostBackend.rosterVerdict]]): how many endpoints gave a
    * cosigner's own answer and the last of them (its code and error), the endpoint asked most
    * recently that could not be reached, and the last error that is neither. */
  private final case class Seen(
      own: Int = 0,
      lastOwn: Option[(String, Exception)] = None,
      unreachable: Option[(String, StatusRuntimeException)] = None,
      other: Option[Exception] = None,
      // Endpoint indices that said they lack the key, latest first: demoted only if the call is served.
      lackedKeyAt: List[Int] = Nil,
  )

  /** An answer the driver checked and refused to use (see `withCheckedFailover`): `code` names it
    * in the `failover=` note, `error` is what the call fails with when no cosigner is left. */
  private final case class Rejected(code: String, error: Exception)

  /** Strictest predicate, for the non-idempotent DKG ceremony: only the endpoint being unreachable
    * at the connection level (no ceremony started) — never a timeout, which may mean the ceremony is
    * still running, and never a leader-side error, which may have struck mid-ceremony. A blind
    * re-run against another leader is exactly what the ceremony guard exists to refuse. */
  private def connectionRefused(status: Status): Boolean =
    status.getCode == Status.Code.UNAVAILABLE

  private def hexOf(b: ByteString): String = b.toByteArray.map("%02x".format(_)).mkString

  /** A well-formed, canonical, non-small-order Ed25519 point: what a group key must be. */
  private def isValidEd25519Key(raw: Array[Byte]): Boolean =
    raw.length == 32 && org.bouncycastle.math.ec.rfc8032.Ed25519.validatePublicKeyFull(raw, 0)

  /** Strict Ed25519 (RFC 8032) verification with BouncyCastle: rejects a non-canonical S, an
    * undecodable R or key, and any wrong length — never throws, returns false. */
  private[backend] def verifyEd25519(rawKey: Array[Byte], msg: Array[Byte], sig: Array[Byte]): Boolean =
    sig.length == 64 && isValidEd25519Key(rawKey) &&
      (try {
        val v = new Ed25519Signer()
        v.init(false, new Ed25519PublicKeyParameters(rawKey, 0))
        v.update(msg, 0, msg.length)
        v.verifySignature(sig)
      } catch { case _: Exception => false })

  /** Wrap a raw 32-byte Ed25519 public key in DER X.509 SubjectPublicKeyInfo — what Canton expects
    * from getPublicKey. The 12-byte prefix is the fixed Ed25519 SPKI header (SEQUENCE, alg OID
    * 1.3.101.112, BIT STRING); we re-parse to normalize to exactly the verifier's encoding. */
  private def ed25519Spki(raw: Array[Byte]): Array[Byte] = {
    val header = Array[Byte](0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00)
    val spki = header ++ raw
    KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(spki)).getEncoded
  }
}
