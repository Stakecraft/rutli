// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli.backend

/** The one place key ids for the cosigner cluster are minted and recognised.
  *
  * Every id the [[FrostBackend]] sends to the cluster is `<prefix><routing tag><name>`:
  *
  *   - `frost-` ids are FROST threshold shares (the Ed25519 namespace/identity keys);
  *   - `rutli-` ids are cluster-hosted whole keys (RSA encryption, AES symmetric).
  *
  * The routing tag decides which RPCs an id is served by. The `prefix` (`frost.key-prefix` in the
  * driver config, default empty) exists so **several participants can share one cosigner cluster**:
  * FROST ids are derived deterministically from Canton's key name, so without a prefix a second
  * participant asks the cluster for the very same `frost-namespace` id and the cluster's create-once
  * guard refuses the DKG with `ALREADY_EXISTS` — correct, because that guard is what protects a
  * live namespace key. A per-participant prefix keeps the ids disjoint instead.
  *
  * With the default empty prefix the ids are byte-for-byte what earlier releases minted, so existing
  * deployments are untouched. Routing is strict: a prefixed driver recognises only ids carrying its
  * own prefix, so the prefix must be chosen before the participant's first bootstrap and never
  * changed afterwards (Canton stores the ids it was handed).
  *
  * The cosigner treats ids as opaque strings but its keystore accepts only `[A-Za-z0-9_-]`, so the
  * prefix is restricted to that alphabet — a bad prefix fails here, at startup, not at the first DKG.
  */
final case class FrostKeyIds(prefix: String) {

  import FrostKeyIds._

  require(
    prefix.matches(PrefixAlphabet),
    s"frost.key-prefix must match [A-Za-z0-9_-]* (cosigner keystore alphabet), got ${prefix.replace("\"", "\\\"")}",
  )

  private val frostPrefix: String = prefix + FrostTag
  private val hostedPrefix: String = prefix + HostedTag

  /** The FROST id for a Canton key name: deterministic, so Canton's `namespace` key is always the
    * same cluster key — and so a second participant on the same cluster collides without a prefix. */
  def frost(keyName: Option[String]): String = {
    val name = keyName.map(sanitize).getOrElse("key")
    s"$frostPrefix$name"
  }

  /** A fresh hosted-key id of the given kind (`enc`, `sym`). A UUID keeps retries of *different*
    * logical keys from colliding while `GenerateKey` stays idempotent for the same id. */
  def hosted(kind: String, keyName: Option[String]): String =
    hosted(kind, keyName, java.util.UUID.randomUUID().toString)

  /** As [[hosted]] with the random part supplied — for tests that need a reproducible id. */
  def hosted(kind: String, keyName: Option[String], uuid: String): String = {
    val name = keyName.map(n => s"-${sanitize(n)}").getOrElse("")
    s"$hostedPrefix$kind$name-$uuid".take(MaxLength)
  }

  /** True when `keyId` is one of this driver's FROST threshold keys. */
  def isFrost(keyId: String): Boolean = keyId.startsWith(frostPrefix)

  /** True when `keyId` is one of this driver's cluster-hosted whole keys. */
  def isHosted(keyId: String): Boolean = keyId.startsWith(hostedPrefix)

  /** True when `keyId` is served by the cluster at all (either routing tag), as opposed to the
    * delegate. */
  def isCluster(keyId: String): Boolean = isFrost(keyId) || isHosted(keyId)
}

object FrostKeyIds {

  /** Routing tag for FROST threshold shares. */
  val FrostTag: String = "frost-"

  /** Routing tag for cluster-hosted (replicated, sealed) whole keys. */
  val HostedTag: String = "rutli-"

  /** What the cosigner keystore accepts in a key id; the prefix must stay inside it. */
  val PrefixAlphabet: String = "[A-Za-z0-9_-]*"

  /** Hard cap on a minted id, so a pathological Canton key name cannot produce an unbounded one. */
  val MaxLength: Int = 300

  /** The ids every release before `frost.key-prefix` minted. */
  val Default: FrostKeyIds = FrostKeyIds("")

  private def sanitize(name: String): String = name.replaceAll("[^A-Za-z0-9_-]", "_")
}
