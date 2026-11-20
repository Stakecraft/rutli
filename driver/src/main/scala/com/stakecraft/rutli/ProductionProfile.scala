// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli

import com.stakecraft.rutli.backend.FrostKeyIds

/** The production profile (`profile = production`): the driver refuses to start while any
  * enforcement setting the threat model assumes is not at its production value, and names each one.
  * `lab` logs the same findings and starts; unset behaves as `lab` with a warning (it becomes
  * `production` in 0.6). `ConfigCheck` prints the same list offline. The cosigner has the same
  * profile; docs/production-profile.md has both tables.
  *
  * A new enforcement setting adds a row here, and a case to `ProductionProfileSpec`, which breaks
  * each setting of a fully enforced config in turn and expects exactly that setting's row.
  */
object ProductionProfile {

  sealed trait Level
  /** Refuses the start under `profile = production`. */
  case object Required extends Level
  /** Reported only: a deployment decision the profile does not make for the operator. */
  case object Advisory extends Level

  /** One setting that is not at its production value: its config key, what the config says, and
    * what the profile requires. */
  final case class Finding(level: Level, setting: String, found: String, required: String) {
    override def toString: String = {
      val tag = if (level == Required) "required" else "advisory"
      s"[$tag] $setting: $found — production requires $required"
    }
  }

  val Production = "production"
  val Lab = "lab"
  val Doc = "docs/production-profile.md"

  /** The configured profile, checked: `Some("production")`, `Some("lab")` or `None` (unset). */
  def of(cfg: RutliConfig): Option[String] = cfg.profile.map(_.trim.toLowerCase) match {
    case p @ (None | Some(Production) | Some(Lab)) => p
    case Some(other) => throw new IllegalArgumentException(s"profile must be production or lab, got '$other' ($Doc)")
  }

  /** Every setting of `cfg` that is not at its production value. Reads nothing but `cfg`. */
  def findings(cfg: RutliConfig): List[Finding] = {
    val out = List.newBuilder[Finding]
    def req(setting: String, found: String, required: String): Unit = out += Finding(Required, setting, found, required)

    if (cfg.backend != "frost") req("backend", s"\"${cfg.backend}\"", "\"frost\" (the namespace key on the cosigner cluster)")
    cfg.frost match {
      case None =>
        if (cfg.backend == "frost") req("frost", "missing", "a frost { ... } block")
      case Some(f) =>
        if (!(f.delegate == "hsm" || (f.delegate == "none" && f.hostedKeys)))
          req(
            "frost.delegate",
            if (f.delegate == "none") "\"none\" without hosted-keys" else s"\"${f.delegate}\"",
            "\"hsm\", or \"none\" with hosted-keys = true (never \"software\": keys in the participant)",
          )
        f.tls match {
          case None => req("frost.tls", "missing (plaintext)", "mutual TLS")
          case Some(t) if t.allowExpiredCa => req("frost.tls.allow-expired-ca", "true", "false")
          case Some(_) =>
        }
        val eps = f.allEndpoints
        if (eps.size < 2)
          req("frost.endpoints", s"${eps.size} endpoint(s)", "every cosigner, at least 2 (a group key needs two agreeing answers)")
        val unnamed = eps.filter(_.tlsName.forall(_.trim.isEmpty)).map(_.url)
        if (unnamed.nonEmpty)
          req("frost.endpoints", s"no tls-name for ${unnamed.mkString(", ")}", "a tls-name on every endpoint (no shared tls.domain)")
        val names = eps.flatMap(_.tlsName).filter(_.trim.nonEmpty)
        if (names.distinct.size != names.size)
          req("frost.endpoints", s"a tls-name used twice (${names.diff(names.distinct).distinct.mkString(", ")})", "a distinct tls-name per cosigner")
        if (!f.signIntentsEnabled) req("frost.sign-intents", "off", "on")
        if (f.clusterId.forall(_.trim.isEmpty)) req("frost.cluster-id", "learned from the cluster", "set (the cosigners' cluster_id)")
        if (f.pinDir.forall(_.trim.isEmpty))
          req("frost.pin-dir", "missing (group-key pins in memory only)", "a directory on the participant's durable volume")
    }
    if (cfg.auditLogPath.forall(_.trim.isEmpty)) req("audit-log-path", "missing", "a path on the participant's durable volume")
    if (cfg.signingJournal.isEmpty) req("signing-journal", "missing", "signing-journal { dir = ... }")
    val usesHsm = cfg.backend == "hsm" || cfg.frost.exists(f => cfg.backend == "frost" && f.delegate == "hsm")
    if (usesHsm && cfg.hsm.exists(h => h.pin.nonEmpty || h.pinEnv.forall(_.trim.isEmpty)))
      req(
        "hsm.pin",
        cfg.hsm.filter(_.pin.nonEmpty).fold("no hsm.pin-env")(_ => "inline in the config (it is used whenever pin-env is unset)"),
        "hsm.pin-env only (the PIN from the environment), no inline hsm.pin",
      )

    // Advisory: the namespace key. Canton names it `<node>-namespace` (older releases: `namespace`),
    // so its FROST id is `<key-prefix>frost-<node>-namespace`; the driver does not know the node name.
    val frostPrefix = cfg.frost.map(_.keyPrefix).getOrElse("") + FrostKeyIds.FrostTag
    def isNamespaceId(id: String): Boolean = id.startsWith(frostPrefix) && id.endsWith("namespace")
    val namespaceIds = s"${frostPrefix}<node>-namespace"
    // Human approval of its signatures: a quorum rule over every FROST key, or one naming it.
    val approved = cfg.approval.exists(_.rules.exists { r =>
      r.mode == com.stakecraft.rutli.policy.ApprovalPolicy.Quorum &&
      (frostPrefix.startsWith(r.keyIdPrefix) || isNamespaceId(r.keyIdPrefix))
    })
    if (!approved)
      out += Finding(
        Advisory,
        "approval",
        s"no quorum rule covering $namespaceIds",
        "a quorum approval rule for the namespace key (docs/approval-quorum.md)",
      )
    // An operator anchor for its first pin.
    if (cfg.backend == "frost" && cfg.frost.exists(f => !f.expectedGroupKeys.keys.exists(isNamespaceId)))
      out += Finding(
        Advisory,
        "frost.expected-group-keys",
        s"no entry for $namespaceIds",
        s"its group key from the key ceremony record, so a first pin is checked against it",
      )
    out.result()
  }

  def required(cfg: RutliConfig): List[Finding] = findings(cfg).filter(_.level == Required)

  /** The startup refusal for a production driver with required findings. */
  def refusal(required: List[Finding]): String =
    (s"profile is \"production\" but ${required.size} enforcement setting(s) are not at their production " +
      s"value ($Doc; com.stakecraft.rutli.tools.ConfigCheck lists them; set profile = lab only for a lab):" ::
      required.map(f => s"  - $f")).mkString("\n")

  /** At startup: refuse a production driver with required findings, otherwise log the findings.
    * Throws [[IllegalArgumentException]], which Canton reports as a driver config error. */
  def enforce(cfg: RutliConfig, logger: org.slf4j.Logger): Unit = {
    val profile = of(cfg)
    val all = findings(cfg)
    val req = all.filter(_.level == Required)
    if (profile.contains(Production) && req.nonEmpty) throw new IllegalArgumentException(refusal(req))
    profile match {
      case Some(Production) => logger.info("profile production: every required enforcement setting is on")
      case Some(_) =>
        logger.info(s"profile lab: ${req.size} enforcement setting(s) not at their production value — never for an authority key ($Doc)")
      case None =>
        logger.warn(
          s"profile is not set: running as lab with ${req.size} enforcement setting(s) not at their production value; " +
            s"set profile = production (or lab explicitly). Unset becomes production in 0.6 ($Doc)"
        )
    }
    all.foreach { f =>
      if (f.level == Advisory) logger.warn(s"production profile, advisory: $f")
      else if (profile.contains(Lab)) logger.info(s"production profile, not met: $f")
      else logger.warn(s"production profile, not met: $f")
    }
  }
}
