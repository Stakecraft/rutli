// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli

import com.digitalasset.canton.crypto.kms.driver.api.v1.KmsDriverFactory
import com.stakecraft.rutli.backend.{FrostBackend, HsmBackend, KmsBackend, SoftwareBackend}
import org.slf4j.Logger
import pureconfig.{ConfigReader, ConfigWriter}
import pureconfig.generic.ProductHint

import scala.concurrent.ExecutionContext

/** Factory registered with Canton via `ServiceLoader` (see the two `META-INF/services` files).
  * Canton instantiates it at startup, parses the driver `config { ... }` block, and calls
  * [[create]] to obtain the [[RutliDriver]].
  *
  * `version` is fixed to 1 by the v1 SPI.
  */
final class RutliDriverFactory extends KmsDriverFactory {

  override type Driver = RutliDriver

  override def name: String = RutliDriverFactory.driverName

  override def buildInfo: Option[String] =
    Option(getClass.getPackage.getImplementationVersion)

  override type ConfigType = RutliConfig

  override def configReader: ConfigReader[RutliConfig] = {
    import pureconfig.generic.semiauto._
    import com.stakecraft.rutli.policy.{Approver, ApprovalRule, ApprovalPolicy}
    // Refuse unknown keys in every block. pureconfig ignores them by default, so a misspelt key
    // silently left a control off: `aproval { ... }` meant no approval block and therefore
    // AutoApproveGate. Field naming stays the default (camelCase field -> kebab-case key).
    // Canton passes `crypto.kms.config` to this reader verbatim (KmsConfig.Driver.config, handed
    // to DriverLoader.load), with no keys of its own, so nothing needs to be tolerated. Canton's
    // own config reader uses the same hint (CantonConfig.preventAllUnknownKeys, pureconfig 0.14.0).
    implicit def strictKeys[T]: ProductHint[T] = ProductHint[T](allowUnknownKeys = false)
    implicit val hsmReader: ConfigReader[HsmConfig] = deriveReader[HsmConfig]
    implicit val frostTlsReader: ConfigReader[FrostTlsConfig] = deriveReader[FrostTlsConfig]
    // An endpoint is `{ url, tls-name }` or, as before, a bare url string.
    implicit val frostEndpointReader: ConfigReader[FrostEndpoint] =
      ConfigReader[String].map(FrostEndpoint(_)).orElse(deriveReader[FrostEndpoint])
    implicit val frostReader: ConfigReader[FrostConfig] = deriveReader[FrostConfig]
    // A rule's mode is `quorum` or `auto`, exactly; anything else fails here, at its own key.
    implicit val ruleReader: ConfigReader[ApprovalRule] = {
      val derived = deriveReader[ApprovalRule]
      ConfigReader.fromCursor[ApprovalRule] { cur =>
        derived.from(cur).flatMap { rule =>
          ApprovalPolicy.modeProblem(rule) match {
            case None => Right(rule)
            case Some(problem) =>
              val at: pureconfig.ConfigCursor = cur.asObjectCursor.flatMap(_.atKey("mode")).getOrElse(cur)
              Left(pureconfig.error.ConfigReaderFailures(at.failureFor(RutliDriverFactory.InvalidApprovalRule(problem))))
          }
        }
      }
    }
    // An approver's key has two names. `public-key-base64` is what the docs and `approve keygen`
    // print. `public-key-base-64` is what pureconfig derives from the field `publicKeyBase64` (a
    // digit run is its own word) and the only name releases up to 0.4.0 read, so a config copied
    // from the docs stopped the participant with "Key not found". Both are read; exactly one must
    // be set, and any other key is refused as in every other block.
    implicit val approverReader: ConfigReader[Approver] = ConfigReader.fromCursor[Approver] { cur =>
      import pureconfig.error.{CannotConvert, ConfigReaderFailures, ConvertFailure, UnknownKey}
      val keyNames = List("public-key-base64", "public-key-base-64")
      cur.asObjectCursor.flatMap { obj =>
        val unknown = obj.map.toList.collect {
          case (k, keyCur) if k != "id" && !keyNames.contains(k) => keyCur.failureFor(UnknownKey(k))
        }
        (unknown, keyNames.filter(obj.map.contains)) match {
          case (h :: t, _) => Left(ConfigReaderFailures(h, t: _*))
          case (Nil, both @ List(_, _)) =>
            val reason = CannotConvert(both.mkString(" and "), "Approver", "both names of the key are set; keep one")
            Left(ConfigReaderFailures(ConvertFailure(reason, obj)))
          case (Nil, present) =>
            // With neither name set this fails with "Key not found" for the documented name.
            val name = present.headOption.getOrElse(keyNames.head)
            for {
              id <- obj.atKey("id").flatMap(_.asString)
              key <- obj.atKey(name).flatMap(_.asString)
            } yield Approver(id, key)
        }
      }
    }
    // The rules are checked while the config is read, not left to the ApprovalPolicy constructor:
    // an exception out of this reader reaches the operator as a stack trace (Canton's DriverLoader
    // catches none here), not as a config error with its path. A misspelt mode (`quorom`,
    // `Quorum`) once meant auto-approve; it is refused at the rule's `mode`, e.g.
    // `approval.rules.0.mode`. What needs the whole policy (a threshold against the approvers, a
    // quorum rule an earlier auto rule shadows) is refused at `approval.rules`, naming the rule.
    implicit val policyReader: ConfigReader[ApprovalPolicy] = {
      val derived = deriveReader[ApprovalPolicy]
      ConfigReader.fromCursor[ApprovalPolicy] { cur =>
        for {
          obj <- cur.asObjectCursor
          rulesCur <- obj.atKey("rules")
          rules <- ConfigReader[List[ApprovalRule]].from(rulesCur)
          approvers <- obj.atKey("approvers").flatMap(c => ConfigReader[List[Approver]].from(c))
          _ <- ApprovalPolicy.ruleProblems(rules, approvers.size) match {
            case Nil => Right(())
            case problems =>
              val failures = problems.map(p => rulesCur.failureFor(RutliDriverFactory.InvalidApprovalRule(p.message)))
              Left(pureconfig.error.ConfigReaderFailures(failures.head, failures.tail: _*))
          }
          policy <- derived.from(cur)
        } yield policy
      }
    }
    implicit val journalReader: ConfigReader[SigningJournalConfig] = deriveReader[SigningJournalConfig]
    implicit val softwareReader: ConfigReader[SoftwareConfig] = deriveReader[SoftwareConfig]
    deriveReader[RutliConfig]
  }

  override def configWriter(confidential: Boolean): ConfigWriter[RutliConfig] = {
    import pureconfig.generic.semiauto._
    // Redact the HSM PIN when `confidential` (used e.g. when Canton echoes config back).
    implicit val hsmWriter: ConfigWriter[HsmConfig] = {
      val base = deriveWriter[HsmConfig]
      if (confidential) base.contramap[HsmConfig](_.copy(pin = None)) else base
    }
    // Redact the TLS private-key path when `confidential` so a config echo (Canton logs / its config
    // API) doesn't reveal where the driver's client private key lives on disk.
    implicit val frostTlsWriter: ConfigWriter[FrostTlsConfig] = {
      val base = deriveWriter[FrostTlsConfig]
      if (confidential) base.contramap[FrostTlsConfig](_.copy(key = "<redacted>")) else base
    }
    implicit val frostEndpointWriter: ConfigWriter[FrostEndpoint] = deriveWriter[FrostEndpoint]
    implicit val frostWriter: ConfigWriter[FrostConfig] = deriveWriter[FrostConfig]
    import com.stakecraft.rutli.policy.{Approver, ApprovalRule, ApprovalPolicy}
    implicit val ruleWriter: ConfigWriter[ApprovalRule] = deriveWriter[ApprovalRule]
    implicit val approverWriter: ConfigWriter[Approver] = deriveWriter[Approver]
    implicit val policyWriter: ConfigWriter[ApprovalPolicy] = deriveWriter[ApprovalPolicy]
    implicit val journalWriter: ConfigWriter[SigningJournalConfig] = deriveWriter[SigningJournalConfig]
    implicit val softwareWriter: ConfigWriter[SoftwareConfig] = deriveWriter[SoftwareConfig]
    deriveWriter[RutliConfig]
  }

  override def create(
      config: RutliConfig,
      loggerFactory: Class[_] => Logger,
      executionContext: ExecutionContext,
  ): RutliDriver = {
    implicit val ec: ExecutionContext = executionContext
    val logger = loggerFactory(classOf[RutliDriver])
    // Before anything is opened or dialled: a production driver with an enforcement gap stops here,
    // naming each setting (docs/production-profile.md).
    ProductionProfile.enforce(config, logger)

    // FROST gRPC calls and approval polling BLOCK. Run them on a dedicated bounded daemon pool so a
    // burst of gated signs or a slow cluster can't starve Canton's shared ExecutionContext. Only
    // created when a blocking component is actually configured; shut down in RutliDriver.close().
    val blockingPool: Option[java.util.concurrent.ExecutorService] =
      if (config.backend == "frost" || config.approval.isDefined)
        Some(RutliDriverFactory.newBlockingPool("rutli-blocking"))
      else None
    val blockingEc: ExecutionContext =
      blockingPool.map(ExecutionContext.fromExecutor).getOrElse(executionContext)

    def buildBackend(kind: String): KmsBackend = kind match {
      case "software" =>
        val persistence = config.software.flatMap { sc =>
          sc.dir.map { dir =>
            val envName = sc.sealSecretEnv.getOrElse(
              throw new IllegalArgumentException(
                "software.dir is set but software.seal-secret-env is not — refusing to persist " +
                  "private keys in plaintext; set the env var name holding the seal master secret"
              )
            )
            val secret = sys.env.getOrElse(
              envName,
              throw new IllegalArgumentException(
                s"software key persistence: env var $envName is not set"
              ),
            )
            logger.info(s"Software backend: sealed key persistence at $dir")
            new com.stakecraft.rutli.backend.SoftKeyStore(
              java.nio.file.Paths.get(dir),
              secret.getBytes(java.nio.charset.StandardCharsets.UTF_8),
            )
          }
        }
        if (persistence.isEmpty)
          logger.warn(
            "Software backend is HEAP-ONLY: keys will not survive a restart. Set " +
              "software { dir, seal-secret-env } for sealed persistence — a lost encryption key " +
              "is unrecoverable."
          )
        new SoftwareBackend(persistence)
      case "hsm" =>
        val hsm = config.hsm.getOrElse(
          throw new IllegalArgumentException("hsm backend requires an `hsm { ... }` config block")
        )
        new HsmBackend(hsm)
      case "none" => new com.stakecraft.rutli.backend.NoDelegateBackend
      case other =>
        throw new IllegalArgumentException(
          s"unsupported backend '$other'; supported: software, hsm, none"
        )
    }

    // Opened before the backend: a new group-key pin is written to it.
    val auditLog = config.auditLogPath.map { p =>
      logger.info(s"Hash-chained audit log at $p")
      com.stakecraft.rutli.audit.HashChainedAuditLog.open(p)
    }

    val backend: KmsBackend = config.backend match {
      case "software" | "hsm" => buildBackend(config.backend)
      case "frost" =>
        val frost = config.frost.getOrElse(
          throw new IllegalArgumentException("backend = \"frost\" requires a `frost { ... }` block")
        )
        val eps = frost.allEndpoints
        if (eps.isEmpty)
          throw new IllegalArgumentException("frost backend requires `endpoint` or `endpoints`")
        // Non-namespace keys go to the delegate backend (the HSM in production).
        if (frost.delegate == "none" && !frost.hostedKeys)
          throw new IllegalArgumentException(
            "frost.delegate = \"none\" requires frost.hosted-keys = true — otherwise nothing " +
              "would serve the participant's encryption and symmetric keys"
          )
        if (frost.tls.isDefined)
          eps.filter(_.tlsName.isEmpty).foreach { e =>
            logger.warn(
              s"FROST: endpoint ${e.url} has no tls-name, so it is verified under " +
                s"${frost.tls.flatMap(_.domain).fold("its host name")(d => s"the shared tls.domain '$d'")}" +
                " — any cosigner certificate carrying that name could answer for it; set " +
                "endpoints = [{ url = \"…\", tls-name = \"cosigner<id>\" }, …]"
            )
          }
        val pinStore = frost.pinDir.map { d =>
          logger.info(s"FROST: group-key pins at $d")
          new com.stakecraft.rutli.backend.GroupKeyPinStore(java.nio.file.Paths.get(d), logger)
        }
        // The pin store against the audit log, which records every pin: a pin file that names another
        // key than its audit entry refuses the start; a pin the log records whose file is gone (and
        // not retired) is refused until re-anchored; a pin the log lacks (a crash between the two
        // writes) is recorded now.
        import com.stakecraft.rutli.backend.PinAudit
        val lostPins: Set[String] = (for {
          store <- pinStore
          path <- config.auditLogPath
        } yield {
          val r = PinAudit.reconcile(
            store.all,
            PinAudit.recorded(com.stakecraft.rutli.audit.HashChainedAuditLog.details(path, PinAudit.Op)),
            store.dir,
          )
          if (r.mismatched.nonEmpty)
            throw new IllegalStateException(
              s"group-key pin file(s) for ${r.mismatched.mkString(", ")} in ${store.dir} name another key than the audit " +
                "log records for them: a pin file was rewritten. The driver refuses to start (docs/disaster-recovery.md §3i)"
            )
          r.unrecorded.foreach { p =>
            logger.warn(s"FROST: the audit log has no entry for the group-key pin of ${p.keyId}; recording it now")
            auditLog.foreach(_.append(PinAudit.Op, PinAudit.detail(p, recovered = true)))
          }
          r.lost
        }).getOrElse(Set.empty)
        new FrostBackend(
          eps.map(_.url),
          buildBackend(frost.delegate),
          logger,
          frost.tls,
          hostedKeys = frost.hostedKeys,
          keyPrefix = frost.keyPrefix,
          endpointTlsNames = eps.flatMap(e => e.tlsName.map(e.url -> _)).toMap,
          clusterId = frost.clusterId,
          signIntents = frost.signIntentsEnabled,
          pinStore = pinStore,
          expectedGroupKeys = frost.expectedGroupKeys,
          lostPins = lostPins,
          onPin = (p: com.stakecraft.rutli.backend.GroupKeyPin) =>
            auditLog.foreach(_.append(com.stakecraft.rutli.backend.PinAudit.Op, com.stakecraft.rutli.backend.PinAudit.detail(p))),
          adoptExistingKeys = frost.adoptExistingKeys.toSet,
        )(blockingEc)
      case other =>
        throw new IllegalArgumentException(
          s"unsupported backend '$other'; supported: software, hsm, frost"
        )
    }

    val approvalGate: com.stakecraft.rutli.policy.ApprovalGate = config.approval match {
      case Some(policy) =>
        logger.info(
          s"M-of-N approval enabled: ${policy.rules.size} rule(s), ${policy.approvers.size} approver(s), inbox=${policy.inboxDir}"
        )
        new com.stakecraft.rutli.policy.FileApprovalGate(policy, logger)(blockingEc)
      case None => com.stakecraft.rutli.policy.AutoApproveGate
    }

    val signingJournal = config.signingJournal.map { j =>
      logger.info(s"Signing journal at ${j.dir} (rateLimit=${j.maxPerWindow.map(m => s"$m/${j.windowSeconds}s").getOrElse("off")})")
      val sj = new com.stakecraft.rutli.guard.SigningJournal(j.dir, j.maxPerWindow, j.windowSeconds, logger)
      sj.recover()
      sj
    }

    logger.info(
      s"Starting Rutli driver (backend=${config.backend}, auditLogging=${config.auditLogging}, auditLogPath=${config.auditLogPath.getOrElse("-")}, approval=${config.approval.isDefined}, journal=${config.signingJournal.isDefined})"
    )
    new RutliDriver(
      backend,
      logger,
      config.auditLogging,
      auditLog,
      approvalGate,
      signingJournal,
      backend.supportedSigningKeySpecs,
      backend.supportedSigningAlgoSpecs,
      backend.supportedEncryptionKeySpecs,
      backend.supportedEncryptionAlgoSpecs,
      blockingPool,
    )
  }
}

object RutliDriverFactory {

  /** The driver name referenced by the Canton node config: `crypto.kms.name = "rutli"`. */
  val driverName: String = "rutli"

  /** An `approval.rules` entry the driver refuses (see [[com.stakecraft.rutli.policy.ApprovalPolicy.ruleProblems]]). */
  final case class InvalidApprovalRule(override val description: String) extends pureconfig.error.FailureReason

  /** A bounded pool of daemon threads for blocking work (FROST RPCs, approval polling). Daemon so
    * it never blocks JVM shutdown; bounded so it can't spawn unboundedly under load. */
  private def newBlockingPool(name: String): java.util.concurrent.ExecutorService = {
    val counter = new java.util.concurrent.atomic.AtomicInteger(0)
    val size = math.max(4, Runtime.getRuntime.availableProcessors)
    java.util.concurrent.Executors.newFixedThreadPool(
      size,
      (r: Runnable) => {
        val t = new Thread(r, s"$name-${counter.incrementAndGet()}")
        t.setDaemon(true)
        t
      },
    )
  }
}
