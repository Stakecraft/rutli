// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli

import com.digitalasset.canton.crypto.kms.driver.api.v1.KmsDriverFactory
import com.stakecraft.rutli.backend.{FrostBackend, HsmBackend, KmsBackend, SoftwareBackend}
import org.slf4j.Logger
import pureconfig.{ConfigReader, ConfigWriter}

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
    implicit val hsmReader: ConfigReader[HsmConfig] = deriveReader[HsmConfig]
    implicit val frostTlsReader: ConfigReader[FrostTlsConfig] = deriveReader[FrostTlsConfig]
    implicit val frostReader: ConfigReader[FrostConfig] = deriveReader[FrostConfig]
    implicit val ruleReader: ConfigReader[ApprovalRule] = deriveReader[ApprovalRule]
    implicit val approverReader: ConfigReader[Approver] = deriveReader[Approver]
    implicit val policyReader: ConfigReader[ApprovalPolicy] = deriveReader[ApprovalPolicy]
    implicit val journalReader: ConfigReader[SigningJournalConfig] = deriveReader[SigningJournalConfig]
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
    implicit val frostWriter: ConfigWriter[FrostConfig] = deriveWriter[FrostConfig]
    import com.stakecraft.rutli.policy.{Approver, ApprovalRule, ApprovalPolicy}
    implicit val ruleWriter: ConfigWriter[ApprovalRule] = deriveWriter[ApprovalRule]
    implicit val approverWriter: ConfigWriter[Approver] = deriveWriter[Approver]
    implicit val policyWriter: ConfigWriter[ApprovalPolicy] = deriveWriter[ApprovalPolicy]
    implicit val journalWriter: ConfigWriter[SigningJournalConfig] = deriveWriter[SigningJournalConfig]
    deriveWriter[RutliConfig]
  }

  override def create(
      config: RutliConfig,
      loggerFactory: Class[_] => Logger,
      executionContext: ExecutionContext,
  ): RutliDriver = {
    implicit val ec: ExecutionContext = executionContext
    val logger = loggerFactory(classOf[RutliDriver])

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
      case "software" => new SoftwareBackend()
      case "hsm" =>
        val hsm = config.hsm.getOrElse(
          throw new IllegalArgumentException("hsm backend requires an `hsm { ... }` config block")
        )
        new HsmBackend(hsm)
      case other =>
        throw new IllegalArgumentException(s"unsupported backend '$other'; supported: software, hsm")
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
        new FrostBackend(eps, buildBackend(frost.delegate), logger, frost.tls)(blockingEc)
      case other =>
        throw new IllegalArgumentException(
          s"unsupported backend '$other'; supported: software, hsm, frost"
        )
    }

    val auditLog = config.auditLogPath.map { p =>
      logger.info(s"Hash-chained audit log at $p")
      com.stakecraft.rutli.audit.HashChainedAuditLog.open(p)
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
