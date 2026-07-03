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
    implicit val hsmReader: ConfigReader[HsmConfig] = deriveReader[HsmConfig]
    implicit val frostTlsReader: ConfigReader[FrostTlsConfig] = deriveReader[FrostTlsConfig]
    implicit val frostReader: ConfigReader[FrostConfig] = deriveReader[FrostConfig]
    deriveReader[RutliConfig]
  }

  override def configWriter(confidential: Boolean): ConfigWriter[RutliConfig] = {
    import pureconfig.generic.semiauto._
    // Redact the HSM PIN when `confidential` (used e.g. when Canton echoes config back).
    implicit val hsmWriter: ConfigWriter[HsmConfig] = {
      val base = deriveWriter[HsmConfig]
      if (confidential) base.contramap[HsmConfig](_.copy(pin = None)) else base
    }
    implicit val frostTlsWriter: ConfigWriter[FrostTlsConfig] = deriveWriter[FrostTlsConfig]
    implicit val frostWriter: ConfigWriter[FrostConfig] = deriveWriter[FrostConfig]
    deriveWriter[RutliConfig]
  }

  override def create(
      config: RutliConfig,
      loggerFactory: Class[_] => Logger,
      executionContext: ExecutionContext,
  ): RutliDriver = {
    implicit val ec: ExecutionContext = executionContext
    val logger = loggerFactory(classOf[RutliDriver])

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
        new FrostBackend(eps, buildBackend(frost.delegate), logger, frost.tls)
      case other =>
        throw new IllegalArgumentException(
          s"unsupported backend '$other'; supported: software, hsm, frost"
        )
    }

    logger.info(
      s"Starting Rutli driver (backend=${config.backend}, auditLogging=${config.auditLogging})"
    )
    new RutliDriver(
      backend,
      logger,
      config.auditLogging,
      backend.supportedSigningKeySpecs,
      backend.supportedSigningAlgoSpecs,
      backend.supportedEncryptionKeySpecs,
      backend.supportedEncryptionAlgoSpecs,
    )
  }
}

object RutliDriverFactory {

  /** The driver name referenced by the Canton node config: `crypto.kms.name = "rutli"`. */
  val driverName: String = "rutli"
}
