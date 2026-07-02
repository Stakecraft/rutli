// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli

import com.digitalasset.canton.crypto.kms.driver.api.v1.KmsDriverFactory
import com.stakecraft.rutli.backend.SoftwareBackend
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
    deriveReader[RutliConfig]
  }

  override def configWriter(confidential: Boolean): ConfigWriter[RutliConfig] = {
    import pureconfig.generic.semiauto._
    // No sensitive fields yet; when backend credentials (HSM PIN, mTLS keys) are added, omit them
    // when `confidential` is true.
    deriveWriter[RutliConfig]
  }

  override def create(
      config: RutliConfig,
      loggerFactory: Class[_] => Logger,
      executionContext: ExecutionContext,
  ): RutliDriver = {
    implicit val ec: ExecutionContext = executionContext
    val logger = loggerFactory(classOf[RutliDriver])

    val backend = config.backend match {
      case "software" => new SoftwareBackend()
      case other =>
        throw new IllegalArgumentException(
          s"unsupported backend '$other'; Phase 0 supports only 'software'"
        )
    }

    logger.info(
      s"Starting Rutli driver (backend=${config.backend}, auditLogging=${config.auditLogging})"
    )
    new RutliDriver(
      backend,
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
