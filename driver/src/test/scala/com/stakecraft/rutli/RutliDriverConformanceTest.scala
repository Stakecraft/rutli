// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli

import com.digitalasset.canton.crypto.kms.driver.api.v1.KmsDriver
import com.digitalasset.canton.crypto.kms.driver.testing.v1.KmsDriverTest

/** Runs the upstream Canton driver conformance suite against [[RutliDriver]] with the Phase 0
  * [[com.stakecraft.rutli.backend.SoftwareBackend]].
  *
  * `allowKeyGeneration = true` because the software backend can generate keys. The suite exercises
  * only the specs the driver advertises, so encryption is tested for RSA-2048 OAEP-SHA256 only in
  * Phase 0 (ECIES(P-256) is intentionally not advertised).
  */
class RutliDriverConformanceTest extends KmsDriverTest {

  override protected def newKmsDriver(): KmsDriver = {
    val factory = new RutliDriverFactory
    factory.create(RutliConfig(), simpleLoggerFactory, parallelExecutionContext)
  }

  "MPC KMS Driver (software backend)" must {
    behave like kmsDriver(allowKeyGeneration = true)
  }
}
