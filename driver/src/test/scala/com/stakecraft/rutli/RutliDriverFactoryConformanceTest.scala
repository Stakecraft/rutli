// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli

import com.digitalasset.canton.crypto.kms.driver.testing.v1.KmsDriverFactoryTest

/** Runs the upstream factory conformance suite against [[RutliDriverFactory]]. */
class RutliDriverFactoryConformanceTest extends KmsDriverFactoryTest {

  override type Factory = RutliDriverFactory

  override protected val factory: RutliDriverFactory = new RutliDriverFactory()

  override protected val config: RutliConfig = RutliConfig()

  "MPC KMS Driver Factory" must {
    behave like kmsDriverFactory()
  }
}
