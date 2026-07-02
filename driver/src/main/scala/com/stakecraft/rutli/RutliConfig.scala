// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli

/** Driver-specific configuration, parsed from the `config { ... }` block of the Canton node's
  * `crypto.kms` section.
  *
  * Phase 0 only exposes the software backend. Later phases add backend selection + backend-specific
  * config (HSM PKCS#11 connection; FROST MPC cluster peers, thresholds, mTLS material).
  *
  * @param backend       Which key backend to use. Phase 0 supports only "software".
  * @param auditLogging  Emit request/response audit lines (placeholder until the Phase 3 audit log).
  */
final case class RutliConfig(
    backend: String = "software",
    auditLogging: Boolean = false,
)
