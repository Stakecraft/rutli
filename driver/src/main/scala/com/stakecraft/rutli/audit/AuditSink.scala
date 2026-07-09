// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli.audit

/** A durable audit sink. `append` must persist the entry (fsync) before returning, or throw — the
  * driver writes ahead of releasing a signature and fails the operation closed if `append` throws.
  * [[HashChainedAuditLog]] is the production implementation; the abstraction keeps the durability
  * contract testable in isolation. */
trait AuditSink {
  def append(op: String, detail: String): Unit
  def close(): Unit
}
