// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli.audit

import java.util.concurrent.ConcurrentLinkedQueue
import scala.jdk.CollectionConverters._

/** Annotations a backend attaches to ONE operation's audit entry — e.g. that a FROST sign failed
  * over from a sick leader (`failover=<from>→<to> reason=<CODE>`).
  *
  * The driver creates one per operation and renders it into that operation's own hash-chained
  * entry, so the evidence of what happened travels with the signature it explains instead of
  * living only in a log line that may be rotated away. Append-only and thread-safe: the backend
  * adds from its blocking pool while the driver renders after the operation's Future completes.
  */
final class AuditNotes private (recording: Boolean) {

  def this() = this(true)

  private val notes = new ConcurrentLinkedQueue[String]()

  /** Append one `key=value ...` note. A no-op on [[AuditNotes.discard]]. */
  def add(note: String): Unit = if (recording) { notes.add(note); () }

  def isEmpty: Boolean = notes.isEmpty

  /** The notes in insertion order, joined with single spaces (empty string when there are none). */
  def render: String = notes.asScala.mkString(" ")
}

object AuditNotes {

  /** Sink for annotations nobody will render: the backend's default outside
    * [[com.stakecraft.rutli.backend.KmsBackend.withAuditNotes]], and the driver's when auditing is
    * off. */
  val discard: AuditNotes = new AuditNotes(recording = false)
}
