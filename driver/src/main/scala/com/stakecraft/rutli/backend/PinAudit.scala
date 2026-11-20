// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli.backend

import java.nio.file.{Files, Path}

/** The pin store checked against the audit log at startup. Every new pin is written to the audit
  * log as `group-key-pin keyId=<id> groupKey=<hex> ...`. The pin file's checksum only catches
  * damage, so the audit log's hash chain is what catches a pin file that was rewritten.
  */
object PinAudit {

  /** The audit-log operation of a group-key pin. */
  val Op: String = "group-key-pin"

  /** The audit detail of `pin` (`recovered` for an entry re-written at startup). */
  def detail(pin: GroupKeyPin, recovered: Boolean = false): String =
    s"keyId=${pin.keyId} groupKey=${pin.groupKeyHex} source=${pin.source} agreedBy=${pin.agreedBy.mkString(",")}" +
      (if (pin.dissent.isEmpty) "" else s" dissent=${pin.dissent.mkString(",")}") +
      (if (recovered) " recovered=startup" else "")

  /** What the audit log says about the pins: the last group key recorded per key id. */
  def recorded(details: List[String]): Map[String, String] =
    details.flatMap { d =>
      val kv = d.split(" ").toList.flatMap { t =>
        val i = t.indexOf('=')
        if (i > 0) Some(t.substring(0, i) -> t.substring(i + 1)) else None
      }.toMap
      for (k <- kv.get("keyId"); g <- kv.get("groupKey")) yield k -> g
    }.toMap // later entries win

  /** The outcome of [[reconcile]]. */
  final case class Result(
      /** Pins on disk that the audit log does not record (a crash between the pin file and its audit
        * entry): to be written to the audit log now. */
      unrecorded: List[GroupKeyPin],
      /** Key ids whose pin file names another group key than the audit log: the start is refused. */
      mismatched: List[String],
      /** Key ids the audit log records whose pin file is gone (and not retired): refused until the
        * file is restored or `frost.expected-group-keys` names the key. */
      lost: Set[String],
  )

  /** Compare the pin store (`pins`) with what the audit log records. A key id whose pin was moved to
    * `<pin-dir>/retired/` on purpose is not lost. */
  def reconcile(pins: Map[String, GroupKeyPin], recordedKeys: Map[String, String], pinDir: Path): Result = {
    val retired = pinDir.resolve("retired")
    def isRetired(keyId: String): Boolean =
      Files.isDirectory(retired) && {
        val s = Files.list(retired)
        try s.anyMatch(p => p.getFileName.toString.startsWith(keyId + GroupKeyPinStore.Suffix))
        finally s.close()
      }
    Result(
      unrecorded = pins.values.filterNot(p => recordedKeys.contains(p.keyId)).toList.sortBy(_.keyId),
      mismatched = pins.values.filter(p => recordedKeys.get(p.keyId).exists(_ != p.groupKeyHex)).map(_.keyId).toList.sorted,
      lost = recordedKeys.keySet.filterNot(k => pins.contains(k) || isRetired(k)),
    )
  }
}
