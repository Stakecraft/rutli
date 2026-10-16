// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli.tools

import com.stakecraft.rutli.audit.HashChainedAuditLog
import com.stakecraft.rutli.guard.SigningJournal

/** Offline, read-only preflight of a participant's driver state before a driver upgrade.
  *
  * Since 0.4.0-rc.2 the driver fails closed at startup on a malformed signing-journal line or a
  * broken audit-log chain (it used to skip them). Run this against the participant's state — ideally
  * a copy of it — first: it reports what the new driver will do with each file and never writes.
  *
  * {{{
  *   java -cp rutli-driver.jar com.stakecraft.rutli.tools.StateCheck \
  *     --audit-log /rutli-state/audit.jsonl --journal-dir /rutli-state/journal
  * }}}
  *
  * Exit 0: the new driver will start (a torn final line, from a crash mid-append, is reported and
  * will be truncated at startup — expected and safe). Exit 1: it will refuse to start; the message
  * names the file and line. Exit 2: usage.
  */
object StateCheck {

  def main(args: Array[String]): Unit = sys.exit(run(args, println, Console.err.println))

  /** The CLI without `sys.exit`, for tests. */
  def run(args: Array[String], out: String => Unit, err: String => Unit): Int = {
    val opts = args.toList.grouped(2).collect { case List(k, v) if k.startsWith("--") => k -> v }.toList
    val audits = opts.collect { case ("--audit-log", v) => v }
    val journals = opts.collect { case ("--journal-dir", v) => v }
    if (audits.isEmpty && journals.isEmpty || opts.length * 2 != args.length) {
      err("usage: StateCheck [--audit-log FILE]... [--journal-dir DIR]...")
      return 2
    }
    var ok = true
    audits.foreach { p =>
      HashChainedAuditLog.preflight(p) match {
        case Right((n, torn)) =>
          out(s"audit log $p: OK, $n entries, hash chain intact" + tornNote(torn))
        case Left(why) => ok = false; err(s"audit log FAILED: $why")
      }
    }
    journals.foreach { d =>
      SigningJournal.preflight(d) match {
        case Right(files) =>
          out(s"signing journal $d: OK, ${files.size} file(s), ${files.map(_._2).sum} entries")
          files.filter(_._3 > 0).foreach { case (f, _, torn) => out(s"  $f" + tornNote(torn)) }
        case Left(why) => ok = false; err(s"signing journal FAILED: $why")
      }
    }
    if (ok) 0 else 1
  }

  private def tornNote(bytes: Int): String =
    if (bytes == 0) ""
    else s"; a torn final line ($bytes bytes, crash mid-append) will be truncated at startup — expected"
}
