// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli.tools

import com.stakecraft.rutli.{ProductionProfile, RutliConfig, RutliDriverFactory}
import pureconfig.ConfigSource

import java.io.File

/** Offline check of a driver config against the production profile (docs/production-profile.md),
  * without starting a participant. It parses the block with the driver's own reader (unknown keys
  * are errors) and lists every enforcement setting that is not at its production value, under any
  * `profile`. It reads only the config file.
  *
  * {{{
  *   java -cp rutli-driver.jar com.stakecraft.rutli.tools.ConfigCheck \
  *     --config participant.conf --at canton.participants.participant1.crypto.kms.config
  * }}}
  *
  * Without `--at` the file is the driver block itself. Exit 0: no required finding (advisory ones
  * may be listed). Exit 1: required findings (a `production` driver would refuse to start). Exit 2:
  * usage, or the config does not load.
  */
object ConfigCheck {

  def main(args: Array[String]): Unit = sys.exit(run(args, println, Console.err.println))

  /** The CLI without `sys.exit`, for tests. */
  def run(args: Array[String], out: String => Unit, err: String => Unit): Int = {
    val opts = args.toList.grouped(2).collect { case List(k, v) if k.startsWith("--") => k -> v }.toMap
    val file = opts.get("--config")
    if (file.isEmpty || opts.size * 2 != args.length || !opts.keySet.subsetOf(Set("--config", "--at"))) {
      err("usage: ConfigCheck --config FILE [--at PATH.TO.crypto.kms.config]")
      return 2
    }
    val f = new File(file.get)
    if (!f.isFile) {
      err(s"ConfigCheck: cannot read ${f.getPath}")
      return 2
    }
    implicit val reader: pureconfig.ConfigReader[RutliConfig] = new RutliDriverFactory().configReader
    val source: ConfigSource = opts.get("--at") match {
      case Some(at) => ConfigSource.file(f).at(at)
      case None     => ConfigSource.file(f)
    }
    source.load[RutliConfig] match {
      case Left(failures) =>
        err(s"ConfigCheck: ${f.getPath} does not load: ${failures.prettyPrint()}")
        2
      case Right(cfg) =>
        // A value the driver itself would refuse at startup (an unknown profile, sign-intents
        // "maybe", a key-prefix outside its alphabet) is a config that does not load: exit 2.
        val checked: Either[String, (Option[String], List[ProductionProfile.Finding])] =
          try Right((ProductionProfile.of(cfg), ProductionProfile.findings(cfg)))
          catch { case e: IllegalArgumentException => Left(e.getMessage) }
        checked match {
          case Left(msg) =>
            err(s"ConfigCheck: ${f.getPath}: $msg")
            2
          case Right((profile, findings)) => report(f, profile, findings, out)
        }
    }
  }

  private def report(f: File, profile: Option[String], findings: List[ProductionProfile.Finding], out: String => Unit): Int = {
    val required = findings.count(_.level == ProductionProfile.Required)
    out(
      s"${f.getPath}: profile ${profile.getOrElse("unset (lab until 0.6)")}, $required required and " +
        s"${findings.size - required} advisory finding(s) (${ProductionProfile.Doc})"
    )
    findings.foreach(fd => out(fd.toString))
    if (required == 0) out("meets the production profile")
    if (required == 0) 0 else 1
  }
}
