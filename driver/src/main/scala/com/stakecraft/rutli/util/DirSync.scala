// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli.util

import org.slf4j.LoggerFactory

import java.nio.channels.FileChannel
import java.nio.file.{FileSystems, Path, StandardOpenOption}
import scala.util.Using

/** Directory fsync: makes a create, rename or delete inside `dir` durable, not just the file's own
  * bytes. Without it a crash can lose a freshly created file even though its contents were fsynced.
  *
  * On a POSIX filesystem every failure propagates — a caller that cannot make its entry durable
  * must not report success (RUTLI-06). The single exception is a platform that genuinely cannot
  * open a directory for fsync (a non-POSIX default filesystem, e.g. Windows): there the failure is
  * logged at WARN and swallowed, because nothing better exists.
  */
object DirSync {

  private val logger = LoggerFactory.getLogger(getClass)

  private val posix: Boolean = FileSystems.getDefault.supportedFileAttributeViews.contains("posix")

  def fsync(dir: Path): Unit = fsync(dir, posix)

  /** `posix` is injectable so the non-POSIX exception path can be tested on any host. */
  private[rutli] def fsync(dir: Path, posix: Boolean): Unit =
    try Using.resource(FileChannel.open(dir, StandardOpenOption.READ))(_.force(true))
    catch {
      case e: Exception if !posix =>
        logger.warn(s"cannot fsync directory $dir on a non-POSIX filesystem (${e.getMessage}); continuing without it")
    }
}
