// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli

import com.stakecraft.rutli.util.DirSync
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.nio.file.Files

class DirSyncSpec extends AnyWordSpec with Matchers {

  "DirSync" should {

    "fsync an existing directory" in {
      DirSync.fsync(Files.createTempDirectory("rutli-dirsync"))
    }

    "propagate the failure on a POSIX filesystem (RUTLI-06)" in {
      val missing = Files.createTempDirectory("rutli-dirsync").resolve("does-not-exist")
      an[java.io.IOException] should be thrownBy DirSync.fsync(missing, posix = true)
    }

    "swallow it only where the platform cannot fsync a directory at all (non-POSIX)" in {
      val missing = Files.createTempDirectory("rutli-dirsync").resolve("does-not-exist")
      DirSync.fsync(missing, posix = false) // logged at WARN, not thrown
    }
  }
}
