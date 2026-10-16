// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli.util

import java.io.IOException
import java.nio.ByteBuffer
import java.nio.channels.WritableByteChannel

/** `WritableByteChannel.write` may consume only part of the buffer and still return normally. A
  * write-ahead record that is fsynced after a short write is a torn line, which recovery then drops
  * — erasing the record of an operation that was released. Loop until the buffer is drained.
  */
object WriteFully {

  def apply(ch: WritableByteChannel, buf: ByteBuffer): Unit =
    while (buf.hasRemaining)
      if (ch.write(buf) == 0 && buf.hasRemaining)
        throw new IOException(s"channel accepted 0 of ${buf.remaining} bytes; refusing to spin")
}
