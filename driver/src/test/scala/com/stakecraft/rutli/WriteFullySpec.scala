// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli

import com.stakecraft.rutli.util.WriteFully
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.channels.WritableByteChannel
import java.nio.charset.StandardCharsets.UTF_8

class WriteFullySpec extends AnyWordSpec with Matchers {

  /** Accepts at most `perCall` bytes per write, like a channel that returns short writes. */
  private class ShortChannel(perCall: Int) extends WritableByteChannel {
    val out = new ByteArrayOutputStream()
    var calls = 0
    def write(src: ByteBuffer): Int = {
      calls += 1
      val n = math.min(perCall, src.remaining)
      val b = new Array[Byte](n)
      src.get(b)
      out.write(b)
      n
    }
    def isOpen: Boolean = true
    def close(): Unit = ()
  }

  "WriteFully" should {

    "drain the whole buffer across short writes (a journal line is never left torn)" in {
      val line = """{"seq":1,"digest":"ab"}""" + "\n"
      val ch = new ShortChannel(perCall = 3)
      WriteFully(ch, ByteBuffer.wrap(line.getBytes(UTF_8)))
      new String(ch.out.toByteArray, UTF_8) shouldBe line
      ch.calls should be > 1
    }

    "refuse a channel that makes no progress instead of spinning or returning early" in {
      an[java.io.IOException] should be thrownBy WriteFully(new ShortChannel(perCall = 0), ByteBuffer.wrap(Array[Byte](1, 2)))
    }
  }
}
