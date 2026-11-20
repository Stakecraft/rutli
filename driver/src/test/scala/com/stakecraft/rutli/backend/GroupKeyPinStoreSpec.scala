// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli.backend

import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import org.slf4j.LoggerFactory

import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, Path}
import java.util.concurrent.{CountDownLatch, Executors, TimeUnit}
import scala.concurrent.duration._
import scala.concurrent.{Await, ExecutionContext, Future}

/** The durable group-key pin store: create-once, never replaced, a damaged file refuses the start. */
class GroupKeyPinStoreSpec extends AnyWordSpec with Matchers {

  private val logger = LoggerFactory.getLogger(classOf[GroupKeyPinStoreSpec])
  private def dir(): Path = Files.createTempDirectory("rutli-pin-store")
  private def pin(keyId: String, key: String, source: String = "dkg"): GroupKeyPin =
    GroupKeyPin(keyId, key, source, List("c1:9101", "c2:9101"), Nil, "2026-11-20T12:00:00Z")
  private val K1 = "11" * 32
  private val K2 = "22" * 32

  "the pin store" should {

    "write a pin once, read it back after a restart, and accept the same key again" in {
      val d = dir()
      val s = new GroupKeyPinStore(d, logger)
      s.create(pin("frost-namespace", K1)) shouldBe pin("frost-namespace", K1)
      new String(Files.readAllBytes(d.resolve("frost-namespace.pin")), UTF_8) should startWith(GroupKeyPinStore.Header)
      val again = new GroupKeyPinStore(d, logger)
      again.get("frost-namespace") shouldBe Some(pin("frost-namespace", K1))
      again.create(pin("frost-namespace", K1, "adopted")).source shouldBe "dkg" // the stored one stands
    }

    "never replace a pin with another key" in {
      val d = dir()
      new GroupKeyPinStore(d, logger).create(pin("frost-namespace", K1))
      val e = the[GroupKeyPinStore.Conflict] thrownBy new GroupKeyPinStore(d, logger).create(pin("frost-namespace", K2))
      e.getMessage should (include(K1) and include(K2) and include("retired/"))
      new GroupKeyPinStore(d, logger).get("frost-namespace").map(_.groupKeyHex) shouldBe Some(K1)
    }

    "let exactly one of two concurrent writers win" in {
      val d = dir()
      val s = new GroupKeyPinStore(d, logger)
      val pool = Executors.newFixedThreadPool(2)
      implicit val ec: ExecutionContext = ExecutionContext.fromExecutor(pool)
      val go = new CountDownLatch(1)
      val results = Seq(K1, K2).map(k => Future { go.await(5, TimeUnit.SECONDS); scala.util.Try(s.create(pin("frost-namespace", k))) })
      go.countDown()
      val done = results.map(f => Await.result(f, 10.seconds))
      pool.shutdown()
      done.count(_.isSuccess) shouldBe 1
      done.count(_.failed.toOption.exists(_.isInstanceOf[GroupKeyPinStore.Conflict])) shouldBe 1
    }

    "refuse to start on a damaged pin file, naming it" in {
      val cases: Seq[(String, String => String)] = Seq(
        "checksum" -> (_.replace(K1, K2)),
        "torn" -> (t => t.dropRight(5)),
        "header" -> (t => t.replace(GroupKeyPinStore.Header, "something else")),
      )
      cases.foreach { case (what, damage) =>
        val d = dir()
        new GroupKeyPinStore(d, logger).create(pin("frost-namespace", K1))
        val f = d.resolve("frost-namespace.pin")
        Files.write(f, damage(new String(Files.readAllBytes(f), UTF_8)).getBytes(UTF_8))
        withClue(what) {
          val e = the[IllegalStateException] thrownBy new GroupKeyPinStore(d, logger)
          e.getMessage should include(f.toString)
        }
      }
    }

    "refuse a pin file whose content names another key" in {
      val d = dir()
      new GroupKeyPinStore(d, logger).create(pin("frost-namespace", K1))
      Files.move(d.resolve("frost-namespace.pin"), d.resolve("frost-signing.pin"))
      the[IllegalStateException] thrownBy new GroupKeyPinStore(d, logger)
    }

    "remove temp files a crash left behind, and ignore files that are not pins" in {
      val d = dir()
      Files.write(d.resolve("frost-namespace.pin.tmp.123"), "half".getBytes(UTF_8))
      Files.write(d.resolve("README"), "x".getBytes(UTF_8))
      new GroupKeyPinStore(d, logger).all shouldBe Map.empty
      Files.exists(d.resolve("frost-namespace.pin.tmp.123")) shouldBe false
    }

    "refuse a key id that cannot name a file" in {
      an[IllegalArgumentException] should be thrownBy new GroupKeyPinStore(dir(), logger).create(pin("../x", K1))
    }
  }
}
