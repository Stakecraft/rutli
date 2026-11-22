// Copyright 2026 StakeCraft LLC
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli.backend

import com.stakecraft.rutli.util.DirSync
import org.slf4j.Logger

import java.io.IOException
import java.nio.channels.FileChannel
import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{FileAlreadyExistsException, Files, Path, StandardOpenOption}
import java.security.MessageDigest
import scala.jdk.CollectionConverters._
import scala.util.Using

/** One pinned group key: the FROST key id, its 32-byte Ed25519 group key (lower-case hex), how it
  * was first established (`dkg`, `adopted` by a roster majority, or `operator` through
  * `frost.expected-group-keys`), which endpoints agreed, which dissented (`endpoint=hex`), and when.
  */
final case class GroupKeyPin(
    keyId: String,
    groupKeyHex: String,
    source: String,
    agreedBy: List[String],
    dissent: List[String],
    pinnedAt: String,
) {
  def groupKeyBytes: Array[Byte] = GroupKeyPinStore.unhex(groupKeyHex)
}

/** The driver's durable group-key pins (`frost.pin-dir`): one create-once file per key id,
  * `<keyId>.pin`, next to the signing journal on the participant's state volume. Beside them,
  * `<keyId>.dkg` lists the DKG ceremony ids this driver sent intents for ([[recordCeremony]]).
  *
  * A pin is written once and never replaced. The write is a temp file (fsynced), then a hard link
  * to the final name (link(2) refuses an existing name, so two writers cannot both win and nothing
  * is overwritten), then a directory fsync. Where a filesystem has no hard links the final name is
  * created with CREATE_NEW instead. A checksum line catches a damaged file: any file that does not
  * parse, whose checksum or key id is wrong, refuses the start, naming the file — never re-pinned
  * automatically. Tampering is caught by the audit log, which records every pin (`group-key-pin`).
  *
  * File format (UTF-8 lines):
  * {{{
  * rutli-group-key-pin v1
  * key-id=<id>
  * group-key=<64 hex>
  * source=dkg|adopted|operator
  * agreed-by=<endpoint>,...
  * dissent=<endpoint>=<64 hex>,...
  * pinned-at=<ISO-8601>
  * sha256=<SHA-256 hex of every line above, each with its newline>
  * }}}
  */
final class GroupKeyPinStore(val dir: Path, logger: Logger) {

  import GroupKeyPinStore._

  Files.createDirectories(dir)

  // Temp files a crash left behind: never a pin (the link is what publishes one).
  Using.resource(Files.list(dir)) { s =>
    s.iterator().asScala.filter(_.getFileName.toString.contains(TmpMarker)).toList
  }.foreach { p =>
    logger.warn(s"FROST: removing a leftover temp file in the pin store: $p")
    Files.deleteIfExists(p)
  }

  private val pins = new java.util.concurrent.ConcurrentHashMap[String, GroupKeyPin]()

  Using.resource(Files.list(dir)) { s =>
    s.iterator().asScala.filter(p => p.getFileName.toString.endsWith(Suffix) && Files.isRegularFile(p)).toList
  }.foreach { p =>
    val pin = read(p)
    pins.put(pin.keyId, pin)
  }

  /** Every pin on disk, by key id. */
  def all: Map[String, GroupKeyPin] = pins.asScala.toMap

  /** The DKG ceremony ids this driver sent intents for, per key id (`<keyId>.dkg`, one id per line,
    * appended and fsynced BEFORE the request goes out). A DKG reply for a key that already existed
    * is this driver's own when it names one of them, also after a restart between the request and
    * the reply. An id for a ceremony that never committed is harmless: no cosigner ever names it. */
  private val ceremonyIds = new java.util.concurrent.ConcurrentHashMap[String, java.util.Set[String]]()

  Using.resource(Files.list(dir)) { s =>
    s.iterator().asScala.filter(p => p.getFileName.toString.endsWith(CeremonySuffix) && Files.isRegularFile(p)).toList
  }.foreach { p =>
    val keyId = p.getFileName.toString.stripSuffix(CeremonySuffix)
    val text = new String(Files.readAllBytes(p), UTF_8)
    // A torn last line is a crash before its fsync: that request was never sent.
    val complete = if (text.endsWith("\n")) text else text.substring(0, text.lastIndexOf('\n') + 1)
    val ids = complete.split("\n").toList.filter(_.nonEmpty)
    val (good, bad) = ids.partition(_.matches(CeremonyIdPattern))
    if (bad.nonEmpty) logger.warn(s"FROST: ignoring ${bad.size} malformed line(s) in $p")
    val set = java.util.concurrent.ConcurrentHashMap.newKeySet[String]()
    good.foreach(set.add)
    ceremonyIds.put(keyId, set)
  }

  /** The DKG ceremony ids recorded for `keyId`. */
  def ceremonies(keyId: String): Set[String] = Option(ceremonyIds.get(keyId)).fold(Set.empty[String])(_.asScala.toSet)

  /** Record, durably, that this driver is about to send a DKG intent naming `ceremonyId` for
    * `keyId`. Returns once the line is fsynced (and, for a new file, the directory). Throws an
    * [[IOException]] when it cannot be made durable: the request must not be sent then. */
  def recordCeremony(keyId: String, ceremonyId: String): Unit = synchronized {
    checkKeyId(keyId)
    if (!ceremonyId.matches(CeremonyIdPattern)) throw new IllegalArgumentException(s"not a DKG ceremony id: $ceremonyId")
    val f = dir.resolve(keyId + CeremonySuffix)
    val created = !Files.exists(f)
    Using.resource(FileChannel.open(f, StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.APPEND)) { ch =>
      com.stakecraft.rutli.util.WriteFully(ch, java.nio.ByteBuffer.wrap((ceremonyId + "\n").getBytes(UTF_8)))
      ch.force(true)
    }
    if (created) DirSync.fsync(dir)
    ceremonyIds.computeIfAbsent(keyId, _ => java.util.concurrent.ConcurrentHashMap.newKeySet[String]()).add(ceremonyId)
    ()
  }

  def get(keyId: String): Option[GroupKeyPin] = Option(pins.get(keyId))

  /** Write `pin` once. Returns the stored pin: `pin` itself, or the one already on disk when it
    * holds the same group key. Throws [[Conflict]] when the file holds another group key, and an
    * [[IOException]] when the pin cannot be made durable (the caller must not use the key then). */
  def create(pin: GroupKeyPin): GroupKeyPin = synchronized {
    checkKeyId(pin.keyId)
    get(pin.keyId) match {
      case Some(existing) => same(existing, pin)
      case None =>
        val target = dir.resolve(pin.keyId + Suffix)
        val bytes = render(pin).getBytes(UTF_8)
        val tmp = dir.resolve(s"${pin.keyId}$TmpMarker${java.util.UUID.randomUUID()}")
        try {
          Using.resource(FileChannel.open(tmp, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) { ch =>
            com.stakecraft.rutli.util.WriteFully(ch, java.nio.ByteBuffer.wrap(bytes))
            ch.force(true)
          }
          val published =
            try { Files.createLink(target, tmp); true }
            catch {
              case _: FileAlreadyExistsException => false
              case _: UnsupportedOperationException | _: java.nio.file.FileSystemException =>
                // No hard links on this filesystem: create the final name exclusively instead.
                try {
                  Using.resource(FileChannel.open(target, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) { ch =>
                    com.stakecraft.rutli.util.WriteFully(ch, java.nio.ByteBuffer.wrap(bytes))
                    ch.force(true)
                  }
                  true
                } catch { case _: FileAlreadyExistsException => false }
            }
          DirSync.fsync(dir)
          if (published) {
            pins.put(pin.keyId, pin)
            pin
          } else {
            val existing = read(target)
            pins.put(existing.keyId, existing)
            same(existing, pin)
          }
        } finally {
          Files.deleteIfExists(tmp)
          ()
        }
    }
  }

  private def same(existing: GroupKeyPin, pin: GroupKeyPin): GroupKeyPin =
    if (existing.groupKeyHex == pin.groupKeyHex) existing
    else
      throw new Conflict(
        s"the pin store already holds group key ${existing.groupKeyHex} for ${pin.keyId} " +
          s"(${dir.resolve(pin.keyId + Suffix)}, ${existing.source}, ${existing.pinnedAt}); refusing ${pin.groupKeyHex}. " +
          "A pin is never replaced: if the key was destroyed on purpose, move the file to retired/ first " +
          "(docs/disaster-recovery.md)"
      )

  private def read(p: Path): GroupKeyPin = readFile(p)
}

object GroupKeyPinStore {

  /** The pin store already holds another group key for the key id. */
  final class Conflict(msg: String) extends Exception(msg)

  val Header = "rutli-group-key-pin v1"
  val Suffix = ".pin"
  private val TmpMarker = ".pin.tmp."
  val Sources: Set[String] = Set("dkg", "adopted", "operator")
  val CeremonySuffix = ".dkg"
  private val CeremonyIdPattern = "dkg-[0-9a-f]{32}"

  /** Read and check one pin file; throws [[IllegalStateException]] naming the file when it is damaged. */
  def readFile(p: Path): GroupKeyPin = {
    def bad(why: String): Nothing =
      throw new IllegalStateException(
        s"group-key pin file $p is damaged ($why). The driver refuses to start rather than pin again: " +
          "restore the file from a backup of the participant's state volume, or move it away after checking the " +
          "key with the ceremony record and set frost.expected-group-keys (docs/production-profile.md)"
      )
    val text = new String(Files.readAllBytes(p), UTF_8)
    val lines = text.split("\n", -1).toList
    if (!text.endsWith("\n")) bad("no final newline: a torn write")
    val body = lines.dropRight(1) // the empty string after the final newline
    if (body.headOption.contains(Header) == false) bad("unknown header")
    val sumLine = body.lastOption.getOrElse(bad("empty"))
    val content = body.dropRight(1)
    if (!sumLine.startsWith("sha256=")) bad("no checksum line")
    if (sumLine.stripPrefix("sha256=") != sha256Hex(content.map(_ + "\n").mkString)) bad("checksum mismatch")
    val kv = content.drop(1).map { l =>
      val i = l.indexOf('=')
      if (i <= 0) bad(s"malformed line '$l'")
      l.substring(0, i) -> l.substring(i + 1)
    }.toMap
    def field(k: String): String = kv.getOrElse(k, bad(s"no $k"))
    def list(k: String): List[String] = field(k).split(",").toList.filter(_.nonEmpty)
    val pin = GroupKeyPin(field("key-id"), field("group-key"), field("source"), list("agreed-by"), list("dissent"), field("pinned-at"))
    if (p.getFileName.toString != pin.keyId + Suffix) bad(s"it names key ${pin.keyId}")
    if (!pin.groupKeyHex.matches("[0-9a-f]{64}")) bad("the group key is not 64 lower-case hex characters")
    if (!Sources.contains(pin.source)) bad(s"unknown source ${pin.source}")
    pin
  }

  /** Read-only check of a pin directory, for `tools.StateCheck`: every pin, or why the driver would
    * refuse to start. Never writes (leftover temp files are reported, not removed). */
  def preflight(dir: Path): Either[String, (List[GroupKeyPin], Int)] =
    if (!Files.isDirectory(dir)) Right((Nil, 0))
    else
      try {
        val files = Using.resource(Files.list(dir))(_.iterator().asScala.toList)
        val pins = files.filter(p => p.getFileName.toString.endsWith(Suffix) && Files.isRegularFile(p)).map(readFile)
        Right((pins.sortBy(_.keyId), files.count(_.getFileName.toString.contains(TmpMarker))))
      } catch { case e: IllegalStateException => Left(e.getMessage) }

  private def checkKeyId(keyId: String): Unit =
    if (!keyId.matches("[A-Za-z0-9_-]+"))
      throw new IllegalArgumentException(s"key id '$keyId' cannot name a pin file ([A-Za-z0-9_-] only)")

  private[rutli] def render(pin: GroupKeyPin): String = {
    val content = List(
      Header,
      s"key-id=${pin.keyId}",
      s"group-key=${pin.groupKeyHex}",
      s"source=${pin.source}",
      s"agreed-by=${pin.agreedBy.mkString(",")}",
      s"dissent=${pin.dissent.mkString(",")}",
      s"pinned-at=${pin.pinnedAt}",
    ).map(_ + "\n").mkString
    content + s"sha256=${sha256Hex(content)}\n"
  }

  private def sha256Hex(s: String): String =
    MessageDigest.getInstance("SHA-256").digest(s.getBytes(UTF_8)).map("%02x".format(_)).mkString

  private[backend] def unhex(h: String): Array[Byte] = h.grouped(2).map(Integer.parseInt(_, 16).toByte).toArray
}
