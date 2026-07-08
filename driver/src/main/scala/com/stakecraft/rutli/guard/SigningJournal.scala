// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli.guard

import org.slf4j.Logger

import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, Path, Paths}
import java.security.MessageDigest
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap
import scala.jdk.CollectionConverters._
import scala.util.control.NonFatal

/** Persistent per-key signing journal — the honest replay/equivocation control at the KMS layer.
  *
  * WHAT THIS CAN DO. Canton hands the driver an opaque 34-byte digest with no height, round, or
  * epoch (see docs/wire-contract.md), so the driver CANNOT tell a legitimate re-sign from a
  * conflicting one, and must NOT refuse a repeat — that would brick a node that legitimately signs
  * the same topology digest twice. What it can do safely:
  *
  *   - record every (key, digest) the driver signs, persistently and crash-safely, so there is a
  *     complete, queryable history for forensics and equivocation *detection*;
  *   - surface a WARNING when a digest is signed more than once for a key (a re-sign — usually
  *     benign at bootstrap, but worth flagging), and count it;
  *   - optionally enforce a per-key rate limit (max signatures per rolling window) to blunt a
  *     runaway or compromised caller, failing over the limit rather than silently signing forever.
  *
  * WHAT THIS DOES NOT DO. It is not semantic double-sign protection à la a validator slashing-DB
  * (which needs the height/round that Canton does not expose here). Do not market it as such.
  *
  * Storage: one append-only JSONL file per key under `dir`, fsynced before the signature is
  * released (write-ahead, like the audit log). Distinct signed digests per key are cached in memory
  * for O(1) repeat detection and rebuilt from the journal on restart.
  */
final class SigningJournal(dir: String, maxPerWindow: Option[Int], windowSeconds: Long, logger: Logger) {

  import SigningJournal._

  private val root: Path = Paths.get(dir)
  Files.createDirectories(root)

  // key -> set of signed digest hashes (hex); key -> recent sign timestamps (epoch millis).
  private val seen = new ConcurrentHashMap[String, java.util.Set[String]]()
  private val recent = new ConcurrentHashMap[String, java.util.List[java.lang.Long]]()

  /** Record an intent to sign `data` with `keyId`. Returns after the journal entry is durable.
    * Throws [[SecurityException]] if a configured rate limit is exceeded (a hard stop); a repeat of
    * an already-signed digest is WARNED and counted, never blocked. `nowMillis` is injectable for
    * tests. */
  def record(keyId: String, data: Array[Byte], nowMillis: Long = System.currentTimeMillis()): Unit = {
    val digestHex = hex(sha256(data))
    val digests = seen.computeIfAbsent(keyId, _ => java.util.concurrent.ConcurrentHashMap.newKeySet[String]())
    val isRepeat = digests.contains(digestHex)

    rateLimit(keyId, nowMillis)

    val entry =
      s"""{"ts":"${Instant.ofEpochMilli(nowMillis)}","keyId":"${esc(keyId)}","digest":"$digestHex","repeat":$isRepeat}"""
    appendDurable(journalFile(keyId), entry)
    digests.add(digestHex)

    if (isRepeat)
      logger.warn(
        s"REPEAT-SIGN: key=$keyId digest=${digestHex.take(16)}… signed again — benign at bootstrap, " +
          "but a repeat digest for a topology key can indicate equivocation; review the journal."
      )
  }

  /** How many distinct digests have been signed for `keyId` (for tests/inspection). */
  def distinctCount(keyId: String): Int = Option(seen.get(keyId)).map(_.size).getOrElse(0)

  private def rateLimit(keyId: String, nowMillis: Long): Unit = maxPerWindow.foreach { max =>
    val windowMs = windowSeconds * 1000
    val stamps = recent.computeIfAbsent(keyId, _ => new java.util.concurrent.CopyOnWriteArrayList[java.lang.Long]())
    stamps.removeIf((t: java.lang.Long) => t < nowMillis - windowMs)
    if (stamps.size >= max)
      throw new SecurityException(
        s"signing rate limit exceeded for key $keyId: $max signatures per ${windowSeconds}s"
      )
    stamps.add(nowMillis)
  }

  /** Rebuild the in-memory digest sets from the on-disk journals (call once at startup). The keyId
    * is read from each line (not the filename), so it round-trips exactly regardless of how the
    * filename was sanitized. */
  def recover(): Unit =
    if (Files.isDirectory(root))
      Using(Files.list(root)) { s =>
        s.iterator().asScala.filter(_.getFileName.toString.endsWith(".jsonl")).foreach { f =>
          try Files.readAllLines(f).asScala.foreach { line =>
            for { keyId <- field(line, "keyId"); digest <- field(line, "digest") }
              seen
                .computeIfAbsent(keyId, _ => java.util.concurrent.ConcurrentHashMap.newKeySet[String]())
                .add(digest)
          } catch { case NonFatal(e) => logger.error(s"journal recover failed for $f: ${e.getMessage}") }
        }
      }

  private def journalFile(keyId: String): Path = root.resolve(s"${encodeKeyFileName(keyId)}.jsonl")

  private def appendDurable(path: Path, line: String): Unit = {
    import java.nio.file.StandardOpenOption._
    val ch = java.nio.channels.FileChannel.open(path, CREATE, WRITE, APPEND)
    try {
      ch.write(java.nio.ByteBuffer.wrap((line + "\n").getBytes(UTF_8)))
      ch.force(true) // fsync before the caller may release the signature (write-ahead)
    } finally ch.close()
  }
}

object SigningJournal {

  def sha256(b: Array[Byte]): Array[Byte] = MessageDigest.getInstance("SHA-256").digest(b)
  def hex(b: Array[Byte]): String = b.map("%02x".format(_)).mkString

  private def esc(s: String): String = s.replace("\\", "\\\\").replace("\"", "\\\"")

  // key ids can contain path-unfriendly chars; hash to a stable filename, keep a readable prefix.
  private def encodeKeyFileName(keyId: String): String = {
    val safe = keyId.replaceAll("[^A-Za-z0-9_.-]", "_").take(64)
    s"$safe.${hex(sha256(keyId.getBytes(UTF_8))).take(16)}"
  }

  private def field(line: String, name: String): Option[String] =
    s"""\"$name\":\"(.*?)\"""".r.findFirstMatchIn(line).map(_.group(1))

  private def Using[R <: AutoCloseable, A](r: R)(f: R => A): A =
    try f(r) finally r.close()
}
