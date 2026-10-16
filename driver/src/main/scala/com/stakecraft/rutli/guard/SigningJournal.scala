// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli.guard

import com.stakecraft.rutli.util.DirSync
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
final class SigningJournal(
    dir: String,
    maxPerWindow: Option[Int],
    windowSeconds: Long,
    logger: Logger,
    // Monotonic clock (nanos) for the in-process rate-limit window; injectable for tests. The
    // wall clock only stamps the journal lines, so an NTP step can never stretch or collapse the
    // window of a running process.
    nanoClock: () => Long = () => System.nanoTime(),
) {

  import SigningJournal._

  private val root: Path = Paths.get(dir)
  Files.createDirectories(root)

  // key -> set of signed digest hashes (hex); key -> recent sign times (monotonic nanos, oldest
  // first); key -> the lock that makes check-and-append atomic per key.
  private val seen = new ConcurrentHashMap[String, java.util.Set[String]]()
  private val recent = new ConcurrentHashMap[String, java.util.ArrayDeque[java.lang.Long]]()
  private val locks = new ConcurrentHashMap[String, Object]()

  private def lockFor(keyId: String): Object = locks.computeIfAbsent(keyId, _ => new Object)

  /** Record an intent to sign `data` with `keyId`. Returns after the journal entry is durable.
    * Throws [[SecurityException]] if a configured rate limit is exceeded (a hard stop); a repeat of
    * an already-signed digest is WARNED and counted, never blocked. The limit check and the append
    * are one atomic step per key, so concurrent signs cannot overshoot the limit. `nowMillis` (the
    * journal line's timestamp) is injectable for tests. */
  def record(keyId: String, data: Array[Byte], nowMillis: Long = System.currentTimeMillis()): Unit = {
    val digestHex = hex(sha256(data))
    val isRepeat = lockFor(keyId).synchronized {
      val digests = seen.computeIfAbsent(keyId, _ => java.util.concurrent.ConcurrentHashMap.newKeySet[String]())
      val repeat = digests.contains(digestHex)

      // The slot is taken before the append and kept if the append fails: a failed attempt still
      // counts against the limit (conservative), and the signature is not released either way.
      rateLimit(keyId)

      val entry =
        s"""{"ts":"${Instant.ofEpochMilli(nowMillis)}","keyId":"${esc(keyId)}","digest":"$digestHex","repeat":$repeat}"""
      appendDurable(journalFile(keyId), entry)
      digests.add(digestHex)
      repeat
    }

    if (isRepeat)
      logger.warn(
        s"REPEAT-SIGN: key=$keyId digest=${digestHex.take(16)}… signed again — benign at bootstrap, " +
          "but a repeat digest for a topology key can indicate equivocation; review the journal."
      )
  }

  /** How many distinct digests have been signed for `keyId` (for tests/inspection). */
  def distinctCount(keyId: String): Int = Option(seen.get(keyId)).map(_.size).getOrElse(0)

  /** Caller holds the key's lock. */
  private def rateLimit(keyId: String): Unit = maxPerWindow.foreach { max =>
    val windowNanos = windowSeconds * 1000000000L
    val now = nanoClock()
    val stamps = recent.computeIfAbsent(keyId, _ => new java.util.ArrayDeque[java.lang.Long]())
    // Differences, not comparisons: System.nanoTime is only meaningful relative to another reading.
    while (!stamps.isEmpty && now - stamps.peekFirst() > windowNanos) stamps.pollFirst()
    if (stamps.size >= max)
      throw new SecurityException(
        s"signing rate limit exceeded for key $keyId: $max signatures per ${windowSeconds}s"
      )
    stamps.addLast(now)
  }

  /** Rebuild in-memory state from the on-disk journals (call once at startup): the distinct-digest
    * sets AND the rate-limit window. The keyId is read from each line (not the filename), so it
    * round-trips exactly regardless of how the filename was sanitized. Rebuilding `recent` from the
    * persisted timestamps means the per-key rate limit survives a restart — otherwise a crash-loop
    * would reset the limiter every restart.
    *
    * Fails closed: a journal that cannot be read, or has a malformed line, throws — skipping it
    * would silently reset the limiter and forget what was signed. The one exception is a torn final
    * line (no trailing newline: a crash mid-append, whose fsync never returned, so the signature
    * was never released): it is truncated away with a warning, so the next append starts on a clean
    * line. A timestamp in the future of `nowMillis` (a clock that was stepped forward) is clamped
    * to now rather than trusted, so it cannot lock the key out beyond one window. */
  def recover(nowMillis: Long = System.currentTimeMillis()): Unit = {
    val windowMs = windowSeconds * 1000
    val nowNanos = nanoClock()
    val files = Using(Files.list(root))(_.iterator().asScala.filter(_.getFileName.toString.endsWith(".jsonl")).toVector)
    files.sortBy(_.getFileName.toString).foreach { f =>
      val lines = readJournal(f)
      val stampsByKey = scala.collection.mutable.Map.empty[String, scala.collection.mutable.ArrayBuffer[Long]]
      lines.zipWithIndex.foreach { case (line, i) =>
        val (keyId, digest, ts) = parseEntry(line).getOrElse(
          throw new IllegalStateException(
            s"signing journal $f line ${i + 1} is malformed; refusing to start (fail closed — the journal " +
              "is the record of what was signed and the rate-limit window)"
          )
        )
        seen.computeIfAbsent(keyId, _ => java.util.concurrent.ConcurrentHashMap.newKeySet[String]()).add(digest)
        if (ts > nowMillis + FutureSkewMillis)
          logger.warn(
            s"signing journal $f line ${i + 1}: timestamp ${Instant.ofEpochMilli(ts)} is in the future " +
              s"(clock stepped?); counting it as now"
          )
        // Reconstruct the rolling rate-limit window from entries still inside it.
        if (maxPerWindow.isDefined) {
          val ageMs = math.max(0L, nowMillis - ts) // clamp: never newer than now
          if (ageMs <= windowMs) stampsByKey.getOrElseUpdate(keyId, scala.collection.mutable.ArrayBuffer.empty) += ageMs
        }
      }
      stampsByKey.foreach { case (keyId, ages) =>
        lockFor(keyId).synchronized {
          val stamps = recent.computeIfAbsent(keyId, _ => new java.util.ArrayDeque[java.lang.Long]())
          // Oldest first (largest age first), as rateLimit expects.
          ages.sortBy(-_).foreach(a => stamps.addLast(nowNanos - a * 1000000L))
        }
      }
    }
  }

  /** The complete, newline-terminated lines of `f`. A torn final line is truncated away (WARN). */
  private def readJournal(f: Path): Vector[String] = {
    val bytes = Files.readAllBytes(f)
    val cut = bytes.lastIndexOf('\n'.toByte) + 1
    if (cut < bytes.length) {
      logger.warn(
        s"signing journal $f ends with a torn line (${bytes.length - cut} bytes, no trailing newline) — a " +
          "crash mid-append; its fsync never returned, so no signature was released. Truncating it."
      )
      val ch = java.nio.channels.FileChannel.open(f, java.nio.file.StandardOpenOption.WRITE)
      try { ch.truncate(cut.toLong); ch.force(true) } finally ch.close()
    }
    new String(bytes, 0, cut, UTF_8).split("\n", -1).dropRight(1).toVector
  }

  private def journalFile(keyId: String): Path = root.resolve(s"${encodeKeyFileName(keyId)}.jsonl")

  private def appendDurable(path: Path, line: String): Unit = {
    import java.nio.file.StandardOpenOption._
    val created = !Files.exists(path)
    val ch = java.nio.channels.FileChannel.open(path, CREATE, WRITE, APPEND)
    try {
      ch.write(java.nio.ByteBuffer.wrap((line + "\n").getBytes(UTF_8)))
      ch.force(true) // fsync before the caller may release the signature (write-ahead)
    } finally ch.close()
    // A newly created file is only durable once its directory entry is (RUTLI-05).
    if (created) DirSync.fsync(root)
  }
}

object SigningJournal {

  def sha256(b: Array[Byte]): Array[Byte] = MessageDigest.getInstance("SHA-256").digest(b)
  def hex(b: Array[Byte]): String = b.map("%02x".format(_)).mkString

  /** How far ahead of the wall clock a journal timestamp may be before recovery logs it as a stepped clock. */
  private val FutureSkewMillis = 60000L

  private val HexDigest = "[0-9a-f]{64}".r

  /** A journal line as `record` writes it: (keyId, digest, epoch millis), or None if malformed. */
  private def parseEntry(line: String): Option[(String, String, Long)] =
    for {
      keyId <- field(line, "keyId")
      digest <- field(line, "digest") if HexDigest.pattern.matcher(digest).matches()
      ts <- field(line, "ts").flatMap(parseTs)
    } yield (keyId, digest, ts)

  /** Parse an ISO-8601 instant (as written in each journal line) back to epoch millis. */
  private def parseTs(s: String): Option[Long] =
    try Some(Instant.parse(s).toEpochMilli)
    catch { case NonFatal(_) => None }

  private def esc(s: String): String = s.replace("\\", "\\\\").replace("\"", "\\\"")

  // key ids can contain path-unfriendly chars; hash to a stable filename, keep a readable prefix.
  private def encodeKeyFileName(keyId: String): String = {
    val safe = keyId.replaceAll("[^A-Za-z0-9_.-]", "_").take(64)
    s"$safe.${hex(sha256(keyId.getBytes(UTF_8))).take(16)}"
  }

  private def field(line: String, name: String): Option[String] =
    raw""""$name":"((?:[^"\\]|\\.)*)"""".r.findFirstMatchIn(line).map(m => unesc(m.group(1)))

  // Inverse of `esc`: a backslash escapes the next character.
  private def unesc(s: String): String =
    """\\(.)""".r.replaceAllIn(s, m => scala.util.matching.Regex.quoteReplacement(m.group(1)))

  private def Using[R <: AutoCloseable, A](r: R)(f: R => A): A =
    try f(r) finally r.close()
}
