// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli.audit

import java.io.{File, FileOutputStream}
import java.nio.charset.StandardCharsets.UTF_8
import java.security.MessageDigest
import java.time.Instant
import scala.io.Source
import scala.util.Using

/** Tamper-evident, hash-chained audit log (Phase 3).
  *
  * Every key operation appends one JSON line: `{seq, ts, op, detail, prev, hash}` where
  * `hash = SHA-256(prev ‖ seq ‖ ts ‖ op ‖ detail)` and `prev` is the previous entry's hash
  * (genesis uses 64 zero hex chars). Any edit, reorder, or deletion of a line breaks every hash
  * after it, so an auditor can verify integrity offline with [[HashChainedAuditLog.verify]] — no
  * trust in the operator's log pipeline required.
  *
  * Durability: each entry is written and fsynced before the operation's result is returned to the
  * caller, and the chain head is recovered from the file on restart, so the chain continues
  * seamlessly across process restarts. Signing is low-frequency (topology changes), so the fsync
  * cost is irrelevant.
  *
  * This is an integrity log, not a confidentiality mechanism: entries contain operation metadata
  * (op, keyId, sizes, outcome) — never key material, message bytes, or signatures.
  */
final class HashChainedAuditLog private (file: File, private var lastHash: String, private var seq: Long)
    extends AuditSink {

  import HashChainedAuditLog._

  private val out = new FileOutputStream(file, /*append=*/ true)

  /** Append one entry; returns after the line is fsynced. Thread-safe. */
  override def append(op: String, detail: String): Unit = synchronized {
    val ts = Instant.now().toString
    val nextSeq = seq + 1
    val hash = entryHash(lastHash, nextSeq, ts, op, detail)
    val line = render(nextSeq, ts, op, detail, lastHash, hash)
    out.write((line + "\n").getBytes(UTF_8))
    out.flush()
    out.getFD.sync()
    seq = nextSeq
    lastHash = hash
  }

  override def close(): Unit = synchronized(out.close())
}

object HashChainedAuditLog {

  val GenesisHash: String = "0" * 64

  /** Open (creating or resuming) the log at `path`. On resume the chain head is recovered from the
    * last line; a corrupt tail fails fast rather than silently forking the chain. */
  def open(path: String): HashChainedAuditLog = {
    val file = new File(path)
    Option(file.getParentFile).foreach(_.mkdirs())
    if (!file.exists() || file.length() == 0) new HashChainedAuditLog(file, GenesisHash, 0L)
    else {
      val last = Using.resource(Source.fromFile(file, "UTF-8"))(_.getLines().foldLeft("")((_, l) => l))
      val f = parse(last).getOrElse(
        throw new IllegalStateException(s"audit log $path has a corrupt final line; refusing to append")
      )
      new HashChainedAuditLog(file, f.hash, f.seq)
    }
  }

  /** Offline verification: recompute the whole chain. Returns the number of valid entries, or the
    * 1-based sequence number of the first broken entry as a Left. */
  def verify(path: String): Either[Long, Long] = {
    var prev = GenesisHash
    var count = 0L
    Using.resource(Source.fromFile(path, "UTF-8")) { src =>
      for (line <- src.getLines()) {
        parse(line) match {
          case Some(e)
              if e.prev == prev && e.seq == count + 1 &&
                entryHash(e.prev, e.seq, e.ts, e.op, e.detail) == e.hash =>
            prev = e.hash
            count += 1
          case _ => return Left(count + 1)
        }
      }
    }
    Right(count)
  }

  // -- wire format (flat JSON object, stable field order; strings JSON-escaped) --

  private final case class Entry(seq: Long, ts: String, op: String, detail: String, prev: String, hash: String)

  private def render(seq: Long, ts: String, op: String, detail: String, prev: String, hash: String): String =
    s"""{"seq":$seq,"ts":"${esc(ts)}","op":"${esc(op)}","detail":"${esc(detail)}","prev":"$prev","hash":"$hash"}"""

  private def parse(line: String): Option[Entry] = {
    // Minimal parser for exactly the format `render` writes (stable field order).
    val re = """\{"seq":(\d+),"ts":"(.*?)","op":"(.*?)","detail":"(.*)","prev":"([0-9a-f]{64})","hash":"([0-9a-f]{64})"\}""".r
    line match {
      case re(seq, ts, op, detail, prev, hash) =>
        Some(Entry(seq.toLong, unesc(ts), unesc(op), unesc(detail), prev, hash))
      case _ => None
    }
  }

  private def esc(s: String): String =
    s.flatMap {
      case '"'          => "\\\""
      case '\\'         => "\\\\"
      case '\n'         => "\\n"
      case '\r'         => "\\r"
      case '\t'         => "\\t"
      case c if c < ' ' => f"\\u${c.toInt}%04x"
      case c            => c.toString
    }

  private def unesc(s: String): String = {
    val b = new StringBuilder(s.length)
    var i = 0
    while (i < s.length) {
      val c = s.charAt(i)
      if (c == '\\' && i + 1 < s.length) {
        s.charAt(i + 1) match {
          case '"'  => b.append('"'); i += 2
          case '\\' => b.append('\\'); i += 2
          case 'n'  => b.append('\n'); i += 2
          case 'r'  => b.append('\r'); i += 2
          case 't'  => b.append('\t'); i += 2
          case 'u' if i + 5 < s.length =>
            b.append(Integer.parseInt(s.substring(i + 2, i + 6), 16).toChar); i += 6
          case other => b.append(other); i += 2
        }
      } else { b.append(c); i += 1 }
    }
    b.toString
  }

  private def entryHash(prev: String, seq: Long, ts: String, op: String, detail: String): String = {
    val md = MessageDigest.getInstance("SHA-256")
    md.update(prev.getBytes(UTF_8))
    md.update(seq.toString.getBytes(UTF_8))
    md.update(ts.getBytes(UTF_8))
    md.update(op.getBytes(UTF_8))
    md.update(detail.getBytes(UTF_8))
    md.digest().map("%02x".format(_)).mkString
  }
}
