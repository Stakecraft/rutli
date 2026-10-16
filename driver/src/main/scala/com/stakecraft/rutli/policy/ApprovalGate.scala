// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli.policy

import org.slf4j.Logger

import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, Path, Paths}
import java.security.{MessageDigest, SecureRandom, Signature}
import java.util.Base64
import scala.concurrent.duration._
import scala.concurrent.{ExecutionContext, Future}
import scala.jdk.CollectionConverters._
import scala.util.Try

/** Decides whether a signing operation may proceed. */
trait ApprovalGate {

  /** Await authorization to sign `data` with `keyId`. The returned Future completes when the
    * operation is approved, and fails (non-fatally) when it is denied or times out. */
  def authorize(keyId: String, data: Array[Byte]): Future[Unit]

  def close(): Unit = ()
}

/** No gating — every operation proceeds immediately. The default. */
object AutoApproveGate extends ApprovalGate {
  override def authorize(keyId: String, data: Array[Byte]): Future[Unit] = Future.unit
}

/** M-of-N approval gate over a file inbox.
  *
  * For a gated key, [[authorize]] writes a pending request to `<inbox>/pending/<requestId>.json`
  * and polls `<inbox>/approvals/` until `threshold` distinct configured approvers have each dropped
  * a valid Ed25519 signature over the request id, or the policy timeout elapses. A random per-
  * request nonce makes the request id unique, so an approval can never be replayed onto a different
  * signing request.
  *
  * The gate verifies every approval signature against the configured approver public keys and
  * counts each approver at most once — so separation of duties is cryptographic, not advisory.
  * Approvers act with the `rutli-approve` CLI (see [[ApproveCli]]).
  */
final class FileApprovalGate(policy: ApprovalPolicy, logger: Logger)(implicit ec: ExecutionContext)
    extends ApprovalGate {

  import FileApprovalGate._

  private val pendingDir = Paths.get(policy.inboxDir, "pending")
  private val approvalsDir = Paths.get(policy.inboxDir, "approvals")
  Files.createDirectories(pendingDir)
  Files.createDirectories(approvalsDir)
  policy.carriedProtocolKeyWarnings.foreach(w => logger.warn(w))

  override def authorize(keyId: String, data: Array[Byte]): Future[Unit] =
    policy.thresholdFor(keyId) match {
      case None            => Future.unit // auto-approved
      case Some(threshold) => awaitQuorum(keyId, data, threshold)
    }

  private def awaitQuorum(keyId: String, data: Array[Byte], threshold: Int): Future[Unit] =
    Future {
      val opDigest = sha256(data)
      val nonce = randomBytes(16)
      val requestId = requestIdFor(keyId, opDigest, nonce)
      writePending(requestId, keyId, opDigest, nonce)
      logger.info(
        s"APPROVAL required: key=$keyId request=$requestId threshold=$threshold — awaiting approvers"
      )

      val deadline = System.nanoTime() + policy.timeout.toNanos
      var approvals = Set.empty[String]
      while (approvals.size < threshold && System.nanoTime() < deadline) {
        approvals = countApprovals(requestId)
        if (approvals.size < threshold) Thread.sleep(policy.pollInterval.toMillis)
      }

      if (approvals.size >= threshold) {
        logger.info(s"APPROVAL granted: request=$requestId by ${approvals.toList.sorted.mkString(",")}")
        cleanup(requestId)
      } else {
        cleanup(requestId)
        throw new SecurityException(
          s"signing denied: request $requestId for key $keyId did not reach $threshold approvals " +
            s"within ${policy.timeout} (got ${approvals.size})"
        )
      }
    }

  /** Distinct approver ids with a valid signature over `requestId`. */
  private def countApprovals(requestId: String): Set[String] = {
    val requestIdBytes = requestId.getBytes(UTF_8)
    listFiles(approvalsDir, s"$requestId.").flatMap { f =>
      Try {
        val a = parseApproval(Files.readString(f))
        for {
          approver <- policy.approverById(a.approverId)
          if a.requestId == requestId
          if verifyEd25519(approver.publicKey, requestIdBytes, Base64.getDecoder.decode(a.signatureB64))
        } yield approver.id
      }.toOption.flatten
    }.toSet
  }

  private def writePending(requestId: String, keyId: String, opDigest: Array[Byte], nonce: Array[Byte]): Unit = {
    val json =
      s"""{"requestId":"$requestId","keyId":"${esc(keyId)}","digest":"${hex(opDigest)}","nonce":"${hex(nonce)}","ts":"${java.time.Instant.now()}"}"""
    val tmp = pendingDir.resolve(s"$requestId.json.tmp")
    Files.write(tmp, json.getBytes(UTF_8))
    Files.move(tmp, pendingDir.resolve(s"$requestId.json"))
  }

  private def cleanup(requestId: String): Unit = {
    Try(Files.deleteIfExists(pendingDir.resolve(s"$requestId.json")))
    listFiles(approvalsDir, s"$requestId.").foreach(f => Try(Files.deleteIfExists(f)))
  }
}

object FileApprovalGate {

  private val rng = new SecureRandom()

  final case class Approval(approverId: String, requestId: String, signatureB64: String)

  def sha256(bytes: Array[Byte]): Array[Byte] = MessageDigest.getInstance("SHA-256").digest(bytes)

  def hex(bytes: Array[Byte]): String = bytes.map("%02x".format(_)).mkString

  /** What an approver signs: `hex(SHA-256(keyId ‖ opDigest ‖ nonce))`. One definition, shared by
    * the gate and the approver CLI, so the CLI can recompute it from the fields it displays. */
  def requestIdFor(keyId: String, opDigest: Array[Byte], nonce: Array[Byte]): String =
    hex(sha256(concat(keyId.getBytes(UTF_8), opDigest, nonce)))

  def verifyEd25519(pub: java.security.PublicKey, msg: Array[Byte], sig: Array[Byte]): Boolean =
    Try {
      val v = Signature.getInstance("Ed25519")
      v.initVerify(pub); v.update(msg); v.verify(sig)
    }.getOrElse(false)

  private def randomBytes(n: Int): Array[Byte] = { val b = new Array[Byte](n); rng.nextBytes(b); b }

  private def concat(parts: Array[Byte]*): Array[Byte] = parts.reduce(_ ++ _)

  private def listFiles(dir: Path, prefix: String): Vector[Path] =
    if (!Files.isDirectory(dir)) Vector.empty
    else
      Using(Files.list(dir))(_.iterator().asScala.filter(_.getFileName.toString.startsWith(prefix)).toVector)
        .getOrElse(Vector.empty)

  // Minimal parser for the flat approval JSON `rutli-approve` writes.
  private def parseApproval(s: String): Approval = {
    def field(name: String): String =
      s"""\"$name\":\"(.*?)\"""".r.findFirstMatchIn(s).map(_.group(1)).getOrElse("")
    Approval(field("approverId"), field("requestId"), field("signature"))
  }

  private def esc(s: String): String = s.replace("\\", "\\\\").replace("\"", "\\\"")

  private def Using[R <: AutoCloseable, A](r: R)(f: R => A): Try[A] =
    try { val a = f(r); r.close(); scala.util.Success(a) }
    catch { case t: Throwable => Try(r.close()); scala.util.Failure(t) }
}
