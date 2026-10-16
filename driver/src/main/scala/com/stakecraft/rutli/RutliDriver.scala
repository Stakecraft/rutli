// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli

import com.digitalasset.canton.crypto.kms.driver.api.v1._
import com.stakecraft.rutli.audit.{AuditNotes, AuditSink}
import com.stakecraft.rutli.backend.KmsBackend
import io.opentelemetry.context.Context
import org.slf4j.Logger

import scala.concurrent.{ExecutionContext, Future}
import scala.util.control.NonFatal
import scala.util.{Failure, Success}

/** Canton KMS Driver implementation.
  *
  * This is a thin policy/routing shell: it satisfies the Canton
  * [[com.digitalasset.canton.crypto.kms.driver.api.v1.KmsDriver]] SPI and delegates every key
  * operation to a [[com.stakecraft.rutli.backend.KmsBackend]]. It performs no cryptography of
  * its own and never holds private key material.
  *
  * Enforced here (not in the backend): M-of-N approval, the tamper-evident hash-chained audit log,
  * and the per-key signing journal (replay detection + rate limit). The OpenTelemetry trace context
  * is accepted per the SPI and can be propagated to those layers.
  *
  * With `auditLogging` enabled every operation is logged (op, keyId, algo, byte sizes, outcome;
  * for a sign also `msg=`, the SHA-256 of the signed bytes).
  * This is the plain-log precursor of the Phase 3 hash-chained audit log, and doubles as the
  * wire-contract capture tool (see docs/wire-contract.md).
  */
final class RutliDriver(
    backend: KmsBackend,
    logger: Logger,
    auditLogging: Boolean,
    auditLog: Option[AuditSink],
    approvalGate: com.stakecraft.rutli.policy.ApprovalGate,
    signingJournal: Option[com.stakecraft.rutli.guard.SigningJournal],
    // Passed as constructor params (not read from `backend`) so the trait's `require(...)` checks,
    // which run during construction, see initialized values regardless of field init order.
    override val supportedSigningKeySpecs: Set[SigningKeySpec],
    override val supportedSigningAlgoSpecs: Set[SigningAlgoSpec],
    override val supportedEncryptionKeySpecs: Set[EncryptionKeySpec],
    override val supportedEncryptionAlgoSpecs: Set[EncryptionAlgoSpec],
    blockingPool: Option[java.util.concurrent.ExecutorService] = None,
)(implicit ec: ExecutionContext)
    extends KmsDriver {

  override def health: Future[KmsDriverHealth] = backend.health

  override def generateSigningKeyPair(
      signingKeySpec: SigningKeySpec,
      keyName: Option[String],
  )(traceContext: Context): Future[String] =
    audited(s"generateSigningKeyPair spec=$signingKeySpec name=${keyName.getOrElse("-")}")(notes =>
      backend.withAuditNotes(notes)(backend.generateSigningKeyPair(signingKeySpec, keyName))
    )(keyId => s"keyId=$keyId")

  override def generateEncryptionKeyPair(
      encryptionKeySpec: EncryptionKeySpec,
      keyName: Option[String],
  )(traceContext: Context): Future[String] =
    audited(s"generateEncryptionKeyPair spec=$encryptionKeySpec name=${keyName.getOrElse("-")}")(notes =>
      backend.withAuditNotes(notes)(backend.generateEncryptionKeyPair(encryptionKeySpec, keyName))
    )(keyId => s"keyId=$keyId")

  override def generateSymmetricKey(keyName: Option[String])(
      traceContext: Context
  ): Future[String] =
    audited(s"generateSymmetricKey name=${keyName.getOrElse("-")}")(notes =>
      backend.withAuditNotes(notes)(backend.generateSymmetricKey(keyName))
    )(keyId => s"keyId=$keyId")

  override def sign(data: Array[Byte], keyId: String, algoSpec: SigningAlgoSpec)(
      traceContext: Context
  ): Future[Array[Byte]] =
    // `msg=` is SHA-256 of the exact bytes signed: `rutli-cosigner audit-cross-check` matches it
    // against the message each cosigner journaled under the intent's request id, so it can name
    // which message the driver signed and which were signed out of band.
    audited(s"sign keyId=$keyId algo=$algoSpec inBytes=${data.length} msg=${RutliDriver.sha256Hex(data)}")(notes =>
      // Human M-of-N approval (for keys the policy gates) runs BEFORE the backend signs, so quorum
      // approval precedes even the threshold signature. Then the signing journal durably records the
      // (key, digest) — and enforces any rate limit — before the signature is produced. Auto-
      // approved, un-journalled keys pass straight through.
      approvalGate.authorizeWithProof(keyId, data).flatMap { approval =>
        signingJournal.foreach(_.record(keyId, data)) // throws (fails the sign) if rate-limited
        // `withAuditNotes` must wrap the backend call itself, here inside the flatMap: a backend may
        // bind the notes to the calling thread (FrostBackend does), and this callback runs on an
        // ExecutionContext thread — wrapping the whole `authorize(...).flatMap` would bind them on
        // the wrong thread and lose a failover from the sign's audit entry.
        // The approvals travel with the sign: the FROST cosigners verify them themselves.
        backend.withAuditNotes(notes)(backend.sign(data, keyId, algoSpec, approval))
      }
    )(sig => s"sigBytes=${sig.length}")

  override def decryptAsymmetric(
      ciphertext: Array[Byte],
      keyId: String,
      algoSpec: EncryptionAlgoSpec,
  )(traceContext: Context): Future[Array[Byte]] =
    audited(s"decryptAsymmetric keyId=$keyId algo=$algoSpec ctBytes=${ciphertext.length}")(notes =>
      backend.withAuditNotes(notes)(backend.decryptAsymmetric(ciphertext, keyId, algoSpec))
    )(pt => s"ptBytes=${pt.length}")

  override def encryptSymmetric(data: Array[Byte], keyId: String)(
      traceContext: Context
  ): Future[Array[Byte]] =
    audited(s"encryptSymmetric keyId=$keyId ptBytes=${data.length}")(notes =>
      backend.withAuditNotes(notes)(backend.encryptSymmetric(data, keyId))
    )(ct => s"ctBytes=${ct.length}")

  override def decryptSymmetric(ciphertext: Array[Byte], keyId: String)(
      traceContext: Context
  ): Future[Array[Byte]] =
    audited(s"decryptSymmetric keyId=$keyId ctBytes=${ciphertext.length}")(notes =>
      backend.withAuditNotes(notes)(backend.decryptSymmetric(ciphertext, keyId))
    )(pt => s"ptBytes=${pt.length}")

  override def getPublicKey(keyId: String)(traceContext: Context): Future[PublicKey] =
    audited(s"getPublicKey keyId=$keyId")(notes =>
      backend.withAuditNotes(notes)(backend.getPublicKey(keyId))
    )(pk => s"spec=${pk.spec} spkiBytes=${pk.key.length}")

  override def keyExistsAndIsActive(keyId: String)(traceContext: Context): Future[Unit] =
    audited(s"keyExistsAndIsActive keyId=$keyId")(notes =>
      backend.withAuditNotes(notes)(backend.keyExistsAndIsActive(keyId))
    )(_ => "")

  override def deleteKey(keyId: String)(traceContext: Context): Future[Unit] =
    audited(s"deleteKey keyId=$keyId")(notes =>
      backend.withAuditNotes(notes)(backend.deleteKey(keyId))
    )(_ => "")

  override def close(): Unit =
    try backend.close()
    finally
      try approvalGate.close()
      finally
        try auditLog.foreach(_.close())
        finally blockingPool.foreach(_.shutdownNow())

  /** Wrap an operation: map failures to [[KmsDriverException]] per the SPI contract (preserving a
    * backend-thrown exception's retryable flag, wrapping anything else as non-retryable), and emit
    * audit records when enabled — a plain log line (`auditLogging`) and/or a tamper-evident entry
    * in the hash-chained audit log (`auditLog`).
    *
    * `f` gets this operation's [[AuditNotes]] to hand to the backend (`backend.withAuditNotes`);
    * whatever the backend notes — e.g. a FROST leader failover — is rendered into this operation's
    * own audit entry, on success and on failure alike.
    */
  private def audited[A](op: => String)(f: AuditNotes => Future[A])(result: A => String): Future[A] = {
    val auditing = auditLogging || auditLog.isDefined
    val notes = if (auditing) new AuditNotes else AuditNotes.discard
    val base =
      (try f(notes)
       catch { case NonFatal(e) => Future.failed(e) }).recoverWith {
        case e: KmsDriverException => Future.failed(e)
        case NonFatal(e)           => Future.failed(KmsDriverException(e, retryable = false))
      }
    if (!auditing) base
    else
      // Write-ahead + fail-closed: the operation's result is observable only AFTER the (fsynced)
      // hash-chained audit entry is durable. If a SUCCESSFUL op cannot be logged, the operation
      // fails rather than returning an unlogged signature. (The plain `auditLogging` logger line
      // stays best-effort; a failed op is logged best-effort and its original error is preserved.)
      base.transform { outcome =>
        val appendError = emitAudit(op, notes, outcome.map(result))
        (outcome, appendError) match {
          case (Success(_), Some(err)) => Failure(KmsDriverException(err, retryable = false))
          case _                       => outcome
        }
      }
  }

  /** Emit the audit records. Returns `Some(error)` iff the DURABLE (hash-chained) append failed —
    * the caller uses that to fail a successful operation closed. The logger line is best-effort.
    *
    * Backend notes go after the operation's own detail and before its result, so `outcome=` stays
    * the last field; with no notes the line is byte-identical to the note-less format. */
  private def emitAudit(op: String, notes: AuditNotes, rendered: scala.util.Try[String]): Option[Throwable] = {
    val (opName, detail) = {
      val space = op.indexOf(' ')
      if (space < 0) (op, "") else (op.substring(0, space), op.substring(space + 1))
    }
    val annotations = if (notes.isEmpty) "" else s" ${notes.render}"
    val line = rendered match {
      case Success(r) => s"$detail$annotations $r outcome=ok"
      case Failure(e) => s"$detail$annotations outcome=failed error=${e.getMessage}"
    }
    if (auditLogging) logger.info(s"AUDIT $opName $line")
    auditLog match {
      case Some(log) =>
        try { log.append(opName, line.trim); None }
        catch {
          case NonFatal(e) =>
            logger.error(s"audit log append failed for $opName: ${e.getMessage}")
            Some(new RuntimeException(s"audit log append failed for $opName: ${e.getMessage}", e))
        }
      case None => None
    }
  }
}

object RutliDriver {

  /** Lower-case hex SHA-256 of `data` — the `msg=` field of a sign's audit entry. */
  def sha256Hex(data: Array[Byte]): String =
    java.security.MessageDigest.getInstance("SHA-256").digest(data).map(b => f"${b & 0xff}%02x").mkString
}
