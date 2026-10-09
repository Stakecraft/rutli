// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli.backend

import java.io.ByteArrayInputStream
import java.nio.ByteBuffer
import java.nio.charset.{CharacterCodingException, CodingErrorAction, StandardCharsets}
import java.nio.file.{Files, Paths}
import java.security.MessageDigest
import java.security.cert.{
  CertificateException,
  CertificateExpiredException,
  CertificateFactory,
  CertificateNotYetValidException,
  X509Certificate,
}
import java.util.{Base64, Date}
import javax.security.auth.x500.X500Principal
import scala.annotation.tailrec

/** The driver's copy of the cosigners' trust-file rule (`frost/cosigner/src/trust.rs`, review M1).
  *
  * Every certificate in a TLS trust file is a trust anchor, and a TLS stack does not check an
  * anchor's validity period (rustls checks nothing at all about it). So the cluster CA file
  * (`frost.tls.ca-cert`) is refused unless every PEM block in it is a `CERTIFICATE` that is a CA
  * (basicConstraints CA, keyCertSign when a keyUsage is present) and valid now. A private key pasted
  * into it is refused by block index and never echoed. `allowExpired` (`allow-expired-ca`) relaxes
  * only the validity period, for a rotation away from a CA that has already expired.
  *
  * The channel is then built from exactly the certificates validated here, not from the file.
  */
object FrostTrustFile {

  /** One validated anchor. */
  final case class Anchor(cert: X509Certificate, subject: String, notAfter: Date, sha256: String, validNow: Boolean) {
    def describe: String = s"subject=\"$subject\" notAfter=${notAfter.toInstant} sha256=$sha256"
  }

  /** Load and validate the trust file at `path`. Throws [[IllegalArgumentException]] (driver init
    * fails) with the path and the reason. */
  def load(path: String, allowExpired: Boolean, now: Date = new Date()): Seq[Anchor] = {
    val bytes =
      try Files.readAllBytes(Paths.get(path))
      catch { case e: java.io.IOException => throw invalid(path, s"cannot read it: $e") }
    validate(bytes, allowExpired, now).fold(msg => throw invalid(path, msg), identity)
  }

  /** The rule itself, on the file's bytes: the anchors in file order, or why the file is refused. */
  def validate(bytes: Array[Byte], allowExpired: Boolean, now: Date = new Date()): Either[String, Seq[Anchor]] =
    for {
      text <- utf8(bytes)
      blocks <- pemBlocks(text)
      _ <- if (blocks.isEmpty) Left("no CERTIFICATE in the trust file") else Right(())
      anchors <- blocks.zipWithIndex.foldLeft[Either[String, Vector[Anchor]]](Right(Vector.empty)) {
        case (acc, ((label, der), i)) => acc.flatMap(done => anchor(i, label, der, allowExpired, now).map(done :+ _))
      }
    } yield anchors

  private def anchor(i: Int, label: String, der: Array[Byte], allowExpired: Boolean, now: Date): Either[String, Anchor] = {
    if (label != "CERTIFICATE")
      return Left(
        s"PEM block $i is a \"$label\", not a CERTIFICATE — a trust file holds only CA certificates " +
          "(if this is a private key, treat it as exposed)"
      )
    val cert =
      try CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(der)) match {
        case c: X509Certificate if java.util.Arrays.equals(c.getEncoded, der) => Some(c)
        case _ => None
      }
      catch { case _: CertificateException => None }
    cert match {
      case None => Left(s"certificate $i: malformed certificate")
      case Some(c) =>
        val subject = c.getSubjectX500Principal.getName(X500Principal.RFC2253)
        // getBasicConstraints: -1 unless the certificate is a CA.
        if (c.getBasicConstraints < 0)
          Left(
            s"certificate $i ($subject) is not a CA certificate (basicConstraints CA) — every " +
              "certificate in a trust file is a trust anchor, so a leaf here would let its key holder " +
              "issue any identity"
          )
        else if (Option(c.getKeyUsage).exists(ku => ku.length <= 5 || !ku(5)))
          Left(s"certificate $i ($subject) may not sign certificates (keyUsage lacks keyCertSign)")
        else {
          val validNow =
            try { c.checkValidity(now); true }
            catch { case _: CertificateExpiredException | _: CertificateNotYetValidException => false }
          if (!validNow && !allowExpired)
            Left(
              s"certificate $i ($subject) is expired or not yet valid (notBefore " +
                s"${c.getNotBefore.toInstant}, notAfter ${c.getNotAfter.toInstant}, now ${now.toInstant}) — " +
                "remove it, or set frost.tls.allow-expired-ca for an emergency rotation away from an expired CA"
            )
          else Right(Anchor(c, subject, c.getNotAfter, sha256Hex(der), validNow))
        }
    }
  }

  /** `(label, DER)` for every PEM block; text outside the blocks is ignored (as the cosigners do). */
  private[backend] def pemBlocks(text: String): Either[String, Vector[(String, Array[Byte])]] = {
    val Begin = "-----BEGIN "
    @tailrec def go(rest: String, acc: Vector[(String, Array[Byte])]): Either[String, Vector[(String, Array[Byte])]] = {
      val start = rest.indexOf(Begin)
      if (start < 0) Right(acc)
      else {
        val after = rest.substring(start + Begin.length)
        val labelEnd = after.indexOf("-----")
        if (labelEnd < 0) Left("malformed PEM header")
        else {
          val label = after.substring(0, labelEnd)
          val body = after.substring(labelEnd + 5)
          val endMarker = s"-----END $label-----"
          val bodyEnd = body.indexOf(endMarker)
          if (bodyEnd < 0) Left("unterminated PEM block")
          else {
            val b64 = body.substring(0, bodyEnd).filterNot(_.isWhitespace)
            val der =
              try Some(Base64.getDecoder.decode(b64))
              catch { case _: IllegalArgumentException => None }
            der match {
              case None => Left("PEM body is not base64")
              case Some(d) => go(body.substring(bodyEnd + endMarker.length), acc :+ (label -> d))
            }
          }
        }
      }
    }
    go(text, Vector.empty)
  }

  private def utf8(bytes: Array[Byte]): Either[String, String] =
    try
      Right(
        StandardCharsets.UTF_8
          .newDecoder()
          .onMalformedInput(CodingErrorAction.REPORT)
          .onUnmappableCharacter(CodingErrorAction.REPORT)
          .decode(ByteBuffer.wrap(bytes))
          .toString
      )
    catch { case _: CharacterCodingException => Left("PEM file is not UTF-8") }

  private def sha256Hex(der: Array[Byte]): String =
    MessageDigest.getInstance("SHA-256").digest(der).map(b => f"${b & 0xff}%02x").mkString

  private def invalid(path: String, msg: String) =
    new IllegalArgumentException(s"FROST: frost.tls.ca-cert $path: $msg")
}
