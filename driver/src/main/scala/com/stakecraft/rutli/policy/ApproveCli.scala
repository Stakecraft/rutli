// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli.policy

import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, Path, Paths}
import java.security.spec.PKCS8EncodedKeySpec
import java.security.{KeyFactory, KeyPairGenerator, Signature}
import java.util.Base64
import scala.jdk.CollectionConverters._
import scala.util.Using

/** Approver-side CLI for the M-of-N signing gate.
  *
  * An approver holds an Ed25519 keypair; the public key is listed in the driver's `approval`
  * policy, the private key stays with the human/role. To authorize a held signing request, the
  * approver signs the request id and drops the signature into the shared inbox — the driver counts
  * distinct valid approver signatures and proceeds at threshold. Each approver acts independently;
  * no approver ever sees or holds key material.
  *
  * Usage:
  * {{{
  *   # one-time: mint an approver key; add the printed public key to the policy `approvers` list
  *   java -cp rutli-driver.jar com.stakecraft.rutli.policy.ApproveCli keygen alice
  *
  *   # authorize: sign pending requests in the inbox with alice's key. Each request's id is
  *   # recomputed from the displayed keyId/digest/nonce first; a mismatch is refused, not signed.
  *   # The operation (SIGN, or a hosted-key DELETE: keyId "delete:<key>") is shown and checked.
  *   java -cp rutli-driver.jar com.stakecraft.rutli.policy.ApproveCli approve \
  *     --inbox /var/rutli/approvals --id alice --key alice.key [--request <id> | --all]
  * }}}
  */
object ApproveCli {

  def main(args: Array[String]): Unit =
    args.headOption match {
      case Some("keygen") => keygen(args.lift(1).getOrElse("approver"))
      case Some("approve") => approve(parseOpts(args.drop(1)))
      case _ =>
        Console.err.println(
          "usage:\n  keygen <name>\n  approve --inbox <dir> --id <approverId> --key <keyfile> [--request <id> | --all]"
        )
        sys.exit(2)
    }

  private def keygen(name: String): Unit = {
    val kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
    val keyFile = Paths.get(s"$name.key")
    Files.write(keyFile, Base64.getEncoder.encode(kp.getPrivate.getEncoded))
    keyFile.toFile.setReadable(false, false)
    keyFile.toFile.setReadable(true, true)
    val pub = Base64.getEncoder.encodeToString(kp.getPublic.getEncoded)
    println(s"Wrote private key to $keyFile (keep secret).")
    println(s"Add this approver to the driver policy:")
    println(s"""  { id = "$name", public-key-base64 = "$pub" }""")
  }

  private def approve(opts: Map[String, String]): Unit = {
    val inbox = opts.getOrElse("inbox", fail("--inbox required"))
    val id = opts.getOrElse("id", fail("--id required"))
    val key = loadPrivateKey(Paths.get(opts.getOrElse("key", fail("--key required"))))
    if (opts.get("request").isEmpty && !opts.contains("all")) fail("pass --request <id> or --all")
    val result = approveInbox(inbox, id, key, opts.get("request"))
    if (result.refused.nonEmpty) {
      Console.err.println(s"REFUSED ${result.refused.size} request(s) whose requestId does not match their fields")
      sys.exit(1)
    }
  }

  /** Outcome of [[approveInbox]]: the request ids signed, and the pending files refused. */
  final case class ApproveResult(approved: Vector[String], refused: Vector[Path])

  /** Sign pending requests in `inbox` (just `only`, or all of them). Before signing, the requestId
    * is RECOMPUTED from the displayed fields — `SHA-256(keyId ‖ digest ‖ nonce)`, exactly as the
    * gate derives it — and a request whose id does not match is refused, never signed. The inbox is
    * a shared writable directory: without this check, anyone who can write it could show an
    * approver one digest while the id they sign is bound to another. */
  def approveInbox(inbox: String, id: String, key: java.security.PrivateKey, only: Option[String]): ApproveResult = {
    val pendingDir = Paths.get(inbox, "pending")
    val approvalsDir = Paths.get(inbox, "approvals")
    Files.createDirectories(approvalsDir)

    val requests: Vector[Path] =
      only match {
        case Some(r) => Vector(pendingDir.resolve(s"$r.json")).filter(Files.exists(_))
        case None =>
          Using(Files.list(pendingDir))(_.iterator().asScala.filter(_.toString.endsWith(".json")).toVector)
            .getOrElse(Vector.empty)
      }

    if (requests.isEmpty) { println("no matching pending requests"); return ApproveResult(Vector.empty, Vector.empty) }

    val approved = Vector.newBuilder[String]
    val refused = Vector.newBuilder[Path]
    requests.foreach { reqFile =>
      val json = Files.readString(reqFile)
      val requestId = field(json, "requestId")
      val keyId = field(json, "keyId")
      val digest = field(json, "digest")
      val nonce = field(json, "nonce")
      val ts = field(json, "ts")
      val op = operationOf(keyId, digest, field(json, "operation"))
      // Surface the bound digest before the approver signs — SoD is cryptographic only if humans
      // verify they are approving the intended operation, not a swapped request id.
      println(s"pending request:")
      println(s"  operation = ${op.fold(identity, _.describe)}")
      println(s"  requestId = $requestId")
      println(s"  keyId     = $keyId")
      println(s"  digest    = $digest   (${op.fold(_ => "?", _.digestMeaning)})")
      println(s"  nonce     = $nonce")
      println(s"  ts        = $ts")
      if (!requestIdMatches(requestId, keyId, digest, nonce)) {
        Console.err.println(
          s"REFUSING $reqFile: requestId does not equal SHA-256(keyId ‖ digest ‖ nonce) of the fields shown " +
            "above — the file was tampered with or is malformed. Not signing."
        )
        refused += reqFile
      } else if (op.isLeft) {
        Console.err.println(s"REFUSING $reqFile: ${op.left.getOrElse("")}. Not signing.")
        refused += reqFile
      } else {
        val sig = Signature.getInstance("Ed25519")
        sig.initSign(key)
        sig.update(requestId.getBytes(UTF_8))
        val sigB64 = Base64.getEncoder.encodeToString(sig.sign())
        val approval =
          s"""{"approverId":"$id","requestId":"$requestId","signature":"$sigB64"}"""
        // requestId is verified 64 lowercase hex above, so it is safe in a file name.
        val out = approvalsDir.resolve(s"$requestId.$id.sig")
        Files.write(out, approval.getBytes(UTF_8))
        println(s"approved $requestId (key=$keyId digest=${digest.take(16)}…) -> $out")
        approved += requestId
      }
    }
    ApproveResult(approved.result(), refused.result())
  }

  /** What a pending request authorizes, read from the fields its requestId is computed over
    * (audit F6): a keyId `delete:<key>` is a hosted-key DELETE (key ids never contain ':'), anything
    * else a SIGN. Never from the unauthenticated `operation` field — which may only agree. */
  sealed trait Operation { def describe: String; def digestMeaning: String }
  final case class SignWith(keyId: String) extends Operation {
    def describe = s"SIGN with key $keyId"
    def digestMeaning = "SHA-256 of the bytes Canton asked to sign"
  }
  final case class DeleteHostedKey(keyId: String) extends Operation {
    def describe = s"DELETE hosted key $keyId (tombstoned cluster-wide)"
    def digestMeaning = "SHA-256 of the key's delete digest — checked"
  }

  val DeletePrefix = "delete:"

  /** The operation, or why the request is refused: a delete whose digest is not its key's delete
    * digest, or an `operation` field that contradicts what the requestId binds. */
  def operationOf(keyId: String, digestHex: String, claimed: String): Either[String, Operation] =
    if (keyId.startsWith(DeletePrefix)) {
      val target = keyId.drop(DeletePrefix.length)
      val expected = FileApprovalGate.hex(
        FileApprovalGate.sha256(com.stakecraft.rutli.backend.FrostIntentSigner.deleteDigest(target))
      )
      if (target.isEmpty || target.contains(':')) Left(s"malformed delete key id '$keyId'")
      else if (digestHex != expected) Left(s"the digest is not the delete digest of $target")
      else if (claimed.nonEmpty && claimed != "delete-hosted-key")
        Left(s"it claims operation '$claimed' but its requestId binds a DELETE of $target")
      else Right(DeleteHostedKey(target))
    } else if (claimed.nonEmpty && claimed != "sign")
      Left(s"it claims operation '$claimed' but its requestId binds a SIGN with $keyId (an old-format delete request? re-issue it)")
    else Right(SignWith(keyId))

  /** True iff `requestId` is exactly what the gate derives from these fields. */
  def requestIdMatches(requestId: String, keyId: String, digestHex: String, nonceHex: String): Boolean =
    HexRe(32).matches(digestHex) && HexRe(16).matches(nonceHex) &&
      requestId == FileApprovalGate.requestIdFor(keyId, unhex(digestHex), unhex(nonceHex))

  private case class HexRe(bytes: Int) {
    private val re = s"[0-9a-f]{${bytes * 2}}".r
    def matches(s: String): Boolean = re.pattern.matcher(s).matches()
  }

  private def unhex(s: String): Array[Byte] =
    s.grouped(2).map(Integer.parseInt(_, 16).toByte).toArray

  private def loadPrivateKey(path: Path): java.security.PrivateKey = {
    val der = Base64.getDecoder.decode(Files.readAllBytes(path))
    KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(der))
  }

  // Reads a string field of the flat pending JSON, undoing the gate's `esc` (a backslash escapes
  // the next character), so a keyId containing a quote or backslash round-trips into the hash.
  private def field(json: String, name: String): String =
    raw""""$name":"((?:[^"\\]|\\.)*)"""".r
      .findFirstMatchIn(json)
      .map(m => """\\(.)""".r.replaceAllIn(m.group(1), x => scala.util.matching.Regex.quoteReplacement(x.group(1))))
      .getOrElse("")

  private def parseOpts(args: Array[String]): Map[String, String] = {
    val m = scala.collection.mutable.Map.empty[String, String]
    var i = 0
    while (i < args.length) {
      val a = args(i)
      if (a.startsWith("--")) {
        val k = a.drop(2)
        if (i + 1 < args.length && !args(i + 1).startsWith("--")) { m(k) = args(i + 1); i += 2 }
        else { m(k) = "true"; i += 1 }
      } else i += 1
    }
    m.toMap
  }

  private def fail(msg: String): Nothing = { Console.err.println(msg); sys.exit(2) }
}
