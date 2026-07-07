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
  *   # authorize: sign pending requests in the inbox with alice's key
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
    val pendingDir = Paths.get(inbox, "pending")
    val approvalsDir = Paths.get(inbox, "approvals")
    Files.createDirectories(approvalsDir)

    val requests: Vector[Path] =
      opts.get("request") match {
        case Some(r) => Vector(pendingDir.resolve(s"$r.json")).filter(Files.exists(_))
        case None if opts.contains("all") =>
          Using(Files.list(pendingDir))(_.iterator().asScala.filter(_.toString.endsWith(".json")).toVector)
            .getOrElse(Vector.empty)
        case None => fail("pass --request <id> or --all")
      }

    if (requests.isEmpty) { println("no matching pending requests"); return }

    requests.foreach { reqFile =>
      val json = Files.readString(reqFile)
      val requestId = field(json, "requestId")
      val sig = Signature.getInstance("Ed25519")
      sig.initSign(key)
      sig.update(requestId.getBytes(UTF_8))
      val sigB64 = Base64.getEncoder.encodeToString(sig.sign())
      val approval =
        s"""{"approverId":"$id","requestId":"$requestId","signature":"$sigB64"}"""
      val out = approvalsDir.resolve(s"$requestId.$id.sig")
      Files.write(out, approval.getBytes(UTF_8))
      println(s"approved $requestId (key=${field(json, "keyId")}) -> $out")
    }
  }

  private def loadPrivateKey(path: Path): java.security.PrivateKey = {
    val der = Base64.getDecoder.decode(Files.readAllBytes(path))
    KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(der))
  }

  private def field(json: String, name: String): String =
    s"""\"$name\":\"(.*?)\"""".r.findFirstMatchIn(json).map(_.group(1)).getOrElse("")

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
