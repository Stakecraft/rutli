// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli.policy

import java.security.KeyFactory
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import scala.concurrent.duration._

/** M-of-N approval policy for signing operations.
  *
  * The Rütli driver only ever sees an opaque pre-hashed payload (Canton's 34-byte digest), so
  * policy is expressed over the KMS key, not transaction semantics. A `sign` for a key whose id
  * matches a `quorum` rule is held until `threshold` distinct configured approvers have each
  * cryptographically signed the request (see [[ApprovalGate]]), or the request times out.
  *
  * Default is no gating (`auto`), so nodes bootstrap and low-value keys sign without human
  * interaction; operators opt specific keys (typically the namespace/identity key) into quorum.
  *
  * @param rules      Ordered key-id-prefix rules; the first match wins. A key matching no rule is
  *                   auto-approved.
  * @param approvers  The approver keyset (id + Ed25519 public key). Approvals are only counted from
  *                   these identities, each at most once per request.
  * @param inboxDir   Directory for the file-based approval exchange (`pending/`, `approvals/`).
  * @param timeout    How long a gated `sign` waits for a quorum before failing.
  * @param pollInterval How often the gate rescans the approvals directory.
  */
object ApprovalPolicy {
  private val ImportMarker = "frost-import-"
  private val ProtocolLabels = List("sig-", "seqauth-")

  /** The two rule modes. Exact and lowercase, as the cosigners read `signing_policy.rules`: any
    * other value, `Quorum` and `quorom` included, is a configuration error, never auto-approve. */
  val Quorum = "quorum"
  val Auto = "auto"

  /** Why `rule`'s mode is refused, or None for `quorum` and `auto`. */
  def modeProblem(rule: ApprovalRule): Option[String] =
    if (rule.mode == Quorum || rule.mode == Auto) None
    else
      Some(
        s"approval rule with key-id-prefix \"${rule.keyIdPrefix}\": mode must be \"$Quorum\" or \"$Auto\" " +
          s"(lowercase), got \"${rule.mode}\""
      )

  /** One thing wrong with a rule: its index in `rules`, and what to tell the operator. */
  final case class RuleProblem(index: Int, message: String)

  /** Everything wrong with `rules` under `approverCount` approvers, checked when the config is read
    * (and again by the constructor):
    *   - a mode other than `quorum` or `auto`;
    *   - a quorum threshold outside 1 to the number of approvers (so a quorum rule with no
    *     approvers configured is refused, not auto-approved);
    *   - a quorum rule that an earlier `auto` rule shadows completely (the earlier prefix is a
    *     prefix of this one, `""` included): first match wins, so it would never hold a key.
    */
  def ruleProblems(rules: List[ApprovalRule], approverCount: Int): List[RuleProblem] =
    rules.zipWithIndex.flatMap { case (r, i) =>
      val what = s"approval rule ${i + 1} (key-id-prefix \"${r.keyIdPrefix}\")"
      val badMode = modeProblem(r)
      if (badMode.isDefined)
        badMode.map(m => RuleProblem(i, m))
      else if (r.mode == Quorum && (r.threshold < 1 || r.threshold > approverCount))
        Some(
          RuleProblem(
            i,
            s"$what: threshold ${r.threshold} must be between 1 and the number of approvers ($approverCount)",
          )
        )
      else if (r.mode == Quorum)
        rules.take(i).zipWithIndex.collectFirst {
          case (earlier, j) if earlier.mode == Auto && r.keyIdPrefix.startsWith(earlier.keyIdPrefix) =>
            RuleProblem(
              i,
              s"$what: this quorum rule never applies, because approval rule ${j + 1} " +
                s"(key-id-prefix \"${earlier.keyIdPrefix}\", auto) comes first and matches every key it would. " +
                "The first matching rule wins: put the quorum rule first, or narrow the auto rule",
            )
        }
      else None
    }
}

final case class ApprovalPolicy(
    rules: List[ApprovalRule],
    approvers: List[Approver],
    inboxDir: String,
    timeout: FiniteDuration = 5.minutes,
    pollInterval: FiniteDuration = 1.second,
) {

  /** Required approval threshold for `keyId`, or None when the key is auto-approved. */
  def thresholdFor(keyId: String): Option[Int] =
    rules.find(r => keyId.startsWith(r.keyIdPrefix)).flatMap {
      case r if r.mode == ApprovalPolicy.Quorum => Some(r.threshold)
      case r if r.mode == ApprovalPolicy.Auto   => None
      // Unreachable once constructed (see the check below); never auto-approve an unknown mode.
      case r => throw new IllegalStateException(s"approval rule mode '${r.mode}' is neither quorum nor auto")
    }

  def approverById(id: String): Option[Approver] = approvers.find(_.id == id)

  /** Quorum rules that would also hold a carried protocol key (roadmap B6, docs/migration.md §8).
    * A rule on `<p>frost-import-`, the natural one for an imported namespace key, matches the
    * protocol ids `<p>frost-import-sig-…` and `<p>frost-import-seqauth-…` too, unless an earlier
    * rule takes them: every confirmation and every sequencer authentication would then wait for
    * approvals. One warning per such rule and label, for the driver to log at startup. */
  def carriedProtocolKeyWarnings: List[String] =
    rules.filter(r => r.mode == ApprovalPolicy.Quorum && r.keyIdPrefix.endsWith(ApprovalPolicy.ImportMarker)).flatMap { r =>
      ApprovalPolicy.ProtocolLabels.flatMap { label =>
        val probe = s"${r.keyIdPrefix}${label}probe"
        thresholdFor(probe).map { _ =>
          s"approval rule key-id-prefix=\"${r.keyIdPrefix}\" (quorum) also holds carried protocol keys " +
            s"\"${r.keyIdPrefix}$label…\": every signature with them would wait for approvals. Put an " +
            s"auto rule for \"${r.keyIdPrefix}$label\" before it, or name the namespace key id exactly " +
            "(docs/migration.md §8)"
        }
      }
    }

  // The config reader reports these as config failures with their path (RutliDriverFactory); this
  // covers a policy built any other way.
  ApprovalPolicy.ruleProblems(rules, approvers.size).headOption.foreach { p =>
    throw new IllegalArgumentException(p.message)
  }
}

/** A single policy rule. `mode` is "quorum" (require `threshold` approvals) or "auto" (no gating,
  * useful to carve an exception out of a broader quorum prefix); anything else is refused. */
final case class ApprovalRule(keyIdPrefix: String, mode: String = "quorum", threshold: Int = 2)

/** An approver identity and its Ed25519 public key (base64 DER X.509 SubjectPublicKeyInfo). */
final case class Approver(id: String, publicKeyBase64: String) {
  lazy val publicKey: java.security.PublicKey =
    KeyFactory
      .getInstance("Ed25519")
      .generatePublic(new X509EncodedKeySpec(Base64.getDecoder.decode(publicKeyBase64)))
}
