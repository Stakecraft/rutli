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
      case r if r.mode == "quorum" => Some(r.threshold)
      case _                       => None
    }

  def approverById(id: String): Option[Approver] = approvers.find(_.id == id)

  /** Quorum rules that would also hold a carried protocol key (roadmap B6, docs/migration.md §8).
    * A rule on `<p>frost-import-`, the natural one for an imported namespace key, matches the
    * protocol ids `<p>frost-import-sig-…` and `<p>frost-import-seqauth-…` too, unless an earlier
    * rule takes them: every confirmation and every sequencer authentication would then wait for
    * approvals. One warning per such rule and label, for the driver to log at startup. */
  def carriedProtocolKeyWarnings: List[String] =
    rules.filter(r => r.mode == "quorum" && r.keyIdPrefix.endsWith(ApprovalPolicy.ImportMarker)).flatMap { r =>
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

  require(
    rules.forall(r => r.mode != "quorum" || (r.threshold >= 1 && r.threshold <= approvers.size)),
    "each quorum rule's threshold must be between 1 and the number of configured approvers",
  )
}

/** A single policy rule. `mode` is "quorum" (require `threshold` approvals) or "auto" (no gating,
  * useful to carve an exception out of a broader quorum prefix). */
final case class ApprovalRule(keyIdPrefix: String, mode: String = "quorum", threshold: Int = 2)

/** An approver identity and its Ed25519 public key (base64 DER X.509 SubjectPublicKeyInfo). */
final case class Approver(id: String, publicKeyBase64: String) {
  lazy val publicKey: java.security.PublicKey =
    KeyFactory
      .getInstance("Ed25519")
      .generatePublic(new X509EncodedKeySpec(Base64.getDecoder.decode(publicKeyBase64)))
}
