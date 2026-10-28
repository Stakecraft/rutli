// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli

import com.stakecraft.rutli.backend.FrostKeyIds
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

/** [[FrostKeyIds]] is the one place cluster key ids are minted and recognised. Two things must
  * hold: the default (empty) prefix reproduces the ids every earlier release minted byte for byte,
  * so existing clusters keep working with no config change; and a non-empty prefix namespaces
  * every id — FROST and hosted — and routes only its own ids to the cluster.
  */
class FrostKeyIdsSpec extends AnyWordSpec with Matchers {

  private val uuidRe = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"

  "FrostKeyIds with the default (empty) prefix" should {
    val ids = FrostKeyIds.Default

    "mint the FROST ids earlier releases minted, byte for byte" in {
      ids.prefix shouldBe ""
      ids.frost(Some("namespace")) shouldBe "frost-namespace"
      ids.frost(Some("signing")) shouldBe "frost-signing"
      ids.frost(Some("participant1-namespace")) shouldBe "frost-participant1-namespace"
      ids.frost(None) shouldBe "frost-key"
    }

    "sanitize a Canton key name to the cosigner keystore alphabet" in {
      ids.frost(Some("p1 namespace/root")) shouldBe "frost-p1_namespace_root"
    }

    "mint hosted ids in the established rutli-<kind>[-<name>]-<uuid> shape" in {
      ids.hosted("enc", Some("encryption"), "0f0f0f0f-0f0f-0f0f-0f0f-0f0f0f0f0f0f") shouldBe
        "rutli-enc-encryption-0f0f0f0f-0f0f-0f0f-0f0f-0f0f0f0f0f0f"
      ids.hosted("sym", None, "0f0f0f0f-0f0f-0f0f-0f0f-0f0f0f0f0f0f") shouldBe
        "rutli-sym-0f0f0f0f-0f0f-0f0f-0f0f-0f0f0f0f0f0f"
      ids.hosted("enc", Some("encryption")) should fullyMatch regex s"rutli-enc-encryption-$uuidRe"
      ids.hosted("sym", None) should fullyMatch regex s"rutli-sym-$uuidRe"
    }

    "route frost- and rutli- ids to the cluster and nothing else" in {
      ids.isFrost("frost-namespace") shouldBe true
      ids.isHosted("frost-namespace") shouldBe false
      ids.isHosted("rutli-enc-x-1") shouldBe true
      ids.isFrost("rutli-enc-x-1") shouldBe false
      ids.isCluster("frost-namespace") shouldBe true
      ids.isCluster("rutli-sym-1") shouldBe true
      ids.isCluster("enc-legacy-hsm-key") shouldBe false
      ids.isCluster("sig-participant1-namespace") shouldBe false
    }

    "cap a pathological id at the maximum length" in {
      val longName = "n" * 1000
      ids.frost(Some(longName)).length should be > FrostKeyIds.MaxLength // FROST ids are not capped
      ids.hosted("enc", Some(longName)).length shouldBe FrostKeyIds.MaxLength
    }
  }

  "FrostKeyIds with a per-participant prefix" should {
    val ids = FrostKeyIds("soak1-")

    "prepend the prefix to every FROST id" in {
      ids.frost(Some("namespace")) shouldBe "soak1-frost-namespace"
      ids.frost(Some("signing")) shouldBe "soak1-frost-signing"
      ids.frost(None) shouldBe "soak1-frost-key"
    }

    "prepend the prefix to every hosted id" in {
      ids.hosted("enc", Some("encryption"), "u") shouldBe "soak1-rutli-enc-encryption-u"
      ids.hosted("sym", None, "u") shouldBe "soak1-rutli-sym-u"
    }

    "route only ids carrying its own prefix to the cluster" in {
      ids.isFrost("soak1-frost-namespace") shouldBe true
      ids.isHosted("soak1-rutli-enc-x-1") shouldBe true
      // Another participant's ids on the same cluster — or a legacy unprefixed id — are not ours.
      ids.isFrost("frost-namespace") shouldBe false
      ids.isFrost("soak2-frost-namespace") shouldBe false
      ids.isHosted("rutli-enc-x-1") shouldBe false
      ids.isCluster("frost-namespace") shouldBe false
      ids.isCluster("soak1-frost-namespace") shouldBe true
    }

    "keep two participants' ids disjoint for the same Canton key name" in {
      // This is the whole point: without a prefix both would ask the cluster for frost-namespace
      // and the second DKG would be refused with ALREADY_EXISTS.
      val a = FrostKeyIds("soak1-").frost(Some("namespace"))
      val b = FrostKeyIds("soak2-").frost(Some("namespace"))
      a should not be b
      FrostKeyIds("soak1-").isFrost(b) shouldBe false
      FrostKeyIds("soak2-").isFrost(a) shouldBe false
    }

    "accept any prefix in the cosigner keystore alphabet, with or without a separator" in {
      FrostKeyIds("p1").frost(Some("namespace")) shouldBe "p1frost-namespace"
      FrostKeyIds("Org_1-").frost(Some("namespace")) shouldBe "Org_1-frost-namespace"
    }
  }

  "FrostKeyIds" should {
    "reject a prefix outside the cosigner keystore alphabet at construction" in {
      // The cosigner would reject such an id at the first DKG; better to fail at driver startup.
      val err = intercept[IllegalArgumentException](FrostKeyIds("soak 1/"))
      err.getMessage should include("frost.key-prefix")
      err.getMessage should include("[A-Za-z0-9_-]")
      intercept[IllegalArgumentException](FrostKeyIds("soak1."))
      intercept[IllegalArgumentException](FrostKeyIds("soak1:"))
    }

    "reject a prefix containing a routing tag, which would put its ids in the other namespace" in {
      // The cosigners read the first frost-/rutli- in an id as its routing tag and create hosted keys
      // only under rutli- ids: with prefix "frost-p1-" every hosted id would read as a FROST id.
      for (bad <- Seq("frost-", "frost-p1-", "p1-frost-", "rutli-", "x-rutli-y", "afrost-")) {
        val err = intercept[IllegalArgumentException](FrostKeyIds(bad))
        err.getMessage should include("frost.key-prefix")
        err.getMessage should include("routing tags")
      }
      // Deployed prefixes, and prefixes that only resemble a tag, stay valid.
      for (ok <- Seq("", "soak1-", "b4-", "b8-", "acme1-", "frost", "rutli", "frostp1-", "rutli_1-"))
        noException should be thrownBy FrostKeyIds(ok)
    }

    "keep the first routing tag in every minted id equal to the one it routes on" in {
      // The cosigner-side rule (a hosted key only under an id whose first tag is rutli-) must accept
      // every hosted id and refuse every FROST id this driver mints, whatever the Canton key name.
      def firstTag(id: String): Option[String] =
        Seq(FrostKeyIds.FrostTag, FrostKeyIds.HostedTag)
          .map(t => t -> id.indexOf(t))
          .filter(_._2 >= 0)
          .sortBy(_._2)
          .headOption
          .map(_._1)
      for (prefix <- Seq("", "soak1-", "frost", "rutli", "p1")) {
        val ids = FrostKeyIds(prefix)
        for (name <- Seq(Some("namespace"), Some("frost-x"), Some("rutli-y"), Some("rutli-frost-z"), None)) {
          firstTag(ids.frost(name)) shouldBe Some(FrostKeyIds.FrostTag)
          firstTag(ids.hosted("enc", name, "u")) shouldBe Some(FrostKeyIds.HostedTag)
        }
      }
    }
  }
}
