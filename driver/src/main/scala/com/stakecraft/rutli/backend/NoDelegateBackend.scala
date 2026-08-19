// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

package com.stakecraft.rutli.backend

import com.digitalasset.canton.crypto.kms.driver.api.v1._

import scala.concurrent.Future

/** The delegate used when `frost.delegate = "none"`: there is no second backend.
  *
  * This is what an HSM-free deployment looks like once the cluster hosts the non-FROST keys too —
  * the participant holds no key material at all. Every operation that reaches this backend is a
  * routing bug (a key id that is neither `frost-` nor `rutli-`), so it fails loudly and names the
  * key rather than silently doing local crypto.
  *
  * It advertises no specs, so [[FrostBackend]]'s advertised set is exactly what the cluster serves.
  */
final class NoDelegateBackend extends KmsBackend {

  override val supportedSigningKeySpecs: Set[SigningKeySpec] = Set.empty
  override val supportedSigningAlgoSpecs: Set[SigningAlgoSpec] = Set.empty
  override val supportedEncryptionKeySpecs: Set[EncryptionKeySpec] = Set.empty
  override val supportedEncryptionAlgoSpecs: Set[EncryptionAlgoSpec] = Set.empty

  private def refuse[A](op: String, detail: String): Future[A] =
    Future.failed(
      new UnsupportedOperationException(
        s"$op is not available: this driver runs with delegate = \"none\", so all key material " +
          s"lives in the FROST cluster ($detail). Configure an hsm/software delegate if you need " +
          "key types the cluster does not serve."
      )
    )

  override def generateSigningKeyPair(spec: SigningKeySpec, keyName: Option[String]): Future[String] =
    refuse("generateSigningKeyPair", s"unsupported signing key spec $spec")

  override def generateEncryptionKeyPair(
      spec: EncryptionKeySpec,
      keyName: Option[String],
  ): Future[String] = refuse("generateEncryptionKeyPair", s"unsupported encryption key spec $spec")

  override def generateSymmetricKey(keyName: Option[String]): Future[String] =
    refuse("generateSymmetricKey", "symmetric keys are served by the cluster")

  override def sign(data: Array[Byte], keyId: String, algo: SigningAlgoSpec): Future[Array[Byte]] =
    refuse("sign", s"unknown key id $keyId")

  override def decryptAsymmetric(
      ciphertext: Array[Byte],
      keyId: String,
      algo: EncryptionAlgoSpec,
  ): Future[Array[Byte]] = refuse("decryptAsymmetric", s"unknown key id $keyId")

  override def encryptSymmetric(data: Array[Byte], keyId: String): Future[Array[Byte]] =
    refuse("encryptSymmetric", s"unknown key id $keyId")

  override def decryptSymmetric(ciphertext: Array[Byte], keyId: String): Future[Array[Byte]] =
    refuse("decryptSymmetric", s"unknown key id $keyId")

  override def getPublicKey(keyId: String): Future[PublicKey] =
    refuse("getPublicKey", s"unknown key id $keyId")

  override def keyExistsAndIsActive(keyId: String): Future[Unit] =
    Future.failed(new NoSuchElementException(s"key not found: $keyId"))

  override def deleteKey(keyId: String): Future[Unit] =
    refuse("deleteKey", s"unknown key id $keyId")

  override def health: Future[KmsDriverHealth] = Future.successful(KmsDriverHealth.Ok)
}
