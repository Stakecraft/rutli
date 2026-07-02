# Phase 1 — HSM backend (PKCS#11)

Keys live in a PKCS#11 HSM / secure enclave; the driver only ever sees public keys and signatures.
This is the first *production-usable* backend and the off-the-shelf FIPS story: a validated HSM
carries the certification, the driver just talks to it.

> Status: **verified against SoftHSM 2.7** (EC P-256/P-384 signing, RSA-2048 OAEP-SHA256
> decryption, AES-128-GCM, and key persistence across restart — 6 live tests). Not yet exercised on
> a broad matrix of production HSMs; treat as pre-production until run on the target device.

## How it works

`HsmBackend` uses the JDK's built-in **SunPKCS11** provider, so it works with any PKCS#11 module:
SoftHSM (dev), YubiHSM 2, Securosys, AWS CloudHSM, or an AWS Nitro-Enclave PKCS#11 shim (prod).

- **Key generation** creates a token keypair. A PKCS#11 KeyStore stores private keys as
  `PrivateKeyEntry`s, which require a certificate, so each key is wrapped in a *storage-envelope*
  X.509 cert. The cert carries the **token's public key** (that's what `getPublicKey` exports) but
  is signed by a throwaway in-JVM key — never the token. So key generation performs **no** signing
  operation on the HSM, which keeps it portable across modules that don't implement multi-part sign.
  The key's spec is encoded in the object label, so it survives restarts with no side table.
- **Signing (ECDSA):** the digest is computed in software, then a **single-part** raw sign runs on
  the token (`NONEwithECDSA` → `CKM_ECDSA`). This avoids `C_SignUpdate`, which SoftHSM (and some
  HSMs) don't implement. Output DER is identical to `SHAxxxwithECDSA`.
- **Signing (Ed25519):** uses the token's EdDSA mechanism *if present*. Support is probed at startup
  and Ed25519 is only advertised when the probe succeeds (SoftHSM 2.7 + JDK 17 SunPKCS11 does not
  expose it; production HSMs like YubiHSM/Securosys do). The namespace Ed25519 key's real home is
  the Phase 2 FROST cluster regardless.
- **RSA-2048 OAEP-SHA256 decryption:** SunPKCS11 rejects OAEP padding at the JCA layer, so the
  **secret** half (raw RSA modexp) runs on the token via `CKM_RSA_X_509` and the OAEP de-padding —
  which needs no secret — is done in software (RFC 8017 EME-OAEP). The private key never leaves the
  HSM. (A vendor's own JCA provider, if it supports OAEP natively, could replace this.)
- **AES-128-GCM** symmetric keys are token secret keys.

## Configuration

```hocon
canton.participants.participant1.crypto {
  provider = kms
  kms {
    type = driver
    name = "rutli"
    config = {
      backend = "hsm"
      audit-logging = true
      hsm = {
        library-path = "/opt/homebrew/lib/softhsm/libsofthsm2.so"  # or your HSM's PKCS#11 module
        slot-list-index = 0        # index into the list of slots holding a token; or set `slot`
        pin-env = "RUTLI_HSM_PIN"  # read the user PIN from this env var (preferred over inline `pin`)
      }
    }
  }
  signing.keys.default       = ec-p-256   # use Ed25519 only if the HSM exposes the mechanism
  signing.algorithms.default = ec-dsa-sha-256
}
```

Never inline the PIN in committed config — use `pin-env`.

## Try it against SoftHSM

```sh
scripts/init-softhsm.sh                 # creates a token, prints the env exports
# paste the printed exports, then:
sbt "driver/testOnly com.stakecraft.rutli.HsmBackendIT"
```

The integration test skips (cancels) automatically when `RUTLI_HSM_LIB` is unset, so plain
`sbt driver/test` stays HSM-free.

## Production notes / follow-ups

- Validate against the actual target HSM — mechanism availability (esp. Ed25519, raw RSA) and
  multi-part behaviour vary by vendor. Where a vendor JCA provider is available and richer than
  SunPKCS11, it can back a variant of this backend.
- High availability: SunPKCS11 is single-module. Multi-HSM HA / failover is a later addition.
- Access control on the token (CKA_SIGN/DECRYPT, PIN policy, per-key auth) is delegated to the HSM
  and its provisioning — document per deployment.
- FIPS: the certification attaches to the HSM module (FIPS 140-2/3), not to this software.
