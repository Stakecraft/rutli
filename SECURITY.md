# Security policy

Rütli manages **authority key material for Canton Network / Splice nodes**, the highest-value
secret a node holds. Treat every change as security-critical.

## Status

- **Pre-1.0 and not yet externally audited.** The latest release is `0.4.1` (`0.4.0` with
  security fixes). The latest release candidate is `0.5.0-rc.1`. An independent third-party audit
  will review `0.5.0`, whose code freeze is planned for mid-December 2026; its report will be
  published in this repository.
- **Internal security review, October 2026.** Two independent reviews of `0.4.0-rc.1`. Every
  critical and high finding is fixed in `0.4.0-rc.2` and `0.4.0-rc.3`. The findings and their status
  are in [docs/security/internal-review-2026-10.md](docs/security/internal-review-2026-10.md).
- **Do not put production authority keys behind Rütli before the external audit is complete.**
  The DevNet soak validator runs on it as test material.

## Supported versions

Until 1.0, the latest release and the latest release candidate receive security fixes. A fix for the
latest release can ship as a patch release from its release branch, as `0.4.1` did; older releases
get none. Upgrade to the latest release.

| Version | Supported |
|---|---|
| `0.5.0-rc.1` (latest candidate) | Yes |
| `0.4.1` (latest release) | Yes |
| `0.4.0` and older | No |

## Reporting a vulnerability

Do **not** open a public issue, pull request or discussion for a security problem. Use GitHub
private vulnerability reporting:
**[Security → Report a vulnerability](https://github.com/Stakecraft/rutli/security/advisories/new)**.

Please include the affected version or commit, the component, a description, steps to reproduce
and the impact you see.

What to expect:

- acknowledgement within 72 hours;
- a first assessment (severity, affected versions) within 7 days;
- a fix, a GitHub Security Advisory and, where it applies, a CVE. We coordinate the disclosure date
  with you, by default no later than 90 days after the report;
- credit in the advisory and the changelog, unless you prefer otherwise.

There is no bug bounty at this time.

## Scope

**In scope:**

- the Canton KMS driver (`driver/`): key routing, intent signing, approval gate, signing journal,
  audit log;
- the cosigner and dealer (`frost/`): DKG, signing, refresh, repair, nonce handling, hosted keys,
  sealing, the split ceremony, and the mesh and client gRPC APIs;
- the deployment artefacts (`deploy/helm`, `deploy/k8s`, `deploy/frost`) and the scripts that
  generate certificates or seal material;
- the runbooks, where following them as written leads to key exposure or loss.

**Out of scope:**

- the `software` backend: in-process keys for integration tests only, insecure by design;
- the soak and CI infrastructure described in the docs (report problems there privately all the
  same);
- issues that need the attacker to already hold `t` shares, or to administer every cosigner's
  trust domain (see the threat model);
- Canton, Splice and third-party dependencies themselves. Report those upstream; tell us if Rütli
  is affected.

## Backends

| Backend | Use | Notes |
|---|---|---|
| `frost` | The production path | Namespace, protocol signing and sequencer authentication keys as FROST-ed25519 shares across a `t`-of-`n` cosigner cluster. Encryption and symmetric keys either cluster-hosted (`frost.delegate = "none"`) or in an HSM (`"hsm"`) |
| `hsm` | Non-Ed25519 keys on a PKCS#11 token | Verified against SoftHSM only. Not in the planned audit scope |
| `software` | Integration tests only | **Never** place namespace, signing or encryption keys behind it |

## What the security properties assume

The guarantees in [docs/security/threat-model.md](docs/security/threat-model.md) hold only for a
cluster where:

- every cosigner and the driver run the same release, upgraded **before** any DKG or refresh;
- the enforcement settings are on, identically, on every node. The list is the table in
  [docs/production-profile.md](docs/production-profile.md): `"profile": "production"` requires all
  of them and a cosigner refuses to start without them, and `rutli-cosigner check-config` shows what
  a config lacks. The Helm chart and `deploy/k8s` set it. Unset behaves as `lab` in 0.5 and becomes
  `production` in 0.6. How to switch the settings on in a running cluster:
  [docs/approval-quorum.md](docs/approval-quorum.md), "Switching enforcement on";
- from 0.5.0 every cosigner with TLS pins its peers' TLS keys (`peers[].tls_spki_sha256`), and
  signing intents are required by default. Upgrading from 0.4.x:
  [docs/upgrading-to-0.5.md](docs/upgrading-to-0.5.md);
- key files are written in format v2 (`keyfile.write_version: 2`, `cluster_uuid` set), and
  `accept_v1: false` once every file is v2;
- the Helm `perNode` topology is used: per-node seal and TLS secrets, no `pods/exec` RBAC (CI
  enforces this with `scripts/check-deploy-policy.sh`);
- **no TLS-terminating service mesh** sits between cosigners. A terminating proxy sees every new
  share;
- for keys that matter, the cosigners sit in **separate trust domains** (clusters, cloud accounts
  or operators). One Kubernetes cluster under one administration is one trust domain, and its
  administrator holds every share. What counts as separate: [docs/audit-prep.md](docs/audit-prep.md#what-counts-as-a-separate-trust-domain).

**Keys from earlier releases.** Every key generated by DKG, and every refresh, on `0.4.0-rc.2` or
earlier sent round-2 packages through the coordinating node, which could reconstruct the key.
Generate or split any key that matters on `0.4.0-rc.3` or later, on a uniformly upgraded cluster.

## Verify the image

From `0.5.0` on, the cosigner image `ghcr.io/stakecraft/rutli-cosigner` is built by
[`.github/workflows/publish-image.yml`](.github/workflows/publish-image.yml) on GitHub-hosted
runners, never on the project's self-hosted CI runners, and only from a `v*` tag. Both platforms
(linux/amd64, linux/arm64) are built natively, without emulation. What a release carries:

- **The multi-arch index** (the digest the deploy files pin). Its `manifests` list holds the two
  platform images and, for each, an attestation manifest that refers to that image
  (`vnd.docker.reference.type: attestation-manifest`, `vnd.docker.reference.digest: <image>`) and
  holds BuildKit's SBOM (SPDX) and provenance for it. That is how BuildKit stores attestations,
  and `docker buildx imagetools create` keeps those entries when it merges the two platforms; the
  release job fails unless the index has both entries and both SBOMs and provenances read back.
- **A keyless cosign signature of the index digest**, made with the workflow's GitHub OIDC identity
  and recorded in Sigstore's public transparency log (Rekor). The index digest is the hash of the
  index, which names every image and attestation manifest above by its digest, so the signature
  covers them. The SBOM and provenance inside are not signed separately.
- **A SLSA build provenance attestation from GitHub for the index digest**, signed with the same
  identity, stored with the repository and pushed to the registry next to the image.

Images up to `0.4.0` were built on the self-hosted runners and are neither signed nor attested.

Verify the digest you deploy before you deploy it (the Helm chart, `deploy/k8s` and the compose
files pin it). You need cosign 3 or newer and the GitHub CLI (`gh`, 2.103 or newer):

```bash
TAG=v0.5.0
IMAGE=ghcr.io/stakecraft/rutli-cosigner@sha256:<index digest>

# Signature: made by publish-image.yml in Stakecraft/rutli, run on that tag
cosign verify "$IMAGE" \
  --certificate-identity "https://github.com/Stakecraft/rutli/.github/workflows/publish-image.yml@refs/tags/$TAG" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# Provenance: same workflow and tag, signed on a GitHub-hosted runner
gh attestation verify "oci://$IMAGE" --repo Stakecraft/rutli \
  --signer-workflow Stakecraft/rutli/.github/workflows/publish-image.yml \
  --source-ref "refs/tags/$TAG" --deny-self-hosted-runners

# The same, from the copy of the attestation stored in the registry instead of GitHub's API
gh attestation verify "oci://$IMAGE" --repo Stakecraft/rutli --bundle-from-oci \
  --signer-workflow Stakecraft/rutli/.github/workflows/publish-image.yml \
  --source-ref "refs/tags/$TAG" --deny-self-hosted-runners
```

The driver jar, the dealer binary and, from 0.6.0, the cosigner binary are signed and attested the
same way (their own workflow,
`release-assets.yml`); how to verify them: [docs/releasing.md](docs/releasing.md#verify-the-release-assets).

The release workflow runs these exact commands as its last step. The first two must succeed; the
third checks the registry copy and is useful where GitHub's API is unreachable. The certificate
identity is exact and case-sensitive:
`https://github.com/Stakecraft/rutli/.github/workflows/publish-image.yml@refs/tags/v<version>`, issuer
`https://token.actions.githubusercontent.com`. A signature from another workflow, ref or repository
is not a Rütli release. `--deny-self-hosted-runners` checks the runner of the job that made the
attestation (the signing job), not the build jobs; those run on hosted runners because the workflow
file at that tag, which the certificate identity names, says so. To read the SBOM of one platform:
`docker buildx imagetools inspect "$IMAGE" --format '{{ json (index .SBOM "linux/amd64").SPDX }}'`.

What this does not protect against. A signature shows where and from which tag an image was built,
not that what was built is benign. Anyone who can push a `v*` tag (an admin account) gets a
correctly signed image of whatever that tag points at, and can edit the workflow in the commit
the tag points at. Anyone with write access can also start the workflow by hand on an existing
release tag: it builds, signs and attests a new index under the same identity and moves the
version tags (`0.5.0`, `0.5`, `latest`) to it, unless the repository's `release` environment
requires a reviewer. Pin by digest, not by tag. A compromised action at its pinned commit, a
compromised base image at its pinned digest or a malicious crate version in `frost/Cargo.lock`
runs inside the build and ends up signed too. Pinning means none of these can change without a
commit in this repository; reviewing those commits, and the commit a tag points at, is what guards
against them.

## Design invariants (must not be violated)

- Canton never sees a private key. The driver returns only public keys, signatures and plaintexts
  of decryptions it was asked for (Canton's external key storage mode).
- No node, operator or dealer ever holds a whole FROST key, except the offline dealer during a
  split ceremony of an existing key. FROST shares cannot be exported.
- DKG and refresh round-2 packages travel node to node; the coordinating node only relays
  round-1 data.
- FROST nonces: fresh per session, from a CSPRNG, burned durably before a signature share is
  released, never reused across restarts. Canonical encodings of the group key and `R` are checked
  at the boundary.
- A cosigner releases a signature share only for the digest named in a client-signed intent it has
  verified (with `require_intent` on), within its own rate limits and ACLs.
- The driver accepts a group key only when at least two cosigners agree on it and none disagrees,
  pins it, and verifies every signature (strict RFC 8032) against the pinned key before returning
  it to Canton.
- Keys at rest are sealed with AES-256-GCM under a per-node key. Key files in format v2 bind their
  header (cluster, node, key id, kind, epoch) as associated data, so a file cannot be moved to
  another node, key or epoch.
- Threshold **decryption** is not attempted. Hosted encryption keys are whole keys, sealed and
  replicated on each cosigner. They leave the cluster only through the offline
  `rutli-cosigner export-key`, run by an operator with the node stopped; the export is
  passphrase-protected (Argon2id) by default.
- Audit log entries are append-only, hash-chained and fsynced before the operation returns. An
  operation that cannot be logged fails closed (`audit-log-path`).

Known residual risks are listed plainly at the end of the
[threat model](docs/security/threat-model.md#residual-risks-stated-plainly).

## Scope reminder

The Canton **namespace root key cannot be rotated**. There is no recovery from its loss beyond a
restore from backup, and no recovery from its compromise beyond offboarding the node or SV. Backup,
share refresh, key ceremonies and migration are in scope precisely because the blast radius is
total.

## License and warranty

Rütli is open source under the [Apache License, Version 2.0](LICENSE). See [NOTICE](NOTICE) for
attributions.

- **No warranty.** The software is provided "AS IS", without warranties or conditions of any kind
  (Apache-2.0, section 7). You are responsible for deciding whether it is fit to protect your keys.
- **No liability.** No contributor is liable for damages arising from its use, including the loss
  or compromise of keys or funds (Apache-2.0, section 8).
- **Best-effort process.** The reporting process above is our commitment to handle reports
  responsibly. It is not a service-level agreement.
- **Contributions,** including security fixes, are accepted under the same license (Apache-2.0,
  section 5).
- **Not affiliated with Digital Asset.** Canton and the Canton KMS Driver API are projects of
  Digital Asset and are used under their own licenses.
