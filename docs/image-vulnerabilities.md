<!--
Copyright 2026 StakeCraft LLC
SPDX-License-Identifier: Apache-2.0
-->

# Vulnerabilities in the cosigner image

What the scanner (trivy, `scripts/quality/image.sh`) reports for `ghcr.io/stakecraft/rutli-cosigner`,
where it comes from, and what is done about it. Numbers are distinct advisory ids by severity, from a
scan on 2026-11-24 of the 0.4.0 image, which has the same base as `frost/Dockerfile` pins today.

| Severity | Found | Fixed by a Debian update | Left |
|---|---:|---:|---:|
| critical | 0 | 0 | 0 |
| high | 14 | 1 | 13 |
| medium | 49 | 14 | 35 |

## Where it comes from

All of it is in the Debian packages of the runtime base (`debian:stable-slim`, trixie); the scan finds
none in the Rust binary. The TLS stack is compiled into the binary (rustls, aws-lc-rs), so OpenSSL is
not a dependency of the daemon; it is in the image because the slim base ships it.

- **Has a fix in Debian's security repository** (libc 2.41-12+deb13u5, zlib 1.3.1-1+deb13u1): applied
  by `apt-get upgrade` in the runtime stage of `frost/Dockerfile`. The pinned base is a snapshot and
  does not have these yet.
- **Has no fix** (status `affected` or `fix_deferred` in the Debian tracker): util-linux and its
  libraries (`mount`, `login`, `libmount1`, …), OpenSSL (`libssl3t64`), SQLite, perl-base, tar, ncurses,
  systemd's libraries, PAM. The daemon links none of them (rustls and aws-lc-rs instead of OpenSSL; no SQLite,
  no PAM); they are in the image because the slim base ships them.

## Reproducibility

The `apt-get upgrade` takes whatever Debian's security repository holds on the day of the build, so
two builds of the same commit can differ in a few packages; before, the digest pin made the base the
same every time. The release image is the thing that is identified (its digest, with the SBOM and
the provenance attached by the release job, which list the package versions that went in), not the
Dockerfile. If bit-for-bit rebuilds matter more than the two libraries, the alternative is to
bump the base digest when a fix lands (Dependabot proposes it monthly) and leave `upgrade` out.

## What would remove the rest

A runtime base that does not ship them, for example `gcr.io/distroless/cc-debian13` (the C library and
libgcc, no shell, no package manager; which libraries the binary needs is to be checked with `ldd`).
That changes the image contract, so it is a decision and not part of this change: no shell for `kubectl exec`, a different uid and `/data` ownership,
and the file layout of the volume would have to be checked against the Helm chart and the compose
files. Until then the findings above stay, and the count that matters is the one the nightly quality
run records for each release (`image.trivy.*` in `quality/baseline.json`).

## Checking

`Image build check` scans the amd64 image it builds on every pull request that touches `frost/` and
prints the same table in the job summary (report only, it does not fail the build). To scan a released
image by hand:

```bash
scripts/quality/install-tools.sh "$HOME/.cache/rutli-quality-tools" trivy
QUALITY_IMAGE=ghcr.io/stakecraft/rutli-cosigner:0.4.0 scripts/quality/collect.sh --only image
```
