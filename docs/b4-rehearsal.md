# B4: cutover rehearsal, a JCE validator moved into Rütli (DevNet plan)

**Status:** plan, ready for review, 2026-10-09. **Roadmap item:** B4 in [roadmap-migration.md](roadmap-migration.md).
**Output:** a proven run of [migration.md](migration.md), the pilot runbook, and its corrections.
**Who runs it:** the operator (Alex) runs every command marked **[MUTATES]**. Claude prepares and reads only
(`kubectl get/describe/logs`, `helm get/list/status/template`). "Seen 2026-10-09" values come from a read-only
inspection on that date. Record them again on the day.

**Shape, in one paragraph.** We onboard a fresh **scratch validator with keys in Postgres (JCE)** on DevNet in
namespace `stakecraft-devnet-rutli-b4`. It is plain Splice 0.9.0, deployed with the NAAS `deploy.sh --skip-kms`.
We carry over **only its namespace key**: Canton `ExportKeyPair` with a password, then the B2 split ceremony
([split-ceremony.md](split-ceremony.md)) into the existing soak cosigner cluster in namespace `rutli`, under the id
`b4-frost-import-<fp8>`. A **new participant** in the same namespace, on a fresh DB, uses driver
`frost.key-prefix = "b4-"`. It registers that key by id and gets **fresh** keys: a signing key by FROST DKG and an
ECIES encryption key hosted by the cluster. It initialises under the **same namespace with a new UID**, publishes
an OTK, connects, and then Splice re-onboards it with a dump, `newParticipantIdentifier` and `migrateValidatorParty`.
This is the B0 shape ([b0-cutover-spike.md](b0-cutover-spike.md)), with every lesson from the 2026-10-09 run
applied. Then we verify (party ID unchanged, wallet, tap, transfers), destroy every copy of the old key with
evidence, and tear the scratch validator down.

---

## 0. Decisions, point of no return, verdict

### Decisions (made for this plan; reasons in one line each)

| # | Decision | Why |
|---|---|---|
| D1 | **Source:** a scratch JCE validator, `stakecraft-devnet-rutli-b4`, deployed with the NAAS `deploy.sh --skip-kms`. Party hint = node identifier = `stakecraft-rutli-b4-1`. | This is the shape a StakeCraft-hosted pilot validator has, including the 4-hourly `pg_dumpall` to a PVC and S3, so the destruction inventory is realistic. Hint = node identifier is the Splice default and the case B0 proved (admin party, PNR at trust-certificate removal). |
| D2 | **Target:** the soak cluster, `rutli`. The new participant uses `frost.key-prefix = "b4-"`. | The soak cluster already serves `frost-namespace`/`frost-signing`. Routing is strict on the prefix, so ids stay disjoint (`FrostKeyIds.scala:37-66`). A prefix is a namespace, not an authorisation boundary: both participants use CN `driver` and share one trust domain (`architecture.md`, *One cluster, several participants*). That is fine for DevNet. A pilot gets its own cluster or its own driver CN. |
| D3 | **Carried over: the namespace key only.** Signing gets a fresh FROST DKG (`b4-frost-signing`); encryption gets a fresh hosted key. | The namespace is the only key whose loss changes identity. A signing or encryption key is per participant, and the new participant is a new member anyway. B3 (RSA import) is **dropped**: the encryption key need not be carried. |
| D4 | **Encryption: ECIES (EC P-256), not RSA.** | (a) Every JCE node, the source included, already runs ECIES, and the Global Synchronizer admits it. (b) This is the build pilots will get (main = 0.3.2 + B2 + C). Rehearsing with RSA would leave the shipped ECIES path untested on a live network, because the soak itself runs RSA. (c) The cost is contained. Creating an EC key needs all 3 cosigners up and upgraded (`hosted-keys.md` §2), which Phase 0 ensures. If ECIES fails at key generation or crypto init, the fallback is RSA (drop two config lines) **before the PNR**, at zero cost. |
| D5 | **Cosigner TLS: `perNode`** (chart default), migrated from the shared Secret in its own rollout (0.5 Step A) **before** the image changes. | Pilots get `perNode`, and the migration procedure (`deploy/k8s/README.md`) has never run on a live cluster. The soak is exactly the "≤ 0.3.x install" it describes. For the ceremony itself, `shared` would be as good: either way `tls-select` leaves each cosigner container with only its own key. That makes the choice cheap to reverse. We keep `rutli-cosigner-tls`, so `helm rollback rutli 4` works until v0.4.0 final. |
| D6 | **Release: `v0.4.0-rc.1`** (SemVer pre-release) for image, chart, driver and dealer. Final `v0.4.0` comes after B4 GO. | Main is unreleased (0.3.2 + B2 + C), and the soak cluster must run a tagged, digest-pinned build. Two release fixes come first (0.3 R1/R2): `publish-image.yml` would also push `latest` for an rc tag, and `CHANGELOG.md` Unreleased has no B2 entry. |
| D7 | **The new participant reuses the Helm release `participant`, on a fresh DB `participant_b4`.** | This is the B0 shape. The Service name `participant` that the validator points at stays, the old DB `participant_1` is never written again, and R-A is a `helm rollback`. |
| D8 | **Splice dump: built from the console, key-free.** We never call the old validator's `GET /admin/participant/identities` (or `/admin/domain/data-snapshot`). | On a JCE node, both endpoints return the plaintext private keys (`NodeIdentitiesDump.KeyPair`), which would be one more copy (L6). Splice 0.9.0 reads a dump's `keys` only in `importKeysFromDump`. It runs only if the participant is **not** yet initialised (`initializeFromDumpAndWait` → `ensureThatB(isNodeInitialized, initializeFromDump)`), and ours is initialised by hand in 4.9. The migrator reads only `dump.id` (verified against the 0.9.0 jar: `NodeInitializer` and `ParticipantPartyMigrator` bytecode; 0.5.5 source: `NodeInitializer.scala:227-312,314-344`, `ParticipantPartyMigrator.scala:53-63`). Fallback is in §7. |
| D9 | **Run `verify-key --sign-test` and `refresh` from the operator laptop**, over three `kubectl port-forward`s with the operator certificate, or the driver certificate for `refresh`. | `deploy/k8s/job-verify-key.example.yaml` targets the raw manifests. The Helm chart's ConfigMap has no `client-operator.json`, and in namespace `rutli` the chart's NetworkPolicy admits only cosigner pods (the namespace is not labelled `rutli.io/client-ns`). Port-forward bypasses NetworkPolicy. The cosigner certs carry `IP:127.0.0.1` and the shared SAN `rutli-cosigner` (seen 2026-10-09), and the client verifies against `tls.domain`. No ceremony key material lands in any cluster Secret. |
| D10 | **Dealer host: preferred** is a real live-boot USB on a spare x86 laptop, air-gapped. **Acceptable for DevNet** is a Linux VM with no network device on the operator Mac. The relaxations are stated in 0.8. | The point is to rehearse the procedure and its timing. The key is a throwaway DevNet scratch key. **User decides.** |
| D11 | **Keep the soak participant on driver 0.3.1.** The B4 participant runs the rc driver. | Driver 0.3.1 is compatible with rc cosigners (0.4). Changing two things at once on the soak would muddy its record. |

### Point of no return (PNR)

The same as B0. The validator party is the old participant's admin party (D1), so it can move only after the old
participant's trust certificate is removed, and a removed participant can never rejoin
(`TopologyMappingChecks.scala:561-566,608-617,1146-1177`).

> **PNR = validator log `Preparing to remove domain trust certificate because we will be migrating stakecraft-rutli-b4-1::…`** (4.13).
> Before it, rollback is clean: R-A, point the releases back at the untouched `participant_1` / `cantonnet_validator`.
> After it, fix forward only (R-B). **Destruction (5.4) only after GO.** Until then the old DB is the rollback path.

### Go: all of these must hold

| # | Criterion |
|---|---|
| G1 | `register_kms_signing_key("b4-frost-import-<fp8>", {Namespace})` on the new participant returns exactly `NS_FP`. |
| G2 | The fresh keys exist: one FROST DKG `b4-frost-signing` (ok), one hosted `b4-rutli-enc-encryption-<uuid>` with spec `ec-p256-ecies`. The driver advertises ECIES (`FROST: every cosigner hosts non-FROST keys (aes-256-gcm, ec-p256-ecies, rsa-2048-oaep-sha256)`). The node initialises as `PAR::<NEW_ID>::<NS_FP>`. No `frost-namespace`-style DKG is attempted. |
| G3 | The new member onboards. The trust certificate is signed via FROST `b4-frost-import-*` (driver audit), and `list_connected` is healthy. |
| G4 | The validator party `stakecraft-rutli-b4-1::<NS_FP>` is hosted only on `PAR::<NEW_ID>` (Submission, threshold 1). The old trust certificate is removed. The party ID equals the Phase 1 baseline. |
| G5 | The ACS diff is explained (as in B0 §4). No `ACS_COMMITMENT_MISMATCH` / `ACS_MISMATCH_NO_SHARED_CONTRACTS` over ≥ 2 reconciliation intervals. |
| G6 | Wallet balance = baseline ± drill activity. A tap succeeds on the new participant. A transfer out (B4 → soak validator party) and a transfer in (soak → B4) both complete. No onboarding secret is used. |
| G7 | ECIES works live: `rutli_hosted_key_ops_total{op="ecdh_derive"}` > 0, no `ecies-failure=` in the B4 driver audit, `rutli_decrypt_rate_limited_total` flat. The **soak participant** shows zero sign errors throughout every B4 window. |
| G8 | The destruction record (split-ceremony.md §8) is complete, with evidence for every location L1–L9 plus the ceremony artefacts. |

### No-go symptoms (what to write up)

| Symptom | Phase | Action |
|---|---|---|
| Any cosigner not Ready after a rollout step, or soak sign errors beyond single failovers | 0 | Roll back that step (0.5). Track B pauses. |
| Scratch validator cannot onboard (sponsor `prepare` 403, sequencer refused) | 1 | Node egress not allowlisted on DevNet (0.9). Fix placement. |
| `Remote export of private keys only allowed when preview is enabled` | 2 | The preview flag did not reach the participant (2.1). |
| Dealer refuses (fingerprint, request authentication, SAS) | 3 | split-ceremony.md §6. **Request authentication or SAS failure = treat as an attack. STOP.** |
| `register_kms_signing_key` errors, or returns a different fingerprint | 4 | STOP → R-A. This is the B2→B0 seam failing. Write it up. |
| `FAILED_PRECONDITION … does not support it` / `The configured default scheme EC-P256 not supported by the KMS` | 4 | A cosigner is not on the rc or is down. Fix it, or fall back to RSA (D4), still before the PNR. |
| Validator log `Node has no identity, generating a new one`, or `need to be rotated because of missing signatures` | 4 | Scale the validator to 0 **immediately** (before the PNR line) → R-A. |
| Migrator error after the PNR line | 4 | R-B (fix forward). Never restart the old participant. |

---

## 1. Phase 0: prerequisites

Work directory, outside the repo and outside every backup (Time Machine, iCloud):
```sh
D=~/b4-drill; mkdir -p $D/{b4,tls,ceremony,evidence} && chmod -R go-rwx $D
tmutil addexclusion $D           # macOS: the export file and driver key must not land in a Time Machine snapshot
RNS=rutli; NS=stakecraft-devnet-rutli-b4
```

### 0.1 Read-only pre-flight (seen 2026-10-09)

| What | Command | Seen 2026-10-09 |
|---|---|---|
| context | `kubectl config current-context` | `hcloud-cluster` |
| cosigner release | `helm -n rutli history rutli` | rev 4, `rutli-cosigner-0.3.2`, image `0.3.2@sha256:af38fd04…6d7d3f` |
| cosigner values | `helm -n rutli get values rutli -o yaml` | `hostedKeys.enabled: true`, `persistence.storageClassName: hcloud-volumes` (nothing else) |
| pods | `kubectl -n rutli get pods -o wide` | `rutli-cosigner-0` hel, `-1` nbg, `-2` fsn, 3/3 Ready |
| TLS Secret | `kubectl -n rutli get secret rutli-cosigner-tls -o json \| jq -r '.data\|keys[]'` | `ca.crt cosigner{1,2,3}.{crt,key} driver.{crt,key}` (shared layout) |
| cluster CA | `kubectl -n rutli get secret rutli-cosigner-tls -o jsonpath='{.data.ca\.crt}' \| base64 -d \| shasum -a 256` | `453bb4aea2088bb5b0b98c4c62a66621519dfc9bd0ae24a61eee2f2d3c12c663`, P-256, CA:TRUE, valid to 2028-10-19 |
| cosigner certs | `… cosigner1.crt … \| openssl x509 -noout -ext basicConstraints,keyUsage,extendedKeyUsage,subjectAltName` | no basicConstraints/KU/EKU. SAN `rutli-cosigner, cosigner1, cosigner-0, localhost, 127.0.0.1`. **Accepted by the dealer**: leaf not a CA, KU/EKU are checked only when present (`request_auth.rs:309-330`); P-256 supported (`request_auth.rs:108-127`) |
| cosigner backups | `kubectl -n rutli get cronjob` | `rutli-cosigner-backup` `17 3 * * *` (from `deploy/soak/k8s/cosigner-backup-exec-cronjob.yaml`, not the chart). It writes `/data/backup-<weekday>` inside each pod and ships nowhere |
| namespace labels | `kubectl get ns rutli stakecraft-devnet-rutli-01 --show-labels` | `rutli` has **no** `rutli.io/client-ns`; rutli-01 has it |
| soak participant | `helm -n stakecraft-devnet-rutli-01 list` | participant rev 5 (`participant_b0`), validator rev 3, driver 0.3.1, no key-prefix |
| node capacity | `kubectl describe node <n> \| sed -n '/Allocated resources/,/Events/p'` | memory requests: **fsn 95 %** (soak + naas-01 + validator-1), hel 34 %, nbg 66 % |
| local certs | `shasum -a 256 deploy/frost/certs/ca.crt` (MPC checkout) | `27c9e079…`: **not** the cluster CA. The CA key that signed the soak certs (July) is elsewhere (0.6) |

### 0.2 Driver 0.3.1 against 0.4.0-rc cosigners: compatible (evidence)

- `cosigner.proto` v0.3.1 → main is **additive only**. New RPCs `KeyStatus`, `CeremonySignTest`, `EcdhDerive`;
  new messages; `NodeInfoReply.hosted_key_specs = 3`. No field renumbered or removed
  (`git diff v0.3.1 origin/main -- frost/cosigner/proto/cosigner.proto`).
- Driver 0.3.1 reads `Capabilities.hosted_key_specs` into a set and only tests membership of RSA/AES
  (`v0.3.1:FrostBackend.scala:202-234`). The new `ec-p256-ecies` entry is ignored.
- The server-side changes the soak driver can meet: DKG refuses ids containing `frost-import-`, which the soak never
  uses; EC keys are created only on request; `CeremonySignTest` is rate-limited. `Sign`/`GroupKey`/`Decrypt` are unchanged.
- A 0.3.2 cosigner ignores unknown config fields (`Config` has no `deny_unknown_fields`, `v0.3.2:config.rs:9`).
  So the order Step A (layout) → Step B (image + `operator_allowlist`) is safe in both directions.
- **Rollback caveat:** once the B4 participant holds an EC key (4.8), rolling the cosigners back below the rc
  takes the B4 participant down (a 0.3.x cosigner cannot serve EC keys). The soak participant is unaffected.

### 0.3 Release candidate `v0.4.0-rc.1` (operator merges, tags and publishes; Claude prepares the PRs)

| # | Step | Expect | STOP if |
|---|---|---|---|
| R1 | PR: in `publish-image.yml`, make `latest` skip pre-releases: `type=raw,value=latest,enable=${{ startsWith(github.ref, 'refs/tags/v') && !contains(github.ref_name, '-') }}`. Without it, the tag push re-publishes `latest` as the rc. (`{{major}}.{{minor}}` is already skipped for pre-releases by `docker/metadata-action`.) | merged | — |
| R2 | PR "chore(release): v0.4.0-rc.1": `frost/Cargo.toml` workspace version, `build.sbt` `ThisBuild / version`, `Chart.yaml` `version`/`appVersion` → `0.4.0-rc.1`. `CHANGELOG.md`: add the **missing B2 entries** (split ceremony, `rutli-dealer`, `share-recipient`/`recipient-sas`/`import-share`/`abort-import`/`verify-key`, operator role, `KeyStatus`/`CeremonySignTest` + rate limit, `tls.layout`/`tls-select`, `operatorAllowlist`) and cut a `[0.4.0-rc.1]` section. Note the chart default `tls.layout: perNode` as an upgrade step. | CI green (`ci.yml`) | CI red |
| R3 | **[MUTATES]** GitHub → Actions → *Publish cosigner image* → *Run workflow* on the R2 commit, input `tag` = `0.4.0-rc.1` (the 0.3.2 pattern: pin first, tag second). | `ghcr.io/stakecraft/rutli-cosigner:0.4.0-rc.1`, multi-arch. Record `DIGEST_RC` = index digest (`docker buildx imagetools inspect …:0.4.0-rc.1`) | build fails |
| R4 | PR "chore(deploy): pin the 0.4.0-rc.1 cosigner image by digest": `values.yaml` `image.tag: "0.4.0-rc.1@sha256:<DIGEST_RC>"`, README. Bump `deploy/k8s/job-verify-key.example.yaml` and `cronjob-refresh.yaml` to the same pin. | merged | — |
| R5 | **[MUTATES]** `git tag -a v0.4.0-rc.1 <R4 commit> -m "v0.4.0-rc.1"` and push. GitHub release **marked pre-release**. The workflow re-runs on the tag: the tag `0.4.0-rc.1` may get a new digest, the pin keeps `DIGEST_RC`, and `latest` does not move (R1). | release page | `latest` moved |
| R6 | Build the artefacts from the tag and attach them with their `sha256` to the release: `sbt driver/assembly` → `driver/target/scala-2.13/rutli-driver.jar` (log line `Loaded driver rutli (API v1) build 0.4.0-rc.1`), and `rutli-dealer` for Linux (0.7) | sha256 recorded | — |
| R7 | Record `JAR_SHA`, `DEALER_SHA`, `DIGEST_RC` in the soak log | — | — |

### 0.4 Operator certificate (operator: needs the cluster CA key)

The soak certs were issued in July by a CA whose key is **not** the local `deploy/frost/certs/ca.key` (0.1). **The user
provides the July `ca.key`.** Check that it matches before using it:
```sh
CA=<dir holding the July ca.key>
kubectl -n rutli get secret rutli-cosigner-tls -o jsonpath='{.data.ca\.crt}' | base64 -d > $D/tls/ca.crt   # public; the cluster's exact CA bytes
diff <(openssl pkey -in $CA/ca.key -pubout) <(openssl x509 -in $D/tls/ca.crt -pubkey -noout) && echo CA-KEY-MATCHES
cd $D/tls
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout operator.key -out operator.csr -subj "/CN=operator/O=rutli"
openssl x509 -req -in operator.csr -CA ca.crt -CAkey $CA/ca.key -CAcreateserial -out operator.crt -days 30 \
  -extfile <(printf 'subjectAltName=DNS:operator\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n')
openssl pkcs8 -topk8 -nocrypt -in operator.key -out operator.pk8 && mv operator.pk8 operator.key && rm -f operator.csr ca.srl && chmod 600 operator.key
```
This is the same profile as `scripts/gen-frost-certs.sh:26-40`, with 30 days of validity. The CN `operator` goes on `operatorAllowlist` (0.5 Step B).
**If the July CA key is lost:** leave `operatorAllowlist` empty and run `verify-key` with the driver certificate. The
code allows it (`service.rs:63-68`, `authorize_either`), but the operator role goes unrehearsed: record that as a gap. Do not re-issue
the cluster PKI for B4.

### 0.5 Cosigner rollout on the soak cluster: two steps, each its own planned soak event

Use a checkout of **main** for Step A (its chart still pins the 0.3.2 image) and the **`v0.4.0-rc.1`** tag for Step B.
Rolling with PDB `minAvailable: 2`, signing continues on 2-of-3 (as in the 0.3.2 rollout, soak log 2026-10-09).

**Step A: TLS layout `shared` → `perNode`, image unchanged (rev 5).**
```sh
helm -n rutli get values rutli -o yaml > $D/rutli-values.pre-b4.yaml
kubectl -n rutli get secret rutli-cosigner-tls -o jsonpath='{.data.ca\.crt}' | base64 -d > $D/tls/ca.crt
shasum -a 256 $D/tls/ca.crt                                             # 453bb4ae…c663
kubectl -n rutli create secret generic rutli-cosigner-ca --from-file=ca.crt=$D/tls/ca.crt            # [MUTATES]
for i in 1 2 3; do                                                                                      # [MUTATES]
  kubectl -n rutli get secret rutli-cosigner-tls -o jsonpath="{.data.cosigner$i\.crt}" | base64 -d > $D/tls/c.crt
  kubectl -n rutli get secret rutli-cosigner-tls -o jsonpath="{.data.cosigner$i\.key}" | base64 -d > $D/tls/c.key
  kubectl -n rutli create secret tls rutli-cosigner-tls-$i --cert=$D/tls/c.crt --key=$D/tls/c.key
done; rm -f $D/tls/c.crt $D/tls/c.key
# driver cert for the B4 bundle (4.0); delete from the laptop right after 4.0
kubectl -n rutli get secret rutli-cosigner-tls -o jsonpath='{.data.driver\.crt}' | base64 -d > $D/tls/driver.crt
kubectl -n rutli get secret rutli-cosigner-tls -o jsonpath='{.data.driver\.key}' | base64 -d > $D/tls/driver.key; chmod 600 $D/tls/driver.key
helm template rutli deploy/helm/rutli-cosigner -n rutli -f $D/rutli-values.pre-b4.yaml | kubectl diff -n rutli -f -
helm -n rutli upgrade rutli deploy/helm/rutli-cosigner -f $D/rutli-values.pre-b4.yaml                 # [MUTATES]
kubectl -n rutli rollout status sts/rutli-cosigner --timeout=15m
for o in 0 1 2; do kubectl -n rutli exec rutli-cosigner-$o -c cosigner -- ls /certs; done
for o in 0 1 2; do kubectl -n rutli exec rutli-cosigner-$o -c cosigner -- sh -c 'sha256sum /certs/ca.crt'; done
```
| Expect | STOP / rollback |
|---|---|
| `kubectl diff`: StatefulSet only. It adds init container `tls-select`, changes the `certs` volume from a Secret to an `emptyDir` (Memory), and adds a projected `tls-src` (`rutli-cosigner-ca` + `-tls-1..3`). Chart labels change; the ConfigMap is **unchanged**. Rendered and checked against rev 4 on 2026-10-09: no other difference. | Any other object or field → STOP |
| Each pod lists exactly `ca.crt cosigner<o+1>.crt cosigner<o+1>.key`. CA sha256 is `453bb4ae…` on all three. `health` is ready. Soak `rutli_sign_requests_total{result="error"}` is flat, apart from single `UNAVAILABLE` failovers during the roll. | A pod stuck in `ContainerCreating` (missing Secret): create it and the roll continues. Anything else: `helm -n rutli rollback rutli 4` |

Do **not** delete `rutli-cosigner-tls` yet. It is the rev 4 rollback path. Delete it after v0.4.0 final (5.6).

**Step B: image → `0.4.0-rc.1` + `operatorAllowlist` (rev 6).**
```sh
git -C <rutli checkout> checkout v0.4.0-rc.1
helm template rutli deploy/helm/rutli-cosigner -n rutli -f $D/rutli-values.pre-b4.yaml --set 'operatorAllowlist={operator}' | kubectl diff -n rutli -f -
helm -n rutli upgrade rutli deploy/helm/rutli-cosigner -f $D/rutli-values.pre-b4.yaml --set 'operatorAllowlist={operator}'   # [MUTATES]
kubectl -n rutli rollout status sts/rutli-cosigner --timeout=15m
kubectl -n rutli get sts rutli-cosigner -o jsonpath='{.spec.template.spec.containers[0].image}{"\n"}'
for o in 0 1 2; do kubectl -n rutli logs rutli-cosigner-$o -c cosigner | head -20 | grep -iE 'identifier|version|share sealing|WITHOUT TLS|WARN'; done
```
| Expect | STOP / rollback |
|---|---|
| Diff: image → `0.4.0-rc.1@sha256:<DIGEST_RC>` (both containers), ConfigMap `"operator_allowlist": ["operator"]` ×3, labels. Each node logs its own identifier (1, 2, 3). No `share sealing DISABLED`, no `running WITHOUT TLS`. Soak sign errors flat. The soak participant keeps signing with driver 0.3.1. | `helm -n rutli rollback rutli 5` (returns to Step A) |

Then the soak-log entries "Planned event: cosigners to perNode TLS / to 0.4.0-rc.1" (template in 5.7).

### 0.6 What runs where (tools on the operator laptop)

- `rutli-cosigner` built **natively** from the tag: `cd frost && cargo build --release -p rutli-cosigner --bin rutli-cosigner`.
  It runs `verify-key`/`refresh` from the laptop (D9).
- Canton console: the participant image, as in B0 1.3 (`linux/amd64` only, use `--platform linux/amd64` on arm64).
  Record `IMAGE_PARTICIPANT` from `kubectl -n $NS get deploy participant -o jsonpath='{.spec.template.spec.containers[0].image}'` after Phase 1.
- `aws` CLI with read and `DeleteObjectVersion` on `canton-k8s-validators-backup` (5.4 L4). **The user provides it.**

### 0.7 Driver jar and dealer binary

- **Driver**: `rutli-driver.jar` from R6. It is copied to the B4 bundle PVC in 4.0, the way the soak did it
  (`deploy/rutli/rutli-prereqs.sh` in the NAAS repo: PVC `rutli-kms-bundle` with `rutli-driver.jar` + `certs/{ca.crt,driver.crt,driver.key}`,
  filled by a temporary pod pinned to the node, **while no participant mounts it**). Keep its sha256 next to it as `rutli-driver.jar.sha256`.
  The soak participant's bundle is not touched (D11).
- **Dealer**: `rutli-dealer` is not in the cosigner image by design (`frost/Dockerfile:8-10`). Build it in the same builder
  image as the daemon, for the dealer host's architecture:
  ```sh
  docker run --rm --platform linux/amd64 -v "$PWD/frost":/src -w /src rust:1-slim \
    cargo build --release -p rutli-cosigner --bin rutli-dealer          # linux/arm64 for an arm64 VM
  shasum -a 256 frost/target/release/rutli-dealer                       # DEALER_SHA, also in the release
  ```
  The `rust:1-slim` glibc must not be newer than the dealer OS. A current Debian stable live image matches.

### 0.8 Dealer host and what DevNet relaxes (decide before Phase 3)

split-ceremony.md §3.3 asks for an air-gapped live-boot machine, no swap, no core handler, root (for `mlockall`).

| Requirement | Preferred (real rehearsal) | DevNet relaxation (acceptable, record it) | Why the relaxation is acceptable here |
|---|---|---|---|
| Air gap | Spare x86 laptop, Wi-Fi off/removed, Debian stable live USB (verified ISO checksum) | Linux VM on the operator Mac (UTM/Lima) with **no network device**; files in via a read-only shared folder, bundles out via a second share | The key is a scratch DevNet key with no value; we rehearse the procedure, not custody |
| No swap / no core handler | `swapon --show` empty; `sysctl kernel.core_pattern` not `|…`; `fs.suid_dumpable` ≠ 2 | Same, inside the VM. **Never** `--allow-swap` / `--allow-core-handler` | The dealer enforces these itself. Keep them on, so the rehearsal shows they pass |
| Separate trust domains (key file vs seal secrets) | Dealer operator ≠ cosigner operators | One person (Alex) holds every role | DevNet only. Pilots must split them (migration.md §1) |
| ≥ 2 independent witnesses | Two people, each with their own `kubectl exec` session | One witness if available, else self-witnessed with screen recording; record it | Gate 0's tooling still runs. Only its human independence is relaxed |
| Destroy boot/transfer media | Wipe or destroy USB | Delete the VM and its disk, empty the shares | — |

### 0.9 Placement and DevNet egress (blocking, decide before Phase 1)

fsn holds the soak and two other DevNet validators at **95 % of memory requested**. A Splice validator requests about 9.5 GiB
(participant 4 Gi, validator-app 4 Gi, postgres 1 Gi, UIs 0.5 Gi), so B4 does **not** fit on fsn. hel has room (34 %), but
it hosts `rutli-cosigner-0` and monitoring. DevNet allowlists validator egress IPs (the laptop got 403 from Scan in
B0), so whichever node B4 runs on, its egress IP must be allowlisted. Check it:
```sh
kubectl run b4-egress-check -n default --rm -i --restart=Never --image=curlimages/curl:8.10.1 \
  --overrides='{"spec":{"nodeSelector":{"kubernetes.io/hostname":"agent-cx33-hel-pim"}}}' -- \
  -s -o /dev/null -w '%{http_code}\n' https://scan.sv-1.dev.global.canton.network.sync.global/api/scan/version
```
`200` → `TARGET_NODE=agent-cx33-hel-pim`. `403` → **the user decides**: allowlist hel's egress IP with the SV operators (takes days),
or free about 10 GiB of requests on fsn (e.g. lower `stakecraft-devnet-stakecraft-naas-01`; never `validator-stakecraft-validator-1`).
B4 Hetzner volumes are bound to the chosen node's location.

---

## 2. Phase 1: stand up the scratch JCE validator

### 1.1 Env overlay (operator, outside the repo)

`$D/env-stakecraft-devnet-rutli-b4.sh` (sources the operator's NAAS `env.sh` for credentials, then overrides):
```sh
source /Users/novy/novy/crypto/stakecraft/Canton/NAAS/k8s/deploy/env.sh
export NAMESPACE="stakecraft-devnet-rutli-b4"
export TENANT_ID="stakecraft-devnet-rutli-b4"
export TARGET_NODE="<0.9>" TARGET_NODE_IP="<0.9 egress IP>"
export CHART_VERSION="0.9.0"                       # env-shared.sh still says 0.5.9
export KMS_PROVIDER="none"                         # JCE: keys in Postgres
export MIGRATION_ID="1"                            # DevNet migration id on 2026-10-07; confirm no DevNet migration since
export VALIDATOR_PARTY_HINT="stakecraft-rutli-b4-1"
export VALIDATOR_NODE_NAME="stakecraft-rutli-b4-1" # = hint (D1)
export VALIDATOR_CONTACT="naas@stakecraft.com"
export SPONSOR_SV_URL="https://sv.sv-1.dev.global.canton.network.sync.global"
export SCAN_URL="https://scan.sv-1.dev.global.canton.network.sync.global"
export TOPUP_ENABLED="false"                       # true after the first tap (1.4)
export BACKUP_LOCAL_COPIES="8"                     # as on rutli-01: realistic L3
# VALIDATOR_AUDIENCE / WALLET_USER_ID: produced by --setup-auth0 (below), or reuse rutli-01's (API-only, see 1.2)
```

### 1.2 Deploy

```sh
cd /Users/novy/novy/crypto/stakecraft/Canton/NAAS/k8s/deploy
./deploy.sh --env $D/env-stakecraft-devnet-rutli-b4.sh --skip-kms --setup-auth0 --dry-run    # review every printed command
./deploy.sh --env $D/env-stakecraft-devnet-rutli-b4.sh --skip-kms --setup-auth0              # [MUTATES]
```
What it runs (from `deploy.sh`): `kubectl create namespace`; the NAAS chart `canton-validator` (secrets, DevNet
onboarding Job → sponsor `POST /api/sv/v0/devnet/onboard/validator/prepare` (`sv-internal.yaml:530`), backup CronJob
`0 */4 * * *` to PVC + S3 `canton-k8s-validators-backup/<ns>/`, ServiceMonitors); tenant Cilium policies
(`network-policies.yaml`); then Splice OCI charts `oci://ghcr.io/digital-asset/decentralized-canton-sync/helm/splice-{postgres,participant,validator}`
`--version 0.9.0` with the generated values (`participant_1`, `cantonnet_validator`, `nodeIdentifier = validatorPartyHint`,
4 Gi/8 Gi participant memory). `--setup-dns --setup-tls` add the wallet UI. They are optional: B4 drives the wallet over the API.
The NAAS identities-dump path (`MIGRATE_IDENTITIES`, `deploy.sh:492-514`) is **not** used. It also writes the Secret key
`identities.json`, but the 0.9.0 chart mounts key `content` (`splice-validator templates/validator.yaml:233-240`). File that as a NAAS bug.

### 1.3 Verify (read-only)

| Check | Command | Pass |
|---|---|---|
| Releases | `helm -n $NS list` | `canton-validator`, `postgres` / `participant` / `validator` at `0.9.0` |
| JCE, no KMS | `kubectl -n $NS get deploy participant -o yaml \| grep -c 'CRYPTO_PROVIDER_KMS\|RUTLI'` | `0` |
| Onboarded | `kubectl -n $NS logs deploy/validator-app \| grep -m1 'ValidatorLicense'`; public: `curl -s localhost:5003/api/validator/v0/validator-user` (port-forward `deploy/validator-app 5003:5003`; `validator-internal.yaml:14`) | `party_id` = `stakecraft-rutli-b4-1::1220…`. Record `VALIDATOR_PARTY`, `NS_FP` (= the part after `::`) |
| Keys in Postgres | `kubectl -n $NS exec postgres-0 -c postgres -- psql -U cnadmin -d participant_1 -tAc "select count(*), count(*) filter (where wrapper_key_id is null) from participant.common_crypto_private_keys"` | `3\|3` (namespace, signing, encryption; all plaintext) |

### 1.4 Coin, top-up, baselines

Tokens: B0 §1.2a `auth.sh` with `NS=stakecraft-devnet-rutli-b4` (Secret `splice-app-validator-ledger-api-auth`).
```sh
curl -sf -X POST localhost:5003/api/validator/v0/wallet/tap -H "authorization: Bearer $VALIDATOR_TOKEN" \
  -H 'content-type: application/json' -d '{"amount":"500"}'                                        # [MUTATES] wallet-internal.yaml:42
curl -sf localhost:5003/api/validator/v0/wallet/balance -H "authorization: Bearer $VALIDATOR_TOKEN" | jq   # :92
```
Then `TOPUP_ENABLED=true ./deploy.sh --env … --skip-kms --validator-only` **[MUTATES]**, as on the soak (`topup.enabled: true`).
Baselines: `WALLET_BALANCE`, `VALIDATOR_PARTY`, `NS_FP`, `ACS_COUNT_PRE` (console, 2.2), traffic state, the three key fingerprints
`NS_FP`/`OLD_SIG_FP`/`OLD_ENC_FP` (2.2).

### 1.5 Let it age ≥ 24 h, then take the baseline inventory (read-only)

The rehearsal wants realistic backups: ≥ 6 local `pg_dumpall` copies and their S3 objects. Then list every location L1–L9
(split-ceremony.md §3.2) into `$D/evidence/inventory-pre.md`:
- **L3:** a `postgres:15-alpine` pod mounting PVC `canton-validator-canton-validator-naas-backup` **read-only**, outside `:00–:25`
  (B0 §2 step 2 shape): `ls -l --time-style=full-iso /backups/`.
- **L4:** `aws s3api get-bucket-versioning --bucket canton-k8s-validators-backup`, `aws s3api get-object-lock-configuration --bucket …`,
  `aws s3api get-bucket-lifecycle-configuration --bucket …`, `aws s3api list-object-versions --bucket canton-k8s-validators-backup --prefix stakecraft-devnet-rutli-b4/`.
  **Object lock on = STOP**: the copies cannot be deleted before retention ends. Decide whether B4 accepts that (record the date).
- **L5:** `kubectl get volumesnapshot -A` (CRD absent = none). Hetzner Cloud has no volume snapshots, but check server backups
  for the node (Hetzner console).
- **L6:** `participantIdentitiesDumpPeriodicBackup` unset in `helm -n $NS get values validator`; `kubectl -n $NS exec deploy/validator-app -- ls -la /domain-upgrade-dump` (empty).

---

## 3. Phase 2: export the namespace key from the JCE participant

### 2.1 Enable preview on the participant (server side) [MUTATES: participant restart]

`ExportKeyPair` is refused server-side unless the **participant's** config has `features.enable-preview-commands`
(`GrpcVaultService.scala:589-597`; the flag reaches the node via `CantonConfig.scala:763`). The console flag alone is not enough.
```sh
helm -n $NS get values participant -o yaml > $D/participant-values.pre-b4.yaml
grep -c additionalEnvVars $D/participant-values.pre-b4.yaml      # expect 0; if not, merge the list by hand (Helm replaces lists)
cat > $D/participant-preview.yaml <<'EOF'
additionalEnvVars:
  - name: ADDITIONAL_CONFIG_B4_PREVIEW
    value: canton.features.enable-preview-commands = yes
EOF
CHART_PARTICIPANT=oci://ghcr.io/digital-asset/decentralized-canton-sync/helm/splice-participant
helm -n $NS upgrade participant $CHART_PARTICIPANT --version 0.9.0 -f $D/participant-values.pre-b4.yaml -f $D/participant-preview.yaml
helm -n $NS history participant     # record PARTICIPANT_REV_PREVIEW
```
Expect: the pod restarts and reconnects (`list_connected` healthy within minutes). The chart passes `additionalEnvVars` through (`splice-participant templates/participant.yaml:107`).

### 2.2 Console and key inventory (operator machine)

`kubectl -n $NS port-forward deploy/participant 5002:5002 5001:5001`. `$D/b4/remote.conf` is B0 §1.3's, with the participant
named `b4`. Start the console with the export password in the environment only:
```sh
EXPORT_PW=$(openssl rand -base64 24); echo "$EXPORT_PW" | pbcopy   # store it in the password manager now, then clear the clipboard
export EXPORT_PW LEDGER_API_TOKEN
docker run --rm -it --platform linux/amd64 -v $D/b4:/b4 -e LEDGER_API_TOKEN -e EXPORT_PW --entrypoint /app/bin/canton $IMAGE_PARTICIPANT -c /b4/remote.conf
```
```scala
import com.digitalasset.canton.crypto._
val p = b4
val NS_FP = p.id.uid.namespace.fingerprint.unwrap
p.keys.secret.list().foreach { k =>
  val u = k.publicKey match { case s: SigningPublicKey => s.usage.mkString(","); case _ => "-" }
  println(s"fp=${k.id} name=${k.name} kms=${k.kmsKeyId} purpose=${k.purpose} usage=$u") }
// Expect 3 keys, kms=None on all: namespace (usage namespace), signing (usage all four), encryption (EC P-256).
val SYNC_ID = p.synchronizers.list_connected().head.physicalSynchronizerId.logical
p.topology.namespace_delegations.list(store = TopologyStoreId.Synchronizer(SYNC_ID), filterNamespace = NS_FP).foreach(println)
```
**Independent fingerprint check (witness):** `NS_FP` from the console must equal **both** (a) the party ID suffix from the
public `GET /api/validator/v0/validator-user` (1.3), served by a different process than the participant console, **and** (b) the
target key of the root namespace delegation printed above. Record `NS_FP`, `OLD_SIG_FP` and `OLD_ENC_FP`.

### 2.3 Export with a password [MUTATES: creates copy L7]

```scala
val nsk = p.keys.secret.list().filter(_.publicKey.fingerprint.unwrap == NS_FP).head
assert(nsk.name.exists(_.unwrap == "namespace"))
p.keys.secret.download_to(nsk.publicKey.fingerprint, "/b4/namespace.export", password = Some(sys.env("EXPORT_PW")))
```
`download_to` is a Preview command (`VaultAdministration.scala:509-528`; console flag in `remote.conf`). Its default protocol version
is `ProtocolVersion.latest`, the one B1's vectors use (`frost/canton-key/testdata/gen/vectors.canton:13,43-47`). Exit the
console, then `unset EXPORT_PW`. Record `shasum -a 256 $D/b4/namespace.export` as `EXPORT_SHA`. Copy the file **once** to the dealer
transfer medium (0.8) and note both copies as L7/L8. Leave preview on until 4.7 replaces these values.

---

## 4. Phase 3: split ceremony on the soak cluster

Follow [split-ceremony.md](split-ceremony.md) §3–§4 exactly. Below are only the soak-specific bindings and commands.
Node *i* = pod `rutli-cosigner-<i-1>`, config `/config/cosigner-<i>.json` (chart `statefulset.yaml`, `cosigner-$((ordinal+1)).json`).

| Parameter | Value |
|---|---|
| `FP` | `NS_FP` from 2.2 (old node + validator-user + root delegation) |
| `KEY_ID` | `b4-frost-import-${FP:4:8}`. The prefix is the B4 driver's `b4-`; the id contains `frost-import-` (`share_delivery.rs:76-99`) |
| `CEREMONY` | `b4-<yyyy-mm-dd>` |
| `t`/`n` | 2 / 3 |

### 3.0 Pre-checks [MUTATES only the suspend]

```sh
kubectl -n rutli patch cronjob rutli-cosigner-backup -p '{"spec":{"suspend":true}}'                       # [MUTATES]
for o in 0 1 2; do kubectl -n rutli logs rutli-cosigner-$o -c cosigner | grep -cE 'share sealing DISABLED|running WITHOUT TLS'; done   # 0 0 0
```
Laptop client configs in `$D/ceremony/` (D9; JSON, so write absolute paths, not `$D`). In `client-operator.json`, endpoints `https://127.0.0.1:1910{1,2,3}` for identifiers 1–3,
`"tls": {"ca_cert": "$D/tls/ca.crt", "cert": "$D/tls/operator.crt", "key": "$D/tls/operator.key", "domain": "rutli-cosigner"}`,
`"threshold": 2`, `"listen": "127.0.0.1:0"`, `"data_dir": "<empty tmp dir>"`, and the allowlists as in `deploy/k8s/cosigner-config.yaml` `client-operator.json`.
`client-driver.json` is the same with `driver.{crt,key}`. Port-forwards (restart them if they drop, B0 lesson):
`kubectl -n rutli port-forward pod/rutli-cosigner-0 19101:9101` (and `-1` → 19102, `-2` → 19103).
Absence check: `rutli-cosigner --config $D/ceremony/client-operator.json verify-key --key-id "$KEY_ID" --expect-fingerprint "$FP"` → the key is absent on all 3.

### 3.1 Steps (each cosigner operator, then dealer, then lead)

| # | Command | Expect | STOP if |
|---|---|---|---|
| S1 recipients | `kubectl -n rutli exec rutli-cosigner-<i-1> -c cosigner -- rutli-cosigner --config /config/cosigner-<i>.json share-recipient --key-id "$KEY_ID" --ceremony-id "$CEREMONY" --out /tmp/r<i>.json`<br>`kubectl -n rutli exec rutli-cosigner-<i-1> -c cosigner -- cat /tmp/r<i>.json > $D/ceremony/r<i>.json` | last line `SAS node <i> <16 hex>` | any error |
| Gate 0 | Witness, own session: `kubectl -n rutli exec rutli-cosigner-<i-1> -c cosigner -- rutli-cosigner --config /config/cosigner-<i>.json recipient-sas --key-id "$KEY_ID"` | same SAS as S1, written into the record | mismatch → §6 of split-ceremony.md, STOP |
| S2 split (dealer host) | `sha256sum rutli-dealer ca.crt namespace.export r1.json r2.json r3.json` (dealer = `DEALER_SHA`, export = `EXPORT_SHA`, CA = `453bb4ae…`)<br>`( IFS= read -rs EXPORT_PW && export EXPORT_PW; ./rutli-dealer split-key --in namespace.export --password-env EXPORT_PW --expect-fingerprint "$FP" --key-id "$KEY_ID" --threshold 2 --ca-cert ca.crt --recipient r1.json --recipient r2.json --recipient r3.json --out-dir out/; unset EXPORT_PW )` | `request node <i>: SAS …` ×3, a SAS prompt per node (type the Gate 0 values), group key == `FP`'s key, `out/share-$KEY_ID-node{1,2,3}.json` + `dealer-record.json`. Record the group key and pkp digest. Power off / delete the VM. | any refusal (split-ceremony.md §6). **Request authentication or SAS failure = attack, STOP** |
| S3 dry run (Gate A) | `kubectl -n rutli exec -i rutli-cosigner-<i-1> -c cosigner -- sh -c 'umask 077; cat > /tmp/share.json' < out/share-$KEY_ID-node<i>.json`<br>`kubectl -n rutli exec rutli-cosigner-<i-1> -c cosigner -- rutli-cosigner --config /config/cosigner-<i>.json import-share --in /tmp/share.json --expect-fingerprint "$FP" --dry-run` | `"outcome": "dry-run"`, `pkp_digest` = dealer's, ×3 | any difference |
| S4 install | `… import-share --in /tmp/share.json --expect-fingerprint "$FP"`, then `kubectl -n rutli exec rutli-cosigner-<i-1> -c cosigner -- rm -f /tmp/share.json /tmp/r<i>.json` | `"outcome": "installed"` ×3 | `failed authentication` → possible exposure, STOP (§6) |
| S5 verify (Gate B) | `rutli-cosigner --config $D/ceremony/client-operator.json verify-key --key-id "$KEY_ID" --expect-fingerprint "$FP" --sign-test` | `OK`, refresh count 0, digest = dealer's, quorums {1,2} {1,3} {2,3} verified | any quorum fails → abort (§7 P3) |
| S6 refresh (Gate C) | `rutli-cosigner --config $D/ceremony/client-driver.json refresh --key-id "$KEY_ID"`, then S5 again | `refresh complete — group key unchanged: …`; `verify-key` `OK`, refresh count 1, **new** pkp digest | half-applied refresh → dead-end id, re-run under `…-2` (split-ceremony.md §6) |
| S7 founding backups | `kubectl -n rutli create job --from=cronjob/rutli-cosigner-backup b4-founding-$(date -u +%Y%m%d%H%M)` + logs; then `kubectl -n rutli patch cronjob rutli-cosigner-backup -p '{"spec":{"suspend":false}}'` | `backup written to /data/backup-<day>` ×3 | job error |

Cosigner audit on the soak dashboard: `rutli_ceremony_requests_total` gains the refresh (and ceremony sign tests), with no
`result="error"`. Soak sign errors stay flat. Fill in the split ceremony record (split-ceremony.md §8) as `$D/evidence/ceremony-record.txt`.

---

## 5. Phase 4: new participant and Splice re-onboard (B0 shape)

Freeze other activity on both validators. Expected outage of the B4 party: 45–90 min (B0: 70 min, plus two key generations).
**Lessons from 2026-10-09 (B0 §3), all apply.** Port-forwards drop when idle. `p.id` is cached after `init_id`, so use
`ParticipantId(NEW_UID)`. OTK propose **without** `signedBy`. `wait_for_initialized()` only after a successful propose
(it has no timeout). `connect_by_config` takes 10–30 min while the member bootstraps about 1 M topology transactions.
`enableParticipantDbConflictCheck=false` on the new DB.

`NEW_ID = stakecraft-rutli-b4-1-mig` (it must never have existed on DevNet; checked in 4.1).

### 4.0 Rütli plumbing in the B4 namespace [MUTATES], while the JCE participant mounts none of it

Mirror NAAS `deploy/rutli/rutli-prereqs.sh` (what the soak used):
```sh
kubectl label namespace $NS rutli.io/client-ns=true --overwrite
kubectl -n stakecraft-devnet-rutli-01 get ciliumnetworkpolicy allow-egress-rutli-kms -o json \
  | jq 'del(.metadata.uid,.metadata.resourceVersion,.metadata.creationTimestamp,.metadata.generation,.metadata.managedFields,.status) | .metadata.namespace="'$NS'"' \
  | kubectl apply -f -      # egress to namespace rutli:9101; the tenant policies from deploy.sh otherwise deny it
for c in rutli-kms-bundle rutli-driver-state; do kubectl -n $NS apply -f - <<EOF
apiVersion: v1
kind: PersistentVolumeClaim
metadata: { name: $c, labels: { app.kubernetes.io/part-of: rutli } }
spec: { accessModes: [ReadWriteOnce], storageClassName: hcloud-volumes, resources: { requests: { storage: 1Gi } } }
EOF
done
kubectl -n $NS run rutli-kms-populate --restart=Never --image=docker.io/library/busybox:1.36 \
  --overrides='{"spec":{"nodeSelector":{"kubernetes.io/hostname":"'$TARGET_NODE'"},"containers":[{"name":"p","image":"docker.io/library/busybox:1.36","command":["sleep","3600"],"volumeMounts":[{"name":"b","mountPath":"/bundle"}]}],"volumes":[{"name":"b","persistentVolumeClaim":{"claimName":"rutli-kms-bundle"}}]}}'
kubectl -n $NS wait --for=condition=Ready pod/rutli-kms-populate --timeout=180s
kubectl -n $NS exec rutli-kms-populate -- mkdir -p /bundle/certs
kubectl cp <rutli>/driver/target/scala-2.13/rutli-driver.jar $NS/rutli-kms-populate:/bundle/rutli-driver.jar
for f in ca.crt driver.crt driver.key; do kubectl cp $D/tls/$f $NS/rutli-kms-populate:/bundle/certs/$f; done
kubectl -n $NS exec rutli-kms-populate -- sh -c 'sha256sum /bundle/rutli-driver.jar /bundle/certs/*'    # = JAR_SHA, CA 453bb4ae…
kubectl -n $NS delete pod rutli-kms-populate
rm -P $D/tls/driver.key       # APFS/SSD: not provable erasure; the driver key also lives in rutli-cosigner-tls and both bundles
```

### 4.1 Console inventory on the old participant (read-only, keep this session open until 4.10)

As B0 §1.4, with these names: `val p = b4`; `OLD_UID`; `ALIAS`/`syncCfg`/`SYNC_ID`; `VALIDATOR_PARTY = PartyId.tryFromProtoPrimitive("stakecraft-rutli-b4-1::" + NS_FP)`
with `assert(VALIDATOR_PARTY.uid.toProtoPrimitive == OLD_UID)`; `PARTIES_PRE` (expect only the validator party); hosting (1 participant, Submission);
`ACS_COUNT_PRE`; `NEW_ID` checks (trust certificate list and party list empty for `stakecraft-rutli-b4-1-mig`). Write the identity snapshot as
`/b4/identity-authorized.bin` (`export_topology_snapshotV2`, NamespaceDelegation + OwnerToKeyMapping, filter `NS_FP`; `TopologyAdministrationGroup.scala:810`).

### 4.2–4.14 Cutover

| # | Step | Command | Expect / verify | STOP if |
|---|---|---|---|---|
| 4.2 | **[MUTATES]** R-A safety net: manual `pg_dumpall` and cosigner backup. This creates one more plaintext copy; it goes on the destruction list. | `JOB=b4-pre-cutover-$(date -u +%Y%m%d%H%M); kubectl -n $NS create job --from=cronjob/canton-validator-canton-validator-naas-backup $JOB && kubectl -n $NS wait --for=condition=complete job/$JOB --timeout=45m && kubectl -n $NS logs job/$JOB \| tail -25`<br>`kubectl -n rutli create job --from=cronjob/rutli-cosigner-backup b4-pre-cutover-cosign` | `SHA-256` (record `BACKUP_SHA`), `S3 verification: OK`, `Backup Complete`; cosigner `backup written` ×3 | `ERROR` |
| 4.3 | **[MUTATES]** Stop the validator app | `kubectl -n $NS scale deploy/validator-app --replicas=0 && kubectl -n $NS wait --for=delete pod -l app=validator-app --timeout=5m` | no pod | lingers |
| 4.4 | **[MUTATES]** Quiesce, reference ACS | `p.synchronizers.disconnect_all()`; `val T_STOP = java.time.Instant.now; val END_OLD = p.ledger_api.state.end()`; `p.repair.export_acs(parties = Set(VALIDATOR_PARTY), ledgerOffset = END_OLD, exportFilePath = "/b4/acs-old.gz")` (`ParticipantRepairAdministration.scala:276`) | `acs-old.gz` non-empty | export error |
| 4.5 | **[MUTATES]** Stop the old participant | `kubectl -n $NS scale deploy/participant --replicas=0 && kubectl -n $NS wait --for=delete pod -l app=participant --timeout=5m` | **zero** participant pods; `participant_1` never written again | any pod |
| 4.6 | Write the B4 participant overlay `$D/participant-b4.yaml` (below) | `diff` against the pre values: only `persistence.databaseName`, `persistence.enableParticipantDbConflictCheck`, `pod.labels`, `additionalEnvVars` (replaces the preview var), `extraVolumes`, `extraVolumeMounts` | anything else |
| 4.7 | **[MUTATES]** New participant on a fresh DB | `helm -n $NS upgrade participant $CHART_PARTICIPANT --version 0.9.0 -f $D/participant-values.pre-b4.yaml -f $D/participant-b4.yaml`; restart the port-forward | `pg-init`: `create database participant_b4`. Log: `Loaded driver rutli (API v1) build 0.4.0-rc.1`, `FROST: every cosigner hosts non-FROST keys (aes-256-gcm, ec-p256-ecies, rsa-2048-oaep-sha256)` (`FrostBackend.scala:392`). `p.health.status` → `WaitingForId`; `p.keys.secret.list()` empty | driver error; ECIES not advertised; DB env not `participant_b4` |
| 4.8 | **[MUTATES]** Register the imported namespace key by id, then mint the fresh keys | `val nsK = p.keys.secret.register_kms_signing_key("<KEY_ID>", Set(SigningKeyUsage.Namespace), "namespace")`; `assert(nsK.fingerprint.unwrap == NS_FP)` (**G1**; `VaultAdministration.scala:178`, `KmsPrivateCrypto.scala:78-104`)<br>`val sigK = p.keys.secret.generate_signing_key("signing", Set(SigningKeyUsage.Protocol, SigningKeyUsage.SequencerAuthentication, SigningKeyUsage.ProofOfOwnership), Some(SigningKeySpec.EcCurve25519))` (`:119`) → DKG `b4-frost-signing`<br>`val encK = p.keys.secret.generate_encryption_key("encryption", Some(EncryptionKeySpec.EcP256))` (`:153`) → hosted `b4-rutli-enc-encryption-<uuid>` | 3 keys listed with `kms=Some(b4-…)`. Audit: `getPublicKey` for `KEY_ID`, one DKG ok, one hosted `generate` with spec `ec-p256-ecies` (**G2**) | fingerprint mismatch → R-A. `FAILED_PRECONDITION … does not support it` → a cosigner is old or down; fix it, or fall back to RSA (D4: remove the two `encryption.*` lines, re-run 4.7 on a **fresh** DB `participant_b4r`. On it, **register** `KEY_ID` and the already-minted `b4-frost-signing` by id, because a second `generate_signing_key("signing")` would hit the DKG's `ALREADY_EXISTS`. Generate only the encryption key) |
| 4.9 | **[MUTATES]** Init under the existing namespace, root delegation, OTK | `val NEW_UID = UniqueIdentifier.tryCreate(NEW_ID, NS_FP)`; `p.topology.init_id_from_uid(NEW_UID)` (`TopologyAdministrationGroup.scala:236`); `p.health.wait_for_ready_for_node_topology()`; `p.topology.transactions.import_topology_snapshot_fromV2("/b4/identity-authorized.bin", TopologyStoreId.Authorized)` (`:450`); `p.topology.owner_to_key_mappings.propose(member = ParticipantId(NEW_UID), keys = NonEmpty(Seq, sigK, encK))` (`:1864`; **no `signedBy`**); then `p.health.wait_for_initialized()` | `PAR::stakecraft-rutli-b4-1-mig::<NS_FP>`. Audit: `sign keyId=<KEY_ID>` ok and `sign keyId=b4-frost-signing` ok (proof of ownership) | rejection → R-A (nothing is on the synchronizer yet) |
| 4.10 | **[MUTATES]** Onboard the new member | `p.synchronizers.connect_by_config(syncCfg)` (`ParticipantAdministration.scala:2436`); `p.synchronizers.list_connected()`; `p.topology.synchronizer_trust_certificates.list(store = Some(TopologyStoreId.Synchronizer(SYNC_ID)), filterUid = NEW_ID)` | after 10–30 min: connected, trust certificate present (**G3**) | `…has rejected our on-boarding attempt` / `…previously been offboarded` → R-A |
| 4.11 | **[MUTATES]** Key-free dump Secret (D8) | `jq -n --arg id "PAR::$OLD_UID" --arg ns "<KEY_ID>" --arg enc "<encK kms id>" --arg snap "$(base64 < $D/b4/identity-authorized.bin \| tr -d '\n')" '{id:$id, keys:[{type:"signing",keyId:$ns,name:"namespace"},{type:"signing",keyId:"b4-frost-signing",name:"signing"},{type:"encryption",keyId:$enc,name:"encryption"}], authorizedStoreSnapshot:$snap, version:"0.9.0"}' > $D/b4/dump-keyfree.json`<br>`jq -e '[.keys[]\|has("keyPair")]\|any\|not' $D/b4/dump-keyfree.json`<br>`kubectl -n $NS create secret generic participant-bootstrap-dump --from-file=content=$D/b4/dump-keyfree.json` | schema of `common-internal.yaml:72-119`; no `keyPair` anywhere; Secret key **`content`** | — |
| 4.12 | **GATE: operator decision to cross the PNR.** G1–G3 green; zero old participant pods; `acs-old.gz`; backup verified; Secret present; the validator overlay diffs against the pre values only in these keys | `helm -n $NS get values validator -o yaml > $D/validator-values.pre-b4.yaml`. Overlay `$D/validator-b4.yaml`:<br>`nodeIdentifier: stakecraft-rutli-b4-1-mig`<br>`participantIdentitiesDumpImport: {secretName: participant-bootstrap-dump, newParticipantIdentifier: stakecraft-rutli-b4-1-mig}`<br>`migrateValidatorParty: true`<br>`persistence: {databaseName: cantonnet_validator_b4}`<br>(`validatorPartyHint` stays `stakecraft-rutli-b4-1`) | — | any unchecked item |
| 4.13 | **[MUTATES] [crosses PNR]** Validator on a fresh DB with the re-onboard config | `helm -n $NS upgrade validator oci://ghcr.io/digital-asset/decentralized-canton-sync/helm/splice-validator --version 0.9.0 -f $D/validator-values.pre-b4.yaml -f $D/validator-b4.yaml`<br>`kubectl -n $NS logs -f deploy/validator-app \| grep -E 'dump\|initialized with id\|Vet\|Preparing to remove\|Unhosting\|Removing\|Hosting\|Importing ACS\|ACS import complete\|primary party\|rotated\|ERROR'` | In order: `Loading participant identities dump` → `node is initialized with id PAR::stakecraft-rutli-b4-1-mig…` (no `Uploading node keys`) → vetting → **PNR** `Preparing to remove domain trust certificate because we will be migrating stakecraft-rutli-b4-1::…` → `Removing domain trust certificate.` → `Hosting … on PAR::stakecraft-rutli-b4-1-mig…` → `Importing ACS for party ids … from scan` → `ACS import complete` → primary party set; `ValidatorLicense … already onboarded` (**G4**) | **Before the PNR line:** any ERROR, `Uploading node keys`, `Node has no identity`, or `need to be rotated` → `kubectl -n $NS scale deploy/validator-app --replicas=0` **immediately** → R-A. **After it:** R-B |
| 4.14 | **[MUTATES]** Normalise | overlay `$D/validator-b4-final.yaml` = 4.12 without `participantIdentitiesDumpImport`/`migrateValidatorParty`; `helm -n $NS upgrade validator … -f validator-values.pre-b4.yaml -f validator-b4-final.yaml`; `kubectl -n $NS delete secret participant-bootstrap-dump` | `Party migration already complete` or a normal init. (The upgrade also drops `deploy.sh`'s validator probe patch; B0 ran on the chart defaults, 60 s / 5.) | a re-migration attempt |

`$D/participant-b4.yaml` (the soak participant's KMS block, `helm -n stakecraft-devnet-rutli-01 get values participant`, plus the prefix and the
ECIES lines from `hosted-keys.md` §2 / `scripts/e2e-ecies-hosted.sh:153-167`):
```yaml
persistence: { databaseName: participant_b4, enableParticipantDbConflictCheck: false }
pod: { labels: { rutli.io/client: "true" } }
additionalEnvVars:
  - { name: EXTRA_CLASSPATH, value: /app/rutli-driver.jar }
  - name: ADDITIONAL_CONFIG_RUTLI_KMS
    value: |
      canton.participants.participant.crypto {
        provider = kms
        kms {
          type = driver
          name = "rutli"
          config = {
            backend = "frost"
            audit-logging = true
            audit-log-path = "/rutli-state/audit.jsonl"
            signing-journal = { dir = "/rutli-state/journal" }
            frost = {
              endpoints = [
                "rutli-cosigner-0.rutli-cosigner.rutli.svc.cluster.local:9101",
                "rutli-cosigner-1.rutli-cosigner.rutli.svc.cluster.local:9101",
                "rutli-cosigner-2.rutli-cosigner.rutli.svc.cluster.local:9101"
              ]
              hosted-keys = true
              delegate = "none"
              key-prefix = "b4-"
              tls = { ca-cert = "/rutli-certs/ca.crt", cert = "/rutli-certs/driver.crt", key = "/rutli-certs/driver.key", domain = "rutli-cosigner" }
            }
          }
        }
        signing.keys.default          = ec-curve-25519
        signing.algorithms.default    = ed-25519
        encryption.keys.default       = ec-p-256
        encryption.algorithms.default = ecies-hkdf-hmac-sha-256-aes-128-cbc
      }
extraVolumeMounts:
  - { name: rutli-kms, mountPath: /app/rutli-driver.jar, subPath: rutli-driver.jar }
  - { name: rutli-kms, mountPath: /rutli-certs, subPath: certs }
  - { name: rutli-state, mountPath: /rutli-state }
extraVolumes:
  - { name: rutli-kms, persistentVolumeClaim: { claimName: rutli-kms-bundle } }
  - { name: rutli-state, persistentVolumeClaim: { claimName: rutli-driver-state } }
```
Why this signing usage: it is least privilege, no `Namespace` (Splice's own TODO at `NodeInitializer.scala:72` questions `All`). It includes
`ProofOfOwnership`, which Splice requires to keep the key in the OTK (B0 §1.2), and it is not an invalid combination (`Signing.scala:783-790`).
If Canton rejects it, use `SigningKeyUsage.All` (the soak's) before the PNR.

---

## 6. Phase 5: verification, destruction, teardown

### 5.1 Verification (G4–G7)

Use B0 §4's table with `NEW_ID`, `VALIDATOR_PARTY`, `acs-old.gz`/`acs-new.gz` (ACS diff), commitments after ≥ 2 intervals, and validator logs
(no `Unknown secret`, no `ValidatorLicense not found`). Added for B4:

| Check | How | Pass |
|---|---|---|
| Party ID unchanged | `validator-user` → `party_id` | = Phase 1 `VALIDATOR_PARTY` |
| Keys | `p.keys.secret.list()` | exactly `KEY_ID` (fp `NS_FP`), `b4-frost-signing`, `b4-rutli-enc-encryption-…`; none `kms=None` |
| Wallet | `wallet/balance` | `WALLET_BALANCE` ± activity |
| **[MUTATES]** Tap | `wallet/tap` `{"amount":"10"}` | succeeds (submission signed by FROST `b4-frost-signing`) |
| **[MUTATES]** Transfers | `POST /api/validator/v0/wallet/transfer-offers` (`wallet-external.yaml:10,213-250`: `receiver_party_id`, `amount`, `description`, `expires_at` µs, `tracking_id`) B4 → soak party `stakecraft-rutli-soak-1::12203286…`, accept in the soak wallet; then soak → B4, accept on B4 (`/transfer-offers/{cid}/accept`, `wallet-internal.yaml:359`) | both complete (**G6**) |
| ECIES live | Grafana `sum(increase(rutli_hosted_key_ops_total{op="ecdh_derive"}[1h]))`; `kubectl -n $NS exec deploy/participant -- grep -c 'ecies-failure=' /rutli-state/audit.jsonl` | > 0; 0 (**G7**) |
| Soak untouched | soak `rutli_sign_requests_total{result="error"}` over every B4 window; soak-check next day | 0; green |
| FROST | `grep -c 'sign keyId=<KEY_ID>.*outcome=ok' /rutli-state/audit.jsonl` (driver file audit; stdout rotates, B0 gap) | ≥ 4 (OTK, trust certificate, admin party mapping removal, old trust certificate removal, new hosting) |

Observation window: **≥ 24 h**, two `soak-check` runs green, before 5.4. Optionally ≥ 72 h as a live ECIES soak (user decides).

### 5.2 Optional: remove the old member's OTK (topology hygiene)

The migrator removes the old trust certificate, not the old OTK, which still lists `OLD_SIG_FP`/`OLD_ENC_FP`. From the **new** participant
(namespace-signed via FROST): `val o = p.topology.owner_to_key_mappings.list(store = Some(TopologyStoreId.Synchronizer(SYNC_ID)), filterKeyOwnerUid = OLD_UID).head`,
then `p.topology.owner_to_key_mappings.propose(member = o.item.member, keys = o.item.keys, ops = TopologyChangeOp.Remove, store = TopologyStoreId.Synchronizer(SYNC_ID))`.
**Unverified on a removed member. Record the outcome; it is not a STOP.**

### 5.3 GO declaration

G1–G7 green → GO, recorded in the soak log. Only now does destruction start.

### 5.4 Destruction inventory, with evidence (L-numbers from split-ceremony.md §3.2)

Every row: the "before" listing, the action, the "after" listing, saved under `$D/evidence/` and summarised in the destruction record
(split-ceremony.md §8). The old **signing and encryption** keys sit in the same rows and copies and go with them.

| # | Location (B4) | Action **[MUTATES]** | Evidence |
|---|---|---|---|
| L1 | `participant_1.participant.common_crypto_private_keys` (3 plaintext rows) | `kubectl -n $NS exec postgres-0 -c postgres -- psql -U cnadmin -d postgres -c 'DROP DATABASE participant_1'` (the old participant can never run again after the PNR). Also `DROP DATABASE cantonnet_validator` (old validator store, no keys, hygiene) | before: row count `3\|3` (1.3); after: `select datname from pg_database` without `participant_1` |
| L2 | WAL in `pg-data-postgres-0` | `SHOW archive_mode` (expect `off`), no replicas. `CHECKPOINT; SELECT pg_switch_wal();` ×3 so the segments recycle. The volume blocks remain until 5.6 deletes the volume | outputs |
| L3 | backup PVC: every `pg_dumpall-*.sql.gz` (+ `.sha256`) with a timestamp ≤ the DROP (Phase 1 copies, 4.2's copy, every 4-hourly copy until the DROP) | one-off `postgres:15-alpine` pod mounting the PVC **read-write** outside `:00–:25`; `rm` the listed files. Then let the next scheduled run complete and check it with B0 §2 step 2's content check | before/after `ls`; new dump: no `participant_1`, `private_keys` rows 0 |
| L4 | S3 `canton-k8s-validators-backup/stakecraft-devnet-rutli-b4/` (`pg_dumpall-*.sql.gz.enc`, `manifest-*.json`; AES-256-CBC under a passphrase, so still the key) | for every **version and delete marker** with `LastModified` ≤ the DROP: `aws s3api delete-object --bucket … --key <k> --version-id <v>` | `list-object-versions` before/after; versioning + lock state (1.5) |
| L5 | snapshots | none expected (1.5) | listings |
| L6 | identities dumps | **none were made** (D8): no call to `/admin/participant/identities`. `dump-keyfree.json` has no keys (delete it as hygiene). `/domain-upgrade-dump` empty | `jq` check output (4.11); `ls` |
| L7 | export file: laptop `$D/b4/namespace.export` + the transfer copy | `rm`; note "APFS/SSD, not provable erasure" | `ls` |
| L8 | operator laptop: `$D/` (excluded from Time Machine in Phase 0), shell history (the password was never typed on a command line), the console container (`--rm`), clipboard | delete `$D/b4/*` except evidence; `docker ps -a` shows no console container | statement |
| L9 | dealer media | delete the VM and its disk, or wipe the USB | statement |
| — | ceremony artefacts | `out/` bundles (dead after install), `r<i>.json` (public), pod `/tmp` (removed in S4) | `ls` in pods: no `/tmp/share.json` |
| — | pre-refresh cosigner backups | none expected (CronJob suspended S0–S7). Check `kubectl -n rutli exec rutli-cosigner-<o> -c cosigner -- ls -la --time-style=full-iso /data/` (no `backup-*` modified between S4 and S6) | listing |

State the residue plainly in the record. Hetzner volume deletion, S3 deletion and SSD `rm` are not provable erasure, and the key existed
whole on the participant host for the life of the scratch validator.

### 5.5 Cluster residue (by design, record it)

`KEY_ID`, `b4-frost-signing` and `b4-rutli-enc-encryption-…` stay on the cosigners. FROST keys have no delete path (the driver refuses
`deleteKey` for FROST; there is no generic destroy, by design). The prefix `b4-` is burned. Retiring the files by hand (as with the July shares,
soak log day 0) is optional and needs a cosigner restart.

### 5.6 Teardown and offboarding (user decides when, after the observation window)

1. **[MUTATES]** Optional: send the B4 wallet's CC to the soak validator party (transfer offer).
2. **[MUTATES]** Offboard the B4 member so it does not hold back sequencer pruning (`SequencerPruningStatus.scala:162-185`). From the B4
   participant: `p.topology.synchronizer_trust_certificates.propose(ParticipantId(NEW_UID), SYNC_ID, store = Some(TopologyStoreId.Synchronizer(SYNC_ID)), change = TopologyChangeOp.Remove)`
   (`TopologyAdministrationGroup.scala:2576-2600`). It is signed by the FROST namespace key, one last exercise of the imported key.
3. **[MUTATES]** `./destroy.sh --env $D/env-stakecraft-devnet-rutli-b4.sh` (plus `--teardown-all` for the Auth0/DNS/TLS from 1.2). PVs are
   `Delete` (seen on rutli-01), so the Hetzner volumes go. Check that `kubectl get pv | grep rutli-b4` is empty.
4. **[MUTATES]** Purge the remaining S3 prefix `stakecraft-devnet-rutli-b4/` (all versions).
5. **[MUTATES]** Separately, after v0.4.0 final: delete `rutli-cosigner-tls` in `rutli` (the rev 4 rollback path; it also holds a copy of the driver key).

### 5.7 Soak-log entry templates

```markdown
**Planned event: cosigners to perNode TLS (chart main, image 0.3.2), HH:MM → HH:MM.** helm rev 5; diff = StatefulSet only
(tls-select, certs emptyDir, tls-src projected); each pod sees only its own key (`ls /certs`); CA sha256 453bb4ae… on all three;
sign failovers <n> (UNAVAILABLE), errors 0. Rollback kept: `helm -n rutli rollback rutli 4` (shared Secret retained).

**Planned event: cosigners to 0.4.0-rc.1, HH:MM → HH:MM.** helm rev 6, digest <DIGEST_RC>, operatorAllowlist [operator];
soak participant stays on driver 0.3.1; sign errors 0. Rollback: `helm -n rutli rollback rutli 5`.

**Planned event: B4 cutover rehearsal, <date> (B4 party unhosted <n> s, B4 wallet down ~<n> min). Soak participant unaffected.**
Runbook: [b4-rehearsal.md](b4-rehearsal.md); pilot runbook: [migration.md](migration.md).
- Source: scratch JCE validator `stakecraft-rutli-b4-1::<NS_FP>` (onboarded <date>, <n> pg_dumpall copies, <n> S3 versions at export).
- Export: ExportKeyPair with password, sha <EXPORT_SHA>; FP checked against validator-user and the root delegation.
- Split ceremony `<CEREMONY>`: KEY_ID <KEY_ID>; Gate 0 SAS ×3; dealer on <host/VM> (relaxations: <…>); group key <…>;
  Gate B (3 quorums) ✓; refresh → Gate C ✓, new digest <…>; founding backups <job>.
- Cutover: T_STOP <ts>; new participant `participant_b4`, driver 0.4.0-rc.1, ECIES advertised; G1 <KEY_ID> → <NS_FP> ✓;
  fresh keys b4-frost-signing (DKG) + <enc id> (ec-p256-ecies); init PAR::stakecraft-rutli-b4-1-mig::<NS_FP>; onboarded <ts>
  (bootstrap <n> min); key-free dump; PNR <ts>; old trust cert removed <ts>; hosted on new <ts>; ACS import <n>; licence found.
- G5 ACS diff <…>; mismatches 0. G6 balance <before> → <after>; tap ✓; transfer out ✓ in ✓. G7 ecdh_derive <n>, ecies failures 0;
  soak sign errors 0.
- Destruction <date>: L1 DROP ✓, L3 <n> files, L4 <n> versions + <n> markers (lock: <off/on until>), L6 none made, L7–L9 ✓. Record: <path>.
- Verdict GO / NO-GO. Deltas to migration.md: <…>.
```

---

## 7. Rollback and abort, per phase

| Phase | Abort point | How |
|---|---|---|
| 0 Step A | any time | `helm -n rutli rollback rutli 4` (needs `rutli-cosigner-tls`, kept). The per-node Secrets may stay |
| 0 Step B | any time before 4.8 | `helm -n rutli rollback rutli 5`. **After 4.8** (an EC key exists) this takes the B4 participant down; soak unaffected |
| 1 | any time | `./destroy.sh --env …` (+ S3 prefix purge) |
| 2 | any time | `helm -n $NS rollback participant <rev before 2.1>`; delete the export file (it stays on the destruction list) |
| 3 | before Gate B | per node: `rutli-cosigner --config /config/cosigner-<i>.json abort-import --key-id "$KEY_ID" --ceremony-id "$CEREMONY" [--yes-delete-installed-share]`; if a share was installed and signed with, **restart that cosigner** (`kubectl -n rutli delete pod rutli-cosigner-<i-1>`, one at a time) before any re-import (split-ceremony.md §5). Resume the backup CronJob |
| 3 | after Gate C | no destroy path: the id stays as residue (5.5). To retry, re-run under `b4-frost-import-<fp8>-2` with a new `CEREMONY` |
| 4 (R-A) | before the PNR line | B0 §5 R-A, with B4 names: scale `validator-app`, then `participant`, to 0; `helm -n $NS rollback participant <PARTICIPANT_REV_PREVIEW>` (old DB `participant_1`, JCE); `helm -n $NS rollback validator <pre rev>`; if 4.10 ran, offboard the orphan `NEW_ID` **from the old JCE participant** (it holds the namespace key; B0 R-A step 4). `NEW_ID` is burned. Delete Secret `participant-bootstrap-dump`. `b4-frost-signing` / the EC key / `KEY_ID` stay as cluster residue |
| 4 (R-B) | after the PNR line | B0 §5 R-B (retry; re-import from Scan in-cluster; migrate forward to `…-mig2` on `participant_b4b`). **Never start the old participant.** Do not run 5.4 until resolved |
| 4 dump fallback | `Uploading node keys` or a dump parse error before the PNR | scale the validator to 0. Fallback: take the real dump but strip keys in the pipe so the plaintext never touches disk: `curl -sf …/admin/participant/identities -H "authorization: Bearer $VALIDATOR_TOKEN" \| jq '.keys = <4.11 keys>' > dump.json`. This needs the **old** validator app running, so it must be done before 4.3; record it as an L6 exposure (memory and transit only) |
| 5 | destruction | irreversible by design; only after GO |

---

## 8. Time estimate (one operator, Claude preparing)

| Phase | Effort | Wall clock |
|---|---|---|
| 0 rc (R1–R7), operator cert, dealer build/VM | 0.5 d | +CI |
| 0 cosigner Step A + B | 1.5 h | — |
| 0.9 placement/egress | 0.5 h | **days** if allowlisting is needed |
| 1 deploy, onboard, tap, baseline | 2–3 h | + ≥ 24 h ageing |
| 2 export | 45 min | — |
| 3 ceremony | 2–3 h | — |
| 4 cutover | 2–3 h | incl. 10–30 min bootstrap |
| 5 verify + observe + destroy + teardown | 3 h | + ≥ 24 h observation |
| **Total** | **≈ 2.5–3 engineer-days** | **≈ 5 calendar days**, if the egress check passes |

## 9. Risks (ranked)

1. **Placement and DevNet egress.** fsn is full (95 % of memory requested), and hel's egress IP may not be allowlisted. If it is not, Phase 1 cannot
   onboard, and allowlisting is an external lead time. Check 0.9 first.
2. **Rollout on the live soak cluster.** Two restarts of all three cosigners under the soak participant. The new chart's `tls-select`/projected
   Secrets have not run live yet. Mitigations: split into A/B, server-side diff, PDB, rollback revisions kept, the shared Secret kept. B4 activity also lands
   in the soak's cosigner metrics. Every window is a planned soak event, so the clean-day counter can exclude it.
3. **ECIES on a live network for the first time** (EcdhDerive under DevNet traffic). Key creation needs all 3 cosigners up. Fallback to RSA
   is cheap only before the PNR. G7 is the signal.
4. **The key-free dump and fresh signing key differ from B0** (B0 used the real KMS-id dump and reused the signing key). Bytecode
   says 0.9.0 never reads the keys of a pre-initialised node. The OTK carries proof-of-ownership signatures, so Splice's rotation
   should not fire. Both have explicit STOP lines before the PNR.
5. **Destruction completeness.** S3 versioning or object lock, the 4-hourly CronJob writing new plaintext copies until the DROP, laptop
   snapshots, Hetzner volume residue. Mitigations: lock check in 1.5, DROP right after GO, the `tmutil` exclusion before export, and the stated
   residual exposure.

Others: the July CA key may be lost (operator role unrehearsed, 0.4); `deploy/k8s/job-verify-key.example.yaml` does not fit Helm installs
(D9); NAAS `deploy.sh` writes the dump Secret under key `identities.json` instead of `content`; one human plays every ceremony role (0.8).

## 10. What the user must decide or provide

1. **The July cluster CA private key** (cert sha256 `453bb4ae…c663`) for the operator certificate, or accept the driver-cert fallback (0.4).
2. **Placement**: run the egress check on hel; if it returns 403, allowlist hel or free fsn requests (0.9).
3. **Dealer host**: live USB on spare hardware, or the no-network VM (0.8). Who witnesses Gate 0.
4. **Release**: approve `v0.4.0-rc.1`, merge R1/R2/R4, run R3, tag R5 (auto mode cannot push or merge).
5. **Auth0**: `--setup-auth0` (and optionally DNS/TLS for the wallet UI) for the scratch validator (1.2).
6. **AWS**: credentials able to list and delete object versions under `canton-k8s-validators-backup/stakecraft-devnet-rutli-b4/`. Confirm object lock is off.
7. **Observation window** before teardown: 24 h minimum, or ≥ 72 h as a live ECIES soak (5.1, 5.6).

---

## Appendix: source references

Canton = `~/.cache/canton-src` (3.6.1; paths under `community/`). Splice = the 0.5.5 checkout in the NAAS repo
(`NAAS/k8s/splice`). The deployed 0.9.0 was checked where noted: charts pulled under the session scratchpad (`splice090/`) and
classes from the 0.9.0 `splice-node.jar`.

| Claim | Where |
|---|---|
| Export is refused unless the node enables preview | `common/.../crypto/admin/grpc/GrpcVaultService.scala:584-597`; `app-base/.../config/CantonConfig.scala:763` |
| Console `download`/`download_to` (Preview), `generate_signing_key`, `generate_encryption_key`, `register_kms_*` | `app-base/.../console/commands/VaultAdministration.scala:119,153,178,213,496,522` |
| `SigningKeyUsage` sets and invalid combinations | `base/.../crypto/Signing.scala:757-790` |
| `init_id_from_uid`, snapshot import/export V2, namespace-delegation list, OTK list, OTK propose (`signedBy` optional), trust-certificate propose | `TopologyAdministrationGroup.scala:236,450,810,1471-1479,1502-1510,1864-1876,2576-2600` |
| `wait_for_initialized` / `wait_for_ready_for_node_topology` | `HealthAdministration.scala:190,201` |
| `connect_by_config`, `config(alias)`, `export_acs` | `ParticipantAdministration.scala:2436,2765`; `ParticipantRepairAdministration.scala:276` |
| Register by KMS id: public key + spec check only | `base/.../crypto/provider/kms/KmsPrivateCrypto.scala:78-104` |
| Dump keys used only when the node is not initialised; migrator reads `dump.id` only | Splice `NodeInitializer.scala:227-253,256-312,314-344`; `ParticipantInitializer.scala:98-108`; `ParticipantPartyMigrator.scala:53-63`; 0.9.0 bytecode (`javap` of `NodeInitializer`, `ParticipantPartyMigrator`) |
| OTK rotation only for signing keys that did not sign | Splice `NodeInitializer.scala:355-436` (`rotateOwnerToKeyMappingNotSignedByKeys`, `performKeyRotation`; log line :408) |
| Dump JSON schema | Splice `apps/common/src/main/openapi/common-internal.yaml:72-119`; `NodeIdentitiesDump.scala:19-110` |
| Validator chart: dump file `content`, `new-participant-identifier`, `migrate-validator-party`, onboarding/DEVNET, `/domain-upgrade-dump` | `splice-validator` 0.9.0 `templates/validator.yaml:76-82,233-252,382-414` |
| Participant chart: `additionalEnvVars`, DB conflict check | `splice-participant` 0.9.0 `templates/participant.yaml:107,187-209` |
| Validator / wallet HTTP | Splice `validator-internal.yaml:14,128,166`; `wallet-internal.yaml:42,92,359`; `wallet-external.yaml:10,213-250`; `sv-internal.yaml:530` |
| Driver key ids and prefix routing | `driver/.../backend/FrostKeyIds.scala:28-66` |
| Driver capability probe and log line | `driver/.../backend/FrostBackend.scala:388-416` |
| v0.3.1 driver ignores unknown specs | `v0.3.1:driver/.../backend/FrostBackend.scala:202-234` |
| Dealer request authentication (leaf, KU/EKU, curves) | `frost/cosigner/src/request_auth.rs:100-145,286-376` |
| Import id rule; DKG refusal | `frost/cosigner/src/share_delivery.rs:76-99` |
| Operator role (KeyStatus, CeremonySignTest; driver role also allowed) | `frost/cosigner/src/service.rs:29-68` |
| `refresh --target` default | `frost/cosigner/src/main.rs:39-47,438-457` |
| Ceremony CLI flags | `frost/cosigner/src/main.rs:115-183`; dealer `frost/cosigner/src/bin/rutli-dealer.rs:45-102` |
| Chart TLS layout, `tls-select`, ConfigMap | `deploy/helm/rutli-cosigner/templates/statefulset.yaml`, `configmap.yaml`; `values.yaml` (`tls`, `operatorAllowlist`) |
| ECIES participant config | `docs/hosted-keys.md` §2; `scripts/e2e-ecies-hosted.sh:153-167` |
| Soak bundle/PVC/Cilium pattern | NAAS `deploy/rutli/rutli-prereqs.sh`; soak log 2026-10-07 (0.3.1 rollout) |
