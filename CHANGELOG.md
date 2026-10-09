# Changelog

All notable changes to Rütli are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions follow [SemVer](https://semver.org/).

## [Unreleased]

### Added
- **ECIES hosted keys (roadmap Track C, v1.5 of `docs/hosted-keys-design.md`).** The cluster now
  hosts EC P-256 encryption keys (`ec-p256-ecies`) beside RSA-2048 and AES-256-GCM, so a participant
  can keep the ECIES key type every JCE node uses — and the one that can become a threshold key
  later — with no HSM and no local key state.
  - **Cosigner:** keygen on aws-lc-rs; SPKI byte-identical to Canton's encoding; sealed, replicated,
    create-once, anti-entropy and portable export like every hosted key. New Signer RPC
    `EcdhDerive(key_id, peer_point) → Z` (the 32-byte x-coordinate of `d·V`): only a 65-byte
    uncompressed point on P-256 is accepted, every other spec and every split-ceremony id is
    refused, and each call is charged to the key's decryption budget (`op="ecdh_derive"` in
    `rutli_hosted_key_ops_total`). `Capabilities` reports the new spec. There is still no export RPC.
  - **`import-key` reads a Canton EC P-256 encryption key** (`keys.secret.download` output, plain or
    password-protected, or a stored row) with `--key-id` and `--expect-fingerprint`, and refuses
    unless the cluster will serve exactly the public key Canton recorded. A migrating node registers
    it by id (`register_kms_encryption_key`) and keeps its encryption key fingerprint. Signing,
    Ed25519, RSA (roadmap B3) and purpose-less PKCS#8 keys are refused.
  - **Driver:** advertises `EcP256` / `EciesHkdfHmacSha256Aes128Cbc` when the cluster reports
    `ec-p256-ecies`; `generateEncryptionKeyPair` and `getPublicKey` follow the key's real spec instead
    of assuming RSA; `decryptAsymmetric` checks Canton's `iv ‖ V ‖ ct ‖ tag` shape (≤ 256 bytes)
    before any cluster call, gets `Z` from `EcdhDerive` and completes the decryption in
    BouncyCastle's own `IESEngine`. To use it, set the participant's
    `crypto.encryption.keys.default = ec-p-256` and
    `crypto.encryption.algorithms.default = ecies-hkdf-hmac-sha-256-aes-128-cbc`; upgrade every
    cosigner first.
  - Verified by the upstream `KmsDriverTest` over the frost backend (`CONFORMANCE=1`), a
    BouncyCastle differential plus a randomised one (200 keys × 10 single-bit mutations per run;
    3000 × 4 in the review), invalid-point tests and `scripts/e2e-ecies-hosted.sh` on a real
    Canton 3.6.1 participant with a generated and a Canton-imported key.
  - **Rollout order: upgrade every cosigner, then switch the participant to ECIES.** A cosigner
    older than this release cannot serve an EC key. `NodeInfo` now reports each node's hosted-key
    specs, and a leader refuses to create an `ec-p256-ecies` key (`FAILED_PRECONDITION`) unless
    every peer reports it and is up. The driver asks every configured cosigner for `Capabilities`
    and advertises ECIES if every cosigner that answers reports it and a majority answers: an old
    cosigner that answers vetoes it, a silent one does not, so a participant still restarts with
    one cosigner down (silent nodes are retried for up to 30 s, 5 s once a majority answered, and
    named at WARN). For an EC hosted key, "not found"/UNIMPLEMENTED answers fail over to the next
    cosigner without making that node the preferred leader; RSA, AES and FROST keys keep
    `NOT_FOUND` authoritative.
  - `import-key --key-prefix P` enforces that `--key-id` is `P + "rutli-" + name`; ids containing
    `frost-` or outside `[A-Za-z0-9_-]` are refused.
  - An ECIES failure the cluster cannot see (MAC or padding, in the driver) is noted in the
    operation's audit entry (`ecies-failure=after-ecdh` / `=shape`) and logged at WARN; see
    `docs/observability.md` for the log-based alert.

### Changed
- The driver builds against BouncyCastle 1.85, the version Canton 3.6.1 ships (and, since Canton's
  jar comes first on its classpath, the one the driver already ran on inside a participant).

### Notes
- Canton's ECIES authenticates the ciphertext but not the IV it prepends, so the first plaintext
  block is malleable. The driver matches Canton's decryptor exactly; see `docs/hosted-keys.md` §5.

## [0.3.2] — 2026-10-09

### Added
- **`frost.key-prefix`** — an optional per-participant prefix prepended to every key id the driver
  mints or looks up on the cluster, FROST and hosted alike. Default `""`, so an existing deployment's
  ids (`frost-namespace`, `frost-signing`, `rutli-enc-…`) are unchanged byte for byte and no config
  edit is needed. Motivation: the 2026-10-07 DevNet soak bring-up pointed a second participant at an
  already-populated cluster. FROST ids derive deterministically from Canton's key name, so the second
  participant asked for the same `frost-namespace` and the cosigner's create-once guard refused its
  DKG with `ALREADY_EXISTS` — correct behaviour, since that guard is what protects a live namespace
  key, but the only workaround was retiring the old shares by hand on every cosigner. With
  `key-prefix = "soak1-"` / `"soak2-"` the two participants birth `soak1-frost-namespace` and
  `soak2-frost-namespace` instead. Every path that builds or recognises an id now goes through one
  helper (`FrostKeyIds`), routing is strict on the full prefix, the prefix is validated against the
  cosigner keystore alphabet at startup, and the cosigners are untouched (ids are opaque to them).
  Docs: `docs/architecture.md` → *One cluster, several participants*.

### Fixed
- **The sign-latency alert and dashboard panel were blind: the cosigner exported a summary, not a
  histogram.** Found on the 2026-10-07 DevNet soak. `metrics-exporter-prometheus` renders any
  `histogram!` with no configured buckets as a Prometheus *summary*, so `/metrics` carried
  `rutli_sign_duration_seconds{quantile="…"}` and no `_bucket` series. Everything that reads the
  metric uses `histogram_quantile()` over `_bucket`. That covers `RutliSignLatencyHigh`, the
  Grafana *Sign Latency* panel and the soak gate's p99, so the alert could never fire and the
  panel never had data on any release up to and including 0.3.1. The cosigner now configures
  explicit buckets for `rutli_sign_duration_seconds`, its only histogram: 0.01, 0.025, 0.05,
  0.075, 0.1, 0.15, 0.25, 0.5, 1, 2.5, 5 and 10 s. Metric names and labels are unchanged. The
  bounds resolve a 50–150 ms FROST round trip and make the soak gate's 1 s an exact bound. The 10 s
  bound is required for the alert. `histogram_quantile()` reports a quantile that lands in `+Inf`
  as the highest finite bound, so with 5 s on top the `> 5` rule could still never fire; promtool
  confirms that case. Unit and HTTP-scrape tests pin the wire format: a histogram with every
  bucket line present and no `quantile=` series.
  - **Soak gate (`deploy/soak/soak-check.sh`).** The p99 branch now gets data. The summary
    fallback stays for clusters with no upgraded leader yet. Mid-rollout, the gate reports how many
    summary-only leaders the p99 leaves out. A `NaN` result now counts as "no data". Buckets with no
    samples in the window used to reach awk as `null` and pass.
  - The rules, dashboard and `docs/observability.md` already assumed a histogram, so they need no
    query changes. The rules header, `docs/observability.md` and `docs/performance.md` now
    document the buckets and the summary on 0.3.1 and earlier.
- **Hosted-key pull replication and read-repair over gRPC were broken: every cosigner believed it
  was node 0.** `hosted::identifier_index` read the last two bytes of a FROST identifier as
  big-endian, but Ed25519 identifiers serialize as a little-endian scalar (id 2 is `02 00 … 00`),
  so it returned 0 for every node. All nodes therefore derived the same distribution key (index 0)
  and reported `NodeInfo.identifier = 0`, while `Peer.FetchKey` wraps its reply to the number in the
  caller's certificate CN (`cosigner2` → 2). The receiver then refused its own envelope
  (`addressed to node 2, not this node (0)`), so read-repair and the pull half of the anti-entropy
  sweep never succeeded on a live cluster. Push replication (`generate_hosted_key`, the push half
  of the sweep) worked by accident: the pusher wraps to whatever `NodeInfo` reports, and that was
  consistently 0. Cluster tests wired nodes with `LocalPeer` and hid it. Found in code review while designing the split ceremony (B2).
  `identifier_index` now decodes little-endian and returns an error for an identifier wider than
  16 bits instead of truncating. Each node now gets its own distribution key, matching what peers
  derive for it from its cert CN.
  - **Commitments stay node-independent.** `hosted_commitment` was keyed off the computing node's
    own distribution key, which only agreed across nodes because they all had index 0. Left alone,
    the fix would have made every replication ack disagree (`stored different material`) and
    failed every hosted-key write. The commitment is now keyed off the index-0 distribution key on
    every node, byte-identical to the 0.3.1 value, so mixed-version clusters keep agreeing.
  - **Rolling upgrade is safe, no ordering required.** Wrap keys are derived on use and never
    stored, and nothing persisted depends on the index: sealed shares and hosted keys are keyed off
    the configured `identifier`, and commitments are computed on demand. Pushes between old and
    fixed nodes work in both directions, since the pusher addresses whatever the target's
    `NodeInfo` reports. A fixed node can pull from any node; an old node still cannot pull until it
    is upgraded, which is no worse than 0.3.1.
  - A new `hosted_grpc` integration test runs three nodes over real mTLS sockets (`cosigner1..3`
    CNs) and covers `NodeInfo`, read-repair via `FetchKey`, push replication and the anti-entropy
    pull. It fails on the old code. `LocalPeer::on_behalf_of` models a remote caller in-process,
    so the in-process repair test wraps to the caller as the network path does.

## [0.3.1] — 2026-10-07

### Changed
- **Conformance target bumped to Canton v3.6.1** — the version Splice DevNet now bundles for
  validators (the previous target, v3.5.6, is 13 patches behind its own line and superseded by the
  3.6 releases). The driver SPI (`kms-driver-api`) is byte-identical between v3.5.6 and v3.6.1, so
  the driver jar is unchanged and works on both lines; local conformance is 65/65 green against
  the v3.6.1 module closure. The bump surfaced three upstream drifts, all absorbed here:
  - Canton 3.6.1 builds on **Scala 2.13.18**, and SIP-51 forbids compiling against its artifacts
    with an older 2.13 compiler — `scalaVersion` bumped from 2.13.16.
  - `scalatest-utils` lost its upstream `publish/skip` and became a *compile*-scoped dependency of
    `community-testing`, so the closure walk's hardcoded exclusion of it had to go.
  - The module-closure walk in `publish-canton-deps.sh` is now **version-scoped**: modules
    published from an older Canton line (3.6.0-SNAPSHOT) no longer mask missing ones for the
    current line (3.7.0-SNAPSHOT) on machines that have built both.
  Docs now point at `canton-open-source-3.6.1`; the daml-components override default moved to a
  snapshot that v3.6.1 itself pins (`3.7.0-snapshot.20260929.14837.0.v5b67d18b`).
- **Kubernetes backups never touch a cosigner's volume from outside.** `deploy/k8s/cronjob-backup.yaml`
  — which until now mounted `cosigner-0`'s ReadWriteOnce PVC into a second pod, the exact pattern
  behind the DevNet soak's incident #1 on 2026-10-07 (`docs/soak-2026-10-devnet.md`) — is replaced
  by the exec design proven on the soak cluster (`deploy/soak/k8s/cosigner-backup-exec-cronjob.yaml`):
  a ServiceAccount whose Role grants only `get` and `pods/exec` on the cosigner pods *by name*, a
  CronJob on a digest-pinned `alpine/k8s` image that runs `rutli-cosigner backup` **inside** each
  cosigner (one `kubectl exec` per ordinal, seven-day rotation under `/data/backup-<weekday>`),
  streams each result out as a tar, and hands the tars to a `ship.sh` you supply in ConfigMap
  `rutli-backup-destination` — the placeholder exits 1, so an unconfigured destination is a failed
  Job rather than a silent gap. The Helm chart gains the same behind `backup.enabled`
  (`backup.ship`, `backup.extraEnv` / `backup.extraVolumes` for credentials and a destination of
  the Job's own) and refuses a `backup.extraVolumes` entry that names a cosigner's
  `data-<fullname>-N` claim; the chart never had a template mounting one elsewhere.
  `deploy/k8s/README.md`, the chart README and `docs/disaster-recovery.md` now state the rule in so
  many words, with the incident: **never mount a cosigner volume into another pod.** The soak
  cluster's applied copy gets the same Role tightening and image digest pin, behaviour unchanged.

### Fixed
- **A single sick cosigner could take down all signing** (DevNet soak incident, 2026-10-07).
  cosigner-0's `/data/keys` became unreadable after an external backup job remounted its RWO
  volume. The node stayed "ready" — its gRPC `Health` always said ok and the Kubernetes probes were
  TCP-only — and answered every `Sign`/`Dkg` with `INTERNAL: io: Permission denied (os error 13)`.
  The driver only failed over on UNAVAILABLE / DEADLINE_EXCEEDED (deliberately, so a real answer
  such as NOT_FOUND is never masked), and cosigner-0 was first in `frost.endpoints`, so every sign
  led from it and failed: 54 consecutive `sign … outcome=failed` audit entries while cosigners 1
  and 2 were healthy. Fixed on both sides:
  - **Driver — leader-side INTERNAL/UNKNOWN now fails over**, but only for operations that are
    safe to re-issue through another leader: `sign` (a fresh session on another leader is safe —
    the abandoned session's nonces are burnt by the cosigner's own abort/TTL logic),
    `getPublicKey`, `keyExistsAndIsActive`, and the hosted-key decrypt/symmetric/key-info reads.
    DKG, hosted `GenerateKey` and `DeleteKey` keep their stricter predicates (ceremonies are
    never retried blind — `docs/testnet-soak.md` → Incidents); NOT_FOUND, INVALID_ARGUMENT,
    ALREADY_EXISTS, FAILED_PRECONDITION, RESOURCE_EXHAUSTED and PERMISSION_DENIED still surface
    immediately from the first node that answers.
  - **Every failover is visible, not silently routed around**: a WARN log line with the endpoint
    and status, and `failover=<from>→<to> reason=<CODE>` recorded in that operation's own
    hash-chained audit entry (new `AuditNotes` plumbing; `KmsBackend.withAuditNotes`).
  - **Sticky preferred leader**: the driver leads from the last endpoint that gave a real answer,
    so one bad node at position 0 no longer adds a failed attempt to every call.
  - **Driver failover alone would not have ended this outage — the cosigner side needed two
    signing-path fixes too.** A cosigner that has signed since start-up keeps its share cached,
    so after its volume broke it still passed sign round 1 (`NonceStore::is_consumed` used
    `Path::exists`, which reads EACCES as "not burnt") and only failed in round 2 on the
    nonce-marker write — and because peers are tried in identifier order, the sick node landed
    in *every* leader's quorum, sinking every signature cluster-wide (reproduced in
    `frost/cosigner/tests/health.rs`). Now: `is_consumed` fails closed on a lookup error (an
    unreadable store is refused in round 1, so leaders skip it like a down peer), and a node
    whose key-store readiness probe last failed refuses `sign_round1`, refuses the DKG/refresh
    ceremony fence (so a ceremony rolls back before any share is rewritten instead of failing
    half-applied at that node's `save`), and answers `NOT_SERVING` → gRPC `UNAVAILABLE` at the
    entry of every store-touching Signer RPC (`Sign`, `Dkg`, `Refresh`, `GroupKey`, `PublicKey`,
    `KeyInfo`, `Decrypt`, `SymmetricEncrypt/Decrypt`, `GenerateKey`, `DeleteKey`) — a status
    every driver version already fails over on, so upgrading the cosigners first is enough.
    Leaders sign around the sick node with the remaining two. Burn-before-sign is unchanged:
    nothing here reuses a nonce; every change only refuses. Related hardening from the same
    review: `KeyStore::read_plaintext`/`delete` use `try_exists`, so an unreadable store is an
    IO error (`INTERNAL`), never `NOT_FOUND` (which Canton's `keyExistsAndIsActive` would have
    believed); peer RPCs (`GrpcPeer`) now carry a 10 s request + connect timeout, so a hung peer
    becomes a round-1 skip instead of a 60 s hang; a timed-out peer counts as unreachable for
    hosted-key writes.
  - **Cosigner readiness reflects key-store readability**: `Signer.Health` now probes
    `data_dir/keys` (list, open+read each key file, create+remove a uniquely named probe
    dotfile — a read-only remount is the same incident; 3 s timeout counts as unresponsive) and
    reports `ok=false, NOT_SERVING: keystore … unreadable: …` when it fails. The node is down
    only when the directory cannot be listed or written or *every* key file fails to open; a
    single unopenable file is counted in `rutli_unreadable_key_files_total` and logged, and the
    node keeps signing its other keys. Probes are single-flight with a 5 s cache (a Health flood
    cannot stack blocking threads; a late result never overwrites a newer verdict); a background
    loop re-probes every 15 s, logs transitions only, and prunes expired pending sign sessions
    while the node is refusing. New `rutli-cosigner health` subcommand (same probe plus a TCP
    check of the gRPC port, no seal secret needed) backs the Kubernetes readiness probe and the
    compose healthchecks, replacing the TCP-only checks; liveness stays TCP so a broken volume
    does not trigger restarts that destroy the evidence. `backup`/`restore` skip dotfiles so a
    live backup can never catch a probe file. New gauge `rutli_keystore_unreadable` and critical
    alert `RutliKeystoreUnreadable` (`deploy/monitoring/prometheus-rules.yml`, PrometheusRule
    regenerated). Note the headless Service publishes not-ready addresses (the mesh needs them
    during DKG), so readiness makes the sick node visible (`READY 0/1`, rollouts, PDB) while the
    driver's failover does the routing. **Upgrade note:** the manifests still pin the 0.3.0
    image, which lacks the subcommand, so the readiness command is `… health || [ $? -eq 2 ]`:
    clap's usage-error exit on an old binary degrades the probe to "process running" (liveness
    still checks the port) instead of leaving pods never Ready. Bump the image pin at the next
    release and drop the fallback.
- **A *hung* data volume froze the whole cosigner, not just its key store.** The readiness probe
  above catches a volume that *fails*; one that stops answering — a dead NFS/CSI hard mount, a
  snapshot hook's `fsfreeze` — parks every thread that touches it. Peer and Signer handlers ran
  their key-store IO (`sign_round1`'s nonce-marker lookup, share loads, hosted-key reads and
  writes) on tokio's async workers, and the shipped 500m CPU limit gives the cgroup-aware runtime
  exactly **one** worker: a single stalled `stat` froze Health, `/metrics`, every peer RPC and the
  probe's own timer, before the verdict could flip to "down". Now:
  - Every `Node` call from an RPC handler, the in-process `LocalPeer` and the orchestrator that may
    touch the store runs on the blocking pool (`Node::blocking`); memory-only and crypto-only calls
    stay inline. Ordering is unchanged: each round 2 is one blocking call that burns its nonce
    marker before computing the share, and runs to completion even if the leader stops waiting;
    ceremony fences are still taken in order before any ceremony IO.
  - The readiness monitor is a dedicated OS thread (`rutli-keystore-watchdog`) and each probe runs
    on a plain thread of its own; `Signer.Health` only awaits a notification. Neither needs the
    async runtime or its blocking pool to be responsive. Single-flight and the 5 s cache are kept;
    at most one probe thread is ever parked on a dead volume.
  - **Debounced "unresponsive"**: a probe that *returns* an error (EACCES, EROFS, ENOSPC, EIO,
    ESTALE…) still refuses round 1 at once, but a probe that merely hangs counts as unresponsive
    only after 6 s — two 3 s probe timeouts, a warning logged after the first — so a short fsfreeze
    that hits all three PVCs together no longer fails every sign cluster-wide. Health still answers
    within 3 s either way. (Previously a single 3 s timeout counted.)
  - The hosted-key mesh RPCs (`ReplicateKey`, `FetchKey`, `ListKeys`, `PurgeKey`) and the local
    anti-entropy sweep now refuse with UNAVAILABLE while the store is down — callers already treat
    that as a missing replica — so peers' anti-entropy cannot park a thread per pass on a dead
    mount.
  - Tests: `frost/cosigner/tests/hung_volume.rs` parks key-store calls through a fault-injection
    seam (`KeyStore::with_io_hook`) on a one-worker runtime and asserts that Health, a peer sign
    round on another key, and a full signature led by the affected node still answer; then that a
    hung probe turns the node away (UNAVAILABLE at once) while another leader signs around it, and
    that the watchdog flips the verdict with no async runtime at all. Verified to fail, not hang,
    with the store calls moved back inline.

### Added
- **`deploy/monitoring/kustomization.yaml`** — Rütli observability for a kube-prometheus-stack
  cluster in one `kubectl apply -k deploy/monitoring`: a ServiceMonitor for the cosigner metrics
  port, the alert rules as a PrometheusRule (`k8s/render-prometheusrule.py` wraps the plain
  `prometheus-rules.yml`, which stays the single source of truth for the compose stacks), a
  NetworkPolicy admitting the `monitoring` namespace to port 9200 (the chart's own policy only
  admits pods labelled `rutli.io/scraper=true`, and a stack-managed Prometheus pod does not carry
  that label), and the Grafana dashboard as a sidecar-discovered ConfigMap (the dashboard now has a
  *Key store readiness* state timeline of `rutli_keystore_unreadable` per instance beside
  *Cosigners Up*, and plots round-1 skips as `increase(…[5m])` per leader so the node being
  skipped around is visible at a glance). First used for the
  DevNet soak validator on 2026-10-07.
- **`deploy/soak/kustomization.yaml`** — the daily soak gate as a Kubernetes CronJob
  (`kubectl apply -k deploy/soak -n monitoring`): runs the unchanged `soak-check.sh` from a
  generated ConfigMap against the stack's Prometheus. `soak-check.sh` gained
  `SOAK_ALERT_FILTER` (regex, default everything) so that on a shared Prometheus only the Rütli
  alerts count. Metrics checks only on k8s — the audit-chain check needs the participant's RWO
  volume, which cannot be mounted twice. **Lesson that shaped this (DevNet soak, 2026-10-07, see
  `docs/soak-2026-10-devnet.md` incident #1):** a first attempt mounted a cosigner's data PVC
  into a backup CronJob pod on the same node; the second mount left `data_dir/keys` unreadable
  to the running cosigner, which kept passing its gRPC health check and answered every sign with
  `INTERNAL` — and because the driver deliberately does not fail over on INTERNAL and that node
  was first in `frost.endpoints`, signing stopped for the participant until the pod was restarted
  (5 minutes, 54 failed signs). Never share a cosigner's volume with another pod; back up via
  `kubectl exec` into the running cosigner instead.

## [0.3.0] — 2026-10-06

### Added
- **Cluster-hosted keys** (`hosted_keys` on the cosigners, `frost.hosted-keys` on the driver): the
  cluster now holds Canton's non-FROST key material too — RSA-2048-OAEP-SHA256 encryption keypairs
  and AES-256-GCM symmetric keys — so a participant can run with **no HSM and no local key state**
  (`frost.delegate = "none"`). Motivated by a DevNet incident where a participant restart destroyed
  a heap-only RSA key that peers were still encrypting to.

  These are **replicated whole keys, not threshold shares**, and the docs say so everywhere: keys
  are generated on one cosigner, wrapped per recipient, replicated to the others and sealed at rest
  on each. The Ed25519 namespace key is untouched and remains genuine 2-of-3 FROST. The security
  tier matches the recoverability tier — the key Canton *cannot* rotate stays in MPC; the keys that
  get only replication are the ones Canton *can* rotate. The cost is stated rather than buried: an
  attacker who extracts one encryption key gains *retrospective* read access to recorded traffic
  encrypted to it.

  - RSA-OAEP runs on `aws-lc-rs`, deliberately **not** the pure-Rust `rsa` crate: RUSTSEC-2023-0071
    (Marvin timing side-channel, key recovery by a network attacker) is still unpatched. The full
    OAEP unpad happens server-side and all decryption failures collapse to one opaque error, so
    there is no padding oracle.
  - Key material never crosses the mesh in the clear even inside mTLS (a service-mesh sidecar
    terminating TLS would otherwise see plaintext keys): each replica is sealed to one recipient
    with ephemeral X25519 → HKDF-SHA256 → AES-256-GCM, AAD-bound to cluster, key id, spec and
    recipient.
  - Write quorum defaults to 2 of 3 — matching the cluster's own fault model, since requiring all
    three would block key rotation whenever a node is down — with cluster-wide rollback below
    quorum, anti-entropy, read-repair, and a `rutli_key_replicas` alert for a shortfall that does
    not heal.
  - Hosted keys are create-once-immutable, so divergence between replicas is a hard error
    (`rutli_anti_entropy_conflicts_total`, page-worthy), never auto-reconciled. Replication applies
    to hosted keys **only** — copying a FROST share would give two nodes the same share and
    silently break the threshold scheme.
  - Stored beside FROST shares in `data_dir/keys/`, so the existing `backup`/`restore` already
    cover them; a rebuilt cosigner re-acquires hosted keys automatically via anti-entropy.
  - **Driver side, completing v1:** `FrostBackend` routes `rutli-`-prefixed key ids to the cluster
    alongside `frost-` (generate, decrypt, symmetric encrypt/decrypt, public key, key info, delete
    — hosted keys *are* deletable, unlike the namespace key, because Canton can rotate them), and
    asks the cluster for its `Capabilities` at startup instead of hardcoding a spec list, so adding
    a key type needs no driver release (an unreachable or older cluster falls back to the
    configured expectation and says so). `frost.delegate = "none"` (`NoDelegateBackend`) leaves no
    local backend at all: every call reaching it is a routing bug, so it fails loudly and names the
    key. There is deliberately **no** fallback to the delegate when the cluster reports a key
    missing — that would silently re-create split custody, which is the failure this feature exists
    to prevent; read-repair is what makes `NOT_FOUND` authoritative.
  - **Export/import of hosted keys** — `rutli-cosigner export-key --key-id … --out FILE
    --passphrase-env VAR` / `import-key --in FILE --passphrase-env VAR`: an offline, portable,
    passphrase-protected copy of one hosted key (Argon2id 64 MiB/t=3 → AES-256-GCM, header bound in
    as AAD so an artifact cannot be relabelled, 12-character minimum passphrase, file created 0600,
    both commands log at WARN). The distinction that matters: `backup` is sealed ciphertext that
    only reopens on the node and cluster it came from and covers routine durability, while `export`
    is portable and covers the two cases backup cannot — a lost seal master secret, and moving a
    key to a different cluster or KMS. Hosted keys only: a FROST share cannot be exported, since no
    node holds a whole namespace key. Import never overwrites differing material
    (create-once-immutable). Deliberately **not** an RPC — an export RPC would turn a stolen driver
    cert from an online, rate-limited decrypt *oracle* into permanent silent possession of the key.
    `docs/hosted-keys.md` §4; recovery procedure and the go-live decision in
    `docs/disaster-recovery.md` §3d.
  - **`rutli_unreadable_key_files_total`** (counter): a key file that cannot be opened — wrong seal
    secret after a rotation, a partial restore, corruption — is now logged, counted and **skipped**
    from the hosted-key inventory instead of failing the whole listing, which would stop
    anti-entropy for every healthy key too and turn one damaged file into a cluster-wide halt of
    self-healing. Skipping is safe (absence from a listing never causes a delete, and a push onto
    an unreadable local file still fails closed). Any non-zero value means some key is silently not
    being replicated or repaired: alert on it.
  - Operator guide: `docs/hosted-keys.md`. Design record and the reasoning for permanently ruling
    out threshold RSA (plus the thresholdable ECIES roadmap): `docs/hosted-keys-design.md`.

  **Verified end-to-end on a real Canton 3.5.6 participant** with `deploy/devnet/canton-hosted.conf`
  (`backend = "frost"`, `hosted-keys = true`, `delegate = "none"`): the node initialises with **no
  local key state and no HSM** — namespace, signing and sequencer-auth Ed25519 keys all born via
  cluster DKG and threshold-signed, plus an RSA-2048 encryption key generated as a cluster-hosted
  key and confirmed replicated to all three cosigners on disk. This is the configuration that would
  have made the DevNet incident a non-event: the participant never holds a private key, so a restart
  cannot lose one. Config gotcha worth knowing: Canton's HOCON name for the algorithm is
  `rsa-oaep-sha-256` (pureconfig kebab-cases `RsaOaepSha256`, splitting the digits), **not** the
  driver SPI's `RsaEsOaepSha256` spelling.

- **Per-key decryption rate limit** (`hosted_keys.decrypt_rate_limit_per_min`, default 6000 —
  100/s sustained on one key, `0` disables). Closes the gap the design record named as the
  highest-value security follow-up: the driver certificate authorizes `Decrypt`, and because
  Canton's encryption keys protect per-view session keys, a stolen one reads *retrospectively* —
  everything ever encrypted to that key. The driver's signing journal cannot bound that (it runs on
  the Canton host and can simply be bypassed), so the ceiling is enforced on the cosigner. Not a
  load shaper: the default is far above real traffic, the cosigner warns with the key id well
  before it starts refusing, and a refusal is `RESOURCE_EXHAUSTED` — which the driver deliberately
  does **not** fail over on, since every node enforces the same limit and retrying elsewhere would
  spread an attacker's load. New `rutli_decrypt_rate_limited_total` and `RutliDecryptRateLimited`.

### Fixed
- **`hosted_keys.write_quorum` was inert.** The field was validated against the roster size at load
  and documented, but the service passed the hardcoded default of 2 to every generate, so a
  configured value did nothing. It is now carried on the signer service and honoured — as a required
  struct field, so it cannot be dropped again.
- **Three hosted-key bugs that only live testing caught.** The in-process tests bypass the gRPC
  service layer, so none of these could have failed a unit test. (1) The gRPC ceremony fence
  accepted only `dkg`/`refresh`, so *every* hosted-key generate failed with `InvalidArgument`;
  `genkey`/`delkey` are now recognised. (2) The cluster-wide fence aborted on the first unreachable
  peer, so a write could never complete with a node down — defeating the entire purpose of the
  2-of-3 write quorum. An unreachable peer is now skipped (a node that is down cannot start a racing
  operation) and the quorum re-checked against the reachable peers, while a peer that *answers* with
  a conflict still aborts the write. (3) That fix at first classified only `UNAVAILABLE` /
  `DEADLINE_EXCEEDED` as absence, which is what the unit test asserted — but a genuinely stopped
  cosigner surfaces as `UNKNOWN("transport error")`, so the case that motivated the fix still
  failed. Now matched narrowly on that shape: our own refusals always carry a specific code
  (`ABORTED`, `FAILED_PRECONDITION`, …), never `UNKNOWN`, so a real conflict cannot be swallowed.
- **CI had been red for eight runs before this work started**, for three unrelated reasons, all now
  fixed: cert files are mode 0600 owned by the host user while the cosigner container runs as uid
  10001 (Docker Desktop on macOS masks host ownership, Linux does not), the GitHub artifact-storage
  quota was failing an otherwise-green test job, and — most consequentially — the TLS smoke test
  pulled the published image instead of building the working tree, so it could have "verified" a
  commit against a released binary. The smoke now also dumps container state and logs on failure;
  without that, a startup crash appeared only as `container ... is unhealthy`.
- **Weekly conformance CI rotted twice over while the tree was untouched.** (1) Digital Asset
  prunes old snapshots from the `public-unstable` dpm registry, so the daml-components version
  pinned *inside* the Canton `v3.5.6` tag stopped existing and `damlInstall` died with "not found"
  whenever the ivy cache had to be rebuilt; `scripts/publish-canton-deps.sh` now overrides the pin
  with a still-published version (bump it when the weekly run reports the next pruning;
  `DAML_COMPONENTS_VERSION=upstream` restores Canton's own pin). (2) Rust 1.99's clippy grew
  `double_must_use`, which fires inside prost/tonic-generated code; the generated `pb` module is
  now lint-exempt (`#[allow(clippy::all)]`) — it is codegen we cannot fix, and `-D warnings` stays
  on for all hand-written code. Also fixed en route: the module-closure walk in
  `publish-canton-deps.sh` silently died under `set -e`/`pipefail` when an ivy.xml had no
  `com.daml` dependencies at all (e.g. `wartremover-annotations`).

### Security
- **The mesh Peer API was unauthenticated (critical; affects ≤ 0.2.1).** Only the Signer API
  enforced the client-cert CN allowlist; every `Peer` RPC — the raw FROST rounds — was reachable by
  **any** cluster-CA-signed certificate, and the driver's cert is signed by that same CA. The
  34-byte Canton-digest guard also lived only in the leader (`orchestrator::sign`), not in
  `Node::sign_round2` behind the Peer RPC. Combined, a holder of the driver cert (or any cosigner
  cert) could call `SignRound1`/`SignRound2` directly on `threshold` cosigners with an arbitrary
  message and aggregate a valid namespace signature offline — bypassing the leader, the digest
  guard, the ceremony fence and the signing journal. Fixed by adding a mandatory-under-TLS
  `peer_allowlist` (cosigner CNs) enforced on **every** Peer RPC, and by enforcing the digest
  length in `Node::sign_round2` as well, so the Peer path fails closed even if the allowlist is
  misconfigured. Operators must add `peer_allowlist` to each cosigner config (the shipped
  compose/k8s/Helm configs now set it; Helm derives `cosigner1..N` by default).

### Added
- **Software-backend sealed key persistence** (`software { dir, seal-secret-env }`): the software
  delegate's keys (RSA-OAEP encryption, AES symmetric, EC signing) are now persisted as
  AES-256-GCM-sealed files (HKDF-keyed from an operator-injected secret, atomic + fsynced writes,
  ciphertext bound to its key id) and reloaded at startup — so a participant restart no longer
  destroys its encryption keys. Field incident on a DevNet validator: heap-only delegate + node
  upgrade → `KmsDecryptError: key not found` → fatal disconnect loop, key unrecoverable (peers keep
  encrypting to the published old key; rotation only fixes future traffic). The driver refuses
  `dir` without a seal secret (no plaintext persistence) and fails loudly on a wrong secret instead
  of starting keyless; heap-only remains for tests, with a startup warning. Recovery runbook for
  the incident (repair.ignore_events + topology rotation) in `docs/disaster-recovery.md` §3b.
- **Published cosigner image** on GHCR: `ghcr.io/stakecraft/rutli-cosigner:0.2.1` (+ `latest`),
  multi-arch (`linux/amd64`, `linux/arm64`). Docker Compose defaults to the published image;
  Helm chart at `deploy/helm/rutli-cosigner`. CI workflow `publish-image.yml` pushes on `v*` tags.
- **`docs/performance.md`** — DevNet multi-region sign latency evidence (~100 ms mean / ~70 ms
  summary p50 over 9k+ OK FROST signs) plus a checklist of benchmarks worth publishing next.

## [0.2.1] — 2026-07-17

Patch on 0.2.0: cluster-wide ceremony fencing, Signer digest enforcement, TLS CI smoke, sealing
migration, k8s/ops hardening — plus the metrics and soak harness landed right after the 0.2.0 tag.

### Security & robustness
- **Cluster-wide refresh/DKG fence:** before any ceremony crypto, the leader takes the per-key
  guard on every peer (`CeremonyFence`), so no node can start a new sign mid-ceremony. The reverse
  fence also applies — if any peer still holds in-flight sign nonces for that key, the fence fails
  (`SignInProgress`) and is rolled back cluster-wide. Closes the per-node fence gap left after the
  second hardening pass.
- **Canton digest length enforced at Sign:** the Signer API rejects messages that are not exactly
  34 bytes (Canton's `0x1220 ‖ sha256(tx)` wire contract), so a miswired client cannot mint
  signatures over arbitrary payloads through the cluster.
- **Plaintext share migration at startup:** with sealing enabled, any leftover plaintext share
  files are re-sealed immediately on cosigner start (not only on the next write). Seal-secret
  minimum length raised to 32 chars.
- **CI TLS smoke:** PR CI brings up the mTLS + sealed compose cluster and runs Health / DKG /
  Sign through the driver cert (plaintext client must be refused).
- **K8s hardening:** required pod anti-affinity, zone topology spread, PDB (`minAvailable: 2`),
  image tag `0.2.1` (digest-pin guidance), narrower NetworkPolicy (namespace + pod labels),
  example backup/refresh CronJobs.
- **ApproveCli** prints `digest` / `nonce` before signing an approval so humans can verify the
  bound operation. Audit engagement checklist in `docs/audit-prep.md`.

### Added
- **Prometheus metrics** (`metrics_listen`): opt-in plaintext `/metrics` endpoint per cosigner —
  sign throughput/latency/outcomes, ceremony outcomes, round-1 peer skips (quorum-margin canary),
  sign aborts, and an in-flight-sessions gauge. Counts and latencies only; never key material,
  digests, or session ids. Wired into the TLS compose (host ports 9201–9203) and the k8s bundle
  (port `metrics`/9200, scrape annotations, NetworkPolicy ingress for `rutli.io/scraper` pods).
  Alert rules + Grafana dashboard in `deploy/monitoring/`; runbook in `docs/observability.md`.
- **Testnet-soak harness** (`deploy/soak/`): one-command stack — the mTLS/sealed cosigner cluster
  (compose `include:`) plus Prometheus (rules loaded, 45-day retention) and Grafana (dashboard
  pre-provisioned) — a daily PASS/FAIL gate (`soak-check.sh`), and a Splice DevNet validator
  overlay (`validator/`): thin derived canton-participant image injecting `rutli-driver.jar` via
  `EXTRA_CLASSPATH` + an `ADDITIONAL_CONFIG_*` compose overlay wiring `crypto.provider = kms` to
  the cluster — no Splice images forked. Runbook with drill calendar and exit criteria in
  `docs/testnet-soak.md`. Whole KMS half verified live: DKG + threshold signs from every leader,
  a sign with one cosigner down, and a mid-traffic refresh (group key unchanged) — all through
  the mTLS + allowlist path, all visible in Prometheus/Grafana, soak gate green.
- **frost/.dockerignore**: the cosigner image build no longer copies the multi-GB host `target/`
  into its context.

## [0.2.0] — 2026-07-17

Devnet-hardened release: encryption-at-rest for shares, proactive refresh, M-of-N signing
approval, tamper-evident audit, disaster recovery, Docker/k8s deployment — plus two full
code-review hardening passes (all findings fixed and regression-tested). Still pre-audit;
see Status in the README.

### Security & robustness (code-review hardening)
- **Ceremony safety:** DKG/refresh for a key are serialized by a per-key guard (no split-brain
  shares); DKG refuses to overwrite an existing key (can't destroy the non-rotatable namespace key);
  out-of-order ceremony RPCs return errors instead of panicking (closes a remote DoS); the driver no
  longer auto-retries DKG on timeout.
- **Ceremony ownership (split-brain after a crash):** an orphaned ceremony guard is preempted only
  after a timeout, and preemption now also drops the dead leader's leftover session state, so a
  superseded DKG/refresh can no longer persist a share — `part2`/`part3` re-check ownership before
  writing. A new sign is fenced out while a ceremony holds the key. Regression-tested.
- **Sign session hygiene:** a duplicate `round1` for a still-in-flight session id is refused instead
  of silently overwriting live nonces; and when a signature gives up (round-2 failure or a
  threshold shortfall after round 1) the leader best-effort aborts the session on every quorum
  member, freeing their round-1 nonces immediately rather than waiting out the pending-TTL sweep.
- **Config redaction:** the confidential config writer (used when Canton echoes driver config back)
  now also redacts the TLS private-key path, not just the HSM PIN.
- **Audit:** the hash-chained log is now genuinely fail-closed — a successful op that can't be logged
  fails rather than returning an unlogged signature.
- **Signing journal:** the per-key rate limit survives a restart (rebuilt from the persisted window).
- **Signer API allowlist:** client-cert CN allowlist so only the driver (not a cosigner cert) can
  request signatures — **required whenever TLS is enabled** (startup fails without it); optional
  only for plaintext dev setups.
- **Durability/isolation:** keystore share writes fsync file + directory; blocking FROST/approval
  work runs on a dedicated bounded pool (not Canton's EC); in-flight sign sessions are TTL-pruned.
- **Docs:** corrected stale claims (mTLS/Raft/refresh/audit/seal-secret) to match the code.

### Added
- **Deployment: Docker & Kubernetes.** A production-flavored compose
  (`deploy/frost/docker-compose.tls.yml`, mutual TLS + sealed shares) alongside the dev one, and a
  full k8s bundle (`deploy/k8s/`: StatefulSet with per-pod durable PVCs, headless service, mTLS,
  sealed shares via a shared HKDF master secret, NetworkPolicy locking the signing port to the mesh
  + the Canton driver, non-root/read-only-rootfs, anti-affinity) with a runbook covering image
  build, cert/secret creation, DKG, and wiring the Canton driver. The mTLS mesh (cosigner↔cosigner
  and driver↔cosigner) is now verified end-to-end.
- **Signing journal** (`signing-journal`): a persistent, per-key, append-only record of every
  digest signed (fsynced before the signature is released), so there is a complete history for
  equivocation *detection* and forensics; repeats of an already-signed digest are flagged and
  counted (never blocked — Canton legitimately re-signs, and the driver only sees an opaque digest
  with no height/round, so semantic double-sign protection is impossible at this layer and is not
  claimed). Optional per-key rate limit (`max-per-window`) as a runaway/compromise brake. Rebuilds
  its state from disk on restart. Records the digest only, never key material.
- **Disaster recovery**: `rutli-cosigner backup`/`restore` copy a node's sealed shares to/from cold
  storage (encrypted at rest, so backups carry no plaintext key material), and the Repairable
  Threshold Scheme primitive (`rutli-frost-core::repair`) rebuilds a lost share from `t` survivors
  with no backup and no key reconstruction — group key unchanged. Full runbook (single-node, disk
  loss, below-threshold catastrophe, compromise, and the pre-go-live checklist) in
  `docs/disaster-recovery.md`. Tested: a wiped node recovers from backup and the cluster signs;
  a lost share is repaired from helpers and signs under the same group key.
- **M-of-N signing approval** (`approval { ... }` policy): high-value keys (by key-id prefix) are
  gated — a `sign` is held until a threshold of named approvers each drop a valid Ed25519 signature
  over the request into a shared inbox, or it fails non-retryably at timeout. A random per-request
  nonce prevents replay; each approver counts at most once; signatures are verified against the
  configured keys (cryptographic separation of duties, not a counter). Approver CLI:
  `com.stakecraft.rutli.policy.ApproveCli` (`keygen`, `approve`). Default is no gating so nodes
  bootstrap unchanged. Outcomes recorded in the hash-chained audit log. See `docs/approval-quorum.md`.
- **Proactive share refresh** (`Signer.Refresh` RPC + `rutli-cosigner refresh --key-id …`):
  re-randomizes every cosigner's share via a dealer-free DKG-style ceremony while keeping the
  group public key — and therefore the Canton node identity — unchanged. Shares stolen before a
  refresh become useless afterwards, so an attacker must compromise ≥ t nodes within one refresh
  epoch. Every node verifies the group key did not drift before persisting (a diverged refresh
  aborts). Old + new shares cannot combine to sign (tested).
- **Share sealing** (`share_seal.secret_env`): key shares are stored as AES-256-GCM envelopes,
  keyed per node via HKDF-SHA256 from an operator-injected master secret (env var from a secret
  manager — never on disk). A copied disk or backup of `data_dir` no longer yields usable shares.
  Legacy plaintext shares remain readable for migration and are re-sealed on next write; a sealed
  share is refused loudly when sealing is unconfigured or the secret is wrong. Software seam for
  future enclave/HSM sealing.
- **Tamper-evident audit log** (`audit-log-path`): every key operation appends a hash-chained JSONL
  entry (`hash = SHA-256(prev ‖ entry)`), fsynced before the result returns; the chain resumes
  across restarts and is verifiable offline (`HashChainedAuditLog.verify`). Any edit, reorder, or
  deletion breaks the chain at the exact entry. Entries carry operation metadata only — never key
  material or signatures. First piece of the Phase 3 institutional-controls layer.
- **Driver-side failover** across the FROST cosigner roster (`frost.endpoints`): any live cosigner
  leads a request; a node is skipped only when unreachable, never masking a real error. Removes the
  single-leader availability gap without a consensus layer (FROST sessions are independent — no
  replicated log to keep consistent, so Raft would buy nothing here).

### Fixed
- **mTLS cert model**: cosigner certs now carry a shared `rutli-cosigner` SAN, matched by the single
  global `tls.domain` used for every peer dial — so the mutual-TLS mesh actually verifies across
  Docker service names and k8s pod DNS alike (the previous per-node `domain` could not match all
  peers). `gen-frost-certs.sh` and the TLS configs updated; TLS configs also enable share sealing.

## [0.1.0] — 2026-07-03

First tagged release. **Devnet-grade, pre-production** — verified end-to-end against a real Canton
node and a live FROST cluster, but not yet hardened (no Raft, shares stored as plaintext JSON) and
not audited. Do not place production authority keys behind it.

### Added
- **Canton KMS Driver** (`driver/`) implementing the v1 KMS Driver SPI — plugs into an unmodified
  Canton 3.5.x node via `crypto.provider = kms`. Passes the upstream conformance suite (32 tests).
- **Backends** behind a common `KmsBackend` seam:
  - `software` — BouncyCastle, integration testing only.
  - `hsm` — PKCS#11 (SunPKCS11); EC P-256/P-384 signing, RSA-2048 OAEP decryption, AES-GCM,
    key persistence. Verified against SoftHSM.
  - `frost` — routes the Ed25519 namespace/identity key to an external FROST cosigner cluster
    (threshold signing; the whole key never exists on any machine), delegates all other keys to
    the HSM/software backend.
- **FROST cluster** (`frost/`, Rust):
  - `rutli-frost-core` — DKG, two-round signing, crash-safe single-use nonce store.
  - `rutli-cosigner` — gRPC cosigner daemon (Signer + Peer services), DKG/sign orchestration.
- **Mutual TLS** on both hops (mesh + driver→cluster) against one cluster CA.
- Per-operation audit logging; wire-contract capture.
- Deployment: `deploy/frost` (Docker compose 2-of-3, plaintext + TLS configs), `deploy/devnet`
  (Canton node on software or FROST backend). Cert + key tooling in `scripts/`.

### Verified
- Real Canton participant boots on `backend = "frost"`: all Ed25519 node keys born via cluster DKG,
  identity topology threshold-signed by a 2-of-3 quorum and accepted by Canton's verifier.
- FROST output passes strict `ed25519-dalek` and stock JDK Ed25519 verification.
- Signing survives one downed cosigner; nonce reuse refused across restarts; below-threshold
  quorums cannot sign; mTLS rejects uncertified clients.

### Known limitations / not yet done
- Static leader (no Raft leader election).
- Shares stored as plaintext JSON (no enclave/HSM sealing).
- No proactive share refresh; DR procedures documented but not automated.
- No M-of-N approval engine / RBAC / hash-chained audit log (Phase 3).
- HSM backend validated only against SoftHSM.
- No third-party security audit.

[0.3.2]: https://github.com/Stakecraft/rutli/releases/tag/v0.3.2
[0.3.1]: https://github.com/Stakecraft/rutli/releases/tag/v0.3.1
[0.3.0]: https://github.com/Stakecraft/rutli/releases/tag/v0.3.0
[0.2.1]: https://github.com/Stakecraft/rutli/releases/tag/v0.2.1
[0.2.0]: https://github.com/Stakecraft/rutli/releases/tag/v0.2.0
[0.1.0]: https://github.com/Stakecraft/rutli/releases/tag/v0.1.0
