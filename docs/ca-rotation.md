# Rotating the cluster CA (mTLS trust domain)

Runbook for replacing the CA that signs every cosigner, driver and operator certificate, **without
downtime of the cosigner cluster** and with one planned participant restart. Written for the
DevNet soak (namespace `rutli`, Helm release `rutli`, participant in `stakecraft-devnet-rutli-01`),
after the 2026-10-09 finding that the soak CA's private key is lost. The procedure is the same for
any install; only the names in §1 change.

Read §2 and §3 once before running anything. Every step marked **[MUTATES]** changes the cluster.

## 1. When and why

The CA key is needed to issue any certificate: an operator certificate (`operator_allowlist`, used
by `verify-key`), a replacement cosigner or driver certificate (compromised key, renewal before
expiry), or a certificate for a new node. Without it the trust domain is frozen until the leaves
expire. Rotate when:

- the CA key is lost (the soak, 2026-10-09: CA `CN=rutli-frost-cluster-ca`, file sha256
  `453bb4aea2088bb5…c663`, valid until 2028-10-19; every leaf also expires 2028-10-19);
- the CA key may be exposed (rotate **now**, then also drop the old CA as fast as §6 allows);
- the CA approaches expiry.

Loss of the CA key is **not** a key-loss event. No share, hosted key, backup or export depends on
it (§2). It is an availability deadline: the cluster keeps working on the existing certificates
until they expire.

## 2. What depends on the CA bytes

Two different things read `tls.ca_cert`.

**The TLS trust anchor.** The cosigners use rustls through tonic, the driver uses Netty. Every
certificate in the file is a trust anchor for both, so a file holding two concatenated CAs trusts
both. This is what makes a dual-CA overlap possible. `FrostTlsTrustBundleSpec` (driver) and
`frost/cosigner/tests/tls_rotation.rs` (cosigner) pin the behaviour.

Because every certificate in the file is an anchor, the file must hold **only valid CA
certificates**: a cosigner leaf in it would let whoever holds that leaf's key mint any identity.
The cosigners (`trust::load_trust_anchors`), `rutli-dealer` and the driver (`FrostTrustFile`)
refuse a file holding anything else (a leaf, a private key, an expired or not-yet-valid CA) and
log each anchor's subject, notAfter and SHA-256 (`trust anchor` in the cosigner log, `FROST: trust
anchor` in the participant log). A cosigner fed a bad file never becomes Ready, so `roll_one`
times out and the phase STOPs with the other two pods still serving; a participant fed one fails
driver init. Build the bundle exactly as Phase 1 says. If the old CA has **already expired**, the
bundle would be refused: set `tls.allowExpiredCa=true` (chart) and `allow-expired-ca = true`
(driver `frost.tls`) for the rotation, and remove both at the close-out.

**The cluster id.** Without a pin, `cluster_id = hex(sha256(ca.crt file bytes)[..8])`
(`wrap::cluster_id_from_ca`, `Config::cluster_id`). Adding a second CA to the file changes the id.
Swapping the CA changes it again. Where the id is used:

| Use | Persisted? | Effect if nodes disagree or the id changes |
|---|---|---|
| Hosted-key replication envelopes (`wrap_for`/`unwrap_key` AAD): `GenerateKey` fan-out, read-repair `FetchKey`, anti-entropy push/pull | **No**, in flight only | Replication between nodes with different ids fails (`key envelope failed authentication`). Decrypt/ECDH are served locally and keep working. Anti-entropy heals once the ids agree again. |
| Split ceremony recipient request (`share-recipient`), dealer check (`rutli-dealer --ca-cert`), share bundle (`import-share` check 3, envelope AAD) | **Yes, while a ceremony is in flight**: `data_dir/ceremony/<key_id>.recipient` (sealed) and the dealer's `r<i>.json` / `share-*-node<i>.json` | A pending recipient or bundle from before the change is refused. Run `abort-import`, then redo the ceremony. |
| Installed shares (`KeyOrigin`), hosted keys at rest (share-seal AEAD, salted by node id only), hosted-key commitments, `backup`/`restore`, `export-key`/`import-key` files | No id inside | **None.** Nothing at rest has to be rewritten. |
| Signing and delete intents (audit C2/M2): every intent names the cluster id, and each cosigner refuses one for another cluster (`rutli_sign_policy_refusals_total{reason="cluster"}`) | No (each intent lives ≤ `intent_max_lifetime_secs`) | The driver names the id it **pinned** (`frost.cluster-id`) or **learned** — the value a majority of the endpoints report in `Capabilities` (audit F5), learned again after a cosigner refuses an intent for its cluster. If the id changes under a pinned driver, every sign is refused with PERMISSION_DENIED until `frost.cluster-id` is updated. |

The driver sees the cluster id: it names it in every signing intent. With the cosigner pin in place
the id never changes, which is one more reason to pin it before the CA file changes. If the driver
pins it too (`frost.cluster-id`, recommended in production — then no cosigner's `Capabilities`
answer is trusted for it), it must be the same value. In an incident where intents are refused for
the cluster id and the cosigners do not set `require_intent`, `frost.sign-intents = off` (driver
restart) stops attaching intents until it is fixed.

So nothing at rest is lost when the id changes. But a rolling restart over a changed CA file leaves
nodes with **different** ids for the length of the roll, and that happens twice: when the second CA
is added and when the old one is dropped. Hosted-key writes during those windows can fail their
write quorum. The fix is to **pin** the id (`cluster_id` in the cosigner config, chart value
`clusterId`) to its current value **before** the file changes, and keep that pin forever. With the
pin, the id never depends on the CA again. Every node must hold the same value. Never unpin or
change it on a live cluster.

> **Older images ignore the pin.** `cluster_id` ships after `0.4.0-rc.1` (CHANGELOG, Unreleased →
> `0.4.0-rc.2` / `0.4.0`). `0.4.0-rc.1` and every older image silently ignore unknown config fields,
> so they accept the pin and derive the id anyway. Check the startup line
> `cluster id <id> (pinned in config)` on **every** pod before any CA byte changes (§5 Phase 0); the
> per-pod gate does exactly that.

From the release that adds the pin on, each cosigner also records the id it runs under in
`data_dir/cluster-id` at its first start and **refuses to start** under a different one
(`cluster id mismatch` in the pod log). Phase 0 passes this check: the pin equals the derived value,
so the id does not change. It is what catches a later `helm upgrade` that dropped `clusterId`
(an upgrade without `-f <saved values>` / `--reuse-values` resets it): the rolled pod never becomes
Ready instead of leaving the cluster. Put the value back and roll that pod again.

The dealer must be told the pinned id after a rotation: `rutli-dealer split-key --ca-cert <current
ca.crt> --cluster-id 453bb4aea2088bb5 …`. Without `--cluster-id` it derives the id from the file,
which then no longer matches.

## 3. Design

Four certificate sets, each a valid state on its own:

| Phase | Cosigner trust (`ca.crt`) | Cosigner leaves | Driver trust | Driver leaf | Restarts |
|---|---|---|---|---|---|
| start | old | old | old | old | — |
| 0 pin | old | old | old | old | cosigner roll (Helm upgrade) |
| A | **old + new** | old | old | old | cosigner roll |
| B | old + new | old | **old + new** | **new** | **participant restart** (planned event) |
| C | old + new | **new** | old + new | new | cosigner roll |
| D | **new** | new | old + new | new | cosigner roll |
| E | new | new | **new** | new | next planned participant restart |

Why this order:

- Every handshake needs each side to trust the other side's issuer. Every adjacent pair of rows is
  mutually compatible. So any mix of restarted and not-yet-restarted pods works, and the cluster
  keeps `t = 2` signing nodes throughout.
- The Secret holds the next phase's material while the roll is in progress. An **unplanned**
  restart of any pod, or of the participant, picks up material that is still compatible with
  everything else running.
- The driver changes once (B), between the two cosigner phases that need it. It must trust the new
  CA before any cosigner presents a new leaf (C). Its new leaf needs every cosigner to trust the new
  CA, which A provides. Dropping the old CA from the driver (E) is cleanup and can wait for any
  later planned restart.
- Merging C and D into one roll (new leaf + new-only trust per pod) would split the mesh for the
  length of the roll. Each rolled pod could then talk only to other rolled pods. Signing would
  survive at 2-of-3 only by luck of ordering. Keep them separate.
- Gate: never start a phase until **every** pod (and, for C, the participant) runs the previous one.
- Rollback is the reverse order, one phase at a time (§7).

No split ceremony may be in flight from Phase A to the end of Phase D: no pending `share-recipient`.
With the pin the id is stable, but recipient request signatures are made by the old leaves and
checked against whatever CA file the dealer is given. Finish or `abort-import` first.

Expected duration: about 2 h of cosigner rolls (3 phases × 3 pods × ~8 min including the 6 min
mesh-check wait) plus Phase 0 and one participant restart.

## 4. Prerequisites

1. **A cosigner release with `cluster_id`** (this change: `0.4.0-rc.2` / `0.4.0`, **not**
   `0.4.0-rc.1`), image pinned by digest in the chart. An `rc.1` or older image ignores the pin and
   keeps deriving the id from the CA file; Phase 0's gate catches that (no `(pinned in config)`
   line), so do not start Phase A on such an image. On the soak, fold Phase 0 into the first
   planned cosigner upgrade to a release that carries this change.
2. **Laptop:** `kubectl` (context `hcloud-cluster`), `helm`, `openssl`, `jq`, `shasum`, and a
   `rutli-cosigner` binary from the same release (`cd frost && cargo build --release -p
   rutli-cosigner --bin rutli-cosigner`). It runs `verify-key` over port-forwards.
3. **Escrow destination for the new CA key**, decided **before** generating it: an encrypted copy
   in two independent places (e.g. the team password manager and an offline USB in the safe),
   with a restore test. This is the step whose absence caused the incident.
4. A quiet window: no split ceremony, no hosted-key rotation planned, soak green
   (`deploy/soak/soak-check.sh` or the Grafana dashboard), all three cosigners Ready.
5. **Inventory of every holder of a cluster certificate.** The soak has one: the soak
   participant's driver (PVC `rutli-kms-bundle` in `stakecraft-devnet-rutli-01`). Check for others:
   a B4 participant, laptops, CI, and every client config this repo ships:
   - `deploy/k8s/cronjob-refresh.yaml`: Secret `rutli-driver-tls` (driver leaf) + CA from
     `rutli-cosigner-ca`;
   - `deploy/k8s/job-verify-key.example.yaml`: Secret `rutli-operator-tls` (operator leaf) + CA
     from `rutli-cosigner-ca`;
   - `deploy/soak/validator/compose-rutli-kms.yaml`: a validator's driver, `./certs/{ca.crt,
     driver.crt,driver.key}` next to the compose file.

   Every **client** must get Phase B treatment (trust old + new, new leaf) **before Phase C**. If it
   still holds an old leaf at Phase D, it is locked out. If it trusts only the old CA at Phase C, it
   rejects the new cosigner leaves. The two `deploy/k8s` clients read `ca.crt` from
   `rutli-cosigner-ca`, so `put_ca` moves their trust with the cosigners' (on `perNode`); only
   their leaf Secrets need a new leaf, between Phase A and Phase D.
6. **The TLS layout.** The soak runs `shared` (one Secret `rutli-cosigner-tls`). After B4 Step A it
   runs `perNode` (`rutli-cosigner-ca` + `rutli-cosigner-tls-{1,2,3}`). Set `LAYOUT` below
   accordingly, and do not change it during the rotation. The **live** soak StatefulSet was
   rendered by an older chart: it mounts the Secret directly at `/certs`, so the kubelet refreshes
   the files inside running pods. From the Phase 0 upgrade on, the chart's `tls-select` init
   container copies the material into memory at pod start, in both layouts. From Phase A on, a pod's
   `/certs` therefore shows exactly what it started with.
7. **Helper pod admission** in the participant namespace (Phase B): `kc get ns $PNS --show-labels`.
   If it enforces Pod Security `restricted`, the root busybox pod below is rejected. B4 §4.0
   ran the same pod in a sibling namespace. Add a non-root `securityContext` matching the
   participant's `fsGroup: 1001` if needed.

### Session setup (every terminal)

```sh
export KUBECONTEXT=hcloud-cluster NS=rutli PNS=stakecraft-devnet-rutli-01
export LAYOUT=shared                      # or perNode — see 4.6
export PIN=453bb4aea2088bb5               # the current derived id; never changes from here on
export KEY_ID=frost-namespace             # the soak's FROST namespace key
export NS_FP=12203286ffe27c94c35ee0aa24a359d41e73f4df6e88d2aab2b72860df79ce8f22ea
export R=~/ca-rotation                    # outside the repo
mkdir -p $R/old $R/new $R/client && chmod 700 $R $R/old $R/new $R/client
kc() { kubectl --context "$KUBECONTEXT" "$@"; }

# Write Secret keys from files in ONE merge patch (a crt and its key change together). The values
# go through a 0600 patch file, never argv.
put() { # put <secret> <key> <file> [<key> <file> ...]
  local s=$1 p body="" sep=""; shift
  while [ $# -ge 2 ]; do
    body="$body$sep\"$1\":\"$(base64 < "$2" | tr -d '\n')\""; sep=","; shift 2
  done
  p=$(mktemp "$R/patch.XXXXXX"); printf '{"data":{%s}}' "$body" > "$p"
  kc -n $NS patch secret "$s" --type merge --patch-file "$p"; local rc=$?; rm -f "$p"; return $rc
}
put_ca() { # put_ca <file>
  if [ "$LAYOUT" = shared ]; then put rutli-cosigner-tls ca.crt "$1"; else put rutli-cosigner-ca ca.crt "$1"; fi
}
put_leaf() { # put_leaf <identifier> <crt> <key>
  if [ "$LAYOUT" = shared ]; then put rutli-cosigner-tls "cosigner$1.crt" "$2" "cosigner$1.key" "$3"
  else put "rutli-cosigner-tls-$1" tls.crt "$2" tls.key "$3"; fi
}
get_ca() { # get_ca <out file> — the CA file the cosigners currently get
  if [ "$LAYOUT" = shared ]; then kc -n $NS get secret rutli-cosigner-tls -o jsonpath='{.data.ca\.crt}'
  else kc -n $NS get secret rutli-cosigner-ca -o jsonpath='{.data.ca\.crt}'; fi | base64 -d > "$1"
}

# Restart ONE cosigner and wait until it is Ready again. `delete pod` bypasses the PDB, so
# check all three are Ready first. Sets T0 (when the pod became Ready) for `gate`.
roll_one() { # roll_one <ordinal>
  [ "$(kc -n $NS get pods -l app.kubernetes.io/name=rutli-cosigner --no-headers | grep -c ' 1/1 .*Running')" = 3 ] \
    || { echo "STOP: not 3/3 Ready before rolling $1"; return 1; }
  kc -n $NS delete pod rutli-cosigner-$1 || return 1
  until kc -n $NS get pod rutli-cosigner-$1 >/dev/null 2>&1; do sleep 2; done
  kc -n $NS wait --for=condition=Ready pod/rutli-cosigner-$1 --timeout=5m || return 1
  T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)
}

# The checks after each pod (see "Per-pod gate" below). Non-zero exit on any STOP.
gate() { # gate <ordinal> <expected sha256 of ca.crt>
  local o=$1 fail=0
  # Exactly $PIN, pinned. `grep -F`: the whole line, not just "some id, pinned".
  kc -n $NS logs rutli-cosigner-$o -c cosigner | grep -F "cluster id $PIN (pinned in config)" \
    || { echo "STOP: pod $o does not run pinned to $PIN"; fail=1; }
  kc -n $NS logs rutli-cosigner-$o -c cosigner | grep 'trust anchor'      # what ca.crt holds, one line per CA
  kc -n $NS exec rutli-cosigner-$o -c cosigner -- sha256sum /certs/ca.crt | grep -q "^$2" \
    && echo "pod $o ca.crt ok" || { echo "STOP: pod $o ca.crt is not $2"; fail=1; }
  echo "waiting 6 min: one anti-entropy sweep from every node to every peer"; sleep 360
  # Only since the pod was Ready: errors from while it was down are expected and not a STOP.
  for p in 0 1 2; do
    kc -n $NS logs rutli-cosigner-$p -c cosigner --since-time="$T0" \
      | grep -Ei 'UnknownIssuer|UnknownCA|BadCertificate|invalid peer certificate|handshake|cannot list keys on peer|sign_round1 failed|replication failed|repair failed|push failed' \
      && { echo "STOP: TLS/mesh errors on pod $p"; fail=1; }
  done
  echo "gate $o: $([ $fail = 0 ] && echo PASS || echo STOP)"; return $fail
}
```

The label selector in `roll_one` is the chart's (`app.kubernetes.io/name=rutli-cosigner`). Check
it once with `kc -n $NS get pods --show-labels`. Always run a phase's roll as
`for o in 2 1 0; do roll_one $o && gate $o <sha> || break; done`. `break` stops at the first
STOP. Then check that the loop ended on `gate 0: PASS` before going on.

**Per-pod gate**, after every `roll_one`:

1. The pod is Ready. Readiness checks the key store and the gRPC port, **not** the mesh.
2. The startup line is `cluster id 453bb4aea2088bb5 (pinned in config)`. From Phase A on, the next
   line also says the pin differs from the CA-derived id. That is expected.
3. `sha256sum /certs/ca.crt` in the pod is the phase's expected hash. From Phase 0 on, this is the
   copy made at pod start, so it proves the pod restarted onto the new material.
4. Since the pod became Ready, through one anti-entropy interval (300 s on the soak; a sweep
   sleeps first, then runs), no TLS or mesh errors on **any** pod. With hosted keys on, every node
   lists keys on every peer each sweep and logs `anti-entropy: cannot list keys on peer` when that
   fails, so one clean interval covers every directed link of the mesh. **Without hosted keys this
   step proves nothing:** no sweep runs, and the mesh only carries signing rounds, between whichever
   nodes the leader picks. The soak has hosted keys on; on an install without them, lean on step 5
   and treat the 6-minute wait as unproven.
5. Signing is unaffected: on the Grafana soak dashboard, `rutli_sign_requests_total{result="error"}`
   stays flat, `rutli_sign_round1_skips_total` stays flat, and ok-signs keep coming. The same
   checks run in `deploy/soak/soak-check.sh`.

**STOP** on any failure: do not roll the next pod. Two nodes are still signing. Restore the previous
phase's material (§7) and roll the failed pod again. A pod that never becomes Ready says why in
`kc -n $NS logs rutli-cosigner-<o> -c cosigner`: `cluster id mismatch` (the pin is missing or
different: fix `clusterId`), or `tls.ca_cert …` (the trust file holds something other than valid
CA certificates).

### Laptop `verify-key` (from Phase A on)

`verify-key` asks every node's Signer API for `KeyStatus` over three port-forwards. It proves the
laptop's certificate is accepted by every node, and that the laptop's trust file accepts every
node's server certificate. Port-forward bypasses the NetworkPolicy. The cosigner certs carry
`IP:127.0.0.1` and the shared SAN `rutli-cosigner`.

```sh
# (Re)start the three port-forwards. They die with their pod: run pf again after every roll.
pf() {
  pkill -f "port-forward pod/rutli-cosigner-" 2>/dev/null; sleep 1
  for o in 0 1 2; do kc -n $NS port-forward pod/rutli-cosigner-$o 1910$((o+1)):9101 >/dev/null 2>&1 & done
  sleep 3
}
# client config: <trust file> <cert> <key>. A Config needs a data_dir and allowlists to validate.
client_cfg() { # client_cfg <name> <ca> <crt> <key>
  mkdir -p $R/client/data-$1
  jq -n --arg ca "$2" --arg crt "$3" --arg key "$4" --arg dd "$R/client/data-$1" '{
    identifier: 1, listen: "127.0.0.1:0", threshold: 2, data_dir: $dd,
    peers: [ {identifier:1,endpoint:"https://127.0.0.1:19101"},
             {identifier:2,endpoint:"https://127.0.0.1:19102"},
             {identifier:3,endpoint:"https://127.0.0.1:19103"} ],
    tls: {ca_cert:$ca, cert:$crt, key:$key, domain:"rutli-cosigner"},
    signer_allowlist:["driver"], peer_allowlist:["cosigner1","cosigner2","cosigner3"],
    operator_allowlist:["operator"] }' > $R/client/$1.json
}
vk() { pf; rutli-cosigner --config $R/client/$1.json verify-key --key-id "$KEY_ID" --expect-fingerprint "$NS_FP"; }
```

Expect `OK`: the key is present on 3/3 nodes, has the same package, and every node's own verifying
share is consistent. `--sign-test` applies only to keys imported by the split ceremony, so it is
not used here.

## 5. Procedure

### Phase 0: pin the cluster id [MUTATES]

Read-only first:

```sh
get_ca $R/old/ca.crt                                        # public
shasum -a 256 $R/old/ca.crt | cut -c1-16                    # must print $PIN (453bb4aea2088bb5)
export SHA_OLD=$(shasum -a 256 $R/old/ca.crt | cut -d' ' -f1)
helm --kube-context $KUBECONTEXT -n $NS get values rutli -o yaml > $R/rutli-values.pre-rotation.yaml
```

If the hash is not `$PIN`, someone has already changed the CA file. Stop and find out why
before going on.

Upgrade to a release with `cluster_id` (`0.4.0-rc.2` / `0.4.0` or later; `0.4.0-rc.1` does not
have it), adding the pin and the operator role. On the soak, do this together with the first
planned image upgrade to such a release. An older image accepts the value and ignores it; the
check below catches that. Keep `tls.layout` as it is.

```sh
helm --kube-context $KUBECONTEXT -n $NS upgrade rutli deploy/helm/rutli-cosigner \
  -f $R/rutli-values.pre-rotation.yaml \
  --set-string clusterId=$PIN --set-json 'operatorAllowlist=["operator"]' \
  --set tls.layout=$LAYOUT                                   # + the release's image values
kc -n $NS rollout status sts/rutli-cosigner --timeout=20m
kc -n $NS get pods -l app.kubernetes.io/name=rutli-cosigner      # AGE: all three restarted by the upgrade?
for o in 0 1 2; do echo "pod $o:"; kc -n $NS logs rutli-cosigner-$o -c cosigner | grep 'cluster id'; done
for o in 0 1 2; do kc -n $NS logs rutli-cosigner-$o -c cosigner | grep -qF "cluster id $PIN (pinned in config)" \
  && echo "pod $o pinned to $PIN" || echo "STOP: pod $o is not pinned to $PIN"; done
```

Expect `cluster id 453bb4aea2088bb5 (pinned in config)` on every pod, with no "differs" line yet,
and on the first start of the new image `cluster id 453bb4aea2088bb5 recorded in
/data/cluster-id`. All of each pod's `cluster id` lines are printed (no `-m1`): a "differs" or
"recorded" line must not hide behind the first match.
During this roll the pinned (new) pods and the derived (old) pods compute the same id, so nothing
can mismatch.

The pod template has no config checksum, so an upgrade that changes only the ConfigMap (the image
already current) restarts nothing, and the pin is not loaded. In that case, or to get the gate
checks anyway, roll by hand:

```sh
T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)
for o in 2 1 0; do roll_one $o && gate $o $SHA_OLD || break; done
```

**STOP** if any pod lacks the line `cluster id 453bb4aea2088bb5 (pinned in config)`. An image without
`cluster_id` support logs no cluster-id line at all (it ignores the pin), and a new image without
the pin logs `(derived from tls.ca_cert)`. Do **not** go on to Phase A until all three show
`pinned`. Grep with the parentheses: from Phase A on, the "differs" line also contains the words
`derived from tls.ca_cert`.

### Phase 1: new PKI, offline [no cluster change]

The driver leaf is **not** issued here. It can sign with the namespace key (CN `driver`, Signer
API) as soon as Phase A trusts the new CA, and Phase B may be days away, so it is issued from
escrow in Phase B and shredded minutes later.

```sh
cd <rutli checkout at the release tag>
RUTLI_CA_CN=rutli-frost-cluster-ca-2026-10 RUTLI_CA_DAYS=3650 \
  RUTLI_CERTS="cosigner1 cosigner2 cosigner3 operator" scripts/gen-frost-certs.sh 3 $R/new
openssl verify -CAfile $R/new/ca.crt $R/new/{cosigner1,cosigner2,cosigner3,operator}.crt
for c in cosigner1 cosigner2 cosigner3 operator; do
  openssl x509 -in $R/new/$c.crt -noout -subject -ext subjectAltName,extendedKeyUsage; done
```

Expect four `OK`. The CNs are `cosigner1..3` and `operator`. The cosigner SANs match the
live ones (`DNS:rutli-cosigner, DNS:cosignerN, DNS:cosigner-(N-1), DNS:localhost, IP:127.0.0.1`).
Compare with
`kc -n $NS get secret rutli-cosigner-tls -o jsonpath='{.data.cosigner1\.crt}' | base64 -d | openssl x509 -noout -ext subjectAltName`.
The new CA has a **different CN** from the old one, so the two are easy to tell apart in the bundle.

**Escrow the new CA key now**, before it touches any cluster, then **shred the plaintext**:

```sh
# PKCS#8 v2, AES-256-CBC, PBKDF2 with 600 000 iterations (a bare `pkey -aes256` is a far weaker KDF).
# Strong passphrase, stored separately from the file.
openssl pkcs8 -topk8 -v2 aes-256-cbc -iter 600000 -in $R/new/ca.key -out $R/new/ca.key.enc
# copy ca.key.enc + ca.crt to the two escrow locations (4.3), then prove a restore works from EACH:
openssl pkey -in <escrow copy>/ca.key.enc -pubout | diff - <(openssl x509 -in $R/new/ca.crt -pubkey -noout) && echo ESCROW-OK
shred -u $R/new/ca.key 2>/dev/null || rm -P $R/new/ca.key; ls $R/new/ca.key 2>/dev/null && echo "STOP: ca.key still there"
```

Record in the soak log: new CA subject, `shasum -a 256 $R/new/ca.crt`, notAfter, the escrow
locations, `ESCROW-OK` for each, and the shred. From here on the CA key exists only encrypted.
Whenever a later step needs it (the driver leaf in Phase B, a re-issue for rollback, a later
operator cert), restore it into a temporary 0700 directory for that one command and shred it
right after:

```sh
ca_restore() { # ca_restore <dir> — decrypt the escrowed CA key next to its certificate
  mkdir -m 700 "$1" && cp $R/new/ca.crt "$1/" \
    && ( umask 077; openssl pkcs8 -in <escrow copy>/ca.key.enc -out "$1/ca.key" )
}
ca_shred() { shred -u "$1/ca.key" 2>/dev/null || rm -P "$1/ca.key"; rm -rf "$1"; }
```

Build the trust bundle, old CA first. `printf` guarantees a newline between the two PEM blocks
even if the old file lacks a trailing one:

```sh
printf '%s\n%s\n' "$(cat $R/old/ca.crt)" "$(cat $R/new/ca.crt)" > $R/bundle.crt
grep -c 'BEGIN' $R/bundle.crt                                  # 2: two blocks, nothing else
openssl crl2pkcs7 -nocrl -certfile $R/bundle.crt | openssl pkcs7 -print_certs -noout   # the two CA subjects
for f in $R/old/ca.crt $R/new/ca.crt; do                       # each a CA, valid now (the nodes refuse anything else)
  openssl x509 -in $f -noout -subject -enddate -checkend 0 -ext basicConstraints; done
export SHA_OLD=$(shasum -a 256 $R/old/ca.crt | cut -d' ' -f1) \
       SHA_BUNDLE=$(shasum -a 256 $R/bundle.crt | cut -d' ' -f1) \
       SHA_NEW=$(shasum -a 256 $R/new/ca.crt | cut -d' ' -f1)
```

Keep the old leaves for rollback (sensitive: 0600 in `$R/old`, shredded at the end):

```sh
( umask 077; for i in 1 2 3; do
  if [ "$LAYOUT" = shared ]; then s=rutli-cosigner-tls c="cosigner$i\.crt" k="cosigner$i\.key"
  else s=rutli-cosigner-tls-$i c='tls\.crt' k='tls\.key'; fi
  kc -n $NS get secret $s -o jsonpath="{.data.$c}" | base64 -d > $R/old/cosigner$i.crt
  kc -n $NS get secret $s -o jsonpath="{.data.$k}" | base64 -d > $R/old/cosigner$i.key
done )
for i in 1 2 3; do openssl verify -CAfile $R/old/ca.crt $R/old/cosigner$i.crt; done   # 3× OK, non-empty
```

The old driver leaf is saved from the PVC in Phase B.

### Phase A: cosigners trust old + new [MUTATES]

```sh
put_ca $R/bundle.crt
for o in 2 1 0; do roll_one $o && gate $o $SHA_BUNDLE || break; done
```

Then the end-to-end check with a **new-CA** client certificate. This is the first moment a new-CA
certificate is accepted anywhere:

```sh
client_cfg op-bundle $R/bundle.crt $R/new/operator.crt $R/new/operator.key && vk op-bundle   # OK
```

### Phase B: driver bundle + new driver leaf (participant restart: planned soak event) [MUTATES]

First issue the driver leaf from escrow and check it against the live cluster. It exists in
plaintext only until the end of this phase's copy:

```sh
ca_restore $R/ca-tmp && RUTLI_CA_DIR=$R/ca-tmp RUTLI_CERTS=driver <rutli checkout>/scripts/gen-frost-certs.sh 3 $R/new
ca_shred $R/ca-tmp
openssl verify -CAfile $R/new/ca.crt $R/new/driver.crt                                       # OK
client_cfg drv-bundle $R/bundle.crt $R/new/driver.crt $R/new/driver.key && vk drv-bundle     # OK: accepted by all 3
```

`drv-bundle` exercises the exact certificate set this phase gives the driver. rustls stands in here
for Netty, whose multi-CA trust is covered by `FrostTlsTrustBundleSpec`.

The participant (`deploy/participant`, `strategy: Recreate`, node `agent-cx33-fsn-vkh`) mounts PVC
`rutli-kms-bundle`, subPath `certs`, at `/rutli-certs`. The driver reads `ca.crt`, `driver.crt` and
`driver.key` only at startup. Write the new files next to the old ones. The PVC is
ReadWriteOnce, so the helper pod must run on the participant's node.

```sh
NODE=$(kc -n $PNS get pod -l app=participant -o jsonpath='{.items[0].spec.nodeName}')   # check the label; expect agent-cx33-fsn-vkh
kc -n $PNS run rutli-kms-ca-rotate --restart=Never --image=docker.io/library/busybox:1.36 \
  --overrides='{"spec":{"nodeSelector":{"kubernetes.io/hostname":"'$NODE'"},"containers":[{"name":"p","image":"docker.io/library/busybox:1.36","command":["sleep","3600"],"volumeMounts":[{"name":"b","mountPath":"/bundle"}]}],"volumes":[{"name":"b","persistentVolumeClaim":{"claimName":"rutli-kms-bundle"}}]}}'
kc -n $PNS wait --for=condition=Ready pod/rutli-kms-ca-rotate --timeout=180s
kc -n $PNS exec rutli-kms-ca-rotate -- sh -c 'cd /bundle/certs && for f in ca.crt driver.crt driver.key; do cp -p $f $f.pre-ca-rotation; done && sha256sum *'
( umask 077; for f in driver.crt driver.key; do                 # the old driver leaf, for rollback and Phase D's negative control
    kc -n $PNS exec rutli-kms-ca-rotate -- cat /bundle/certs/$f > $R/old/$f; done )
openssl verify -CAfile $R/old/ca.crt $R/old/driver.crt          # OK
kc cp $R/bundle.crt      $PNS/rutli-kms-ca-rotate:/bundle/certs/ca.crt.new
kc cp $R/new/driver.crt  $PNS/rutli-kms-ca-rotate:/bundle/certs/driver.crt.new
kc cp $R/new/driver.key  $PNS/rutli-kms-ca-rotate:/bundle/certs/driver.key.new
# `cat >` rewrites the existing files in place, keeping the owner and mode the participant reads
# them with (busybox has no chmod/chown --reference); then the .new copies go.
kc -n $PNS exec rutli-kms-ca-rotate -- sh -c 'cd /bundle/certs && for f in ca.crt driver.crt driver.key; do cat $f.new > $f && rm $f.new; done &&
  ls -ln && sha256sum ca.crt driver.crt'                                                        # ca.crt = $SHA_BUNDLE; modes/owners unchanged
kc -n $PNS delete pod rutli-kms-ca-rotate
```

Every other driver-certificate holder from the inventory (4.5) gets the same leaf now, e.g. the
refresh CronJob's `rutli-driver-tls` (`kc -n $NS create secret tls rutli-driver-tls
--cert=$R/new/driver.crt --key=$R/new/driver.key --dry-run=client -o yaml | kc apply -f -`). Then
shred the plaintext key; a rollback or a later client re-issues one from escrow:

```sh
shred -u $R/new/driver.key 2>/dev/null || rm -P $R/new/driver.key; rm -rf $R/client/drv-bundle.json $R/client/data-drv-bundle
```

The files are now in place for the **next** participant start. An unplanned restart in between is
safe: Phase A made every cosigner accept them. Restart at the planned time and log it as a soak
event:

```sh
kc -n $PNS rollout restart deploy/participant && kc -n $PNS rollout status deploy/participant --timeout=15m
kc -n $PNS logs deploy/participant | grep -E 'Loaded driver rutli|FROST: mutual TLS channel'      # 3 channels
kc -n $PNS logs deploy/participant --since=15m | grep -Ei 'UNAVAILABLE|handshake|certificate|PKIX' # empty
```

Expect the participant healthy, ok-signs resuming on the dashboard with zero sign errors, and
`soak-check.sh` PASS. **STOP** → §7 B.

### Phase C: new cosigner leaves [MUTATES]

```sh
for i in 1 2 3; do put_leaf $i $R/new/cosigner$i.crt $R/new/cosigner$i.key; done
for o in 2 1 0; do roll_one $o && gate $o $SHA_BUNDLE || break; done
```

Then check that every node now serves a new leaf:

```sh
client_cfg op-new $R/new/ca.crt $R/new/operator.crt $R/new/operator.key && vk op-new   # OK only once all 3 are rolled
```

`vk op-new` trusts **only** the new CA. Its `OK` proves every node presents a new leaf. It is the
gate for Phase D.

### Phase D: cosigners drop the old CA [MUTATES]

```sh
put_ca $R/new/ca.crt
for o in 2 1 0; do roll_one $o && gate $o $SHA_NEW || break; done
vk op-new                                                                  # OK
```

Negative control: an old-CA client certificate (the old driver leaf saved in Phase B) must now be
refused by every node. Its trust file is the bundle, so the client side accepts the servers. The
refusal can only come from the cosigners no longer trusting the old CA:

```sh
[ -s $R/old/driver.crt ] && [ -s $R/old/driver.key ] || echo "STOP: old driver leaf missing"
client_cfg old-driver $R/bundle.crt $R/old/driver.crt $R/old/driver.key
vk old-driver > $R/neg.txt 2>&1; rc=$?; cat $R/neg.txt     # no pipe: $rc is verify-key's own exit code
[ $rc -ne 0 ] || echo "STOP: verify-key succeeded with an old-CA certificate"
# One line per node, each naming the TLS alert; anything else (a config error, a timeout) is a STOP.
[ "$(grep -E '^  node [0-9]+ ' $R/neg.txt | grep -Ec 'UnknownCA|unknown ca|BadCertificate')" = 3 ] \
  && echo "negative control PASS" || echo "STOP: not 3 TLS refusals"
```

`verify-key` prints the transport error behind each failure (`received fatal alert: UnknownCA`).
A binary older than that prints only `transport error`, and this check STOPs; use the release's
binary (4.2).

In TLS 1.3 the node's alert races the client's first request, so the RPC error itself may read
`connection closed` or `broken pipe` instead of the alert. `verify-key` then probes the node with a
bare handshake and appends what the node answered, e.g. `… connection closed (TLS probe: refused
after the handshake: received fatal alert: UnknownCA)`; the grep above matches either form. A line
with `connection closed` and **no** `(TLS probe: …)` means the probe got no refusal: the node
accepted the certificate or did not answer. That is a STOP: the node is down or still trusts the
old CA. Check it with `vk op-new` and the node's logs before going on. Binaries without the probe
print the bare `connection closed` about half the time: re-run, or use the release's binary.

On `shared`, the Secret still carries the old `driver.crt`/`driver.key`. The cosigners never used
them. After confirming nothing else reads them (the NAAS `rutli-prereqs.sh` copied them once into
the PVC bundle), remove them:

```sh
kc -n $NS patch secret rutli-cosigner-tls --type json -p '[{"op":"remove","path":"/data/driver.crt"},{"op":"remove","path":"/data/driver.key"}]'
```

### Phase E: driver drops the old CA (next planned participant restart) [MUTATES]

As in Phase B, with only `ca.crt` ← `$R/new/ca.crt` (sha256 `$SHA_NEW`). Remove the
`*.pre-ca-rotation` files in the same helper-pod session. Then, at the participant's next planned
restart, check the same log lines as in Phase B. Until then the driver trusting the old CA is
harmless only if the old key is truly gone; if it may be exposed, do E right after D.

### Close-out

- `shred -u`/`rm -P` `$R/old/*.key`, `$R/new/*.key` and `$R/client` (the CA key and the new
  driver key were shredded in Phase 1 and Phase B; check they are gone). On APFS/SSD this is not
  provable erasure; record it like the B4 destruction list.
- Remove `tls.allowExpiredCa` / `allow-expired-ca` if the rotation needed them (§2).
- Keep `operator.crt/.key` only where verify-key runs, or re-issue a short-lived one per use from
  escrow (`RUTLI_CA_DIR=<escrow restore dir> RUTLI_CERTS=operator scripts/gen-frost-certs.sh 3 <out>`).
- Soak log: phases, timestamps, hashes, the participant restart, and gate results.
- Calendar: the new leaves expire 825 days after issue. Renew 60 days ahead from escrow.
- The pin stays. `clusterId` remains in the Helm values for the life of the cluster. Every later
  `helm upgrade` must carry it: `helm get values rutli -o yaml > saved.yaml` and `-f saved.yaml`, or
  `--reuse-values`. A plain `helm upgrade --set …` resets it; the pods then refuse to start
  (`cluster id mismatch`) instead of leaving the cluster, and the rollout stalls at the first pod.
  Never copy `clusterId` into another cluster's values.
- The dealer from now on: `rutli-dealer split-key --ca-cert <new ca.crt, alone> --cluster-id 453bb4aea2088bb5 …`.
  Not the bundle: if the old key was exposed, the bundle would let old-CA-minted recipient
  requests verify, and only the SAS check would stand in the way.

## 6. Speed when the old key may be compromised

Phases A through D carry no waiting beyond the gates, so the old CA can be gone from the cosigners
within about 2 h. Do E immediately after D (a second participant restart) instead of waiting for
a planned one. Until D completes, anyone holding the old key can mint certificates the cosigners
accept. The signer/peer/operator allowlists are CN-based, so an attacker can mint a cert with CN
`driver` and use the Signer API. Treat that window as an incident.

## 7. Rollback

Always in reverse order, one phase at a time. Undo the later phase before the earlier one. The
material for every earlier state is in `$R/old` (old CA, old cosigner and driver leaves) and, until
Phase E, in the PVC `*.pre-ca-rotation` files. After the close-out shreds `$R/old`, there is no way
back past Phase D. That is intended: the old CA cannot be re-trusted for leaves nobody can renew.

| Undo | Commands | Precondition |
|---|---|---|
| E | Helper pod: `ca.crt` ← bundle. Restart the participant. | — |
| D | `put_ca $R/bundle.crt`, then `roll_one`/`gate` 2 1 0 with `$SHA_BUNDLE`. | — |
| C | `put_leaf $i $R/old/cosigner$i.crt $R/old/cosigner$i.key` for i=1..3, then roll 2 1 0. | D undone (cosigners trust old + new) |
| B | Helper pod: `for f in ca.crt driver.crt driver.key; do cat $f.pre-ca-rotation > $f; done` (after E, from `$R/old` via `kc cp`), then restart the participant. | C undone, or the driver would no longer trust the new leaves still in use |
| A | `put_ca $R/old/ca.crt`, then roll 2 1 0 with `$SHA_OLD`. | B undone (the driver's new leaf needs the new CA trusted) |
| 0 | `helm rollback rutli <rev>`, then `for o in 2 1 0; do roll_one $o \|\| break; done` and check each pod's `cluster id` line: `(derived from tls.ca_cert)` with `$PIN`, or no line on an image older than the pin (`gate` expects the pin, so not `gate` here). The pod template has no config checksum, so a rollback that changes only the ConfigMap restarts nothing by itself. Safe at any time *only before A*. Once the CA file changed, an unpinned node derives a different id, and a node with this release refuses to start under it (`cluster id mismatch`). | A undone |

Single-pod failure mid-phase: put the previous phase's material back for the whole Secret, which
is compatible with every pod still running, and roll the failed pod again. Do not continue the
phase.

## 8. Without the pin (fallback, not recommended)

If the rotation has to run on an image without `cluster_id`, it still works. The cost is two
windows, during the Phase A and Phase D rolls, in which nodes disagree on the id. In those windows:

- hosted-key `GenerateKey` may miss its write quorum: do not rotate or create hosted keys (no
  participant key rotation);
- read-repair and anti-entropy between mismatched nodes fail and log; they heal within one sweep
  after the roll;
- FROST signing and hosted-key decrypt/ECDH are not affected;
- after the rotation the id is the hash of the **new** `ca.crt`. Pass that file to every later
  `rutli-dealer --ca-cert`.

The pin removes all of that for one config line, so prefer waiting for the release. (On a release
that has the pin, an unpinned rotation is not even possible without
`clusterIdChangeAllowed=true`: each node refuses to start under the changed derived id.)

## 9. Other installs

- **Raw manifests** (`deploy/k8s`): add `"cluster_id": "<16 hex>"` to every `cosigner-N.json` in
  `cosigner-config.yaml` (and keep it there: each node records its id in `data_dir/cluster-id` and
  refuses another). Secrets as in `secrets.example.yaml` (shared layout). Roll with
  `kubectl delete pod` as above.
- **Docker Compose** (`deploy/frost`): the same config field. Restart one container at a time
  (`docker compose restart cosignerN`). The certs are bind-mounted, so replace the files in place.
- **Adding a node or issuing an operator cert later:** restore the CA key from escrow into a
  temporary 0700 dir, then `RUTLI_CA_DIR=<dir> RUTLI_CERTS="operator" scripts/gen-frost-certs.sh 3 <out>`.
  Delete the plaintext key afterwards.
