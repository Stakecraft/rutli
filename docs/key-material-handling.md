# Key material at rest: handling and destruction

What "delete" does and does not do in Rütli and in the runbooks, how to handle key material on a
workstation so that there is little to destroy, the list of places a copy can be, and the step
that closes the gap: rotating the sealing key. Read it before you destroy anything.

## What delete does

Rütli deletes by removing a file (`unlink`), and replaces by writing a new file over the old
name (`rename`). Neither overwrites the old bytes. After a refresh, a re-seal, a hosted-key delete
or a tombstone purge, the previous file's blocks are free but not erased. On flash, network,
copy-on-write and thin-provisioned storage an overwrite would not erase them either, and a snapshot
or a backup keeps them whatever you do to the live volume.

With sealing configured (required for hosted keys), key material in a file is protected by the
**sealing key**, not by deletion: key files are sealed with AES-256-GCM under the node's
data-encryption key (DEK), which comes from the node's seal bundle (or, on a legacy cluster, from
the shared master secret).

**A copy of a sealed file is usable by anyone who also has the DEK that sealed it.** So the question
for any old copy is not "was it deleted" but "does a copy of its DEK still exist". Three
consequences:

- A refresh gives every node a new share and leaves the older copies as they were. It does not
  change any DEK. Old-epoch shares of `t` nodes from one sharing still combine with each other
  while those copies and their DEKs exist: in backups, in snapshots, in free blocks. A refresh
  protects against an attacker who has fewer than `t` shares of one epoch and no old storage.
- A hosted key (ECIES, RSA, AES) is one whole key in one file. One copy from one node and that
  node's DEK are the key. There is no threshold at rest.
- A DEK that was "dropped" from the seal bundle (`seal drop-previous`) is gone from the bundle only.
  It is destroyed when **every** other copy is destroyed too: earlier values of the seal Secret
  (in etcd and its history and snapshots, in secret-manager or GitOps history), the escrowed bundle
  the disaster-recovery runbook asks you to keep while old backups exist, the legacy master and its
  escrow, and files on operator machines. Nothing in Rütli checks this.

The one erasure that works is **destroying the DEK**: files sealed under it stay unreadable even
if copies remain. It works per node and for all of that node's files sealed under it. The seal
bundle also holds the node's distribution key, which `rotate-dek` does not change (with the legacy
master it is derived from the master); replacing it takes `seal new-node` and new peer pins
([disaster-recovery.md](disaster-recovery.md) §3h).

## Keep the material off disks you cannot destroy

Everything in the runbooks that handles key material on a workstation (export files, share bundles,
CA and driver keys, seal bundles, the dealer's output) should live only in a place you can destroy
as a whole. Export `RUTLI_WORK` as the mount point of that place; the runbooks create their working
directory `$D` inside it.

- **A memory disk.** Not encrypted, and gone on unmount or reboot. Linux:
  ```bash
  sudo mount -t tmpfs -o size=128m,mode=0700,uid=$(id -u),gid=$(id -g) tmpfs /mnt/rutli-work
  export RUTLI_WORK=/mnt/rutli-work
  ```
  Keep swap off or encrypted. macOS: check that swap is encrypted (`sysctl vm.swapusage` prints
  "(encrypted)"), then
  ```bash
  dev=$(hdiutil attach -nomount ram://262144 | awk '{print $1}')   # 128 MiB
  diskutil erasevolume APFS rutli-work "$dev"
  export RUTLI_WORK=/Volumes/rutli-work
  sudo tmutil addexclusion -v /Volumes/rutli-work
  # at the end: hdiutil detach "$dev"
  ```
- **Or an encrypted sparse image**, when the material must survive a reboot:
  ```bash
  hdiutil create -size 64m -type SPARSE -fs APFS -encryption AES-256 -stdinpass -volname rutli-work ~/rutli-work
  tmutil addexclusion ~/rutli-work.sparseimage
  hdiutil attach ~/rutli-work.sparseimage -stdinpass
  export RUTLI_WORK=/Volumes/rutli-work
  ```
  The passphrase is asked once, without confirmation: a typo makes the image unopenable. Do not
  store it next to the image. Keep the image out of synced folders and out of backups, and check
  `tmutil listlocalsnapshots /`: a local snapshot taken while the material lay on the ordinary
  disk keeps it.

Never in your home or `$TMPDIR`. When the work is done, **destroy the place, not the files**:
unmount it (`hdiutil detach`, or `umount`), delete the sparse image, and discard the passphrase. Do
not rely on `rm -P` (it has no effect on current macOS) or on `shred` (not on macOS, and on
journaling, copy-on-write, flash and network storage it overwrites nothing that matters). Neither
method is a proof of erasure; a memory disk that is unmounted, or an encrypted image whose key is
gone, is the best you can do on an operator machine.

## Where a copy can be

Walk this list when you destroy a key's material, after a split ceremony, at the end of a migration
and after a compromise. For each place, say in your record whether it was destroyed, how, and by
whom, or that it could not be.

| Place | What it can hold | How it ends |
|---|---|---|
| Each cosigner's data volume | live key files; older files in free blocks (earlier epochs, files before a re-seal, a purged tombstone, pending recipient files of a split ceremony); staged files of an aborted refresh (quarantined for up to 7 days, or until the operator acts if a split was detected); leftovers such as `*.json.tmp`; any `backup-*` or `retired-*` directory someone moved there | rotate the node's DEK and destroy the old one (below); delete the volume and every snapshot of it |
| Each cosigner's backup volume | sealed key files of every retained epoch: the newest 14 tars with the chart's pvc destination (`backup.destination.keep`; a backup is taken on every key-file change and daily, so 14 tars may be a few days) | the same; shorten the retention, then rotate |
| An off-cluster backup destination | whatever its retention keeps, including old object versions | expire every version; rotate |
| Volume snapshots of either volume | everything above, frozen | delete them |
| The Kubernetes node's disk | the backup sidecar's staging copies and the pod's `/tmp` (disk-backed `emptyDir`), where bundles and request files are copied during ceremonies | wipe or replace the node disk; pass key material to a tool on stdin instead of copying it to `/tmp` |
| The seal Secret and its history | the DEKs: current, previous, and old values in etcd, etcd snapshots, GitOps or secret-manager history, cluster backups | destroy every old value; enable encryption of Secrets at rest |
| The legacy master secret and its escrow | on a cluster that came from `secret_env`: the one secret that derives every original DEK and every distribution key | destroy it once every node has rotated its DEK and dropped the previous one |
| Operator workstations | export files, share bundles, certificates and keys, seal bundles, `pre-pernode-*.tar` style backups | the memory disk or image above; delete what is outside it |
| Dealer media | the boot medium and transfer media of a split ceremony | destroy the media |
| The old participant | database rows, dead tuples, WAL and archives, dumps, object versions, identity dumps, retired volumes, snapshots | [split-ceremony.md](split-ceremony.md) §3.2 and §9, [migration.md](migration.md) Step 8 |
| Core dumps and swap | a crashed cosigner can leave plaintext shares in a core file on the node (the cosigner does not switch core dumps off) | turn core dumps off on the nodes, keep swap encrypted |

## Close the gap: rotate the sealing key

After the **first refresh of an imported key** (split ceremony), after **moving off the legacy
shared master**, and after **any suspected exposure of a node's seal bundle**, rotate the sealing
key of **every** node, one at a time, and destroy the old one. After **a hosted key is deleted**,
first wait until every node has dropped the retained material (the grace period,
`hosted_keys.delete_grace_secs`, 7 days by default, has passed and each node has logged that the
retained material was dropped), then rotate every node, and do not `hosted-undelete` the key
afterwards. A node that rotates during the grace period re-seals the tombstone, key included,
under the new DEK, and the backup sidecar copies it at once.

The steps, with the commands that exist today:

1. Take a backup of the node. Check that `keyfile status` shows every file under the current DEK.
2. `seal rotate-dek --in <current-bundle>.json --out <new-bundle>.json` writes a bundle with a fresh
   random DEK and keeps the old one as a previous DEK, so every file still opens. The distribution
   key is unchanged.
3. Replace the node's seal Secret with the new bundle and restart the node. At start it re-seals
   the files in `keys/` and `keys/.staged/` under the new DEK. Pending recipient files of a split
   ceremony (`ceremony/*.recipient`) are re-sealed only by `keyfile migrate`, which needs the
   daemon stopped, writes format v2 and needs `keyfile.cluster_uuid`. Check `keyfile status`: no file
   under a previous DEK, and `RutliKeyFilesUnopenable` quiet.
4. Take a new backup.
5. `seal drop-previous --in <new-bundle>.json --out <final-bundle>.json`, replace the Secret again,
   restart the node, and check `keyfile status` (nothing under a previous or unknown DEK) and
   `RutliKeyFilesUnopenable`.
6. Delete the old backups and snapshots, and the volumes you no longer need, **before** step 7:
   step 7 gives up restoring from them (the disaster-recovery runbook keeps the previous bundle
   escrowed for as long as old backups are kept; this is the trade-off, §3h).
7. **Destroy every other copy of the old DEK**: the previous Secret values and the escrowed old
   bundle, the legacy master and its escrow, workstation files. Until then step 5 has erased
   nothing.
8. Record what you did.

What this does not cover: files outside `keys/` and the staging directories, other than the
pending recipient files named in step 3 (an old `backup-*` or `retired-*` directory is not
re-sealed, so it opens only with the old DEK: destroy that DEK, or delete the directory and its
volume); the node's distribution key and, with the legacy master, the master that derives it;
anything copied out in plain text; and the whole key where it existed whole before the split (see
[split-ceremony.md](split-ceremony.md)).

Rotation tied to the refresh schedule, so that this happens without an operator step, is planned
for 0.6 ([roadmap.md](roadmap.md)). Until then it is a manual step.

## Related

- [security/threat-model.md](security/threat-model.md), "Key material at rest and its lifetime".
- [disaster-recovery.md](disaster-recovery.md): backups and refreshes, rotating the seal key.
- [runbook-per-node-seal.md](runbook-per-node-seal.md): leaving the shared master.
