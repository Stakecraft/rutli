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

Key material in a file is protected by the **sealing key**, not by deletion: the key files are
sealed with AES-256-GCM under the node's data-encryption key (DEK), which comes from the node's seal
bundle (or, on a legacy cluster, from the shared master secret).

**A copy of a sealed file is usable by anyone who also has the DEK that sealed it.** So the question
for any old copy is not "was it deleted" but "does a copy of its DEK still exist". Three
consequences:

- A refresh gives every node a new share and leaves the older copies as they were. It does not
  change any DEK. Old-epoch shares of `t` nodes from the same epoch still combine with each other
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
if copies remain. It works per node and for all of that node's files sealed under it.

## Keep the material off disks you cannot destroy

Everything in the runbooks that handles key material on a workstation (export files, share bundles,
CA and driver keys, seal bundles, the dealer's output) should live only in a place you can destroy as a whole:

- **An encrypted memory disk.** Linux: `mount -t tmpfs -o size=128m,mode=0700 tmpfs /mnt/rutli-work`,
  with swap off or encrypted. macOS (FileVault on, which encrypts swap: `fdesetup status`):
  ```bash
  diskutil erasevolume APFS rutli-work $(hdiutil attach -nomount ram://262144)   # 128 MiB, gone on detach or reboot
  tmutil addexclusion -p /Volumes/rutli-work
  ```
- **Or an encrypted sparse image**, when the material must survive a reboot:
  ```bash
  hdiutil create -size 64m -type SPARSE -fs APFS -encryption AES-256 -stdinpass -volname rutli-work ~/rutli-work
  hdiutil attach ~/rutli-work.sparseimage -stdinpass
  tmutil addexclusion -p /Volumes/rutli-work ~/rutli-work.sparseimage
  ```
  Type the passphrase when asked; do not store it next to the image. Keep the image out of
  synced folders and out of backups. Check `tmutil listlocalsnapshots /`: a local snapshot taken
  while the material lay on the ordinary disk keeps it.

Set `D` (the runbooks' working directory) to the mount point, not to a directory in your home or
`$TMPDIR`. When the work is done, **destroy the place, not the files**: unmount it
(`hdiutil detach /Volumes/rutli-work`, or `umount`), delete the sparse image, and discard the
passphrase. Do not rely on `rm -P` (it has no effect on current macOS) or on `shred` (not on macOS,
and on journaling, copy-on-write, flash and network storage it overwrites nothing that matters).
Neither method is a proof of erasure; the encrypted place, with its key gone, is the best you can
do on an operator machine.

## Where a copy can be

Walk this list when you destroy a key's material, after a split ceremony, at the end of a migration
and after a compromise. For each place, say in your record whether it was destroyed, how, and by
whom, or that it could not be.

| Place | What it can hold | How it ends |
|---|---|---|
| Each cosigner's data volume | live key files; older files in free blocks (earlier epochs, files before a re-seal, a purged tombstone); staged files of an aborted refresh (kept in quarantine for up to 7 days); pending recipient files of a split ceremony; leftovers such as `*.json.tmp`; any `backup-*` or `retired-*` directory someone moved there | rotate the node's DEK and drop the old one (below); delete the volume and every snapshot of it |
| Each cosigner's backup volume | sealed key files of every retained epoch (`backup.destination.keep`, 14 by default) | the same; shorten the retention, then rotate |
| An off-cluster backup destination | whatever its retention keeps, including old object versions | expire every version; rotate |
| Volume snapshots of either volume | everything above, frozen | delete them |
| The Kubernetes node's disk | the backup sidecar's staging copies and the pod's `/tmp` (disk-backed `emptyDir`), where bundles and request files are copied during ceremonies | wipe or replace the node disk; do not copy key material through `/tmp` where a tool can read it from stdin |
| The seal Secret and its history | the DEKs: current, previous, and old values in etcd, etcd snapshots, GitOps or secret-manager history, cluster backups | destroy every old value; enable encryption of Secrets at rest |
| The legacy master secret and its escrow | on a cluster that came from `secret_env`: the one secret that derives every original DEK | destroy it once every node has rotated its DEK and dropped the previous one |
| Operator workstations | export files, share bundles, certificates and keys, seal bundles, `pre-pernode-*.tar` style backups | the encrypted place above; delete what is outside it |
| Dealer media | the boot medium and transfer media of a split ceremony | destroy the media |
| The old participant | database rows, dead tuples, WAL and archives, dumps, object versions, identity dumps, retired volumes, snapshots | [split-ceremony.md](split-ceremony.md) §3.2 and §9, [migration.md](migration.md) Step 8 |
| Core dumps and swap | a crashed cosigner can leave plaintext shares in a core file on the node | turn core dumps off on the nodes, keep swap encrypted |

## Close the gap: rotate the sealing key

After the **first refresh of an imported key** (split ceremony), after **moving off the legacy
shared master**, after **a hosted key is deleted**, and after **any suspected exposure
of a node's seal bundle**, rotate that node's sealing key and destroy the old one. Do it one node at
a time, with the commands that exist today (`rutli-cosigner seal …`, `keyfile …`):

1. Take a backup of the node. Check `keyfile status` shows every file under the current DEK.
2. `seal rotate-dek --in <current-bundle>.json --out <new-bundle>.json` writes a bundle with a fresh
   random DEK and keeps the old one as a previous DEK, so every file still opens. The distribution
   key is unchanged.
3. Replace the node's seal Secret with the new bundle and restart the node. It re-seals the key
   files under the new DEK at start (`keyfile migrate` does it too). Check `keyfile status`: no file
   under a previous DEK.
4. Take a new backup.
5. `seal drop-previous --in <new-bundle>.json --out <final-bundle>.json`, replace the Secret again.
6. **Destroy every other copy of the old DEK**: the previous Secret values and the escrowed
   old bundle, the legacy master and its escrow, workstation files. Until then step 5 has
   erased nothing.
7. Delete the old backups and snapshots that no longer need to be restorable, and record what you
   did.

What this does not cover: files outside `keys/` and the staging directories (an old `backup-*` or
`retired-*` directory is not re-sealed, so it opens only with the old DEK: destroy that DEK, or
delete the directory and its volume); anything copied out in plain text; and the whole key where it
existed whole before the split (see [split-ceremony.md](split-ceremony.md)).

Rotation tied to the refresh schedule, so that this happens without an operator step, is planned
for 0.6. Until then it is a manual step.

## Related

- [security/threat-model.md](security/threat-model.md), "Key material at rest and its lifetime".
- [disaster-recovery.md](disaster-recovery.md): backups and refreshes, rotating the seal key.
- [runbook-per-node-seal.md](runbook-per-node-seal.md): leaving the shared master.
