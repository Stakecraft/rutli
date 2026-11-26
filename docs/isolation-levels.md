# Isolation between key owners

A **key owner** is the organisation whose Canton participants use the keys: usually one validator
operator with one or more participants. This page says how far one owner's keys are kept apart
from another's, and what an operator who serves several owners can choose.

The rule: **one cosigner cluster serves the participants of one organisation. Different owners get
different clusters.** The reasons are in the threat model
([One cluster, one key owner](security/threat-model.md#one-cluster-one-key-owner)); the short
version is below.

This page is about the boundary between owners. The boundary between the cosigners of one cluster
(each cosigner in its own cluster or cloud account, under different administrators) is a separate
question with its own go-live gate
([audit-prep.md](audit-prep.md#what-counts-as-a-separate-trust-domain)), and it applies to every
cosigner cluster at every level here.

## Inside one cosigner cluster

Participants that share a cluster are separated at the API and nowhere else.

| Separated per participant | Shared by everything in the cluster |
|---|---|
| The driver certificate CN, with a pin on its key (`signing_policy.signer_pins`) | The sealing key: one per node, for every key file on that node |
| The key ids the CN may use (`signing_policy.signer_acl`, by key-id prefix) | The key directory, the cosigner process and its memory, the backup archives |
| Sign rate limits and approval rules, by key-id prefix | Hosted encryption keys: whole on every node |
| | The approver list (`signing_policy.approvers`) |
| | The refresher and operator roles: no per-key ACL |
| | The cluster CA that issues every client certificate |

So the ACL stops one participant from calling another participant's key. It does not limit what a
compromised cosigner, a leaked seal bundle or a stolen backup exposes: each of them covers the keys
of every participant on that cluster in the same way.

The two profiles differ in how firm the API separation is
([production-profile.md](production-profile.md)):

- **`production`** requires `signer_acl_required: true`, an ACL entry and a pin for every driver
  CN, and a seal bundle per node. Every participant is limited to its own key-id prefixes.
- **`lab`** (and an unset profile) does not. A driver CN without an ACL entry can use every key on
  the cluster, and with the legacy shared seal secret (`share_seal.secret_env`) one secret opens
  the key files of every node. Treat everything on a lab cluster as one owner's.

Neither profile adds a boundary on disk or in memory.

## Level 1: a cosigner cluster per owner

Each owner gets its own install of the cosigners: its own Kubernetes namespace, seal bundles,
cluster CA and certificates, `cluster_id` and `keyfile.cluster_uuid`, data volumes, backup
destination, approvers and refresher credential. The installs may run in the same Kubernetes
cluster. This needs no code change and is the supported way to serve more than one owner today.

What it stops:

- A driver certificate of one owner is not trusted by another owner's cosigners at all: there is
  no shared CA and no ACL to get wrong.
- A seal bundle, a backup or a volume of one owner opens nothing of another owner's.
- A compromised cosigner process holds the shares and hosted keys of one owner only.
- Approvers, the refresher, rate limits and approval rules are per owner.
- An owner who leaves is removed by destroying that install's secrets, volumes and backups
  ([key-material-handling.md](key-material-handling.md)).

What it does not stop:

- A Kubernetes cluster-admin, or anyone who can read Secrets or exec into pods in several
  namespaces, reaches every owner's cluster.
- Root on a Kubernetes node, or a container escape, reaches every cosigner pod scheduled on that
  node, whichever owner it belongs to.
- A deploy pipeline, GitOps controller or secret store with access to several installs.
- The operator. One team that runs every owner's cosigners can sign with every owner's keys.

## Level 2: dedicated nodes, or a dedicated Kubernetes cluster, per owner

Level 1, plus the owner's cosigners run on machines nobody else's cosigners use.

- **Dedicated nodes** (a node pool with taints, or dedicated hosts): root on a node or a container
  escape now reaches one owner. The control plane is still shared, so a cluster-admin and a reader
  of Secrets across namespaces are not stopped.
- **A dedicated Kubernetes cluster or cloud account**: its own API server, etcd and credentials.
  This also stops an administrator of one owner's cluster from reaching another's, as long as no
  person, pipeline or organisation-level role has admin on both. The table in
  [audit-prep.md](audit-prep.md#what-counts-as-a-separate-trust-domain) lists what counts as
  separate.

What it does not stop: the operator who administers all of these clusters. That needs a share
outside the operator's reach, which is the next level.

## Planned, not available: a cosigner held by the key owner

With one cosigner of the cluster run by the key owner, the operator would no longer hold every
share of that owner's signing keys. This is a topic for 1.0 ([roadmap.md](roadmap.md)). There is
no design yet: who holds which share, whether the owner's cosigner is required for every
signature, and how ceremonies and recovery work across two organisations are open questions.
Nothing in a current release supports it, and it is not a commitment.

It would cover signing keys only while hosted encryption keys are whole on every node; see
threshold ECIES below.

## What the roadmap changes

Each line is a planned item in [roadmap.md](roadmap.md), not a shipped feature.

- **0.6, sealing secret from an external key manager (issue #333).** The secret that seals the key
  files no longer has to be a Kubernetes Secret, so reading Secrets is not enough to open key
  files. It does not by itself separate owners inside one cosigner cluster.
- **1.0, threshold ECIES.** The encryption key is held as shares, like the signing keys. One
  compromised cosigner no longer reads the hosted ECIES keys of the participants it serves.
- **2.0, confidential computing (issue #335).** Cosigners in an attested environment, so root on
  the host or a memory snapshot does not reveal a share. This is the item that addresses a shared
  Kubernetes node.

## Choosing

| Situation | Level |
|---|---|
| Several participants of one organisation | One cluster, a `frost.key-prefix`, a driver CN and an ACL entry per participant ([architecture.md](architecture.md), "One cluster, several participants") |
| Participants of different organisations, one operator trusted by all of them | Level 1 |
| The same, and a break-in on a shared machine must not cross owners | Level 2 |
| The operator must not be able to sign alone | Not available yet |
