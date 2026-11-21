// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Backup retention by epoch: which archives of a node's backup directory may be deleted.
//!
//! The backup sidecar writes one tar per run (`node-<N>-<stamp>.tar`, the node's sealed key files at
//! the archive root). Every FROST key file carries a clear v2 header with its epoch, so the epoch of
//! each archive can be read without the sealing key. An archive of an older epoch is a recovery
//! copy of a sharing that has been replaced, and also a second copy of old shares for as long as it
//! exists; this module decides when it goes.
//!
//! # The rule
//!
//! Per FROST key `k`, `P_k` is the highest epoch that is **proven** (a `keyfile prove` marker, see
//! [`crate::proof`]), whose marker matches the sharing's digest, and which is **old enough** (the
//! marker's age is the smaller of its recorded time and its file's modification time, so a clock set
//! back does not age it; a marker dated in the future does not count). Other kinds of key file
//! (hosted keys, tombstones) have no epoch to prove: they only have to be as the proven archive has
//! them. `F` is the newest verified archive that holds every live key that way: each FROST key at
//! exactly its `P_k` and digest. `F` exists only when every live FROST key is proven. An archive `A`
//! is deleted only if all of these hold:
//!
//! 1. every file of `A` has a readable v2 header for this cluster and node ("epoch readable");
//! 2. every key in `A` is a live key;
//! 3. `F` exists;
//! 4. every FROST key in `A` is **older** than `P_k`, or exactly as `F` has it, and at least one is
//!    older; every other key in `A` is as `F` has it;
//! 5. (`keep_older_epochs` = N) `A`'s epoch of every key is not among the N highest distinct epochs
//!    below `P_k` that archives hold.
//!
//! So the previous epoch is deleted only when the new one is proven **and** has aged; with no proof,
//! nothing is deleted by epoch. `F` and the newest archive are never deleted, so a complete verified
//! set of the proven epoch always remains.
//!
//! **Verified** means: the tar reads to its end, every key file in it has a v2 header for this
//! cluster and node whose key id is the file's name, and it holds at least one key. It does **not**
//! mean restorable: the sidecar has no sealing key, so opening the files stays the operator's
//! restore drill.
//!
//! # Fail closed
//!
//! Nothing is deleted when this node's own live epoch is behind any archive's readable header (a
//! node that missed a refresh: its older archives are its way back), when the newest archive's key
//! set or sharing is not the live one (a backup is pending), when the newest archive cannot be read,
//! or on any error. When the live key files are not v2 (no clear epoch) or the node has no
//! `keyfile.cluster_uuid`, the epoch rule cannot run and only the plain count cap applies.
//!
//! The count cap (`keep_count`) is the hard bound on the directory. It deletes the oldest archives
//! first, but only an archive whose every key state (key, kind, epoch, digest) another kept archive
//! also holds, so it removes copies and never the last copy of anything; never the newest archive,
//! never `F`, never an archive it cannot read.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::seal::KeyFileHeader;

/// What a key file's clear header says (the fields retention compares).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyInfo {
    pub key_id: String,
    pub kind: String,
    pub epoch: u64,
    pub digest: String,
    pub cluster: String,
    pub node: u16,
    /// The id of the DEK that sealed the file: two files of one state sealed under different DEKs
    /// are not copies of each other.
    pub dek_id: String,
}

impl From<KeyFileHeader> for KeyInfo {
    fn from(h: KeyFileHeader) -> Self {
        KeyInfo {
            key_id: h.key_id,
            kind: h.kind,
            epoch: h.epoch,
            digest: h.digest,
            cluster: h.cluster,
            node: h.node,
            dek_id: h.dek_id,
        }
    }
}

/// One archive as read: its name and, per key file, the header (`None`: not a readable v2 header).
#[derive(Debug, Clone)]
pub struct Archive {
    pub name: String,
    /// `Err`: the tar could not be read to its end.
    pub files: Result<BTreeMap<String, Option<KeyInfo>>, String>,
}

/// A proof of an epoch that is old enough, as `plan` needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    pub digest: String,
    /// Age in milliseconds: the smaller of the recorded time's and the file's.
    pub age_ms: u64,
}

pub struct Settings {
    pub node: u16,
    pub cluster_uuid: Option<String>,
    pub min_proof_age_ms: u64,
    pub keep_older_epochs: usize,
    /// The count cap; 0 = no cap.
    pub keep_count: usize,
}

/// Why an archive stays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Why {
    /// A file in it has no readable v2 header, or the tar cannot be read.
    EpochUnreadable,
    /// It holds a key this node no longer lists.
    KeyNotLive,
    /// A key in it has no proven, old-enough epoch.
    UnprovenEpoch,
    /// No verified archive holds every live key at its proven epoch.
    NoProvenArchive,
    /// It holds a key newer than, or differently from, the proven archive.
    AtOrAfterProvenEpoch,
    /// Every key in it is as the proven archive has it: it is a copy, not an older epoch.
    NothingOlder,
    /// `keep_older_epochs` asks for it.
    KeepOlderEpochs,
    /// The newest archive, or the proven one: never deleted.
    Protected,
}

impl Why {
    pub fn code(self) -> &'static str {
        match self {
            Why::EpochUnreadable => "epoch-unreadable",
            Why::KeyNotLive => "key-not-live",
            Why::UnprovenEpoch => "unproven-epoch",
            Why::NoProvenArchive => "no-proven-archive",
            Why::AtOrAfterProvenEpoch => "at-or-after-proven-epoch",
            Why::NothingOlder => "nothing-older",
            Why::KeepOlderEpochs => "keep-older-epochs",
            Why::Protected => "protected",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Keep(Why),
    /// Deleted by the epoch rule; `covered_by` is the proven archive that holds the proven sharing.
    DeleteOlderEpoch {
        covered_by: String,
    },
    /// Deleted by the count cap.
    DeleteCountCap,
}

/// Why nothing at all was decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Skip {
    /// Fail closed: no deletion of any kind.
    Closed(String),
    /// The epoch rule cannot run; the old count cap still does.
    CapOnly(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub skip: Option<Skip>,
    /// In archive (name) order.
    pub verdicts: Vec<(String, Verdict)>,
}

fn verified(a: &Archive, s: &Settings) -> bool {
    let Ok(files) = &a.files else { return false };
    let Some(uuid) = s.cluster_uuid.as_deref() else {
        return false;
    };
    !files.is_empty()
        && files.iter().all(|(stem, info)| {
            info.as_ref()
                .is_some_and(|i| i.key_id == *stem && i.cluster == uuid && i.node == s.node)
        })
}

fn info<'a>(a: &'a Archive, key: &str) -> Option<&'a KeyInfo> {
    a.files.as_ref().ok()?.get(key)?.as_ref()
}

/// Decide the fate of every archive. `live`: this node's key files' headers (`None`: not a readable
/// v2 header). `proofs`: `(key, epoch)` -> the proof, already filtered to markers that are not dated
/// in the future. Pure: no I/O.
pub fn plan(
    archives: &[Archive],
    live: &BTreeMap<String, Option<KeyInfo>>,
    proofs: &BTreeMap<(String, u64), Proof>,
    s: &Settings,
) -> Plan {
    let mut sorted: Vec<&Archive> = archives.iter().collect();
    sorted.sort_by(|a, b| a.name.cmp(&b.name));
    let names: Vec<String> = sorted.iter().map(|a| a.name.clone()).collect();
    let keep_all = |why: Why| -> Vec<(String, Verdict)> {
        names
            .iter()
            .map(|n| (n.clone(), Verdict::Keep(why)))
            .collect()
    };
    let closed = |reason: &str| Plan {
        skip: Some(Skip::Closed(reason.into())),
        verdicts: keep_all(Why::Protected),
    };

    if sorted.is_empty() {
        return Plan {
            skip: None,
            verdicts: Vec::new(),
        };
    }

    // 0. What the epoch rule needs to exist at all.
    if s.cluster_uuid.is_none() {
        return cap_only(
            &names,
            s,
            "this node has no keyfile.cluster_uuid, so no key-file header can be tied to it",
        );
    }
    if live.is_empty() {
        return closed("this node lists no key files");
    }
    if live.values().any(|i| i.is_none()) {
        return cap_only(
            &names,
            s,
            "a live key file has no readable v2 header (migrate the node's key files to v2)",
        );
    }
    let live: BTreeMap<&String, &KeyInfo> = live
        .iter()
        .filter_map(|(k, i)| i.as_ref().map(|i| (k, i)))
        .collect();

    // 1. Fail closed on anything that says this node or its newest backup is not in step.
    let newest = *sorted.last().expect("not empty");
    if !verified(newest, s) {
        return closed(
            "the newest archive cannot be read or is not a complete v2 backup of this node",
        );
    }
    // Any readable header at a higher epoch than the live one, verified archive or not.
    for a in &sorted {
        let Ok(files) = &a.files else { continue };
        for (stem, i) in files {
            let (Some(i), Some(l)) = (i, live.get(stem)) else {
                continue;
            };
            if i.kind == l.kind && is_frost(i) && i.epoch > l.epoch {
                return closed("this node's live epoch is behind an archive's (a missed refresh: its older archives are its way back)");
            }
        }
    }
    let newest_keys: BTreeSet<&String> = newest.files.as_ref().expect("verified").keys().collect();
    let live_keys: BTreeSet<&String> = live.keys().copied().collect();
    if newest_keys != live_keys {
        return closed(
            "the newest archive's key set is not the live key set (a backup is pending)",
        );
    }
    for (stem, l) in &live {
        let i = info(newest, stem).expect("same key set");
        if i.kind != l.kind || i.epoch != l.epoch || i.digest != l.digest {
            return closed(
                "the newest archive is not at the live epoch and sharing (a backup is pending)",
            );
        }
    }

    // 2. P_k: the highest proven, old-enough epoch of each live FROST key whose digest is one we
    // hold. Other kinds (hosted keys, tombstones) have no epochs to prove.
    let mut proven: BTreeMap<&String, (u64, &String)> = BTreeMap::new();
    for ((key, epoch), proof) in proofs {
        let Some(l) = live.get(key) else { continue };
        if !is_frost(l) || proof.age_ms < s.min_proof_age_ms || *epoch > l.epoch {
            continue;
        }
        let known = (*epoch == l.epoch && proof.digest == l.digest)
            || sorted.iter().filter(|a| verified(a, s)).any(|a| {
                info(a, key)
                    .is_some_and(|i| is_frost(i) && i.epoch == *epoch && i.digest == proof.digest)
            });
        if !known {
            continue;
        }
        if proven.get(key).is_none_or(|(e, _)| epoch > e) {
            proven.insert(key, (*epoch, &proof.digest));
        }
    }
    let frost_keys: Vec<&&String> = live
        .iter()
        .filter(|(_, l)| is_frost(l))
        .map(|(k, _)| k)
        .collect();
    let all_proven = !frost_keys.is_empty() && frost_keys.iter().all(|k| proven.contains_key(**k));

    // 3. F: the newest verified archive that holds every live key as the proven sharing has it: FROST
    // keys at exactly their proven epoch and digest, every other key as it is live.
    let holds_proven = |a: &Archive| -> bool {
        verified(a, s)
            && live.iter().all(|(k, l)| match proven.get(*k) {
                Some((e, d)) => {
                    info(a, k).is_some_and(|i| is_frost(i) && i.epoch == *e && &i.digest == *d)
                }
                None => {
                    !is_frost(l)
                        && info(a, k).is_some_and(|i| {
                            i.kind == l.kind && i.epoch == l.epoch && i.digest == l.digest
                        })
                }
            })
    };
    let proven_archive: Option<&Archive> = if all_proven {
        sorted.iter().rev().copied().find(|a| holds_proven(a))
    } else {
        None
    };

    // 4. Verdicts.
    let mut protected: BTreeSet<String> = BTreeSet::new();
    protected.insert(newest.name.clone());
    if let Some(f) = proven_archive {
        protected.insert(f.name.clone());
    }
    // For keep_older_epochs: the distinct epochs below P_k that verified archives hold, per key.
    let mut below: BTreeMap<&String, BTreeSet<u64>> = BTreeMap::new();
    for a in sorted.iter().filter(|a| verified(a, s)) {
        for (k, (p, _)) in &proven {
            if let Some(i) = info(a, k) {
                if i.epoch < *p {
                    below.entry(k).or_default().insert(i.epoch);
                }
            }
        }
    }
    let kept_older: BTreeMap<&String, BTreeSet<u64>> = below
        .into_iter()
        .map(|(k, set)| (k, set.into_iter().rev().take(s.keep_older_epochs).collect()))
        .collect();

    let mut verdicts: Vec<(String, Verdict)> = Vec::new();
    for a in &sorted {
        let verdict = if protected.contains(&a.name) {
            Verdict::Keep(Why::Protected)
        } else if !verified(a, s) {
            Verdict::Keep(Why::EpochUnreadable)
        } else {
            let files = a.files.as_ref().expect("verified");
            if files.keys().any(|k| !live.contains_key(k)) {
                Verdict::Keep(Why::KeyNotLive)
            } else if !all_proven {
                Verdict::Keep(Why::UnprovenEpoch)
            } else if let Some(f) = proven_archive {
                classify(a, f, &live, &proven, &kept_older)
            } else {
                Verdict::Keep(Why::NoProvenArchive)
            }
        };
        verdicts.push((a.name.clone(), verdict));
    }

    // The count cap, the hard bound on the directory. It only deletes an archive whose every key
    // state (key, kind, epoch, digest) another remaining archive holds as well, so it takes
    // duplicates and never the last copy of anything; and never the newest or the proven archive,
    // nor one it cannot read.
    if s.keep_count > 0 {
        let holders = |state: &(String, String, u64, String, String),
                       verdicts: &[(String, Verdict)],
                       except: &str|
         -> bool {
            sorted.iter().any(|b| {
                b.name != except
                    && verified(b, s)
                    && verdicts
                        .iter()
                        .any(|(n, v)| *n == b.name && matches!(v, Verdict::Keep(_)))
                    && info(b, &state.0).is_some_and(|i| {
                        i.kind == state.1
                            && i.epoch == state.2
                            && i.digest == state.3
                            && i.dek_id == state.4
                    })
            })
        };
        let mut remaining = verdicts
            .iter()
            .filter(|(_, v)| matches!(v, Verdict::Keep(_)))
            .count();
        for a in &sorted {
            if remaining <= s.keep_count {
                break;
            }
            let idx = verdicts
                .iter()
                .position(|(n, _)| *n == a.name)
                .expect("every archive has a verdict");
            let Some((_, Verdict::Keep(why))) = verdicts.get(idx) else {
                continue;
            };
            if protected.contains(&a.name) || !verified(a, s) || *why == Why::EpochUnreadable {
                continue;
            }
            let states: Vec<(String, String, u64, String, String)> = a
                .files
                .as_ref()
                .expect("verified")
                .iter()
                .filter_map(|(k, i)| {
                    i.as_ref().map(|i| {
                        (
                            k.clone(),
                            i.kind.clone(),
                            i.epoch,
                            i.digest.clone(),
                            i.dek_id.clone(),
                        )
                    })
                })
                .collect();
            let snapshot = verdicts.clone();
            if states.iter().all(|st| holders(st, &snapshot, &a.name)) {
                if let Some((_, v)) = verdicts.get_mut(idx) {
                    *v = Verdict::DeleteCountCap;
                    remaining -= 1;
                }
            }
        }
    }

    // Defensive: at least one verified archive is kept, always.
    let kept_verified = verdicts.iter().any(|(n, v)| {
        matches!(v, Verdict::Keep(_)) && sorted.iter().any(|a| &a.name == n && verified(a, s))
    });
    if !kept_verified {
        return closed("internal: the plan would leave no verified archive");
    }
    Plan {
        skip: None,
        verdicts,
    }
}

fn is_frost(i: &KeyInfo) -> bool {
    i.kind == "frost-share"
}

/// The plain count cap (the old behaviour), for when the epoch rule cannot run: oldest first, never
/// the newest.
fn cap_only(names: &[String], s: &Settings, reason: &str) -> Plan {
    let mut verdicts: Vec<(String, Verdict)> = names
        .iter()
        .map(|n| (n.clone(), Verdict::Keep(Why::Protected)))
        .collect();
    if s.keep_count > 0 {
        let mut remaining = verdicts.len();
        let last = verdicts.len().saturating_sub(1);
        for (i, (_, v)) in verdicts.iter_mut().enumerate() {
            if remaining <= s.keep_count {
                break;
            }
            if i != last {
                *v = Verdict::DeleteCountCap;
                remaining -= 1;
            }
        }
    }
    Plan {
        skip: Some(Skip::CapOnly(reason.into())),
        verdicts,
    }
}

/// The epoch rule for one verified archive `a` of a node whose live keys are all proven and held by
/// `f`: delete it only if every key in it is as `f` has it or older than the proven epoch, and at
/// least one FROST key in it is older.
fn classify(
    a: &Archive,
    f: &Archive,
    live: &BTreeMap<&String, &KeyInfo>,
    proven: &BTreeMap<&String, (u64, &String)>,
    kept_older: &BTreeMap<&String, BTreeSet<u64>>,
) -> Verdict {
    let Ok(files) = &a.files else {
        return Verdict::Keep(Why::EpochUnreadable);
    };
    let mut older = false;
    for (k, i) in files {
        let (Some(i), Some(l)) = (i, live.get(k)) else {
            return Verdict::Keep(Why::KeyNotLive);
        };
        if is_frost(i) && is_frost(l) {
            let Some((p, d)) = proven.get(k) else {
                return Verdict::Keep(Why::UnprovenEpoch);
            };
            if i.epoch < *p {
                if kept_older.get(k).is_some_and(|set| set.contains(&i.epoch)) {
                    return Verdict::Keep(Why::KeepOlderEpochs);
                }
                older = true;
            } else if !(i.epoch == *p && &i.digest == *d) {
                return Verdict::Keep(Why::AtOrAfterProvenEpoch);
            }
        } else if info(f, k)
            .is_none_or(|fi| fi.kind != i.kind || fi.epoch != i.epoch || fi.digest != i.digest)
        {
            // A key of another kind that `f` does not hold in this state.
            return Verdict::Keep(Why::AtOrAfterProvenEpoch);
        }
    }
    if older {
        Verdict::DeleteOlderEpoch {
            covered_by: f.name.clone(),
        }
    } else {
        Verdict::Keep(Why::NothingOlder)
    }
}

// ---- reading archives ---------------------------------------------------------------------------

/// Read a tar's root-level `*.json` key files and the header of each, with the residue scan's reader
/// ([`crate::residue::visit_tar_key_entries`]: checksums verified, no link followed, entry and size
/// limits; a truncated or damaged tar is an `Err`). The data of every other entry (journals) is not
/// read. An entry larger than the reader's limit has no header (`None`).
pub fn read_archive(path: &Path) -> Result<BTreeMap<String, Option<KeyInfo>>, String> {
    let mut out: BTreeMap<String, Option<KeyInfo>> = BTreeMap::new();
    crate::residue::visit_tar_key_entries(path, |name, bytes| {
        let entry = name.strip_prefix("./").unwrap_or(name);
        // Root-level key files only: `<id>.json`, not a dot-file, not in a directory.
        if entry.contains('/') || !entry.ends_with(".json") || entry.starts_with('.') {
            return;
        }
        let stem = entry.trim_end_matches(".json").to_string();
        out.insert(
            stem,
            bytes.and_then(|b| crate::seal::header_of(b).map(KeyInfo::from)),
        );
    })?;
    Ok(out)
}

/// The `node-<N>-<stamp>.tar` files of `dir` for `node`, as archives, by name.
pub fn read_dir(dir: &Path, node: u16) -> Result<Vec<Archive>, String> {
    let prefix = format!("node-{node}-");
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .map_err(|e| format!("cannot list {}: {e}", dir.display()))?
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with(&prefix) && n.ends_with(".tar"))
        .collect();
    names.sort();
    Ok(names
        .into_iter()
        .map(|name| Archive {
            files: read_archive(&dir.join(&name)),
            name,
        })
        .collect())
}

/// This node's live key files' headers.
pub fn read_live(keys_dir: &Path) -> Result<BTreeMap<String, Option<KeyInfo>>, String> {
    let mut out = BTreeMap::new();
    for e in std::fs::read_dir(keys_dir)
        .map_err(|e| format!("cannot list {}: {e}", keys_dir.display()))?
        .flatten()
    {
        let name = e.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') || !name.ends_with(".json") {
            continue;
        }
        let bytes = std::fs::read(e.path()).map_err(|e| format!("cannot read {name}: {e}"))?;
        out.insert(
            name.trim_end_matches(".json").to_string(),
            crate::seal::header_of(&bytes).map(KeyInfo::from),
        );
    }
    Ok(out)
}

/// The proofs on disk: every well-formed marker, with its age (the smaller of its recorded time's
/// and its file's), skipping markers dated in the future.
pub fn read_proofs(keys_dir: &Path, now_ms: u64) -> BTreeMap<(String, u64), Proof> {
    let mut out = BTreeMap::new();
    let Ok(rd) = std::fs::read_dir(keys_dir.join(crate::proof::DIR)) else {
        return out;
    };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let Some(stem) = name.strip_suffix(".json") else {
            continue;
        };
        let Some((key, epoch)) = stem.rsplit_once('.') else {
            continue;
        };
        let Ok(epoch) = epoch.parse::<u64>() else {
            continue;
        };
        let Some(marker) = crate::proof::read_marker(keys_dir, key, epoch) else {
            continue;
        };
        if marker.proven_ms > now_ms {
            continue;
        }
        let file_ms = e
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(now_ms, |d| d.as_millis() as u64);
        let age_ms = (now_ms - marker.proven_ms).min(now_ms.saturating_sub(file_ms));
        out.insert(
            (key.to_string(), epoch),
            Proof {
                digest: marker.pkp_digest,
                age_ms,
            },
        );
    }
    out
}

/// Run retention on `dir`: read, plan, and (unless `dry_run`) delete. Returns the plan. Any error
/// reading the directory is an `Err` and nothing is deleted.
pub fn run(
    dir: &Path,
    keys_dir: &Path,
    s: &Settings,
    now_ms: u64,
    dry_run: bool,
) -> Result<Plan, String> {
    let archives = read_dir(dir, s.node)?;
    let live = read_live(keys_dir)?;
    let proofs = read_proofs(keys_dir, now_ms);
    let plan = plan(&archives, &live, &proofs, s);
    if !dry_run {
        let mut done: Vec<&str> = Vec::new();
        for (name, verdict) in &plan.verdicts {
            if matches!(
                verdict,
                Verdict::DeleteOlderEpoch { .. } | Verdict::DeleteCountCap
            ) {
                let p: PathBuf = dir.join(name);
                std::fs::remove_file(&p).map_err(|e| {
                    format!(
                        "cannot delete {}: {e} (already deleted before this error: {})",
                        p.display(),
                        done.join(", ")
                    )
                })?;
                done.push(name);
            }
        }
    }
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLUSTER: &str = "2b0c6a52-4c1e-4b7a-9d1e-3f1a7c2e9b10";
    const DAY: u64 = 86_400_000;

    fn settings() -> Settings {
        Settings {
            node: 1,
            cluster_uuid: Some(CLUSTER.into()),
            min_proof_age_ms: 7 * DAY,
            keep_older_epochs: 0,
            keep_count: 0,
        }
    }

    fn ki(key: &str, epoch: u64, digest: &str) -> KeyInfo {
        KeyInfo {
            key_id: key.into(),
            kind: "frost-share".into(),
            epoch,
            digest: digest.into(),
            cluster: CLUSTER.into(),
            node: 1,
            dek_id: "00".into(),
        }
    }

    /// An archive of single-key sharings: `(key, epoch, digest)`.
    fn arch(name: &str, keys: &[(&str, u64, &str)]) -> Archive {
        Archive {
            name: name.into(),
            files: Ok(keys
                .iter()
                .map(|(k, e, d)| (k.to_string(), Some(ki(k, *e, d))))
                .collect()),
        }
    }

    fn live(keys: &[(&str, u64, &str)]) -> BTreeMap<String, Option<KeyInfo>> {
        keys.iter()
            .map(|(k, e, d)| (k.to_string(), Some(ki(k, *e, d))))
            .collect()
    }

    fn proofs(p: &[(&str, u64, &str, u64)]) -> BTreeMap<(String, u64), Proof> {
        p.iter()
            .map(|(k, e, d, age)| {
                (
                    (k.to_string(), *e),
                    Proof {
                        digest: d.to_string(),
                        age_ms: *age,
                    },
                )
            })
            .collect()
    }

    fn verdict<'a>(p: &'a Plan, name: &str) -> &'a Verdict {
        &p.verdicts.iter().find(|(n, _)| n == name).unwrap().1
    }

    // Archives a1 (epoch 1), a2 (epoch 2), a3 (epoch 3, live).
    fn three() -> Vec<Archive> {
        vec![
            arch("a1", &[("k", 1, "d1")]),
            arch("a2", &[("k", 2, "d2")]),
            arch("a3", &[("k", 3, "d3")]),
        ]
    }

    #[test]
    fn the_previous_epochs_go_only_when_the_new_one_is_proven_and_old_enough() {
        let l = live(&[("k", 3, "d3")]);
        let p = plan(
            &three(),
            &l,
            &proofs(&[("k", 3, "d3", 8 * DAY)]),
            &settings(),
        );
        assert!(p.skip.is_none());
        assert_eq!(
            verdict(&p, "a1"),
            &Verdict::DeleteOlderEpoch {
                covered_by: "a3".into()
            }
        );
        assert_eq!(
            verdict(&p, "a2"),
            &Verdict::DeleteOlderEpoch {
                covered_by: "a3".into()
            }
        );
        assert_eq!(verdict(&p, "a3"), &Verdict::Keep(Why::Protected));
    }

    #[test]
    fn kept_because_the_new_epoch_is_unproven_too_young_or_the_proof_is_for_another_sharing() {
        let l = live(&[("k", 3, "d3")]);
        for (why, pr) in [
            ("no proof", proofs(&[])),
            ("too young", proofs(&[("k", 3, "d3", 6 * DAY)])),
            ("another sharing", proofs(&[("k", 3, "other", 9 * DAY)])),
            (
                "proof of an epoch no archive holds",
                proofs(&[("k", 5, "d5", 9 * DAY)]),
            ),
        ] {
            let p = plan(&three(), &l, &pr, &settings());
            assert!(p.skip.is_none(), "{why}");
            for n in ["a1", "a2"] {
                assert_eq!(
                    verdict(&p, n),
                    &Verdict::Keep(Why::UnprovenEpoch),
                    "{why}: {n}"
                );
            }
        }
    }

    #[test]
    fn an_unproven_newer_epoch_keeps_the_proven_one_and_everything_above_it() {
        // Epoch 2 proven and old; epoch 3 live and unproven: epoch 1 goes, epoch 2 stays.
        let l = live(&[("k", 3, "d3")]);
        let p = plan(
            &three(),
            &l,
            &proofs(&[("k", 2, "d2", 20 * DAY)]),
            &settings(),
        );
        assert_eq!(
            verdict(&p, "a1"),
            &Verdict::DeleteOlderEpoch {
                covered_by: "a2".into()
            }
        );
        assert_eq!(verdict(&p, "a2"), &Verdict::Keep(Why::Protected));
        assert_eq!(verdict(&p, "a3"), &Verdict::Keep(Why::Protected));
    }

    #[test]
    fn nothing_is_deleted_when_the_proven_sharing_itself_is_not_backed_up() {
        // Epoch 2 is proven but only epoch 1 and 3 archives exist: deleting epoch 1 would leave only
        // the unproven epoch 3.
        let l = live(&[("k", 3, "d3")]);
        let archives = vec![arch("a1", &[("k", 1, "d1")]), arch("a3", &[("k", 3, "d3")])];
        let p = plan(
            &archives,
            &l,
            &proofs(&[("k", 2, "d2", 20 * DAY)]),
            &settings(),
        );
        // The proof's digest is held by no archive, so it does not count as a proven epoch at all.
        assert_eq!(verdict(&p, "a1"), &Verdict::Keep(Why::UnprovenEpoch));
    }

    #[test]
    fn a_key_the_node_no_longer_lists_keeps_its_archives() {
        let l = live(&[("k", 3, "d3")]);
        let mut archives = three();
        archives[0] = arch("a1", &[("k", 1, "d1"), ("gone", 1, "g1")]);
        let p = plan(
            &archives,
            &l,
            &proofs(&[("k", 3, "d3", 9 * DAY)]),
            &settings(),
        );
        assert_eq!(verdict(&p, "a1"), &Verdict::Keep(Why::KeyNotLive));
        assert!(matches!(
            verdict(&p, "a2"),
            Verdict::DeleteOlderEpoch { .. }
        ));
    }

    #[test]
    fn an_archive_whose_epoch_cannot_be_read_is_never_deleted_by_the_epoch_rule() {
        let l = live(&[("k", 3, "d3")]);
        let mut archives = three();
        // a1 holds a v1 (header-less) file; a2 is a damaged tar.
        archives[0] = Archive {
            name: "a1".into(),
            files: Ok([("k".to_string(), None)].into_iter().collect()),
        };
        archives[1] = Archive {
            name: "a2".into(),
            files: Err("truncated".into()),
        };
        let p = plan(
            &archives,
            &l,
            &proofs(&[("k", 3, "d3", 9 * DAY)]),
            &settings(),
        );
        assert_eq!(verdict(&p, "a1"), &Verdict::Keep(Why::EpochUnreadable));
        assert_eq!(verdict(&p, "a2"), &Verdict::Keep(Why::EpochUnreadable));
    }

    #[test]
    fn a_header_for_another_cluster_or_node_or_key_makes_an_archive_unreadable() {
        let l = live(&[("k", 3, "d3")]);
        let mut other_cluster = ki("k", 1, "d1");
        other_cluster.cluster = "someone-else".into();
        let mut other_node = ki("k", 2, "d2");
        other_node.node = 2;
        let archives = vec![
            Archive {
                name: "a1".into(),
                files: Ok([("k".to_string(), Some(other_cluster))]
                    .into_iter()
                    .collect()),
            },
            Archive {
                name: "a2".into(),
                files: Ok([("k".to_string(), Some(other_node))].into_iter().collect()),
            },
            Archive {
                name: "a2b".into(),
                files: Ok([("k".to_string(), Some(ki("renamed", 2, "d2")))]
                    .into_iter()
                    .collect()),
            },
            arch("a3", &[("k", 3, "d3")]),
        ];
        let p = plan(
            &archives,
            &l,
            &proofs(&[("k", 3, "d3", 9 * DAY)]),
            &settings(),
        );
        for n in ["a1", "a2", "a2b"] {
            assert_eq!(verdict(&p, n), &Verdict::Keep(Why::EpochUnreadable), "{n}");
        }
    }

    #[test]
    fn fail_closed_when_this_nodes_live_epoch_is_behind_an_archive() {
        // A node that missed a refresh: live epoch 2, an archive at 3 (taken before it went stale).
        let l = live(&[("k", 2, "d2")]);
        let archives = three();
        let p = plan(
            &archives,
            &l,
            &proofs(&[("k", 2, "d2", 20 * DAY)]),
            &settings(),
        );
        assert!(matches!(p.skip, Some(Skip::Closed(_))));
        assert!(p
            .verdicts
            .iter()
            .all(|(_, v)| matches!(v, Verdict::Keep(_))));
    }

    #[test]
    fn fail_closed_when_the_key_set_or_the_sharing_of_the_newest_archive_is_not_the_live_one() {
        let archives = three();
        // A key the newest archive does not hold yet.
        let l = live(&[("k", 3, "d3"), ("new", 1, "n1")]);
        let p = plan(
            &archives,
            &l,
            &proofs(&[("k", 3, "d3", 9 * DAY)]),
            &settings(),
        );
        assert!(matches!(p.skip, Some(Skip::Closed(_))), "a new key");
        // The live key is newer than the newest archive (a backup after the refresh is pending).
        let l = live(&[("k", 4, "d4")]);
        let p = plan(
            &archives,
            &l,
            &proofs(&[("k", 3, "d3", 9 * DAY)]),
            &settings(),
        );
        assert!(matches!(p.skip, Some(Skip::Closed(_))), "a pending backup");
        // Same epoch, another sharing.
        let l = live(&[("k", 3, "other")]);
        let p = plan(
            &archives,
            &l,
            &proofs(&[("k", 3, "d3", 9 * DAY)]),
            &settings(),
        );
        assert!(
            matches!(p.skip, Some(Skip::Closed(_))),
            "a different sharing at the same epoch"
        );
        // The newest archive is unreadable.
        let mut a = three();
        a[2] = Archive {
            name: "a3".into(),
            files: Err("truncated".into()),
        };
        let p = plan(
            &a,
            &live(&[("k", 3, "d3")]),
            &proofs(&[("k", 3, "d3", 9 * DAY)]),
            &settings(),
        );
        assert!(matches!(p.skip, Some(Skip::Closed(_))), "newest unreadable");
    }

    #[test]
    fn with_v1_live_files_or_no_cluster_uuid_only_the_count_cap_runs() {
        let archives = three();
        let mut s = settings();
        s.keep_count = 2;
        let l: BTreeMap<String, Option<KeyInfo>> = [("k".to_string(), None)].into_iter().collect();
        let p = plan(&archives, &l, &proofs(&[]), &s);
        assert!(matches!(p.skip, Some(Skip::CapOnly(_))));
        assert_eq!(verdict(&p, "a1"), &Verdict::DeleteCountCap);
        assert_eq!(verdict(&p, "a2"), &Verdict::Keep(Why::Protected));
        s.cluster_uuid = None;
        let p = plan(&archives, &live(&[("k", 3, "d3")]), &proofs(&[]), &s);
        assert!(matches!(p.skip, Some(Skip::CapOnly(_))));
        assert_eq!(verdict(&p, "a1"), &Verdict::DeleteCountCap);
    }

    #[test]
    fn the_count_cap_never_deletes_the_newest_or_the_proven_archive() {
        let l = live(&[("k", 4, "d4")]);
        // Epoch 2 proven; epoch 3 and 4 unproven. A cap of 2 would take the oldest two.
        let archives = vec![
            arch("a1", &[("k", 1, "d1")]),
            arch("a2", &[("k", 2, "d2")]),
            arch("a3", &[("k", 3, "d3")]),
            arch("a4", &[("k", 4, "d4")]),
        ];
        let mut s = settings();
        s.keep_count = 2;
        let p = plan(&archives, &l, &proofs(&[("k", 2, "d2", 9 * DAY)]), &s);
        assert!(p.skip.is_none());
        assert_eq!(
            verdict(&p, "a1"),
            &Verdict::DeleteOlderEpoch {
                covered_by: "a2".into()
            }
        );
        assert_eq!(
            verdict(&p, "a2"),
            &Verdict::Keep(Why::Protected),
            "the proven archive stays"
        );
        assert_eq!(
            verdict(&p, "a3"),
            &Verdict::Keep(Why::AtOrAfterProvenEpoch),
            "the only copy of epoch 3: the cap does not take it"
        );
        assert_eq!(
            verdict(&p, "a4"),
            &Verdict::Keep(Why::Protected),
            "the newest stays"
        );
    }

    #[test]
    fn the_count_cap_takes_copies_oldest_first_and_never_the_last_copy_of_anything() {
        let l = live(&[("k", 3, "d3")]);
        let archives = vec![
            arch("a1", &[("k", 3, "d3")]),
            arch("a2", &[("k", 3, "d3")]),
            arch("a3", &[("k", 3, "d3")]),
            arch("a4", &[("k", 3, "d3")]),
        ];
        let mut s = settings();
        s.keep_count = 2;
        // Nothing proven: the epoch rule keeps everything, the cap removes copies, oldest first.
        let p = plan(&archives, &l, &proofs(&[]), &s);
        assert_eq!(verdict(&p, "a1"), &Verdict::DeleteCountCap);
        assert_eq!(verdict(&p, "a2"), &Verdict::DeleteCountCap);
        assert_eq!(verdict(&p, "a3"), &Verdict::Keep(Why::UnprovenEpoch));
        assert_eq!(verdict(&p, "a4"), &Verdict::Keep(Why::Protected));
    }

    #[test]
    fn the_cap_never_deletes_the_last_archive_of_the_last_proven_epoch_even_when_the_proof_is_too_young(
    ) {
        // Review input A: epoch 2 proof only a day old (minimum 7): no proven archive exists, so the cap
        // must still not take the unique archives of epochs 1 and 2.
        let l = live(&[("k", 3, "d3")]);
        let archives = vec![
            arch("a1", &[("k", 1, "d1")]),
            arch("a2", &[("k", 2, "d2")]),
            arch("a3", &[("k", 3, "d3")]),
            arch("a4", &[("k", 3, "d3")]),
        ];
        let mut s = settings();
        s.keep_count = 2;
        let p = plan(&archives, &l, &proofs(&[("k", 2, "d2", DAY)]), &s);
        for n in ["a1", "a2"] {
            assert!(matches!(verdict(&p, n), Verdict::Keep(_)), "{n}: {p:?}");
        }
        assert_eq!(
            verdict(&p, "a3"),
            &Verdict::DeleteCountCap,
            "a copy of the newest"
        );
    }

    #[test]
    fn two_files_of_one_state_under_different_deks_are_not_copies_for_the_cap() {
        let l = live(&[("k", 3, "d3")]);
        let mut old_dek = arch("a1", &[("k", 3, "d3")]);
        if let Some(Some(i)) = old_dek.files.as_mut().unwrap().get_mut("k") {
            i.dek_id = "old".into();
        }
        let archives = vec![
            old_dek,
            arch("a2", &[("k", 3, "d3")]),
            arch("a3", &[("k", 3, "d3")]),
        ];
        let mut s = settings();
        s.keep_count = 1;
        let p = plan(&archives, &l, &proofs(&[]), &s);
        assert_eq!(
            verdict(&p, "a1"),
            &Verdict::Keep(Why::UnprovenEpoch),
            "the only copy sealed under the old DEK stays"
        );
        assert_eq!(verdict(&p, "a2"), &Verdict::DeleteCountCap);
    }

    #[test]
    fn a_hosted_key_does_not_stop_older_frost_epochs_from_going() {
        // Review input B and finding 2: a live hosted key (no epoch to prove) in every archive.
        let hosted = |epoch_unused: u64| {
            let _ = epoch_unused;
            KeyInfo {
                key_id: "h".into(),
                kind: "hosted-key".into(),
                epoch: 0,
                digest: "hd".into(),
                cluster: CLUSTER.into(),
                node: 1,
                dek_id: "00".into(),
            }
        };
        let with_hosted = |name: &str, e: u64, d: &str| {
            let mut a = arch(name, &[("k", e, d)]);
            a.files
                .as_mut()
                .unwrap()
                .insert("h".into(), Some(hosted(0)));
            a
        };
        let mut l = live(&[("k", 3, "d3")]);
        l.insert("h".into(), Some(hosted(0)));
        let archives = vec![
            with_hosted("a1", 1, "d1"),
            with_hosted("a2", 2, "d2"),
            with_hosted("a3", 3, "d3"),
        ];
        let p = plan(
            &archives,
            &l,
            &proofs(&[("k", 3, "d3", 9 * DAY)]),
            &settings(),
        );
        assert!(
            matches!(verdict(&p, "a1"), Verdict::DeleteOlderEpoch { .. }),
            "{p:?}"
        );
        assert!(matches!(
            verdict(&p, "a2"),
            Verdict::DeleteOlderEpoch { .. }
        ));
        // A hosted key that changed since (another digest) is not as the proven archive has it.
        let mut other = with_hosted("a1", 1, "d1");
        if let Some(Some(h)) = other.files.as_mut().unwrap().get_mut("h") {
            h.digest = "other".into();
        }
        let archives = vec![
            other,
            with_hosted("a2", 2, "d2"),
            with_hosted("a3", 3, "d3"),
        ];
        let p = plan(
            &archives,
            &l,
            &proofs(&[("k", 3, "d3", 9 * DAY)]),
            &settings(),
        );
        assert_eq!(verdict(&p, "a1"), &Verdict::Keep(Why::AtOrAfterProvenEpoch));
    }

    #[test]
    fn a_frost_key_that_was_not_refreshed_needs_its_own_proof_and_then_does_not_block() {
        // a refreshed to 2, b still at 1 in every archive.
        let l = live(&[("a", 2, "a2"), ("b", 1, "b1")]);
        let archives = vec![
            arch("x1", &[("a", 1, "a1"), ("b", 1, "b1")]),
            arch("x2", &[("a", 2, "a2"), ("b", 1, "b1")]),
        ];
        let only_a = plan(
            &archives,
            &l,
            &proofs(&[("a", 2, "a2", 9 * DAY)]),
            &settings(),
        );
        assert_eq!(
            verdict(&only_a, "x1"),
            &Verdict::Keep(Why::UnprovenEpoch),
            "b is unproven"
        );
        let both = plan(
            &archives,
            &l,
            &proofs(&[("a", 2, "a2", 9 * DAY), ("b", 1, "b1", 9 * DAY)]),
            &settings(),
        );
        assert!(
            matches!(verdict(&both, "x1"), Verdict::DeleteOlderEpoch { .. }),
            "{both:?}"
        );
    }

    #[test]
    fn a_higher_epoch_in_an_archive_that_is_not_verified_still_fails_closed() {
        // The node is at 2; an archive at 3 holds one foreign file, so it is not "verified", but its
        // header for k still says epoch 3.
        let l = live(&[("k", 2, "d2")]);
        let mut odd = arch("a3", &[("k", 3, "d3")]);
        odd.files.as_mut().unwrap().insert("alien".into(), None);
        let archives = vec![
            arch("a1", &[("k", 1, "d1")]),
            arch("a2", &[("k", 2, "d2")]),
            odd,
        ];
        // The newest (a3) is unreadable as a complete backup: closed for that reason already; make a
        // verified newest archive so the behind check is what trips.
        let mut archives2 = archives.clone();
        archives2.push(arch("a4", &[("k", 2, "d2")]));
        let p = plan(
            &archives2,
            &l,
            &proofs(&[("k", 2, "d2", 9 * DAY)]),
            &settings(),
        );
        assert!(
            matches!(p.skip, Some(Skip::Closed(ref why)) if why.contains("behind")),
            "{p:?}"
        );
    }

    #[test]
    fn keep_older_epochs_holds_back_the_n_highest_epochs_below_the_proven_one() {
        let l = live(&[("k", 4, "d4")]);
        let archives = vec![
            arch("a1", &[("k", 1, "d1")]),
            arch("a2", &[("k", 2, "d2")]),
            arch("a3", &[("k", 3, "d3")]),
            arch("a4", &[("k", 4, "d4")]),
        ];
        let mut s = settings();
        s.keep_older_epochs = 1;
        let p = plan(&archives, &l, &proofs(&[("k", 4, "d4", 9 * DAY)]), &s);
        assert!(matches!(
            verdict(&p, "a1"),
            Verdict::DeleteOlderEpoch { .. }
        ));
        assert!(matches!(
            verdict(&p, "a2"),
            Verdict::DeleteOlderEpoch { .. }
        ));
        assert_eq!(verdict(&p, "a3"), &Verdict::Keep(Why::KeepOlderEpochs));
    }

    #[test]
    fn several_keys_need_every_one_proven_before_an_archive_goes() {
        let l = live(&[("a", 2, "a2"), ("b", 2, "b2")]);
        let archives = vec![
            arch("x1", &[("a", 1, "a1"), ("b", 1, "b1")]),
            arch("x2", &[("a", 2, "a2"), ("b", 2, "b2")]),
        ];
        // Only key a is proven at epoch 2.
        let p = plan(
            &archives,
            &l,
            &proofs(&[("a", 2, "a2", 9 * DAY)]),
            &settings(),
        );
        assert_eq!(verdict(&p, "x1"), &Verdict::Keep(Why::UnprovenEpoch));
        // Both proven.
        let p = plan(
            &archives,
            &l,
            &proofs(&[("a", 2, "a2", 9 * DAY), ("b", 2, "b2", 9 * DAY)]),
            &settings(),
        );
        assert!(matches!(
            verdict(&p, "x1"),
            Verdict::DeleteOlderEpoch { .. }
        ));
    }

    #[test]
    fn no_single_archive_holding_every_proven_epoch_means_nothing_is_deleted() {
        // Both keys are proven at epoch 2, but no archive holds both at epoch 2 (x1 has a@2, b@1;
        // x2 has a@1, b@2): deleting either would lose one proven sharing.
        let l = live(&[("a", 3, "a3"), ("b", 3, "b3")]);
        let archives = vec![
            arch("x1", &[("a", 2, "a2"), ("b", 1, "b1")]),
            arch("x2", &[("a", 1, "a1"), ("b", 2, "b2")]),
            arch("x3", &[("a", 3, "a3"), ("b", 3, "b3")]),
        ];
        let p = plan(
            &archives,
            &l,
            &proofs(&[("a", 2, "a2", 9 * DAY), ("b", 2, "b2", 9 * DAY)]),
            &settings(),
        );
        assert!(p.skip.is_none());
        assert_eq!(verdict(&p, "x1"), &Verdict::Keep(Why::NoProvenArchive));
        assert_eq!(verdict(&p, "x2"), &Verdict::Keep(Why::NoProvenArchive));
    }

    #[test]
    fn archives_at_the_proven_epoch_stay_and_only_the_newest_of_them_is_protected() {
        let l = live(&[("k", 3, "d3")]);
        let archives = vec![
            arch("a1", &[("k", 1, "d1")]),
            arch("a2", &[("k", 2, "d2")]),
            arch("a2b", &[("k", 2, "d2")]),
            arch("a3", &[("k", 3, "d3")]),
        ];
        let p = plan(
            &archives,
            &l,
            &proofs(&[("k", 2, "d2", 9 * DAY)]),
            &settings(),
        );
        assert_eq!(
            verdict(&p, "a1"),
            &Verdict::DeleteOlderEpoch {
                covered_by: "a2b".into()
            }
        );
        assert_eq!(
            verdict(&p, "a2"),
            &Verdict::Keep(Why::NothingOlder),
            "a copy of the proven archive, not an older epoch"
        );
        assert_eq!(verdict(&p, "a2b"), &Verdict::Keep(Why::Protected));
    }

    #[test]
    fn an_empty_directory_or_one_archive_has_nothing_to_delete() {
        let p = plan(&[], &live(&[("k", 3, "d3")]), &proofs(&[]), &settings());
        assert!(p.skip.is_none() && p.verdicts.is_empty());
        let one = vec![arch("a3", &[("k", 3, "d3")])];
        let p = plan(
            &one,
            &live(&[("k", 3, "d3")]),
            &proofs(&[("k", 3, "d3", 9 * DAY)]),
            &settings(),
        );
        assert_eq!(verdict(&p, "a3"), &Verdict::Keep(Why::Protected));
    }

    // ---- reading real tars ---------------------------------------------------------------------

    fn v2_file(key: &str, epoch: u64, digest: &str) -> Vec<u8> {
        serde_json::to_vec_pretty(&serde_json::json!({
            "v": 2,
            "hdr": {"fmt": "rutli-keyfile/2", "cluster": CLUSTER, "node": 1, "key_id": key, "kind": "frost-share",
                    "epoch": epoch, "digest": digest, "dek_id": "00112233"},
            "nonce": "00", "ct": "00",
        }))
        .unwrap()
    }

    /// Make a tar the way the backup script does (symlinks into a stage, `tar -h`).
    fn make_tar(dir: &Path, name: &str, files: &[(&str, Vec<u8>)], journal: bool) {
        let data = dir.join(format!("{name}.data"));
        let stage = dir.join(format!("{name}.stage"));
        std::fs::create_dir_all(&data).unwrap();
        std::fs::create_dir_all(&stage).unwrap();
        for (n, bytes) in files {
            std::fs::write(data.join(n), bytes).unwrap();
            std::os::unix::fs::symlink(data.join(n), stage.join(n)).unwrap();
        }
        if journal {
            let j = stage.join("journal").join("k");
            std::fs::create_dir_all(&j).unwrap();
            let seg = data.join("0001.jsonl");
            std::fs::write(&seg, vec![b'x'; 5000]).unwrap();
            std::os::unix::fs::symlink(&seg, j.join("0001.jsonl")).unwrap();
            std::fs::create_dir_all(stage.join(".cleared")).unwrap();
            std::fs::write(stage.join(".cleared").join("k.abc"), b"").unwrap();
        }
        let ok = std::process::Command::new("tar")
            .arg("-h")
            .arg("-C")
            .arg(&stage)
            .arg("-cf")
            .arg(dir.join(name))
            .arg(".")
            .status()
            .unwrap()
            .success();
        assert!(ok, "tar");
    }

    #[test]
    fn it_reads_the_key_headers_of_a_real_tar_and_skips_journals_and_markers() {
        let d = tempfile::tempdir().unwrap();
        make_tar(
            d.path(),
            "node-1-20261120T000000Z.tar",
            &[
                ("k.json", v2_file("k", 3, "dd")),
                ("other.json", v2_file("other", 0, "")),
            ],
            true,
        );
        let files = read_archive(&d.path().join("node-1-20261120T000000Z.tar")).unwrap();
        assert_eq!(
            files.keys().cloned().collect::<Vec<_>>(),
            vec!["k".to_string(), "other".to_string()]
        );
        let k = files["k"].as_ref().unwrap();
        assert_eq!((k.epoch, k.digest.as_str(), k.node), (3, "dd", 1));
    }

    #[test]
    fn a_v1_file_a_truncated_tar_and_a_bad_checksum_are_not_readable() {
        let d = tempfile::tempdir().unwrap();
        make_tar(
            d.path(),
            "v1.tar",
            &[(
                "k.json",
                br#"{"v":1,"sealed":true,"nonce":"00","ct":"00"}"#.to_vec(),
            )],
            false,
        );
        assert_eq!(read_archive(&d.path().join("v1.tar")).unwrap()["k"], None);

        make_tar(
            d.path(),
            "ok.tar",
            &[("k.json", v2_file("k", 1, "d"))],
            false,
        );
        let bytes = std::fs::read(d.path().join("ok.tar")).unwrap();
        // GNU tar pads the archive to 10 KiB: cut inside the entries, not inside the padding.
        for (i, cut) in [700usize, 1100, 1600].into_iter().enumerate() {
            let name = format!("cut{i}.tar");
            std::fs::write(d.path().join(&name), &bytes[..cut.min(bytes.len())]).unwrap();
            assert!(
                read_archive(&d.path().join(&name)).is_err(),
                "truncated at {cut}"
            );
        }
        let mut bad = bytes.clone();
        bad[0] ^= 0x55;
        std::fs::write(d.path().join("bad.tar"), &bad).unwrap();
        assert!(read_archive(&d.path().join("bad.tar")).is_err(), "checksum");
        std::fs::write(d.path().join("empty.tar"), b"").unwrap();
        assert!(
            read_archive(&d.path().join("empty.tar")).is_err(),
            "empty file"
        );
        std::fs::write(d.path().join("junk.tar"), vec![7u8; 2048]).unwrap();
        assert!(
            read_archive(&d.path().join("junk.tar")).is_err(),
            "not a tar"
        );
    }

    #[test]
    fn run_deletes_only_what_the_plan_says_and_dry_run_deletes_nothing() {
        let d = tempfile::tempdir().unwrap();
        let backups = d.path().join("backup");
        let keys = d.path().join("keys");
        std::fs::create_dir_all(&backups).unwrap();
        std::fs::create_dir_all(&keys).unwrap();
        for (i, (epoch, digest)) in [(1u64, "d1"), (2, "d2"), (3, "d3")].iter().enumerate() {
            make_tar(
                &backups,
                &format!("node-1-2026112{i}T000000Z.tar"),
                &[("k.json", v2_file("k", *epoch, digest))],
                false,
            );
        }
        std::fs::write(keys.join("k.json"), v2_file("k", 3, "d3")).unwrap();
        // A proof of epoch 3, stamped 10 days ago (the marker file itself is new, so its mtime is
        // "now": the age is the smaller of the two, hence too young) ...
        let now = crate::intent::now_ms();
        let marker = crate::proof::Marker {
            v: 1,
            key_id: "k".into(),
            epoch: 3,
            group_key: "g".into(),
            pkp_digest: "d3".into(),
            proven_ms: now - 10 * DAY,
            report_sha256: "r".into(),
            statement: crate::proof::STATEMENT.into(),
        };
        std::fs::create_dir_all(keys.join(crate::proof::DIR)).unwrap();
        std::fs::write(
            crate::proof::marker_path(&keys, "k", 3),
            serde_json::to_vec(&marker).unwrap(),
        )
        .unwrap();
        let p = run(&backups, &keys, &settings(), now, false).unwrap();
        assert!(
            p.verdicts
                .iter()
                .all(|(_, v)| matches!(v, Verdict::Keep(_))),
            "{p:?}"
        );
        assert_eq!(
            std::fs::read_dir(&backups)
                .unwrap()
                .filter(|e| e
                    .as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".tar"))
                .count(),
            3
        );
        // ... but seen from 10 days later the file's age agrees with the record: now it deletes.
        let later = now + 10 * DAY;
        let dry = run(&backups, &keys, &settings(), later, true).unwrap();
        assert_eq!(
            dry.verdicts
                .iter()
                .filter(|(_, v)| matches!(v, Verdict::DeleteOlderEpoch { .. }))
                .count(),
            2
        );
        assert!(
            std::fs::read_dir(&backups)
                .unwrap()
                .flatten()
                .filter(|e| e.file_name().to_string_lossy().ends_with(".tar"))
                .count()
                == 3,
            "dry run deletes nothing"
        );
        run(&backups, &keys, &settings(), later, false).unwrap();
        let left: Vec<String> = std::fs::read_dir(&backups)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tar"))
            .collect();
        assert_eq!(left, vec!["node-1-20261122T000000Z.tar".to_string()]);
    }

    #[test]
    fn a_marker_dated_in_the_future_or_a_clock_set_back_does_not_age_a_proof() {
        let d = tempfile::tempdir().unwrap();
        let keys = d.path();
        let now = crate::intent::now_ms();
        let mut m = crate::proof::Marker {
            v: 1,
            key_id: "k".into(),
            epoch: 3,
            group_key: "g".into(),
            pkp_digest: "d3".into(),
            proven_ms: now + DAY,
            report_sha256: "r".into(),
            statement: crate::proof::STATEMENT.into(),
        };
        std::fs::create_dir_all(keys.join(crate::proof::DIR)).unwrap();
        std::fs::write(
            crate::proof::marker_path(keys, "k", 3),
            serde_json::to_vec(&m).unwrap(),
        )
        .unwrap();
        assert!(read_proofs(keys, now).is_empty(), "dated in the future");
        // Recorded 30 days ago on a clock set back, but the file was written just now.
        m.proven_ms = now - 30 * DAY;
        std::fs::write(
            crate::proof::marker_path(keys, "k", 3),
            serde_json::to_vec(&m).unwrap(),
        )
        .unwrap();
        let proofs = read_proofs(keys, now);
        assert!(
            proofs[&("k".to_string(), 3)].age_ms < DAY,
            "the file's age wins: {proofs:?}"
        );
    }
}
