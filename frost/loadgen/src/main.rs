// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! `rutli-loadgen`: a load generator for a Rütli cosigner cluster.
//!
//! It talks to the `Signer` API the way the Canton KMS driver does: mutual TLS with the driver
//! certificate, one signed intent per request, and a sticky leader with failover to the next
//! cosigner when the contacted one does not answer. Every answer is checked (a signature with
//! `verify_strict` against the key's group key, an ECDH secret against a locally computed one), so
//! a wrong answer is never counted as a success.
//!
//! One run is one command: it scrapes every cosigner's `/metrics` page, generates the load, scrapes
//! again, probes `Health`, and prints one JSON document on stdout (progress goes to stderr). The
//! exit code says whether the run could be made, not what the cluster answered: refusals are the
//! expected result of a limit test, and judging them is the caller's job
//! (`scripts/perf/run.py`).
//!
//! Commands:
//! - `wait`: until every cosigner answers `Health` ok.
//! - `setup`: make sure the FROST keys (DKG) and the hosted ECIES keys of a run exist.
//! - `sign`: signatures, at a fixed rate (`--rate`) or as fast as `--clients` clients get answers.
//! - `ecdh`: `EcdhDerive` on a hosted ECIES key, the cluster's part of an ECIES decryption.
//! - `dkg`: many DKGs at once, on distinct keys or all on the same one.
//! - `refresh`: share refreshes of one key.
//!
//! A test tool. It is not in the cosigner image and not in a release.

// gRPC statuses are passed around by value, as in the cosigner: boxing each one would not make a
// test tool better.
#![allow(clippy::result_large_err)]

mod prom;
mod stats;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use clap::{Args, Parser, Subcommand, ValueEnum};
use rutli_cosigner::intent;
use rutli_cosigner::node::CeremonyKind;
use rutli_cosigner::pb;
use rutli_cosigner::pb::signer_client::SignerClient;
use rutli_cosigner::request_auth::NodeSigner;
use serde::Serialize;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

use stats::{code_name, Outcome, Recorder};

/// How long a sign intent is valid: far inside the cosigners' default ceiling (300 s), far beyond
/// any request this tool waits for.
const INTENT_LIFETIME_MS: u64 = 120_000;
const ECIES_SPEC: &str = "ec-p256-ecies";

#[derive(Parser)]
#[command(name = "rutli-loadgen", about = "Load generator for a Rütli cosigner cluster (a test tool)")]
struct Cli {
    /// A cosigner, as `NAME=URL`: the name its TLS certificate carries and its Signer endpoint,
    /// e.g. `cosigner1=https://cosigner1:9101`. Repeat for every cosigner, in roster order.
    #[arg(long = "target", required = true, value_parser = name_value)]
    targets: Vec<(String, String)>,
    /// The cluster CA certificate (PEM).
    #[arg(long)]
    ca: PathBuf,
    /// The client certificate (PEM): a `signer_allowlist` identity, as the driver's.
    #[arg(long)]
    cert: PathBuf,
    /// The client certificate's key (PKCS#8 PEM). It also signs the intents.
    #[arg(long)]
    key: PathBuf,
    /// A cosigner's metrics page, as `NAME=URL` (plain HTTP), e.g.
    /// `cosigner1=http://cosigner1:9200/metrics`. Without any, the report has no server side.
    #[arg(long = "metrics", value_parser = name_value)]
    metrics: Vec<(String, String)>,
    /// Longest wait for one answer from one cosigner.
    #[arg(long, default_value_t = 30)]
    timeout_secs: u64,
    /// The driver's policy for calls that fail over other than signatures (ECDH): each attempt at
    /// one cosigner gets this deadline, and on it the call moves to the next cosigner. Default:
    /// --timeout-secs. The driver uses 10 s (frost.attempt-timeout).
    #[arg(long)]
    attempt_timeout_secs: Option<f64>,
    /// The same for signatures, which move on with the same intent. Default:
    /// --attempt-timeout-secs. The driver uses 5 s (frost.sign-attempt-timeout).
    #[arg(long)]
    sign_attempt_timeout_secs: Option<f64>,
    /// The driver's budget for one call across all its attempts: each attempt's deadline is cut
    /// to what is left of it, and no attempt starts with less than 50 ms left (the call then ends
    /// with DEADLINE_EXCEEDED). Default: none. The driver uses 30 s (frost.request-timeout).
    #[arg(long)]
    request_timeout_secs: Option<f64>,
    /// Where a signature starts, as the driver's `frost.sign-leader`: `sticky` (the client's
    /// leader, as every other call) or `rotate` (the next cosigner in turn that was not demoted
    /// within the last 60 s; the sticky leader when none is healthy). Failover then walks the
    /// ring from the start either way. Under `rotate` a signature never moves the sticky leader;
    /// only a failure (the cosigner did not serve) does, and demotes that cosigner.
    #[arg(long, value_enum, default_value_t = SignLeader::Sticky)]
    sign_leader: SignLeader,
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum SignLeader {
    Sticky,
    Rotate,
}

/// How long a demoted cosigner is skipped as the start of a rotated signature (the driver's
/// `frost.leader-recovery`).
const LEADER_RECOVERY: Duration = Duration::from_secs(60);

#[derive(Subcommand)]
enum Command {
    /// Wait until every cosigner answers Health ok.
    Wait {
        #[arg(long, default_value_t = 120)]
        within_secs: u64,
    },
    /// Make sure the keys of a run exist: a DKG per FROST key, a hosted ECIES key per id.
    Setup {
        #[arg(long = "frost-key")]
        frost_keys: Vec<String>,
        /// Hosted key ids contain `rutli-`.
        #[arg(long = "ecies-key")]
        ecies_keys: Vec<String>,
    },
    /// Signatures.
    Sign {
        /// FROST key to sign with; several are used in turn.
        #[arg(long = "key", required = true)]
        keys: Vec<String>,
        #[command(flatten)]
        load: Load,
    },
    /// EcdhDerive on a hosted ECIES key.
    Ecdh {
        #[arg(long)]
        key: String,
        #[command(flatten)]
        load: Load,
    },
    /// DKGs: request number i generates `<prefix>-<i>`, or with --same-key they all ask for
    /// `<prefix>`.
    Dkg {
        #[arg(long)]
        prefix: String,
        #[arg(long)]
        same_key: bool,
        /// Retry a DKG answered UNAVAILABLE (a node not serving, such as a ceremony still
        /// resolving: what the driver hands Canton as retryable) or ABORTED (another ceremony holds
        /// the key) up to this many times, with jittered exponential backoff (0.5 s doubling to
        /// 4 s), each with a fresh ceremony intent. A leader that passes a member's ABORTED on as
        /// INTERNAL ("already in progress", #146) is retried the same way.
        #[arg(long, default_value_t = 0)]
        retry_aborted: u32,
        #[command(flatten)]
        load: Load,
    },
    /// Share refreshes of one key.
    Refresh {
        #[arg(long)]
        key: String,
        #[command(flatten)]
        load: Load,
    },
    /// Time the Peer API's ListKeys (the hosted-key inventory anti-entropy reads) on every
    /// cosigner. Needs a cosigner identity: --peer-cert and --peer-key.
    ListKeys {
        /// Calls per cosigner.
        #[arg(long, default_value_t = 5)]
        repeat: u32,
        /// A cosigner certificate (PEM), on the cosigners' peer_allowlist.
        #[arg(long)]
        peer_cert: PathBuf,
        /// Its key (PKCS#8 PEM).
        #[arg(long)]
        peer_key: PathBuf,
    },
}

/// The shape of a load.
#[derive(Args, Clone)]
struct Load {
    /// A label for the report.
    #[arg(long, default_value = "")]
    name: String,
    /// Stop after this long. At least one of --duration-secs and --count is needed.
    #[arg(long, default_value_t = 0)]
    duration_secs: u64,
    /// Stop after this many requests.
    #[arg(long, default_value_t = 0)]
    count: u64,
    /// Requests per second, started on time whether or not earlier ones were answered (open
    /// loop). 0: every client sends its next request when the last one is answered (closed loop).
    #[arg(long, default_value_t = 0.0)]
    rate: f64,
    /// Independent clients, each with its own connections and its own sticky leader. Client i
    /// starts at cosigner i mod n, unless --prefer.
    #[arg(long, default_value_t = 1)]
    clients: usize,
    /// Open loop only: most requests in flight at once. A request beyond it is not sent and
    /// counted as CLIENT_SATURATED.
    #[arg(long, default_value_t = 4096)]
    max_in_flight: usize,
    /// Every client starts at this cosigner (a --target name).
    #[arg(long)]
    prefer: Option<String>,
    /// Report the first answer, whatever it is: never try another cosigner.
    #[arg(long)]
    no_failover: bool,
    /// A cosigner that is restarted during the run (a --metrics name): its counters start again
    /// from zero, so the scrape before the run is not subtracted from it.
    #[arg(long = "restarted")]
    restarted: Vec<String>,
    /// Before the load starts, every client opens its connection to its first cosigner, all at
    /// once, and the time each takes is reported (`connect`): the cost of many clients
    /// connecting together, apart from the requests.
    #[arg(long)]
    eager_connect: bool,
}

fn name_value(s: &str) -> Result<(String, String), String> {
    match s.split_once('=') {
        Some((name, value)) if !name.is_empty() && !value.is_empty() => Ok((name.to_string(), value.to_string())),
        _ => Err(format!("expected NAME=URL, got {s:?}")),
    }
}

type Fail = Box<dyn std::error::Error + Send + Sync>;

/// What every command needs: where the cosigners are and who we are.
struct Ctx {
    targets: Vec<(String, String)>,
    tls: ClientTlsConfig,
    signer: NodeSigner,
    metrics: Vec<(String, String)>,
    timeout: Duration,
    /// The deadline of one attempt of a call that fails over (signatures, and other calls), and
    /// the call's budget across its attempts (None: no budget).
    sign_attempt: Duration,
    attempt: Duration,
    budget: Option<Duration>,
    rotate_signs: bool,
}

impl Ctx {
    fn new(cli: &Cli) -> Result<Self, Fail> {
        let read = |p: &PathBuf| std::fs::read(p).map_err(|e| format!("cannot read {}: {e}", p.display()));
        let attempt = positive_secs(cli.attempt_timeout_secs, "--attempt-timeout-secs")?
            .unwrap_or(Duration::from_secs(cli.timeout_secs.max(1)));
        let tls = ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(read(&cli.ca)?))
            .identity(Identity::from_pem(read(&cli.cert)?, read(&cli.key)?));
        let signer = NodeSigner::from_files(&cli.cert, &cli.key)?;
        Ok(Self {
            targets: cli.targets.clone(),
            tls,
            signer,
            metrics: cli.metrics.clone(),
            timeout: Duration::from_secs(cli.timeout_secs.max(1)),
            attempt,
            sign_attempt: positive_secs(cli.sign_attempt_timeout_secs, "--sign-attempt-timeout-secs")?.unwrap_or(attempt),
            budget: positive_secs(cli.request_timeout_secs, "--request-timeout-secs")?,
            rotate_signs: cli.sign_leader == SignLeader::Rotate,
        })
    }

    /// A client for target `i`. The connection is made on first use and again after it breaks, so
    /// a cosigner that is down now is no error here.
    fn connect(&self, i: usize) -> Result<SignerClient<Channel>, Fail> {
        let (name, url) = self.targets.get(i).ok_or_else(|| format!("no target {i}"))?;
        let endpoint = Endpoint::from_shared(url.clone())
            .map_err(|e| format!("bad endpoint {url}: {e}"))?
            .connect_timeout(Duration::from_secs(5))
            .tls_config(self.tls.clone().domain_name(name.clone()))?;
        Ok(SignerClient::new(endpoint.connect_lazy()))
    }

    /// A client for target `i`, connected now: how long the connection (TCP and TLS) took, or why
    /// it failed.
    async fn connect_now(&self, i: usize) -> (Result<SignerClient<Channel>, String>, Duration) {
        let begun = Instant::now();
        let Some((name, url)) = self.targets.get(i) else {
            return (Err(format!("no target {i}")), begun.elapsed());
        };
        let endpoint = match Endpoint::from_shared(url.clone())
            .map_err(|e| e.to_string())
            .and_then(|e| e.connect_timeout(self.timeout).tls_config(self.tls.clone().domain_name(name.clone())).map_err(|e| e.to_string()))
        {
            Ok(e) => e,
            Err(e) => return (Err(e), begun.elapsed()),
        };
        let channel = endpoint.connect().await.map_err(|e| {
            let source = std::error::Error::source(&e).map(|s| format!(": {s}")).unwrap_or_default();
            format!("{e}{source}")
        });
        (channel.map(SignerClient::new), begun.elapsed())
    }

    fn connect_all(&self) -> Result<Vec<SignerClient<Channel>>, Fail> {
        (0..self.targets.len()).map(|i| self.connect(i)).collect()
    }

    fn index_of(&self, name: &str) -> Result<usize, Fail> {
        self.targets
            .iter()
            .position(|(n, _)| n == name)
            .ok_or_else(|| format!("{name:?} is not a --target name").into())
    }
}

/// `call` bounded by `limit`: a cosigner that does not answer in time counts as DEADLINE_EXCEEDED.
async fn bounded<T>(
    limit: Duration,
    call: impl std::future::Future<Output = Result<tonic::Response<T>, tonic::Status>>,
) -> Result<T, tonic::Status> {
    match tokio::time::timeout(limit, call).await {
        Ok(answer) => answer.map(tonic::Response::into_inner),
        Err(_) => Err(tonic::Status::deadline_exceeded(format!("no answer within {} s", limit.as_secs()))),
    }
}

/// Did the contacted cosigner fail to serve (the driver's rule for trying the next one), as
/// opposed to answering with a refusal? UNAVAILABLE and DEADLINE_EXCEEDED, and a status that tonic
/// built from a broken connection (it carries the transport error as its source).
fn not_serving(status: &tonic::Status) -> bool {
    use tonic::Code::*;
    match status.code() {
        Unavailable | DeadlineExceeded => true,
        Unknown | Cancelled | Internal => std::error::Error::source(status).is_some(),
        _ => false,
    }
}

/// One logical client: a connection per cosigner and a sticky leader.
struct Client {
    conns: Vec<SignerClient<Channel>>,
    leader: AtomicUsize,
    /// The rotation counter of rotated signatures: one per client, as one per driver.
    cursor: AtomicUsize,
    /// When each cosigner last failed to serve this client: nanoseconds since `epoch`, plus one
    /// (0 = never).
    demoted: Vec<AtomicU64>,
    epoch: Instant,
}

/// How one request travelled: the codes that made the client move to another cosigner, and the
/// cosigner (index into the targets) that gave the final answer.
#[derive(Default)]
struct Route {
    failovers: Vec<&'static str>,
    leader: Option<usize>,
}

/// A seconds flag as a Duration; it must be positive.
fn positive_secs(value: Option<f64>, flag: &str) -> Result<Option<Duration>, Fail> {
    match value {
        None => Ok(None),
        Some(v) if v.is_finite() && v > 0.0 => Ok(Some(Duration::from_secs_f64(v))),
        Some(v) => Err(format!("{flag} must be a positive number of seconds, got {v}").into()),
    }
}

/// No attempt starts with less than this left of the call's budget (the driver's MinAttempt).
const MIN_ATTEMPT: Duration = Duration::from_millis(50);

/// The deadline of the next attempt: `limit`, cut to what is left of `budget` after `elapsed`;
/// `None` when the budget is spent (less than [`MIN_ATTEMPT`] left) after at least one attempt.
/// The first attempt always runs.
fn attempt_deadline(limit: Duration, budget: Option<Duration>, elapsed: Duration, tried: usize) -> Option<Duration> {
    match budget.map(|b| b.saturating_sub(elapsed)) {
        None => Some(limit),
        Some(left) if tried > 0 && left < MIN_ATTEMPT => None,
        Some(left) => Some(limit.min(left)),
    }
}

/// A ceremony answer a client retries: UNAVAILABLE (a node not serving, e.g. "a ceremony … is
/// staged and still resolving — retry shortly"), which the driver reports to Canton as retryable
/// (`RutliDriver.transient`); ABORTED (another ceremony holds the key); or a leader's INTERNAL that
/// carries a member's "already in progress" (#146).
fn contended(s: &tonic::Status) -> bool {
    matches!(s.code(), tonic::Code::Unavailable | tonic::Code::Aborted)
        || (s.code() == tonic::Code::Internal && s.message().contains("already in progress"))
}

/// The pause before retry `attempt` (1, 2, ...): 0.5 s doubling to at most 4 s, a random half to
/// all of it, so that colliding clients spread out.
fn backoff(attempt: u32) -> Duration {
    let full = (0.5 * 2f64.powi(attempt.saturating_sub(1).min(3) as i32)).min(4.0);
    Duration::from_secs_f64(full * (0.5 + 0.5 * rand::random::<f64>()))
}

impl Client {
    fn new(conns: Vec<SignerClient<Channel>>, leader: usize) -> Self {
        let demoted = (0..conns.len()).map(|_| AtomicU64::new(0)).collect();
        Client { conns, leader: AtomicUsize::new(leader), cursor: AtomicUsize::new(0), demoted, epoch: Instant::now() }
    }

    fn now(&self) -> u64 {
        u64::try_from(self.epoch.elapsed().as_nanos()).unwrap_or(u64::MAX).saturating_add(1)
    }

    /// Not demoted within [`LEADER_RECOVERY`].
    fn healthy(&self, i: usize) -> bool {
        let at = self.demoted.get(i).map_or(0, |d| d.load(Ordering::Relaxed));
        at == 0 || self.now().saturating_sub(at) > LEADER_RECOVERY.as_nanos() as u64
    }

    /// Cosigner `i` did not serve: it is demoted, and if it is the sticky leader the next one is
    /// (a compare-and-set: it never overrides a newer leader).
    fn demote(&self, i: usize) {
        if let Some(d) = self.demoted.get(i) {
            d.store(self.now(), Ordering::Relaxed);
        }
        let next = (i + 1) % self.conns.len();
        let _ = self.leader.compare_exchange(i, next, Ordering::Relaxed, Ordering::Relaxed);
    }

    /// Where a rotated signature starts: the next cosigner in turn that is healthy, else the
    /// sticky leader.
    fn sign_start(&self) -> usize {
        let n = self.conns.len();
        let first = self.cursor.fetch_add(1, Ordering::Relaxed) % n;
        (0..n).map(|k| (first + k) % n).find(|&i| self.healthy(i)).unwrap_or(self.leader.load(Ordering::Relaxed) % n)
    }

    /// Run `call` against the leader; while the answer is [`not_serving`] and `failover` is on,
    /// move to the next cosigner and stay there. One attempt at a time, each with the deadline
    /// `limit`, cut to what is left of `budget` (the whole call's, across attempts) if there is
    /// one: the driver's policy (`FrostBackend.withCheckedFailover`). Returns the final answer and
    /// its [`Route`].
    async fn call<T, Fut>(
        &self,
        failover: bool,
        limit: Duration,
        budget: Option<Duration>,
        start: Option<usize>,
        call: impl Fn(SignerClient<Channel>) -> Fut,
    ) -> (Result<T, tonic::Status>, Route)
    where
        Fut: std::future::Future<Output = Result<tonic::Response<T>, tonic::Status>>,
    {
        let n = self.conns.len();
        let mut moves = Vec::new();
        // `start`: a rotated signature's own start; it never moves the sticky leader.
        let mut at = start.unwrap_or_else(|| self.leader.load(Ordering::Relaxed)) % n;
        let began = Instant::now();
        loop {
            let Some(deadline) = attempt_deadline(limit, budget, began.elapsed(), moves.len()) else {
                let spent = tonic::Status::deadline_exceeded(format!(
                    "request timeout {} s spent after {} cosigner(s)",
                    budget.unwrap_or_default().as_secs_f64(),
                    moves.len()
                ));
                return (Err(spent), Route { failovers: moves, leader: Some(at) });
            };
            // `at` is reduced modulo `n = conns.len()` (one connection per --target, which clap
            // requires), here and at every step below, so it is in range.
            #[allow(clippy::indexing_slicing)]
            let conn = self.conns[at].clone();
            match bounded(deadline, call(conn)).await {
                // A cosigner that did not serve is demoted, the last one asked too; the sticky
                // leader moves only through `demote`'s compare-and-set, so a slower call never
                // moves it back to a cosigner another call has just demoted.
                Err(status) if failover && not_serving(&status) && moves.len() + 1 < n => {
                    moves.push(code_name(status.code()));
                    self.demote(at);
                    at = (at + 1) % n;
                }
                answer => {
                    if failover && matches!(&answer, Err(status) if not_serving(status)) {
                        self.demote(at);
                    }
                    return (answer, Route { failovers: moves, leader: Some(at) });
                }
            }
        }
    }
}

/// What a load run sends.
enum Op {
    Sign { keys: Vec<(String, ed25519_dalek::VerifyingKey)> },
    Ecdh { key_id: String, peer_point: Vec<u8>, expected: Vec<u8> },
    /// `first_key`: with `same_key`, the group key of the first OK answer. Every later OK must
    /// carry the same one, or two ceremonies each believe they generated the key.
    Dkg { prefix: String, same_key: bool, first_key: Mutex<Option<Vec<u8>>>, retry_aborted: u32 },
    Refresh { key_id: String, group_key: Vec<u8> },
}

impl Op {
    /// Ceremonies are never re-run on another cosigner by a client that does not know whether the
    /// first one started (the driver's rule).
    fn may_fail_over(&self) -> bool {
        matches!(self, Op::Sign { .. } | Op::Ecdh { .. })
    }
}

struct Run {
    ctx: Arc<Ctx>,
    cluster_id: String,
    op: Op,
    failover: bool,
    started: Instant,
    recorder: Mutex<Recorder>,
}

impl Run {
    fn ceremony_intent(&self, kind: CeremonyKind, key_id: &str) -> Result<pb::SignedIntent, tonic::Status> {
        let unsigned = intent::ceremony_intent(
            &self.cluster_id,
            kind,
            key_id,
            intent::new_request_id(),
            intent::now_ms(),
            INTENT_LIFETIME_MS,
        );
        intent::sign_intent(&self.ctx.signer, &unsigned).map_err(|e| tonic::Status::internal(format!("client: {e}")))
    }

    /// One request, number `seq` of the run, through `client`. Recorded when it returns.
    async fn request(&self, client: &Client, seq: u64) {
        // Calls that fail over get the driver's per-attempt deadline and budget; a ceremony gets
        // one attempt with the whole timeout, as the driver gives it.
        let (limit, budget) = match self.op {
            Op::Sign { .. } => (self.ctx.sign_attempt, self.ctx.budget),
            _ if self.op.may_fail_over() => (self.ctx.attempt, self.ctx.budget),
            _ => (self.ctx.timeout, None),
        };
        let failover = self.failover && self.op.may_fail_over();
        let at = self.started.elapsed();
        let begun = Instant::now();
        // (the final answer as "what was wrong with an OK", how it travelled)
        let (answer, moves): (Result<Option<String>, tonic::Status>, Route) = match &self.op {
            Op::Sign { keys } => {
                // `keys` is not empty (clap: `--key` is required) and the index is reduced modulo its length.
                #[allow(clippy::indexing_slicing)]
                let (key_id, group) = &keys[(seq % keys.len() as u64) as usize];
                // Canton's sign payload: 0x1220 ‖ a SHA-256 digest (docs/wire-contract.md).
                let mut message = vec![0x12, 0x20];
                message.extend_from_slice(&random::<32>());
                let now = intent::now_ms();
                let unsigned = pb::SignIntent {
                    version: intent::INTENT_VERSION,
                    cluster_id: self.cluster_id.clone(),
                    purpose: intent::PURPOSE_SIGN.into(),
                    key_id: key_id.clone(),
                    digest: message.clone(),
                    request_id: intent::new_request_id().to_vec(),
                    issued_at_ms: now,
                    not_after_ms: now + INTENT_LIFETIME_MS,
                    approval_nonce: Vec::new(),
                    approvals: Vec::new(),
                    ..Default::default()
                };
                match intent::sign_intent(&self.ctx.signer, &unsigned) {
                    Err(e) => (Err(tonic::Status::internal(format!("client: {e}"))), Route::default()),
                    Ok(signed) => {
                        // One intent for the call: a failover presents the same one, as the
                        // driver does, so the cosigners charge it once.
                        let request =
                            pb::SignRequest { key_id: key_id.clone(), message: message.clone(), intent: Some(signed) };
                        let start = self.ctx.rotate_signs.then(|| client.sign_start());
                        let (answer, moves) = client
                            .call(failover, limit, budget, start, |mut c| {
                                let request = request.clone();
                                async move { c.sign(request).await }
                            })
                            .await;
                        (answer.map(|reply| check_signature(group, &message, &reply.signature)), moves)
                    }
                }
            }
            Op::Ecdh { key_id, peer_point, expected } => {
                let request = pb::EcdhDeriveRequest { key_id: key_id.clone(), peer_point: peer_point.clone() };
                let (answer, moves) = client
                    .call(failover, limit, budget, None, |mut c| {
                        let request = request.clone();
                        async move { c.ecdh_derive(request).await }
                    })
                    .await;
                let check = |reply: pb::EcdhDeriveReply| {
                    (reply.shared_secret != *expected).then(|| "the ECDH secret differs from the locally computed one".to_string())
                };
                (answer.map(check), moves)
            }
            Op::Dkg { prefix, same_key, first_key, retry_aborted } => {
                let key_id = if *same_key { prefix.clone() } else { format!("{prefix}-{seq}") };
                // The first group key any request learned for the contested key id: every later
                // answer, and every key an ALREADY_EXISTS points at, must be the same one.
                let same_as_first = |key: &[u8]| -> Option<String> {
                    if key.len() != 32 {
                        return Some(format!("a group key of {} bytes", key.len()));
                    }
                    if *same_key {
                        let mut first = first_key.lock().unwrap_or_else(|p| p.into_inner());
                        if first.get_or_insert_with(|| key.to_vec()).as_slice() != key {
                            return Some("two DKGs of one key id answered different group keys".to_string());
                        }
                    }
                    None
                };
                let mut attempt = 0u32;
                loop {
                    // A fresh ceremony intent per attempt: a ceremony id is used once per node.
                    let signed = match self.ceremony_intent(CeremonyKind::Dkg, &key_id) {
                        Ok(s) => s,
                        Err(status) => break (Err(status), Route::default()),
                    };
                    let request = pb::DkgRequest { key_id: key_id.clone(), intent: Some(signed) };
                    let (answer, moves) = client
                        .call(false, limit, budget, None, |mut c| {
                            let request = request.clone();
                            async move { c.dkg(request).await }
                        })
                        .await;
                    match answer {
                        Err(s) if attempt < *retry_aborted && contended(&s) => {
                            attempt += 1;
                            tokio::time::sleep(backoff(attempt)).await;
                        }
                        Err(s) if s.code() == tonic::Code::AlreadyExists && *same_key => {
                            // Another request generated it: the key it points at must be the one
                            // the winners answered.
                            let at = moves.leader.unwrap_or(0);
                            let wrong = match client.conns.get(at).cloned() {
                                None => Some(format!("GroupKey after ALREADY_EXISTS: no connection {at}")),
                                Some(mut c) => {
                                    let req = pb::GroupKeyRequest { key_id: key_id.clone() };
                                    match bounded(limit, c.group_key(req)).await {
                                        Ok(reply) => same_as_first(&reply.group_verifying_key),
                                        Err(e) => Some(format!("GroupKey after ALREADY_EXISTS: {}: {}", code_name(e.code()), e.message())),
                                    }
                                }
                            };
                            match wrong {
                                None => break (Err(s), moves),
                                Some(w) => break (Ok(Some(w)), moves),
                            }
                        }
                        answer => break (answer.map(|reply| same_as_first(&reply.group_verifying_key)), moves),
                    }
                }
            }
            Op::Refresh { key_id, group_key } => match self.ceremony_intent(CeremonyKind::Refresh, key_id) {
                Err(status) => (Err(status), Route::default()),
                Ok(signed) => {
                    let request = pb::RefreshRequest { key_id: key_id.clone(), intent: Some(signed) };
                    let (answer, moves) = client
                        .call(false, limit, budget, None, |mut c| {
                            let request = request.clone();
                            async move { c.refresh(request).await }
                        })
                        .await;
                    let check = |reply: pb::RefreshReply| {
                        (reply.group_verifying_key != *group_key).then(|| "the refresh changed the group key".to_string())
                    };
                    (answer.map(check), moves)
                }
            },
        };
        let latency = begun.elapsed();
        let (code, bad_answer, message) = match answer {
            Ok(None) => ("OK", false, None),
            Ok(Some(wrong)) => ("OK", true, Some(wrong)),
            Err(status) => (code_name(status.code()), false, Some(status.message().to_string())),
        };
        let leader = moves.leader.and_then(|i| self.ctx.targets.get(i)).map(|t| t.0.clone());
        let outcome = Outcome { at, latency, code, failovers: moves.failovers, bad_answer, leader };
        self.recorder.lock().unwrap_or_else(|p| p.into_inner()).record(outcome, message);
    }
}

fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
    bytes
}

/// `None` if `signature` is a valid Ed25519 signature of `message` under `group`, else why not.
fn check_signature(group: &ed25519_dalek::VerifyingKey, message: &[u8], signature: &[u8]) -> Option<String> {
    let Ok(sig) = ed25519_dalek::Signature::from_slice(signature) else {
        return Some(format!("a signature of {} bytes", signature.len()));
    };
    group.verify_strict(message, &sig).err().map(|e| format!("the signature does not verify: {e}"))
}

/// Generate the load of `load` and return the client's side of the report.
async fn generate(run: Arc<Run>, load: &Load) -> Result<stats::ClientReport, Fail> {
    if load.duration_secs == 0 && load.count == 0 {
        return Err("give --duration-secs or --count (or both)".into());
    }
    if load.clients == 0 {
        return Err("--clients must be at least 1".into());
    }
    let ctx = &run.ctx;
    let prefer = load.prefer.as_deref().map(|name| ctx.index_of(name)).transpose()?;
    let mut clients = Vec::with_capacity(load.clients);
    for i in 0..load.clients {
        clients.push(Arc::new(Client::new(ctx.connect_all()?, prefer.unwrap_or(i % ctx.targets.len()))));
    }
    let mut connect_report = None;
    if load.eager_connect {
        // Every client's first cosigner, connected at the same moment.
        let mut tasks = tokio::task::JoinSet::new();
        for (i, client) in clients.iter_mut().enumerate() {
            let first = client.leader.load(Ordering::Relaxed);
            let ctx = run.ctx.clone();
            tasks.spawn(async move { (i, first, ctx.connect_now(first).await) });
        }
        let mut micros = Vec::new();
        let mut errors: BTreeMap<String, u64> = BTreeMap::new();
        let mut sample = None;
        let mut connected: Vec<(usize, usize, SignerClient<Channel>)> = Vec::new();
        while let Some(joined) = tasks.join_next().await {
            let (i, first, (result, took)) = joined?;
            match result {
                Ok(conn) => {
                    micros.push(took.as_micros() as u64);
                    connected.push((i, first, conn));
                }
                Err(e) => {
                    let kind = if took >= run.ctx.timeout { "timeout" } else { "error" };
                    *errors.entry(kind.to_string()).or_default() += 1;
                    sample.get_or_insert(e);
                }
            }
        }
        for (i, first, conn) in connected {
            let client = clients.get_mut(i).and_then(Arc::get_mut).expect("one client per index, not shared yet");
            if let Some(slot) = client.conns.get_mut(first) {
                *slot = conn;
            }
        }
        connect_report = Some(stats::ConnectReport { latency: stats::latency_of(&mut micros), errors, error_sample: sample });
    }
    let deadline = (load.duration_secs > 0).then(|| Duration::from_secs(load.duration_secs));
    let count = load.count;
    let over = move |started: Instant, seq: u64| {
        (count > 0 && seq >= count) || deadline.is_some_and(|d| started.elapsed() >= d)
    };
    let started = run.started;
    // This process's open descriptors, sampled while the load runs (Linux /proc).
    let fd_peak = Arc::new(AtomicU64::new(0));
    let sampler = {
        let peak = fd_peak.clone();
        tokio::spawn(async move {
            loop {
                if let Some(n) = open_fds() {
                    peak.fetch_max(n, Ordering::Relaxed);
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        })
    };

    if load.rate > 0.0 {
        // Open loop: a request starts every 1/rate seconds, answered or not.
        let mut tick = tokio::time::interval(Duration::from_secs_f64(1.0 / load.rate));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Burst);
        let in_flight = Arc::new(tokio::sync::Semaphore::new(load.max_in_flight.max(1)));
        let mut tasks = tokio::task::JoinSet::new();
        let mut seq = 0u64;
        loop {
            tick.tick().await;
            if over(started, seq) {
                break;
            }
            match in_flight.clone().try_acquire_owned() {
                Ok(permit) => {
                    // `clients` has `--clients` >= 1 entries (checked above); the index is reduced modulo its length.
                    #[allow(clippy::indexing_slicing)]
                    let (run, client) = (run.clone(), clients[(seq % clients.len() as u64) as usize].clone());
                    tasks.spawn(async move {
                        run.request(&client, seq).await;
                        drop(permit);
                    });
                }
                Err(_) => run.recorder.lock().unwrap_or_else(|p| p.into_inner()).saturated(),
            }
            seq += 1;
            while tasks.try_join_next().is_some() {}
        }
        while tasks.join_next().await.is_some() {}
    } else {
        // Closed loop: every client sends its next request when the last one is answered.
        let next = Arc::new(AtomicU64::new(0));
        let mut tasks = tokio::task::JoinSet::new();
        for client in clients {
            let (run, next) = (run.clone(), next.clone());
            tasks.spawn(async move {
                loop {
                    let seq = next.fetch_add(1, Ordering::Relaxed);
                    if over(started, seq) {
                        break;
                    }
                    run.request(&client, seq).await;
                }
            });
        }
        while tasks.join_next().await.is_some() {}
    }

    let wall = started.elapsed();
    let recorder = std::mem::take(&mut *run.recorder.lock().unwrap_or_else(|p| p.into_inner()));
    let mut report = recorder.report(wall);
    report.connect = connect_report;
    sampler.abort();
    if let Some(n) = open_fds() {
        fd_peak.fetch_max(n, Ordering::Relaxed);
    }
    report.fd_peak = Some(fd_peak.load(Ordering::Relaxed)).filter(|n| *n > 0);
    report.fd_limit = fd_soft_limit();
    Ok(report)
}

/// How many file descriptors this process holds now (Linux; None elsewhere).
fn open_fds() -> Option<u64> {
    std::fs::read_dir("/proc/self/fd").ok().map(|d| d.count() as u64)
}

/// This process's soft limit on open files, from /proc/self/limits (Linux; None elsewhere).
fn fd_soft_limit() -> Option<u64> {
    let text = std::fs::read_to_string("/proc/self/limits").ok()?;
    text.lines()
        .find(|l| l.starts_with("Max open files"))
        .and_then(|l| l.split_whitespace().nth(3))
        .and_then(|v| v.parse().ok())
}

/// Every metrics page, by target name; and the scrapes that failed, in words.
async fn scrape(ctx: &Ctx) -> (BTreeMap<String, prom::Scrape>, Vec<String>) {
    let (mut pages, mut errors) = (BTreeMap::new(), Vec::new());
    for (name, url) in &ctx.metrics {
        match prom::fetch(url, Duration::from_secs(5)).await {
            Ok(text) => {
                pages.insert(name.clone(), prom::parse(&text));
            }
            Err(e) => errors.push(format!("{name}: {e}")),
        }
    }
    (pages, errors)
}

/// Health of every cosigner, by name: `true` only for an `ok` answer within five seconds.
async fn health(ctx: &Ctx) -> BTreeMap<String, bool> {
    let mut out = BTreeMap::new();
    for (i, (name, _)) in ctx.targets.iter().enumerate() {
        let ok = match ctx.connect(i) {
            Ok(mut c) => bounded(Duration::from_secs(5), c.health(pb::HealthRequest {})).await.is_ok_and(|h| h.ok),
            Err(_) => false,
        };
        out.insert(name.clone(), ok);
    }
    out
}

/// Wait until every cosigner answers Health ok; how long that took.
async fn wait_healthy(ctx: &Ctx, within: Duration) -> Result<Duration, Fail> {
    let started = Instant::now();
    loop {
        let state = health(ctx).await;
        if state.values().all(|ok| *ok) {
            return Ok(started.elapsed());
        }
        if started.elapsed() >= within {
            let down: Vec<&String> = state.iter().filter(|(_, ok)| !**ok).map(|(n, _)| n).collect();
            return Err(format!("not healthy after {} s: {down:?}", within.as_secs()).into());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// The cluster id the intents must name: what the cosigners report, by the driver's rule (at
/// least two agree, and more report it than any other value).
async fn cluster_id(ctx: &Ctx) -> Result<String, Fail> {
    let mut answers = Vec::new();
    for i in 0..ctx.targets.len() {
        if let Ok(reply) = bounded(ctx.timeout, ctx.connect(i)?.capabilities(pb::CapabilitiesRequest {})).await {
            answers.push(reply.cluster_id);
        }
    }
    intent::agree_on_cluster_id(&answers, ctx.targets.len())
        .ok_or_else(|| format!("the cosigners do not agree on a cluster id (answers: {answers:?})").into())
}

/// The group key of FROST key `key_id`, as the first cosigner that answers reports it.
async fn group_key(ctx: &Ctx, key_id: &str) -> Result<Vec<u8>, tonic::Status> {
    let mut last = tonic::Status::unavailable("no cosigner configured");
    for i in 0..ctx.targets.len() {
        let Ok(mut c) = ctx.connect(i) else { continue };
        match bounded(ctx.timeout, c.group_key(pb::GroupKeyRequest { key_id: key_id.to_string() })).await {
            Ok(reply) => return Ok(reply.group_verifying_key),
            Err(status) if not_serving(&status) => last = status,
            Err(status) => return Err(status),
        }
    }
    Err(last)
}

/// The same through `KeyStatus`, which the refresher role may call (it may not call `GroupKey`).
async fn status_group_key(ctx: &Ctx, key_id: &str) -> Result<Vec<u8>, tonic::Status> {
    let mut last = tonic::Status::unavailable("no cosigner configured");
    for i in 0..ctx.targets.len() {
        let Ok(mut c) = ctx.connect(i) else { continue };
        match bounded(ctx.timeout, c.key_status(pb::KeyStatusRequest { key_id: key_id.to_string() })).await {
            Ok(reply) => return Ok(reply.group_verifying_key),
            Err(status) if not_serving(&status) => last = status,
            Err(status) => return Err(status),
        }
    }
    Err(last)
}

fn verifying_key(key_id: &str, bytes: &[u8]) -> Result<ed25519_dalek::VerifyingKey, Fail> {
    let raw: [u8; 32] = bytes.try_into().map_err(|_| format!("{key_id}: a group key of {} bytes", bytes.len()))?;
    Ok(ed25519_dalek::VerifyingKey::from_bytes(&raw).map_err(|e| format!("{key_id}: not an Ed25519 key: {e}"))?)
}

#[derive(Serialize)]
struct LoadReport {
    command: &'static str,
    name: String,
    started_at_ms: u64,
    cluster_id: String,
    /// The load as asked for.
    duration_secs: u64,
    count: u64,
    rate: f64,
    clients: usize,
    failover: bool,
    /// The client's deadline policy for calls that fail over (seconds; budget null: none).
    sign_attempt_timeout_secs: f64,
    attempt_timeout_secs: f64,
    request_timeout_secs: Option<f64>,
    client: stats::ClientReport,
    server: prom::ServerReport,
    /// Health of every cosigner right after the run.
    health: BTreeMap<String, bool>,
}

/// Scrape, generate, scrape, probe: one load command from start to report.
async fn load_command(ctx: Arc<Ctx>, command: &'static str, op: Op, cluster: String, load: Load) -> Result<LoadReport, Fail> {
    for name in &load.restarted {
        if !ctx.metrics.iter().any(|(n, _)| n == name) {
            return Err(format!("--restarted {name:?} is not a --metrics name").into());
        }
    }
    let started_at_ms = intent::now_ms();
    let (before, mut scrape_errors) = scrape(&ctx).await;
    let failover = !load.no_failover && op.may_fail_over();
    let run = Arc::new(Run {
        ctx: ctx.clone(),
        cluster_id: cluster.clone(),
        op,
        failover: !load.no_failover,
        started: Instant::now(),
        recorder: Mutex::new(Recorder::default()),
    });
    let client = generate(run, &load).await?;
    eprintln!(
        "{command} {}: {} requests, {} ok, errors {:?}, p50 {} ms, p99 {} ms",
        load.name, client.requests, client.ok, client.errors, client.latency.p50_ms, client.latency.p99_ms
    );
    let (after, after_errors) = scrape(&ctx).await;
    scrape_errors.extend(after_errors);
    let names: Vec<String> = ctx.metrics.iter().map(|(n, _)| n.clone()).collect();
    let server = prom::report(&before, &after, &names, &load.restarted, scrape_errors);
    Ok(LoadReport {
        command,
        name: load.name.clone(),
        started_at_ms,
        cluster_id: cluster,
        duration_secs: load.duration_secs,
        count: load.count,
        rate: load.rate,
        clients: load.clients,
        failover,
        sign_attempt_timeout_secs: ctx.sign_attempt.as_secs_f64(),
        attempt_timeout_secs: ctx.attempt.as_secs_f64(),
        request_timeout_secs: ctx.budget.map(|b| b.as_secs_f64()),
        client,
        server,
        health: health(&ctx).await,
    })
}

#[derive(Serialize)]
struct SetupReport {
    command: &'static str,
    cluster_id: String,
    /// FROST key id -> group key (hex), and whether this run generated it.
    frost_keys: BTreeMap<String, SetupKey>,
    /// Hosted ECIES key id -> SubjectPublicKeyInfo (hex), and whether this run generated it.
    ecies_keys: BTreeMap<String, SetupKey>,
}

#[derive(Serialize)]
struct SetupKey {
    public_key: String,
    created: bool,
}

async fn setup(ctx: &Ctx, frost_keys: &[String], ecies_keys: &[String]) -> Result<SetupReport, Fail> {
    let cluster = cluster_id(ctx).await?;
    let mut leader = ctx.connect(0)?;
    let mut report =
        SetupReport { command: "setup", cluster_id: cluster.clone(), frost_keys: BTreeMap::new(), ecies_keys: BTreeMap::new() };
    for key_id in frost_keys {
        let (key, created) = match group_key(ctx, key_id).await {
            Ok(key) => (key, false),
            Err(status) if status.code() == tonic::Code::NotFound => {
                let unsigned = intent::ceremony_intent(
                    &cluster,
                    CeremonyKind::Dkg,
                    key_id,
                    intent::new_request_id(),
                    intent::now_ms(),
                    INTENT_LIFETIME_MS,
                );
                let request =
                    pb::DkgRequest { key_id: key_id.clone(), intent: Some(intent::sign_intent(&ctx.signer, &unsigned)?) };
                let reply = bounded(Duration::from_secs(120), leader.dkg(request))
                    .await
                    .map_err(|s| format!("DKG of {key_id}: {:?}: {}", s.code(), s.message()))?;
                (reply.group_verifying_key, true)
            }
            Err(status) => return Err(format!("GroupKey of {key_id}: {:?}: {}", status.code(), status.message()).into()),
        };
        verifying_key(key_id, &key)?;
        eprintln!("setup: FROST key {key_id} {}", if created { "generated" } else { "exists" });
        report.frost_keys.insert(key_id.clone(), SetupKey { public_key: hex::encode(key), created });
    }
    // A hosted key is created under a generate intent naming the cosigner asked to lead (by its
    // roster identifier, from Capabilities) and the spec. A cosigner of a release before generate
    // intents reports identifier 0 and gets none: the cluster suite generates keys on the previous
    // release before it upgrades.
    let leader_id = if ecies_keys.is_empty() {
        0
    } else {
        bounded(ctx.timeout, leader.capabilities(pb::CapabilitiesRequest {}))
            .await
            .map_err(|s| format!("Capabilities: {:?}: {}", s.code(), s.message()))?
            .node_identifier
    };
    // Paced: a cosigner accepts a bounded rate of pushes to its peers (a hosted-key generation
    // costs one at each), and answers UNAVAILABLE past it. Such an answer is retried for that key
    // after a pause, a few times, instead of failing the setup. Every attempt carries a freshly
    // signed intent: each node spends an intent's request id at its fence, so a retry with the
    // first attempt's intent would be refused there.
    const GENERATIONS_PER_SEC: f64 = 10.0;
    for key_id in ecies_keys {
        let mut attempt = 0;
        let reply = loop {
            let intent = match leader_id {
                0 => None,
                id => {
                    let id = u16::try_from(id)
                        .map_err(|_| format!("GenerateKey of {key_id}: roster identifier {id} out of range"))?;
                    let unsigned = intent::generate_intent(
                        &cluster,
                        key_id,
                        ECIES_SPEC,
                        id,
                        intent::new_request_id(),
                        intent::now_ms(),
                        INTENT_LIFETIME_MS,
                    );
                    Some(intent::sign_intent(&ctx.signer, &unsigned)?)
                }
            };
            let request = pb::GenerateKeyRequest { key_id: key_id.clone(), spec: ECIES_SPEC.into(), intent };
            tokio::time::sleep(Duration::from_secs_f64(1.0 / GENERATIONS_PER_SEC)).await;
            match bounded(ctx.timeout, leader.generate_key(request)).await {
                Err(s) if s.code() == tonic::Code::Unavailable && attempt < 5 => {
                    attempt += 1;
                    eprintln!("setup: hosted key {key_id}: UNAVAILABLE ({}), retrying in {} s", s.message(), 2 * attempt);
                    tokio::time::sleep(Duration::from_secs(2 * attempt)).await;
                }
                answer => break answer,
            }
        }
        .map_err(|s| format!("GenerateKey of {key_id}: {:?}: {}", s.code(), s.message()))?;
        eprintln!("setup: hosted key {key_id} {} ({} replicas)", if reply.created { "generated" } else { "exists" }, reply.replicas);
        report
            .ecies_keys
            .insert(key_id.clone(), SetupKey { public_key: hex::encode(reply.public_key_der), created: reply.created });
    }
    Ok(report)
}

/// An ECDH request for hosted key `key_id` and the secret the cluster must answer: a fresh
/// ephemeral key pair on our side, agreed locally with the hosted public key.
async fn ecdh_op(ctx: &Ctx, key_id: &str) -> Result<Op, Fail> {
    use aws_lc_rs::agreement::{agree_ephemeral, EphemeralPrivateKey, UnparsedPublicKey, ECDH_P256};
    let reply = bounded(ctx.timeout, ctx.connect(0)?.public_key(pb::PublicKeyRequest { key_id: key_id.to_string() }))
        .await
        .map_err(|s| format!("PublicKey of {key_id}: {:?}: {}", s.code(), s.message()))?;
    if reply.spec != ECIES_SPEC {
        return Err(format!("{key_id} is a {:?} key, not {ECIES_SPEC}", reply.spec).into());
    }
    // A P-256 SubjectPublicKeyInfo ends with the 65-byte uncompressed point.
    let spki = reply.public_key_der;
    let hosted_point = spki
        .len()
        .checked_sub(65)
        .and_then(|at| spki.get(at..))
        .filter(|point| point.first() == Some(&0x04))
        .ok_or_else(|| format!("{key_id}: unexpected public key encoding ({} bytes)", spki.len()))?;
    let rng = aws_lc_rs::rand::SystemRandom::new();
    let ours = EphemeralPrivateKey::generate(&ECDH_P256, &rng).map_err(|_| "P-256 key generation failed")?;
    let peer_point = ours.compute_public_key().map_err(|_| "P-256 public key failed")?.as_ref().to_vec();
    let expected = agree_ephemeral(ours, UnparsedPublicKey::new(&ECDH_P256, hosted_point), "local ECDH failed", |z| {
        Ok(z.to_vec())
    })?;
    Ok(Op::Ecdh { key_id: key_id.to_string(), peer_point, expected })
}

fn print_json(report: &impl Serialize) -> Result<(), Fail> {
    println!("{}", serde_json::to_string_pretty(report)?);
    Ok(())
}

async fn run(cli: Cli) -> Result<(), Fail> {
    let ctx = Arc::new(Ctx::new(&cli)?);
    let ca = cli.ca.clone();
    match cli.command {
        Command::Wait { within_secs } => {
            let took = wait_healthy(&ctx, Duration::from_secs(within_secs)).await?;
            print_json(&serde_json::json!({ "command": "wait", "healthy_after_secs": (took.as_secs_f64() * 10.0).round() / 10.0 }))
        }
        Command::Setup { frost_keys, ecies_keys } => print_json(&setup(&ctx, &frost_keys, &ecies_keys).await?),
        Command::Sign { keys, load } => {
            let cluster = cluster_id(&ctx).await?;
            let mut with_group = Vec::new();
            for key_id in keys {
                let group = group_key(&ctx, &key_id)
                    .await
                    .map_err(|s| format!("GroupKey of {key_id}: {:?}: {}", s.code(), s.message()))?;
                with_group.push((key_id.clone(), verifying_key(&key_id, &group)?));
            }
            print_json(&load_command(ctx, "sign", Op::Sign { keys: with_group }, cluster, load).await?)
        }
        Command::Ecdh { key, load } => {
            let cluster = cluster_id(&ctx).await?;
            let op = ecdh_op(&ctx, &key).await?;
            print_json(&load_command(ctx, "ecdh", op, cluster, load).await?)
        }
        Command::Dkg { prefix, same_key, retry_aborted, load } => {
            let cluster = cluster_id(&ctx).await?;
            print_json(&load_command(ctx, "dkg", Op::Dkg { prefix, same_key, first_key: Mutex::new(None), retry_aborted }, cluster, load).await?)
        }
        Command::ListKeys { repeat, peer_cert, peer_key } => {
            print_json(&list_keys(&ctx, &peer_cert, &peer_key, repeat, &ca).await?)
        }
        Command::Refresh { key, load } => {
            let cluster = cluster_id(&ctx).await?;
            // KeyStatus, not GroupKey: a refresh runs with the refresher's certificate, as the
            // refresh job does, and that role may read a key's status but not call the Signer API.
            let group = status_group_key(&ctx, &key)
                .await
                .map_err(|s| format!("KeyStatus of {key}: {:?}: {}", s.code(), s.message()))?;
            print_json(&load_command(ctx, "refresh", Op::Refresh { key_id: key, group_key: group }, cluster, load).await?)
        }
    }
}

#[derive(Serialize)]
struct ListKeysReport {
    command: &'static str,
    /// cosigner -> what it answered and how long it took.
    targets: BTreeMap<String, ListKeysTarget>,
}

#[derive(Serialize, Default)]
struct ListKeysTarget {
    /// Entries in its inventory (live keys and tombstones), from the last call.
    keys: usize,
    calls: u32,
    errors: u32,
    /// Of the successful calls.
    mean_ms: f64,
    max_ms: f64,
    error_sample: Option<String>,
}

/// Peer.ListKeys on every cosigner, `repeat` times each, as a cosigner (`peer_cert`) would call it.
async fn list_keys(ctx: &Ctx, cert: &PathBuf, key: &PathBuf, repeat: u32, ca: &PathBuf) -> Result<ListKeysReport, Fail> {
    use rutli_cosigner::pb::peer_client::PeerClient;
    let read = |p: &PathBuf| std::fs::read(p).map_err(|e| format!("cannot read {}: {e}", p.display()));
    let tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(read(ca)?))
        .identity(Identity::from_pem(read(cert)?, read(key)?));
    let mut out = ListKeysReport { command: "list-keys", targets: BTreeMap::new() };
    for (name, url) in &ctx.targets {
        let endpoint = Endpoint::from_shared(url.clone())
            .map_err(|e| format!("bad endpoint {url}: {e}"))?
            .connect_timeout(Duration::from_secs(5))
            .tls_config(tls.clone().domain_name(name.clone()))?;
        let mut client = PeerClient::new(endpoint.connect_lazy());
        let mut t = ListKeysTarget::default();
        let mut total = Duration::ZERO;
        for _ in 0..repeat.max(1) {
            t.calls += 1;
            let begun = Instant::now();
            match bounded(ctx.timeout, client.list_keys(pb::ListKeysRequest {})).await {
                Ok(reply) => {
                    let took = begun.elapsed();
                    total += took;
                    t.keys = reply.keys.len();
                    t.max_ms = t.max_ms.max(took.as_secs_f64() * 1000.0);
                }
                Err(status) => {
                    t.errors += 1;
                    t.error_sample.get_or_insert_with(|| format!("{}: {}", code_name(status.code()), status.message()));
                }
            }
        }
        let ok = t.calls - t.errors;
        if ok > 0 {
            t.mean_ms = (total.as_secs_f64() * 1000.0 / ok as f64 * 1000.0).round() / 1000.0;
        }
        t.max_ms = (t.max_ms * 1000.0).round() / 1000.0;
        out.targets.insert(name.clone(), t);
    }
    Ok(out)
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli).await {
        eprintln!("rutli-loadgen: {e}");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_value_pairs() {
        assert_eq!(
            name_value("cosigner1=https://cosigner1:9101").unwrap(),
            ("cosigner1".to_string(), "https://cosigner1:9101".to_string())
        );
        // Only the first `=` separates: a URL may contain more.
        assert_eq!(name_value("a=http://h/m?x=1").unwrap().1, "http://h/m?x=1");
        assert!(name_value("https://cosigner1:9101").is_err());
        assert!(name_value("=url").is_err());
        assert!(name_value("name=").is_err());
    }

    #[test]
    fn attempts_follow_the_drivers_deadline_policy() {
        let s = Duration::from_secs;
        // No budget: every attempt gets the full attempt deadline.
        assert_eq!(attempt_deadline(s(5), None, s(100), 2), Some(s(5)));
        // 30 s budget: 5 s attempts until less than 5 s is left, then what is left.
        assert_eq!(attempt_deadline(s(5), Some(s(30)), s(0), 0), Some(s(5)));
        assert_eq!(attempt_deadline(s(5), Some(s(30)), s(27), 2), Some(s(3)));
        // Spent (under 50 ms left) after an attempt: no further attempt.
        assert_eq!(attempt_deadline(s(5), Some(s(30)), Duration::from_millis(29_960), 1), None);
        assert_eq!(attempt_deadline(s(5), Some(s(30)), s(31), 1), None);
        // The first attempt always runs, even on a spent budget (with what is left: nothing).
        assert_eq!(attempt_deadline(s(5), Some(s(30)), s(31), 0), Some(Duration::ZERO));
        assert!(positive_secs(Some(0.0), "--x").is_err());
        assert!(positive_secs(Some(-1.0), "--x").is_err());
        assert_eq!(positive_secs(Some(0.5), "--x").unwrap(), Some(Duration::from_millis(500)));
        assert_eq!(positive_secs(None, "--x").unwrap(), None);
    }

    #[tokio::test]
    async fn rotated_signs_skip_a_demoted_cosigner_and_never_move_the_sticky_leader() {
        let conns: Vec<SignerClient<Channel>> = (0..3)
            .map(|_| SignerClient::new(Endpoint::from_static("http://127.0.0.1:1").connect_lazy()))
            .collect();
        let c = Client::new(conns, 0);
        assert_eq!((0..6).map(|_| c.sign_start()).collect::<Vec<_>>(), vec![0, 1, 2, 0, 1, 2]);
        assert_eq!(c.leader.load(Ordering::Relaxed), 0);
        // Node 1 failed: skipped as a start, and the sticky leader (0) stays.
        c.demote(1);
        assert_eq!((0..6).map(|_| c.sign_start()).collect::<Vec<_>>(), vec![0, 2, 2, 0, 2, 2]);
        assert_eq!(c.leader.load(Ordering::Relaxed), 0);
        // The leader failed: the sticky leader moves on (compare-and-set: 0 -> 1); demoting 2,
        // not the leader, leaves it. With every node demoted a signature starts at the sticky leader.
        c.demote(0);
        c.demote(2);
        assert_eq!(c.leader.load(Ordering::Relaxed), 1);
        assert!((0..3).all(|_| c.sign_start() == 1));
    }

    #[test]
    fn contended_ceremonies_are_retried_with_jittered_backoff() {
        assert!(contended(&tonic::Status::aborted("a dkg ceremony (id dkg-x) is already in progress")));
        assert!(contended(&tonic::Status::internal("rpc status: Aborted, message: \"a dkg ceremony … is already in progress\"")));
        assert!(!contended(&tonic::Status::internal("something else")));
        assert!(!contended(&tonic::Status::already_exists("key exists")));
        assert!(contended(&tonic::Status::unavailable("not serving: a ceremony for k (dkg-x) is staged and still resolving — retry shortly")));
        for (attempt, full) in [(1, 0.5), (2, 1.0), (3, 2.0), (4, 4.0), (9, 4.0)] {
            let b = backoff(attempt).as_secs_f64();
            assert!(b >= full / 2.0 - 1e-9 && b <= full + 1e-9, "attempt {attempt}: {b}");
        }
    }

    #[test]
    fn only_a_cosigner_that_does_not_serve_is_failed_over() {
        assert!(not_serving(&tonic::Status::unavailable("could not reach signing threshold")));
        assert!(not_serving(&tonic::Status::deadline_exceeded("slow")));
        // Real answers of a live node: the next cosigner would say the same.
        for refusal in [
            tonic::Status::resource_exhausted("rate limit"),
            tonic::Status::permission_denied("signing intent refused"),
            tonic::Status::not_found("unknown key"),
            tonic::Status::internal("a bug"),
            tonic::Status::unknown("no transport error behind it"),
        ] {
            assert!(!not_serving(&refusal), "{refusal:?}");
        }
    }

    #[test]
    fn a_signature_is_checked_strictly() {
        use ed25519_dalek::Signer;
        let key = ed25519_dalek::SigningKey::from_bytes(&random::<32>());
        let message = [0x12u8, 0x20, 7, 7, 7];
        let sig = key.sign(&message).to_bytes();
        assert_eq!(check_signature(&key.verifying_key(), &message, &sig), None);
        assert!(check_signature(&key.verifying_key(), b"another message", &sig).is_some());
        assert!(check_signature(&key.verifying_key(), &message, &sig[..63]).is_some());
    }
}
