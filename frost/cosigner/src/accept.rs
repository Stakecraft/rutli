// Copyright 2026 StakeCraft LLC
// SPDX-License-Identifier: Apache-2.0

//! The gRPC server's accept loop.
//!
//! tonic's own listener (`Server::serve_with_shutdown(addr, ..)`) retries only a fixed list of
//! accept errors; anything else, running out of file descriptors (`EMFILE`) among them, ends its
//! incoming stream, and the server then returns `Ok(())` as if it had been shut down. The same list
//! decides what a failed TLS handshake does. This module feeds tonic its connections instead:
//!
//! - [`incoming`] accepts in its own task and never ends on an error: a transient one is retried
//!   at once, anything else (descriptor exhaustion) after a short backoff, with a warning and
//!   `rutli_grpc_accept_errors_total` (alert `RutliGrpcAcceptErrors`).
//! - At most [`connection_limit`] connections are open at a time; past it, new ones wait in the
//!   kernel's listen backlog until one closes, so accepted connections cannot use up the descriptors
//!   the key store and the peer channels need (`rutli_grpc_connections`,
//!   `rutli_grpc_connection_limit`).
//! - [`Conn`] gives each connection [`HANDSHAKE_TIMEOUT`] from accept to finish its TLS handshake
//!   (without TLS: to send its first bytes), and turns a handshake I/O error into one tonic
//!   retries, so one bad handshake never ends the server.
//!
//! What this does not do: a client that opens connections faster than the deadline frees them can
//! still keep new connections waiting (no longer stop the server); network policy in front of the
//! gRPC port is what limits who can try. Per-connection stream and message limits are separate.
//!
//! The daemon also treats a server that returns without a shutdown request as an error (see
//! `serve` in `main.rs`).

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tokio::time::Sleep;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::server::Connected;

/// Time a connection has from accept to get going (see [`Deadline`]). A client that has not got
/// that far is disconnected, and its descriptor and connection slot are free again. Mutual TLS
/// between cosigners and the driver takes milliseconds.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// How long a new connection has to get going, and what counts as going.
#[derive(Debug, Clone, Copy)]
pub struct Deadline {
    pub timeout: Duration,
    /// With TLS the deadline ends when the handshake is done (tonic takes the connection). The
    /// first HTTP/2 bytes cannot be told apart below rustls, which may already hold them from the
    /// handshake's last read, so a client that holds a valid certificate is not timed beyond that.
    /// Without TLS it ends with the first bytes read after tonic took the connection.
    pub tls: bool,
}

impl Deadline {
    pub fn new(timeout: Duration, tls: bool) -> Self {
        Self { timeout, tls }
    }
}
/// The most connections served at once, however high the descriptor limit.
pub const MAX_CONNECTIONS: usize = 4096;
/// The listen backlog the gRPC socket asks for: connections the kernel completes before the accept
/// loop takes them. `TcpListener::bind` asks for 128, which a burst of new clients (every driver
/// reconnecting after a restart) overflows; the kernel then drops their SYNs and each client waits
/// out its SYN retransmissions (1 s, 3 s, ...) before it is even connected. The kernel caps the
/// value at `net.core.somaxconn` (4096 by default since Linux 5.4).
pub const LISTEN_BACKLOG: u32 = 4096;
/// Descriptors kept back from the connection cap for key files, journal segments, the instance
/// lock, outbound peer channels and the metrics listener; under a low limit, half of it is kept.
pub const FD_RESERVE: u64 = 256;

const BACKOFF_MIN: Duration = Duration::from_millis(50);
const BACKOFF_MAX: Duration = Duration::from_secs(1);
/// At most one warning per this interval for repeated accept errors or a full connection cap.
const WARN_EVERY: Duration = Duration::from_secs(10);

/// The connection cap for a soft descriptor limit: the limit less [`FD_RESERVE`]; under a limit
/// below twice the reserve, half of it, so half stays for everything else; at most
/// [`MAX_CONNECTIONS`] (1024 gives 768, 128 gives 64, 64 gives 32).
pub fn connection_limit(fd_soft_limit: u64) -> usize {
    let cap = fd_soft_limit
        .saturating_sub(FD_RESERVE)
        .max(fd_soft_limit / 2)
        .max(1);
    usize::try_from(cap)
        .unwrap_or(usize::MAX)
        .min(MAX_CONNECTIONS)
}

/// Bind the gRPC listener on `addr` with a listen backlog of `backlog` (see [`LISTEN_BACKLOG`]),
/// with `SO_REUSEADDR` set as `TcpListener::bind` sets it on Unix.
pub fn bind(addr: std::net::SocketAddr, backlog: u32) -> io::Result<tokio::net::TcpListener> {
    let socket = if addr.is_ipv4() {
        tokio::net::TcpSocket::new_v4()?
    } else {
        tokio::net::TcpSocket::new_v6()?
    };
    #[cfg(unix)]
    socket.set_reuseaddr(true)?;
    socket.bind(addr)?;
    socket.listen(backlog)
}

/// A source of accepted connections ([`tokio::net::TcpListener`], or a fake in tests).
pub trait Listener: Send + 'static {
    type Io: Send + 'static;
    fn accept(&self) -> impl Future<Output = io::Result<Self::Io>> + Send;
}

impl Listener for tokio::net::TcpListener {
    type Io = tokio::net::TcpStream;
    async fn accept(&self) -> io::Result<tokio::net::TcpStream> {
        let (stream, _) = tokio::net::TcpListener::accept(self).await?;
        // What tonic's own listener does under `Server::builder()`.
        let _ = stream.set_nodelay(true);
        Ok(stream)
    }
}

/// Start accepting on `listener`, at most `limit` connections at a time. The stream never yields an
/// error and never ends while the server polls it; the accept task stops once the stream is dropped.
pub fn incoming<L: Listener>(
    listener: L,
    limit: usize,
    deadline: Deadline,
) -> ReceiverStream<io::Result<Conn<L::Io>>> {
    let (tx, rx) = mpsc::channel(1);
    metrics::gauge!(crate::metrics::GRPC_CONNECTION_LIMIT).set(limit as f64);
    tokio::spawn(accept_loop(
        listener,
        Arc::new(Semaphore::new(limit)),
        limit,
        tx,
        deadline,
    ));
    ReceiverStream::new(rx)
}

async fn accept_loop<L: Listener>(
    listener: L,
    slots: Arc<Semaphore>,
    limit: usize,
    tx: mpsc::Sender<io::Result<Conn<L::Io>>>,
    deadline: Deadline,
) {
    let mut backoff = BACKOFF_MIN;
    let mut full = Throttle::default();
    let mut failing = Throttle::default();
    loop {
        let slot = if let Ok(slot) = Arc::clone(&slots).try_acquire_owned() {
            slot
        } else {
            if let Some(waited) = full.due() {
                tracing::warn!(
                    limit,
                    times = waited,
                    "gRPC connection limit reached; new connections wait in the listen backlog until one closes"
                );
            }
            tokio::select! {
                slot = Arc::clone(&slots).acquire_owned() => match slot {
                    Ok(slot) => slot,
                    Err(_) => return, // never closed
                },
                () = tx.closed() => return,
            }
        };
        let accepted = tokio::select! {
            accepted = listener.accept() => accepted,
            () = tx.closed() => return,
        };
        match accepted {
            Ok(io) => {
                backoff = BACKOFF_MIN;
                if tx.send(Ok(Conn::new(io, slot, deadline))).await.is_err() {
                    return;
                }
            }
            Err(e) => {
                drop(slot);
                // A connection the client gave up on before accept: nothing to wait for or report.
                // Linux also passes network errors of the pending connection up through accept(2).
                if matches!(
                    e.kind(),
                    io::ErrorKind::ConnectionAborted
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::Interrupted
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::NetworkDown
                        | io::ErrorKind::NetworkUnreachable
                        | io::ErrorKind::HostUnreachable
                ) {
                    continue;
                }
                metrics::counter!(crate::metrics::GRPC_ACCEPT_ERRORS).increment(1);
                if let Some(times) = failing.due() {
                    tracing::warn!(
                        error = %e,
                        times,
                        retry_in_ms = backoff.as_millis() as u64,
                        "accepting a gRPC connection failed; retrying (out of file descriptors?)"
                    );
                }
                tokio::select! {
                    () = tokio::time::sleep(backoff) => {}
                    () = tx.closed() => return,
                }
                backoff = (backoff * 2).min(BACKOFF_MAX);
            }
        }
    }
}

/// Rate limit for a repeated warning: [`Throttle::due`] answers `Some(count)` at most once per
/// [`WARN_EVERY`], with how often the event happened since the last warning.
#[derive(Default)]
struct Throttle {
    last: Option<Instant>,
    count: u64,
}

impl Throttle {
    fn due(&mut self) -> Option<u64> {
        self.count += 1;
        if self.last.is_some_and(|t| t.elapsed() < WARN_EVERY) {
            return None;
        }
        self.last = Some(Instant::now());
        Some(std::mem::take(&mut self.count))
    }
}

/// One accepted connection: its connection slot, the deadline, and the open-connection gauge,
/// around the socket.
pub struct Conn<IO> {
    io: IO,
    _slot: OwnedSemaphorePermit,
    /// Until the connection is going ([`Deadline`]): the deadline. Dropped once it is going.
    handshake: Option<Pin<Box<Sleep>>>,
    tls: bool,
    /// Set by [`Connected::connect_info`], which tonic calls once the TLS handshake is done (at once
    /// without TLS). From then on errors go to hyper, not to tonic's accept path.
    accepted: AtomicBool,
    /// The deadline no longer applies: set at `connect_info` with TLS, by the first bytes read
    /// after it without.
    going: AtomicBool,
}

impl<IO> Conn<IO> {
    fn new(io: IO, slot: OwnedSemaphorePermit, deadline: Deadline) -> Self {
        metrics::gauge!(crate::metrics::GRPC_CONNECTIONS).increment(1.0);
        Self {
            io,
            _slot: slot,
            handshake: Some(Box::pin(tokio::time::sleep(deadline.timeout))),
            tls: deadline.tls,
            accepted: AtomicBool::new(false),
            going: AtomicBool::new(false),
        }
    }

    /// tonic has taken the connection: with TLS the handshake is done and the deadline is over;
    /// without TLS it runs on until the first bytes are read.
    pub(crate) fn mark_accepted(&self) {
        self.accepted.store(true, Ordering::Release);
        if self.tls {
            self.going.store(true, Ordering::Release);
        }
    }

    fn is_accepted(&self) -> bool {
        self.accepted.load(Ordering::Acquire)
    }

    /// While the connection is not yet going: an error if the deadline has passed (registering
    /// for it otherwise). `None` once it is going.
    fn handshake_expired(&mut self, cx: &mut Context<'_>) -> Option<io::Error> {
        if self.going.load(Ordering::Acquire) {
            self.handshake = None;
            return None;
        }
        let deadline = self.handshake.as_mut()?;
        if deadline.as_mut().poll(cx).is_ready() {
            self.handshake = None;
            metrics::counter!(crate::metrics::GRPC_HANDSHAKE_TIMEOUTS).increment(1);
            // ConnectionAborted: an error kind tonic's accept path skips rather than ending on.
            return Some(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "connection did not finish its TLS handshake (or send its first bytes) in time",
            ));
        }
        None
    }

    /// Before tonic has taken the connection, an I/O error reaches tonic's accept path, which ends
    /// the server on any kind outside its short retry list (a `TimedOut` from TCP keepalive, say).
    /// Map those to `ConnectionReset`, which it skips. Afterwards errors go to hyper, unchanged.
    fn handshake_error(&self, e: io::Error) -> io::Error {
        if self.is_accepted() || tonic_skips(e.kind()) {
            return e;
        }
        io::Error::new(io::ErrorKind::ConnectionReset, e)
    }
}

/// The accept-error kinds tonic 0.12 skips (`handle_accept_error`); any other kind ends its
/// incoming stream and, with it, the server.
fn tonic_skips(kind: io::ErrorKind) -> bool {
    matches!(
        kind,
        io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::Interrupted
            | io::ErrorKind::InvalidData
            | io::ErrorKind::UnexpectedEof
            | io::ErrorKind::WouldBlock
    )
}

impl<IO> Drop for Conn<IO> {
    fn drop(&mut self) {
        metrics::gauge!(crate::metrics::GRPC_CONNECTIONS).decrement(1.0);
    }
}

impl<IO: Connected> Connected for Conn<IO> {
    type ConnectInfo = IO::ConnectInfo;
    fn connect_info(&self) -> Self::ConnectInfo {
        // tonic asks for this when it takes the connection: after the TLS handshake (it asks the
        // TLS stream, which asks this), or at once without TLS. Nothing else calls it.
        self.mark_accepted();
        self.io.connect_info()
    }
}

impl<IO: AsyncRead + Unpin> AsyncRead for Conn<IO> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(e) = self.handshake_expired(cx) {
            return Poll::Ready(Err(e));
        }
        let before = buf.filled().len();
        match Pin::new(&mut self.io).poll_read(cx, buf) {
            Poll::Ready(Err(e)) => Poll::Ready(Err(self.handshake_error(e))),
            Poll::Ready(Ok(())) => {
                // Without TLS, bytes read after tonic took the connection: HTTP/2 has started.
                if self.handshake.is_some() && self.is_accepted() && buf.filled().len() > before {
                    self.going.store(true, Ordering::Release);
                    self.handshake = None;
                }
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<IO: AsyncWrite + Unpin> AsyncWrite for Conn<IO> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(e) = self.handshake_expired(cx) {
            return Poll::Ready(Err(e));
        }
        match Pin::new(&mut self.io).poll_write(cx, buf) {
            Poll::Ready(Err(e)) => Poll::Ready(Err(self.handshake_error(e))),
            other => other,
        }
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        if let Some(e) = self.handshake_expired(cx) {
            return Poll::Ready(Err(e));
        }
        match Pin::new(&mut self.io).poll_write_vectored(cx, bufs) {
            Poll::Ready(Err(e)) => Poll::Ready(Err(self.handshake_error(e))),
            other => other,
        }
    }

    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(e) = self.handshake_expired(cx) {
            return Poll::Ready(Err(e));
        }
        match Pin::new(&mut self.io).poll_flush(cx) {
            Poll::Ready(Err(e)) => Poll::Ready(Err(self.handshake_error(e))),
            other => other,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // A shutdown is the end anyway: no deadline check, only the error mapping.
        match Pin::new(&mut self.io).poll_shutdown(cx) {
            Poll::Ready(Err(e)) => Poll::Ready(Err(self.handshake_error(e))),
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
    use tokio_stream::StreamExt;

    fn emfile() -> io::Error {
        io::Error::from_raw_os_error(libc::EMFILE)
    }

    /// Hands out the scripted results in order, then a fresh in-memory stream on every call. The
    /// client ends are kept, so a server end sees a silent peer, not end-of-file.
    struct Scripted(
        Mutex<VecDeque<io::Result<DuplexStream>>>,
        Mutex<Vec<DuplexStream>>,
    );

    impl Scripted {
        fn new(script: Vec<io::Result<DuplexStream>>) -> Self {
            Self(Mutex::new(script.into()), Mutex::new(Vec::new()))
        }
    }

    impl Listener for Scripted {
        type Io = DuplexStream;
        async fn accept(&self) -> io::Result<DuplexStream> {
            let next = self.0.lock().unwrap().pop_front();
            if let Some(r) = next {
                r
            } else {
                let (server, client) = tokio::io::duplex(64);
                self.1.lock().unwrap().push(client);
                Ok(server)
            }
        }
    }

    /// The reason this module exists: tonic 0.12's own accept path ends the server on `EMFILE`,
    /// and the server returns `Ok(())` without any shutdown signal. If this starts failing, tonic
    /// retries such errors now and the own loop could be simplified.
    #[tokio::test]
    async fn tonic_ends_serving_after_an_emfile_from_its_incoming_stream() {
        let incoming = tokio_stream::iter(vec![Err::<DuplexStream, io::Error>(emfile())])
            .chain(tokio_stream::pending());
        let served = tonic::transport::Server::builder()
            .add_routes(tonic::service::Routes::default())
            .serve_with_incoming_shutdown(incoming, std::future::pending::<()>());
        let outcome = tokio::time::timeout(Duration::from_secs(10), served).await;
        assert!(
            matches!(outcome, Ok(Ok(()))),
            "tonic returned {outcome:?}; expected Ok(()) right after the EMFILE, with no shutdown signal"
        );
    }

    /// The same EMFILE (twice) through this module's loop: retried after a backoff, the next
    /// connection is served, and the stream yields no error.
    #[tokio::test]
    async fn the_accept_loop_retries_descriptor_exhaustion_and_never_yields_an_error() {
        let listener = Scripted::new(vec![Err(emfile()), Err(emfile())]);
        let mut stream = incoming(listener, 8, Deadline::new(HANDSHAKE_TIMEOUT, true));
        let first = tokio::time::timeout(Duration::from_secs(10), stream.next())
            .await
            .expect("a connection after the errors");
        assert!(
            matches!(first, Some(Ok(_))),
            "the stream must yield the next connection, not an error"
        );
    }

    #[tokio::test]
    async fn no_more_than_the_limit_are_open_at_once() {
        let mut stream = incoming(
            Scripted::new(Vec::new()),
            2,
            Deadline::new(HANDSHAKE_TIMEOUT, true),
        );
        let a = stream.next().await.unwrap().unwrap();
        let _b = stream.next().await.unwrap().unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(200), stream.next())
                .await
                .is_err(),
            "a third connection must wait while two are open"
        );
        drop(a);
        let third = tokio::time::timeout(Duration::from_secs(10), stream.next()).await;
        assert!(
            matches!(third, Ok(Some(Ok(_)))),
            "closing one frees its slot"
        );
    }

    #[tokio::test]
    async fn a_connection_that_does_not_finish_its_handshake_is_cut() {
        let mut stream = incoming(
            Scripted::new(Vec::new()),
            2,
            Deadline::new(Duration::from_millis(50), true),
        );
        let mut conn = stream.next().await.unwrap().unwrap();
        let mut buf = [0u8; 8];
        let read = tokio::time::timeout(Duration::from_secs(10), conn.read(&mut buf))
            .await
            .expect("the deadline ends the read");
        let e = read.expect_err("a silent peer past the deadline is an error");
        assert_eq!(e.kind(), io::ErrorKind::ConnectionAborted);
        assert!(
            tonic_skips(e.kind()),
            "tonic must skip it, not end the server"
        );
    }

    fn conn(io: DuplexStream, timeout: Duration, tls: bool) -> Conn<DuplexStream> {
        let slots = Arc::new(Semaphore::new(1));
        Conn::new(
            io,
            slots.try_acquire_owned().unwrap(),
            Deadline::new(timeout, tls),
        )
    }

    /// With TLS, tonic taking the connection means the mutual-TLS handshake is done: no deadline
    /// after that, even for a connection that stays silent.
    #[tokio::test]
    async fn with_tls_a_completed_handshake_ends_the_deadline() {
        let (server, _client) = tokio::io::duplex(64);
        let mut conn = conn(server, Duration::from_millis(50), true);
        conn.mark_accepted();
        let mut buf = [0u8; 8];
        assert!(
            tokio::time::timeout(Duration::from_millis(300), conn.read(&mut buf))
                .await
                .is_err(),
            "an idle connection past its handshake just waits for data"
        );
    }

    /// With TLS, bytes before tonic took the connection are the handshake: they do not end the
    /// deadline.
    #[tokio::test]
    async fn with_tls_handshake_bytes_do_not_end_the_deadline() {
        let (server, mut client) = tokio::io::duplex(64);
        let mut conn = conn(server, Duration::from_millis(100), true);
        client.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 8];
        assert_eq!(conn.read(&mut buf).await.unwrap(), 5);
        let read = tokio::time::timeout(Duration::from_secs(10), conn.read(&mut buf))
            .await
            .expect("the deadline still ends the read");
        assert_eq!(
            read.expect_err("cut").kind(),
            io::ErrorKind::ConnectionAborted
        );
    }

    /// Without TLS tonic takes the connection at once: a silent one is still cut at the deadline.
    #[tokio::test]
    async fn without_tls_a_silent_connection_is_cut_at_the_deadline() {
        let (server, _client) = tokio::io::duplex(64);
        let mut conn = conn(server, Duration::from_millis(50), false);
        conn.mark_accepted();
        let mut buf = [0u8; 8];
        let read = tokio::time::timeout(Duration::from_secs(10), conn.read(&mut buf))
            .await
            .expect("the deadline ends the read");
        assert_eq!(
            read.expect_err("cut").kind(),
            io::ErrorKind::ConnectionAborted
        );
    }

    /// Without TLS, the first bytes after tonic took the connection end the deadline.
    #[tokio::test]
    async fn without_tls_the_first_bytes_end_the_deadline() {
        let (server, mut client) = tokio::io::duplex(64);
        let mut conn = conn(server, Duration::from_millis(50), false);
        conn.mark_accepted();
        client.write_all(b"PRI").await.unwrap();
        let mut buf = [0u8; 8];
        assert_eq!(conn.read(&mut buf).await.unwrap(), 3);
        assert!(
            tokio::time::timeout(Duration::from_millis(300), conn.read(&mut buf))
                .await
                .is_err(),
            "an idle connection in use just waits for data"
        );
    }

    /// An I/O error during the handshake reaches tonic's accept path: kinds it would end the
    /// server on are mapped to one it skips; after the handshake nothing is changed.
    #[test]
    fn handshake_errors_are_mapped_to_a_kind_tonic_skips() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        rt.block_on(async {
            let slots = Arc::new(Semaphore::new(1));
            let conn = Conn::new(
                (),
                Arc::clone(&slots).try_acquire_owned().unwrap(),
                Deadline::new(HANDSHAKE_TIMEOUT, true),
            );
            let mapped = conn.handshake_error(io::Error::new(io::ErrorKind::TimedOut, "keepalive"));
            assert_eq!(mapped.kind(), io::ErrorKind::ConnectionReset);
            assert!(
                mapped.to_string().contains("keepalive"),
                "the cause stays readable: {mapped}"
            );
            let kept =
                conn.handshake_error(io::Error::new(io::ErrorKind::InvalidData, "bad record"));
            assert_eq!(kept.kind(), io::ErrorKind::InvalidData);
            conn.mark_accepted();
            let after = conn.handshake_error(io::Error::new(io::ErrorKind::TimedOut, "later"));
            assert_eq!(
                after.kind(),
                io::ErrorKind::TimedOut,
                "after the handshake errors pass unchanged"
            );
        });
    }

    #[test]
    fn the_connection_cap_follows_the_descriptor_limit() {
        assert_eq!(connection_limit(1024), 768);
        assert_eq!(connection_limit(512), 256);
        assert_eq!(connection_limit(128), 64);
        assert_eq!(connection_limit(64), 32);
        assert_eq!(connection_limit(1), 1);
        assert_eq!(connection_limit(1 << 20), MAX_CONNECTIONS);
        assert_eq!(connection_limit(u64::MAX), MAX_CONNECTIONS);
    }

    #[test]
    fn repeated_warnings_are_throttled_and_counted() {
        let mut t = Throttle::default();
        assert_eq!(t.due(), Some(1));
        assert_eq!(t.due(), None);
        assert_eq!(t.due(), None);
        t.last = Some(Instant::now() - WARN_EVERY);
        assert_eq!(
            t.due(),
            Some(3),
            "the warning reports the events since the last one"
        );
    }
}
