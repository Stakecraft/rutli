// Copyright 2026 StakeCraft LLC
// SPDX-License-Identifier: Apache-2.0

//! An in-memory network for mesh tests that must not bind a TCP port: a tonic server reads its
//! connections from [`MemNet::listen`], and a client dials it through [`MemNet::dialer`], which a
//! [`rutli_cosigner::tls::PeerDial`] wraps exactly as it wraps TCP in the daemon. Each connection is
//! a `tokio::io::duplex` pair. The server side reports a (blank) TCP connect info, so tonic's TLS
//! layer exposes the client certificate to `Request::peer_certs`, as it does on a real socket.
//!
//! Faults ([`MemNet::fault`], [`MemNet::fault_link`]), per listening address or per directed link:
//! - `Blackhole`: both directions of every existing connection stop delivering (reads pend; writes
//!   fill the pipe, then pend), and a new dial pends — a dropped SYN — until the fault heals. What
//!   was written meanwhile is delivered after the heal, as TCP retransmits it.
//! - `Refuse`: a new dial is refused and existing connections are reset — a crashed process.
//! - `Heal`: back to normal.
//!
//! [`MemNet::relisten`] brings a new server up under the same address while the connections to the
//! old one stay blackholed for good: a pod replaced under a new IP behind the same name.

#![allow(dead_code)]

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio::sync::mpsc;
use tonic::codegen::http::Uri;
use tonic::transport::server::{Connected, TcpConnectInfo};

/// A network fault ([`MemNet::fault`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    Blackhole,
    Refuse,
    Heal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GateState {
    Open,
    Blackhole,
    Refused,
}

/// One fault domain: a listening address (one generation of it) or a directed link.
#[derive(Default)]
struct Gate {
    state: Mutex<(Option<GateState>, Vec<Waker>)>,
}

impl Gate {
    fn get(&self) -> GateState {
        self.state.lock().unwrap().0.unwrap_or(GateState::Open)
    }

    fn set(&self, fault: Fault) {
        let mut s = self.state.lock().unwrap();
        s.0 = Some(match fault {
            Fault::Blackhole => GateState::Blackhole,
            Fault::Refuse => GateState::Refused,
            Fault::Heal => GateState::Open,
        });
        for w in s.1.drain(..) {
            w.wake();
        }
    }

    fn park(&self, cx: &Context<'_>) {
        self.state.lock().unwrap().1.push(cx.waker().clone());
    }
}

/// The gates one connection passes through.
#[derive(Clone, Default)]
struct Gates(Vec<Arc<Gate>>);

impl Gates {
    fn state(&self) -> GateState {
        let states: Vec<GateState> = self.0.iter().map(|g| g.get()).collect();
        if states.contains(&GateState::Refused) {
            GateState::Refused
        } else if states.contains(&GateState::Blackhole) {
            GateState::Blackhole
        } else {
            GateState::Open
        }
    }

    /// `Ready(Ok)` when open, `Ready(Err)` when refused, `Pending` (woken on a change) when
    /// blackholed.
    fn poll_pass(&self, cx: &Context<'_>) -> Poll<std::io::Result<()>> {
        match self.state() {
            GateState::Open => Poll::Ready(Ok(())),
            GateState::Refused => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "connection reset (memnet fault)",
            ))),
            GateState::Blackhole => {
                for g in &self.0 {
                    g.park(cx);
                }
                // Re-check: a heal between the first look and parking must not be missed.
                match self.state() {
                    GateState::Blackhole => Poll::Pending,
                    GateState::Open => Poll::Ready(Ok(())),
                    GateState::Refused => Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionReset,
                        "connection reset (memnet fault)",
                    ))),
                }
            }
        }
    }
}

/// One end of an in-memory connection, behind its gates.
pub struct GatedIo {
    io: DuplexStream,
    gates: Gates,
    live: Option<Arc<AtomicUsize>>,
}

impl Drop for GatedIo {
    fn drop(&mut self) {
        if let Some(live) = &self.live {
            live.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

impl AsyncRead for GatedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.gates.poll_pass(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.io).poll_read(cx, buf),
            other => other,
        }
    }
}

impl AsyncWrite for GatedIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.gates.state() == GateState::Refused {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "connection reset (memnet fault)",
            )));
        }
        Pin::new(&mut self.io).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

/// The server end of one in-memory connection.
pub struct MemIo(GatedIo);

impl Connected for MemIo {
    type ConnectInfo = TcpConnectInfo;
    fn connect_info(&self) -> TcpConnectInfo {
        TcpConnectInfo {
            local_addr: None,
            remote_addr: None,
        }
    }
}

impl AsyncRead for MemIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for MemIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

type Incoming = mpsc::UnboundedSender<std::io::Result<MemIo>>;

/// One listening address: its queue of incoming connections and the gate of this generation.
struct Route {
    incoming: Incoming,
    gate: Arc<Gate>,
}

#[derive(Default)]
struct Net {
    routes: HashMap<String, Route>,
    /// Directed links (dialler name, address).
    links: HashMap<(String, String), Arc<Gate>>,
    /// Dials per address, and client ends alive per address.
    dials: HashMap<String, usize>,
    live: HashMap<String, Arc<AtomicUsize>>,
}

/// Named in-memory listeners (`host:port` → the server's queue of incoming connections).
#[derive(Clone, Default)]
pub struct MemNet {
    net: Arc<Mutex<Net>>,
}

impl MemNet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Listen at `authority` (`host:port`); replaces whatever listened there (a node restarted
    /// with other material, or an impostor taking over the address).
    pub fn listen(
        &self,
        authority: &str,
    ) -> tokio_stream::wrappers::UnboundedReceiverStream<std::io::Result<MemIo>> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.net.lock().unwrap().routes.insert(
            authority.to_string(),
            Route {
                incoming: tx,
                gate: Arc::default(),
            },
        );
        tokio_stream::wrappers::UnboundedReceiverStream::new(rx)
    }

    /// A new server under `authority`: the connections to the old one stay blackholed for good
    /// (no heal reaches them), new dials reach the new listener.
    pub fn relisten(
        &self,
        authority: &str,
    ) -> tokio_stream::wrappers::UnboundedReceiverStream<std::io::Result<MemIo>> {
        if let Some(old) = self.net.lock().unwrap().routes.get(authority) {
            old.gate.set(Fault::Blackhole);
        }
        self.listen(authority)
    }

    /// Apply `fault` to every connection to `authority` (its current listener) and to new dials.
    pub fn fault(&self, authority: &str, fault: Fault) {
        if let Some(r) = self.net.lock().unwrap().routes.get(authority) {
            r.gate.set(fault);
        }
    }

    /// Apply `fault` to the directed link from dialler `from` ([`MemNet::dialer_from`]) to
    /// `authority`: its connections, both directions, and its new dials.
    pub fn fault_link(&self, from: &str, authority: &str, fault: Fault) {
        self.link(from, authority).set(fault);
    }

    fn link(&self, from: &str, authority: &str) -> Arc<Gate> {
        self.net
            .lock()
            .unwrap()
            .links
            .entry((from.to_string(), authority.to_string()))
            .or_default()
            .clone()
    }

    /// How many connections dialler `from` ("" for [`MemNet::dialer`]) opened to `authority`.
    pub fn dials(&self, from: &str, authority: &str) -> usize {
        self.net
            .lock()
            .unwrap()
            .dials
            .get(&format!("{from}->{authority}"))
            .copied()
            .unwrap_or(0)
    }

    /// Client ends of `from` to `authority` still open (dropped when the client's connection ends).
    pub fn live(&self, from: &str, authority: &str) -> usize {
        self.net
            .lock()
            .unwrap()
            .live
            .get(&format!("{from}->{authority}"))
            .map_or(0, |l| l.load(Ordering::SeqCst))
    }

    /// A connector that opens a new in-memory connection to the listener at the URI's authority.
    pub fn dialer(&self) -> MemDial {
        MemDial {
            net: self.clone(),
            from: None,
        }
    }

    /// [`MemNet::dialer`] as dialler `from`, whose links [`MemNet::fault_link`] can cut.
    pub fn dialer_from(&self, from: &str) -> MemDial {
        MemDial {
            net: self.clone(),
            from: Some(from.to_string()),
        }
    }
}

#[derive(Clone)]
pub struct MemDial {
    net: MemNet,
    from: Option<String>,
}

/// Waits while the gates are blackholed: a dial whose SYN is dropped.
struct Passable(Gates);

impl std::future::Future for Passable {
    type Output = std::io::Result<()>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.0.poll_pass(cx)
    }
}

impl tonic::codegen::Service<Uri> for MemDial {
    type Response = TokioIo<GatedIo>;
    type Error = std::io::Error;
    type Future =
        Pin<Box<dyn std::future::Future<Output = std::io::Result<TokioIo<GatedIo>>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let authority = uri
            .authority()
            .map_or_default(std::string::ToString::to_string);
        let link = self.from.as_ref().map(|f| self.net.link(f, &authority));
        let counter = format!("{}->{authority}", self.from.as_deref().unwrap_or(""));
        let net = self.net.clone();
        Box::pin(async move {
            let gate = net
                .net
                .lock()
                .unwrap()
                .routes
                .get(&authority)
                .map(|r| r.gate.clone());
            let Some(gate) = gate else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    format!("nothing listens at {authority}"),
                ));
            };
            let gates = Gates(std::iter::once(gate).chain(link).collect());
            match gates.state() {
                GateState::Refused => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionRefused,
                        "connection refused (memnet fault)",
                    ))
                }
                GateState::Blackhole => Passable(gates.clone()).await.map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::ConnectionRefused,
                        "connection refused (memnet fault)",
                    )
                })?,
                GateState::Open => {}
            }
            // The listener may have been replaced while the dial waited: dial the current one.
            let (tx, gate, live) = {
                let mut n = net.net.lock().unwrap();
                *n.dials.entry(counter.clone()).or_default() += 1;
                let live = n.live.entry(counter).or_default().clone();
                let route = n
                    .routes
                    .get(&authority)
                    .map(|r| (r.incoming.clone(), r.gate.clone()));
                let Some((tx, gate)) = route else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionRefused,
                        format!("nothing listens at {authority}"),
                    ));
                };
                (tx, gate, live)
            };
            let gates = Gates(
                std::iter::once(gate)
                    .chain(gates.0.into_iter().skip(1))
                    .collect(),
            );
            let (client, server) = tokio::io::duplex(64 * 1024);
            let server = MemIo(GatedIo {
                io: server,
                gates: gates.clone(),
                live: None,
            });
            match tx.send(Ok(server)) {
                Ok(()) => {
                    live.fetch_add(1, Ordering::SeqCst);
                    Ok(TokioIo::new(GatedIo {
                        io: client,
                        gates,
                        live: Some(live),
                    }))
                }
                Err(_) => Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    "listener closed",
                )),
            }
        })
    }
}
