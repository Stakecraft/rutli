// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! An in-memory network for mesh tests that must not bind a TCP port: a tonic server reads its
//! connections from [`MemNet::listen`], and a client dials it through [`MemNet::dialer`], which a
//! [`rutli_cosigner::tls::PeerDial`] wraps exactly as it wraps TCP in the daemon. Each connection is
//! a `tokio::io::duplex` pair. The server side reports a (blank) TCP connect info, so tonic's TLS
//! layer exposes the client certificate to `Request::peer_certs`, as it does on a real socket.

#![allow(dead_code)]

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio::sync::mpsc;
use tonic::codegen::http::Uri;
use tonic::transport::server::{Connected, TcpConnectInfo};

/// The server end of one in-memory connection.
pub struct MemIo(DuplexStream);

impl Connected for MemIo {
    type ConnectInfo = TcpConnectInfo;
    fn connect_info(&self) -> TcpConnectInfo {
        TcpConnectInfo { local_addr: None, remote_addr: None }
    }
}

impl AsyncRead for MemIo {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for MemIo {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
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

/// Named in-memory listeners (`host:port` → the server's queue of incoming connections).
#[derive(Clone, Default)]
pub struct MemNet {
    routes: Arc<Mutex<HashMap<String, Incoming>>>,
}

impl MemNet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Listen at `authority` (`host:port`); replaces whatever listened there (a node restarted
    /// with other material, or an impostor taking over the address).
    pub fn listen(&self, authority: &str) -> tokio_stream::wrappers::UnboundedReceiverStream<std::io::Result<MemIo>> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.routes.lock().unwrap().insert(authority.to_string(), tx);
        tokio_stream::wrappers::UnboundedReceiverStream::new(rx)
    }

    /// A connector that opens a new in-memory connection to the listener at the URI's authority.
    pub fn dialer(&self) -> MemDial {
        MemDial { net: self.clone() }
    }
}

#[derive(Clone)]
pub struct MemDial {
    net: MemNet,
}

impl tonic::codegen::Service<Uri> for MemDial {
    type Response = TokioIo<DuplexStream>;
    type Error = std::io::Error;
    type Future = std::future::Ready<std::io::Result<TokioIo<DuplexStream>>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let authority = uri.authority().map(|a| a.to_string()).unwrap_or_default();
        let route = self.net.routes.lock().unwrap().get(&authority).cloned();
        std::future::ready(match route {
            Some(tx) => {
                let (client, server) = tokio::io::duplex(64 * 1024);
                match tx.send(Ok(MemIo(server))) {
                    Ok(()) => Ok(TokioIo::new(client)),
                    Err(_) => Err(std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "listener closed")),
                }
            }
            None => Err(std::io::Error::new(std::io::ErrorKind::ConnectionRefused, format!("nothing listens at {authority}"))),
        })
    }
}
