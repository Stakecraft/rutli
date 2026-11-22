// Copyright 2026 StakeCraft LLC
// SPDX-License-Identifier: Apache-2.0

//! A node's sign round-2 store work on request ([`Node::with_sign_store_hook`]): pass, fail with an
//! OS error (an injected `EIO` is a definite I/O error, which file permissions cannot give a test
//! running as root), or hold — a hung volume — until set to something else.
//!
//! [`Node::with_sign_store_hook`]: rutli_cosigner::node::Node::with_sign_store_hook

#![allow(dead_code)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use rutli_cosigner::node::SignStoreHook;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Store {
    Ok,
    Fail(i32),
    Hold,
}

pub struct StoreFault {
    state: Mutex<Store>,
    changed: Condvar,
    /// Round 2s held right now.
    held: AtomicUsize,
}

impl StoreFault {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(Store::Ok),
            changed: Condvar::new(),
            held: AtomicUsize::new(0),
        })
    }

    pub fn set(&self, store: Store) {
        *self.state.lock().unwrap() = store;
        self.changed.notify_all();
    }

    /// Round 2s waiting in [`Store::Hold`] right now.
    pub fn held(&self) -> usize {
        self.held.load(Ordering::SeqCst)
    }

    pub fn hook(self: &Arc<Self>) -> SignStoreHook {
        let me = self.clone();
        Arc::new(move |_key: &str, _session: &str| {
            let mut state = me.state.lock().unwrap();
            loop {
                match *state {
                    Store::Ok => return Ok(()),
                    Store::Fail(errno) => return Err(std::io::Error::from_raw_os_error(errno)),
                    Store::Hold => {
                        me.held.fetch_add(1, Ordering::SeqCst);
                        state = me.changed.wait(state).unwrap();
                        me.held.fetch_sub(1, Ordering::SeqCst);
                    }
                }
            }
        })
    }
}
