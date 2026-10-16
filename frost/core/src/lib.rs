// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! FROST-ed25519 threshold signing core for the Rütli Canton KMS.
//!
//! This crate contains the pure protocol logic each cosigner runs:
//!
//! - [`dkg`] — distributed key generation, the default. The group key is *born distributed*; the
//!   full private key never exists anywhere.
//! - [`dealer`] — a one-time trusted-dealer split of an **existing** Ed25519 key, for migrating a
//!   Canton node's key into a cluster without changing its namespace (milestone B2). Strictly
//!   weaker than DKG: that key existed whole on the old node and in its backups before the split.
//! - [`session`] — the two-round signing flow (commit → sign → aggregate) producing a standard
//!   RFC 8032 Ed25519 signature. It is format-identical to a single-signer one, not
//!   value-identical (FROST's nonce is random, RFC 8032's is derived from the message), and
//!   Canton's verifier — like any stock Ed25519 verifier — accepts it unchanged.
//! - [`nonce_store`] — a crash-safe single-use guard for signing nonces. Reusing a round-1 nonce
//!   across two messages leaks the participant's key share; the store persists a session marker
//!   *before* any share leaves the process, so not even a crash+restart can lead to reuse.
//!
//! Everything here is deliberately network-free and deterministic-input, so the cosigner daemon
//! (gRPC) stays a thin shell and this crate carries the security-critical logic under test.
//!
//! The message signed for Canton is its 34-byte pre-hashed payload (`0x1220 ‖ sha256(tx)`, see
//! docs/wire-contract.md) — plain Ed25519 over those bytes, not Ed25519ph.

// The error enum wraps frost/io types that are large by value; boxing every `?` site to shrink the
// Err variant would hurt readability more than it helps here.
#![allow(clippy::result_large_err)]

pub mod dealer;
pub mod dkg;
pub mod nonce_store;
pub mod refresh;
pub mod repair;
pub mod session;

pub use frost_ed25519 as frost;

use thiserror::Error;

/// Errors surfaced by the signing core.
#[derive(Debug, Error)]
pub enum CoreError {
    #[error("FROST protocol error: {0}")]
    Frost(#[from] frost_ed25519::Error),

    #[error("nonce store: {0}")]
    NonceStore(String),

    #[error("nonce for session {0} was already used — refusing to sign (reuse leaks the key share)")]
    NonceReuse(String),

    #[error("unknown signing session: {0}")]
    UnknownSession(String),

    #[error("round1 called twice for in-flight session {0} — use a fresh session id")]
    DuplicateSession(String),

    /// Round 2 for a session does not match what its round 1 was bound to (key, message, signer
    /// set, this cosigner's own commitment, or — later — the signing intent). Refused before the
    /// nonce marker burns; the session's nonces are dropped, so no share is ever released for it.
    #[error("round 2 for session {session} does not match its round-1 binding: {what}")]
    BindingMismatch { session: String, what: &'static str },

    /// A round-1 binding that cannot be honoured (a malformed message or signer set).
    #[error("invalid session binding: {0}")]
    InvalidBinding(String),

    #[error("ceremony called out of order: {0}")]
    InvalidCeremonyState(&'static str),

    /// A trusted-dealer split or a public key package failed a check. Never carries key material.
    #[error("dealer: {0}")]
    Dealer(String),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, CoreError>;
