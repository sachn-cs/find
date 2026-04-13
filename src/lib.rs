// Copyright (c) 2026 Sachin (https://github.com/sachn-cs)
// Released under MIT OR Apache-2.0. See LICENSE-MIT or LICENSE-APACHE.
// THIS SOFTWARE IS FOR EDUCATIONAL AND RESEARCH PURPOSES ONLY.

//! # Secp256k1 Find Tool
//!
//! A high-performance, production-grade Rust implementation of a multi-variant
//! range-splitting algorithm for secp256k1 private key discovery.
//!
//! ## 🛠 Architectural Overview
//! The system is engineered around a modular pipeline that separates
//! elliptic curve primitives from high-level search orchestrators:
//!
//! 1.  **ECC Primitives ([`ecc`]):** Hardened abstractions for SEC1 parsing
//!     and point arithmetic ($P \pm Q$, $d \cdot G$). Ensures mathematical
//!     integrity and range-validation for all field elements.
//! 2.  **Search Engine ([`search`]):** The core logic layer implementing
//!     the parallel sweep, $O(1)$ variant-lookup indexing, and binary caching
//!     protocols.
//! 3.  **Error System ([`error`]):** A unified failure model providing
//!     context-aware resilience for I/O, serialization, and cryptographic errors.
//!
//! ## 🔬 Fundamental Logic
//! The search is based on the mathematical invariant:
//! $$x(j \cdot G) = x(P - V \cdot G)$$
//! which implies that the private key $d$ for point $P$ must be one of:
//! - $d = V + j \pmod n$ (Positive Parity)
//! - $d = V - j \pmod n$ (Negative Parity)
//!
//! This crate exploits this symmetry to search 512 variants simultaneously
//! within a single scalar multiplication sweep, effectively splitting the
//! search space into parallelized log-ranges.

pub mod ecc;
pub mod error;
pub mod search;

/// Standard Result type used throughout the find crate for idiomatic error handling.
pub type Result<T> = std::result::Result<T, error::FindError>;
