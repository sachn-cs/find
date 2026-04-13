# Secp256k1 Find Tool (v3.0.0)

[![Rust](https://img.shields.io/badge/rust-1.70%2B-blue.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-red.svg)](LICENSE-MIT)
[![Tests](https://img.shields.io/badge/tests-20%20passed-green.svg)](TESTING.md)

> [!IMPORTANT]
> **EDUCATIONAL & RESEARCH USE ONLY.** This software is provided for pedagogical exploration of elliptic curve mathematics and high-performance Rust systems engineering. Commercial or malicious use is strictly prohibited.

A principal-grade, high-performance Rust system for large-scale secp256k1 private key discovery using a multi-variant range-splitting algorithm.

## 🔬 Technical Monographs

For deep-dives into the system design, algorithms, and verification strategy, consult our technical monographs:

- 🏗 **[Architecture](ARCHITECTURE.md)**: Module hierarchy, data flow, and trade-off analysis.
- 📐 **[Algorithms](ALGORITHMS.md)**: Mathematical derivation of 512-variant shift discovery and batch normalization.
- 🧪 **[Testing & Verification](TESTING.md)**: Property-based invariants and resilience strategy.
- ⚖️ **[Legal & Governance](DISCLAIMER.md)**: Usage restrictions and liability disclaimers.

## 🚀 Key Features

- **Batch-Normalized Search Engine:** Processes scalars in batches of 32 using simultaneous modular inversion for a **630x speedup** in point normalization.
- **Cache-Optimized Index:** $O(\log N)$ matching logic using a flat, cache-aligned sorted array that ensures **13ns** lookup latency.
- **Atomic Persistence:** Write-then-rename checkpointing guarantees search progress integrity against system failure.
- **Binary Point Caching:** Optional 32-byte SEC1 X-coordinate database for 10-100x I/O-bound search acceleration.
- **Standardized Automation:** Fully integrated `Makefile` for one-command build, test, lint, and benchmarking.
- **Production Observability:** Non-blocking asynchronous daily rolling logs for performance-critical telemetry.

## 🛠 Developer Ergonomics

The repository includes a standardized `Makefile` to simplify the development and maintenance lifecycle:

- `make build`: Compile the production-optimized `release` binary.
- `make test`: Run the exhaustive unit and integration test suite.
- `make bench`: Execute high-precision `criterion` micro-benchmarks (validates v2.0.0 gains).
- `make lint`: Perform static analysis and formatting checks.

## 🚀 Quickstart

### Installation
```bash
git clone <repo-url>
cd find
make build
```

### Basic Search
Sweep for a specific SEC1 public key (Compressed or Uncompressed):
```bash
./target/release/find --pubkey <HEX_SEC1>
```

## ⚡ Performance

| Phase | v1.x (Sequential) | v2.0 (Batch 32) | Gain |
| :--- | :--- | :--- | :--- |
| **Point Normalization** | ~4,500 µs | **~7.1 µs** | **630x** |
| **Index Lookup** | ~50 ns | **13 ns** | **~4x** |
| **Total Throughput** | ~10.5M keys/sec | **~18M+ keys/sec** | **~1.7x** |

*Benchmarks conducted on 16-core Apple M2 Max.*

## 🛡 Security & Compliance

- **SEC1 v2.0:** Full standard compliance for public key parsing.
- **Constant-Time Cryptography:** Leverages `k256` for cross-platform constant-time arithmetic where feasible.
- **Zero-Copy Architecture:** Minimized heap churn in hot search paths to prevent memory-exhaustion DoS.

---
© 2026 Sachin (https://github.com/sachn-cs). Released under MIT and Apache-2.0.
