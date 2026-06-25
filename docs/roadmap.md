# Roadmap

This document describes the project's direction. It is **not** a contract — items may be removed, reprioritized, or kept indefinitely as research scope dictates.

## Current Status

The project is at **v1.0.0**: a complete, fully-tested secp256k1 search engine. All stated goals in [overview.md](overview.md) are met.

## Future Work

Items under consideration, in rough order of likely value:

### Near term
- **Improved progress visualization and ETA estimation.** Currently the orchestrator logs progress per chunk; a TUI would make long-running searches easier to monitor.
- **Comprehensive benchmarking suite with historical tracking.** Integrate `criterion`'s `benches.csv` output with a trend dashboard.
- **Pluggable variant generation.** Allow users to define custom variant sets (e.g. focused on a specific range).

### Medium term
- **Additional curve support.** The algorithm generalizes naturally to any short-Weierstrass curve. Initial candidates: `secp256r1` (P-256), `secp384r1` (P-384), `secp224r1` (P-224). The RustCrypto `elliptic-curves` workspace provides crates for each.
- **REST API for remote search management.** A small HTTP layer over the orchestrator would enable multi-machine coordination.
- **Distributed search coordination.** Shared checkpoints and cache files across machines, with a coordinator process that partitions the range and aggregates results.

### Long term
- **GPU acceleration.** A CUDA or OpenCL backend for the sweep. The variant-index and batch-normalization strategy is well-suited to GPU architectures. A proof-of-concept is the first step; a production-ready implementation is significantly more work.
- **WebAssembly compilation.** A `wasm32-unknown-unknown` build would enable browser-based demonstrations of the algorithm.
- **Formal verification.** Mechanized proof of the matching invariant and the batch normalization correctness, ideally in a proof assistant such as Coq or Lean.

## Non-Goals

The following are explicitly **out of scope** and will not be pursued:

- **Production key recovery tooling.** The project is for education and research. Building a tool optimized for "real" key recovery would conflict with the [disclaimer](../DISCLAIMER.md).
- **Wallet integration or address generation.** This is a search engine, not a wallet.
- **Altcoin-specific features.** The tool is curve-general (in principle) but is bound to secp256k1 in the current implementation. Adding per-coin logic is out of scope.
- **Mobile platforms (iOS/Android).** The search workload is CPU- and disk-intensive; mobile is not a practical target. The library could in principle be compiled for these targets, but no official build matrix is planned.

## Versioning Policy

The project follows [Semantic Versioning](https://semver.org/):

- **MAJOR** — incompatible API or behavior change.
- **MINOR** — backwards-compatible feature addition.
- **PATCH** — backwards-compatible bug fix.

See [maintenance/release.md](maintenance/release.md) for the release process.

## Supported Versions

| Version | Supported |
|---|---|
| 1.x | Yes — current stable line |
| 0.x | No — pre-stable; not recommended for any use |

## Deprecation Policy

When a feature is deprecated:

1. The deprecation is announced in [CHANGELOG.md](../CHANGELOG.md) under `### Deprecated`.
2. The deprecation note in the source code includes the version that will remove the feature and the recommended replacement.
3. Deprecated features remain functional for at least one minor release cycle before removal.

## Contributing Ideas

If you would like to suggest a roadmap item, open a [feature request](../.github/ISSUE_TEMPLATE/feature_request.md) on GitHub. See [CONTRIBUTING.md](../CONTRIBUTING.md) for the contribution workflow.
