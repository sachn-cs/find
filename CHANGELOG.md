# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-04-12

### Added
- **High-Performance Rust Core**: Replaced the Python prototype with a production-grade Rust implementation using `k256` and `rayon`.
- **512-Variant Search Engine**: Implemented range-splitting using powers of 2 ($2^0..2^{255}$) and cumulative summations.
- **Ambiguity Handling**: Added explicit candidate disambiguation to handle Y-parity during X-coordinate matching ($v \pm j$).
- **Structured Observability**: Added non-blocking rolling file logs using `tracing-appender` and daily logs in the `./logs` directory.
- **Export Capabilities**: Added JSON export for generated subtraction variants via the `--output-dir` flag.
- **Comprehensive Testing**: Added property-based tests (`proptest`), unit tests for edge cases, and robust integration tests.
- **Mathematical Documentation**: Added deep architectural and mathematical documentation across the codebase.

### Changed
- Refactored error handling to use `thiserror` for unified, contextual error reporting.
- Optimized critical point arithmetic paths to minimize allocations and redundant coordinate conversions.

### Fixed
- Fixed a panic condition in the variant generator when a subtraction resulted in the Identity point (point at infinity).
- Corrected out-of-range scalar scalar conversion logic for BigUint summations exceeding the curve order.
