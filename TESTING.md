# Verification Strategy: High-Performance search

This document outlines the testing philosophy and verification methodologies used to guarantee the mathematical integrity and production reliability of the `find` tool.

## 🔬 Philosophy: Behavioral Verification

The testing strategy prioritizes **functional correctness across state transitions** over superficial line coverage. We categorize our tests into four critical layers:

### 1. Mathematical Invariant Testing (Property-Based)

Using the `proptest` crate, we verify that the algorithmic invariant $x(jG) = x(P - VG)$ holds true for $j$ across the entire 64-bit scalar field.

**Core Prop-Test Invariant:**
For any randomly generated scalar $d$ and any variant shift $V$, the engine **must** be able to recover $d$ if $j = |d - V|$ is within the search range.

### 2. Randomized Discovery Verification

A mandatory randomized test executes on every build:
- **Input:** A seeded, deterministic 6-8 digit scalar (using `ChaCha8Rng`).
- **Process:** Derives a target point $P$, generates 512 variants, and runs a parallel sweep.
- **Goal:** Validates that the engine successfully extracts the correct candidate in a real-world execution flow.

### 3. Edge Case & Boundary Analysis

We explicitly test known cryptographic and logic boundaries:
- **Small Scalars:** $j = 1$ (closest search boundary).
- **Large Scalars:** $j = 99,999,999$ (upper 8-digit boundary).
- **Patterned Scalars:**
    - Palindromes (e.g., `123321`)
    - Repeated digits (e.g., `111111`)
    - Alternating bit-patterns.
- **Collision Handling:** Ensuring the `VariantIndex` handles mathematically identical shift amounts (e.g., $2^0 == \sum 2^0$) without logic panics.

### 4. System Resilience & I/O

- **Atomic Checkpointing:** Verified through idempotency tests where the same search is run sequentially.
- **Fail-Fast Parsing:** Injects invalid SEC1 prefixes (e.g., `0x05`) and malformed hex strings to ensure no silent failures.
- **Zero-Copy Integrity:** Checked via clippy and linting to ensure no redundant heap allocations are introduced into the search loop.

### 5. High-Precision Benchmarking (Performance Verification)

With the introduction of Batch Normalization in v2.0.0, performance is now a verified pillar. We use `criterion` to validate:
- **Normalization Amortization:** Ensures simultaneous inversion remains efficient.
- **Index Latency:** Monitors binary search performance over the flat array.
- **Regression Tracking:** Validates that new commits do not degrade cryptographic throughput.

## Execution

Run the complete verification and production lifecycle via the `Makefile`:

```bash
# Standard test suite
make test

# Performance verification (Criterion)
make bench

# Static analysis and linting
make lint
```

To run property-tests with increased case counts:
```bash
PROPTEST_CASES=1000 cargo test --release
```
