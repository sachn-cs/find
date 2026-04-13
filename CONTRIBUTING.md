# Contributing to the Find Tool

Thank you for your interest in contributing to the `find` tool. This project is dedicated to high-performance cryptographic research and educational exploration of secp256k1 mathematics.

## Governance Standards

To ensure the technical and legal integrity of the project, all contributors must adhere to the following standards:

### 1. Research-Focused Intent
Contributions must align with the pedagogical and research-focused mission of the project. We do not accept features designed for non-educational or non-research use cases.

### 2. Technical Rigor
- **Rust Idioms**: Follow PEP 8 (for design) and idiomatic Rust standards. Use `cargo clippy` and `cargo fmt`.
- **Zero-Warning Policy**: Code must compile without warnings on the stable toolchain.
- **Verification**: New features must be accompanied by rigorous unit and/or property-based tests.

### 3. Workflow Usage
We follow a standardized developer lifecycle organized via the `Makefile`:
1.  `make lint`: Run all static analysis.
2.  `make test`: Run functional verification.
3.  `make bench`: Perform performance regression testing.

### 4. License Compliance
By contributing, you agree that your contributions will be licensed under the same dual MIT/Apache-2.0 license as the repository.

---
**Principled contributions that advance cryptographic education are always welcome.**
