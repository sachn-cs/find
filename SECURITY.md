# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 1.0.x   | :white_check_mark: |
| < 1.0.0 | :x: |

## Reporting a Vulnerability

This is an educational and research project. If you discover a security issue:

1. **Do not open a public issue.**
2. Email the maintainer at the address listed in the repository profile.
3. Include a clear description, reproduction steps, and expected impact.
4. Allow up to 7 days for an initial response.

## Scope

We consider vulnerabilities in the following areas:

- Cryptographic correctness (wrong curve math, scalar overflow, off-by-one)
- File-system race conditions (checkpoint corruption, cache poisoning)
- Memory safety (panics, undefined behavior in unsafe blocks — none present)
- Dependency vulnerabilities (tracked via `cargo audit` in CI)

Out of scope:
- Social engineering, phishing, or physical attacks
- Attacks requiring local privileged access to the research machine

## Disclosure Timeline

- **Day 0** — Report received
- **Day 7** — Initial triage and acknowledgment
- **Day 30** — Fix developed and tested
- **Day 45** — Public disclosure via GitHub Security Advisory (if applicable)
