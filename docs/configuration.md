# Configuration

The `find` tool has a deliberately small configuration surface. Most behavior is fixed in source; only a handful of environment variables and CLI flags are exposed for run-time tuning.

## Environment variables

| Variable | Default | Effect |
|---|---|---|
| `RUST_LOG` | `info` | Log level filter for `tracing-subscriber` (e.g. `debug`, `trace`, `info`, `warn`, `error`) |
| `RUST_BACKTRACE` | `0` | Set to `1` to print backtraces on panic |
| `CARGO_TERM_COLOR` | (auto) | Standard Cargo color setting; propagated to the build pipeline |

### `RUST_LOG` examples

```bash
# Default: info-level events only
find --pubkey 0279be66...

# Debug-level: per-batch progress, variant construction details
RUST_LOG=debug find --pubkey 0279be66...

# Trace-level: every scalar multiplication, every cache write
RUST_LOG=trace find --pubkey 0279be66...

# Filter to a specific module
RUST_LOG=find::search=debug find --pubkey 0279be66...

# Combine: debug for the search module, info elsewhere
RUST_LOG=info,find::search=debug find --pubkey 0279be66...
```

The full `tracing-subscriber` directive syntax is documented at <https://docs.rs/tracing-subscriber/latest/tracing_subscriber/struct.EnvFilter.html>.

## CLI flags

See [cli.md](cli.md) for the complete flag reference. The CLI flags that affect runtime behavior are:

| Flag | Default | Effect |
|---|---|---|
| `--output-dir` | `data` | Root for checkpoints, caches, and exported variant metadata |
| `--log-dir` | `logs` | Directory for daily-rolling log files |
| `--cache-points` | `false` | Generate and persist binary cache files |

## Compile-time constants

The following constants are defined in source and are not configurable at run time. Changing them requires editing the source and recompiling. They are documented here for transparency.

### Search parameters

| Constant | Defined in | Value | Purpose |
|---|---|---|---|
| `MAX_SEARCH` | `src/orchestrator.rs` | `u64::MAX` (2^64 - 1) | Theoretical upper bound of the search range |
| `MIN_J` | `src/orchestrator.rs` | `1` | Minimum non-zero search scalar (excludes the identity point) |
| `BATCH_SIZE` | `src/search.rs` | `32` | Number of points per batch normalization |
| `CACHE_CHUNK_SIZE` | `src/orchestrator.rs` | `1_000_000_000` | Scalars per cache chunk (one billion) |
| `TRILLION` | `src/orchestrator.rs` | `1_000_000_000_000` | Step size for human-readable audit boundary logging |

### Audit boundary

The orchestrator logs an informational message at every `32 × TRILLION = 3.2 × 10^13` scalar steps. This is a non-load-bearing constant used for long-running research observability; it does not affect correctness.

### Pre-allocation

When `--cache-points` is enabled, the orchestrator pre-allocates the cache file to `(chunk_end - chunk_start + 1) × 32` bytes before writing. The pre-allocation is a hint to the file system and may be ignored (e.g. on filesystems that do not support `fallocate`).

## `Cargo.toml` features

The `find` crate does not currently expose any `#[cfg(feature = ...)]` gates. All dependencies and features are static:

| Dependency | Features enabled |
|---|---|
| `k256` | `arithmetic`, `serde`, `bits`, `pkcs8` |
| `tracing-subscriber` | `env-filter` |
| `clap` | `derive`, `env` |

If a future feature gate is added, it will be documented here.

## Release profile

The release binary in `Cargo.toml` is optimized for maximum throughput:

```toml
[profile.release]
opt-level = 3
lto = "fat"
codegen-units = 1
panic = 'abort'
strip = true
overflow-checks = true
```

| Setting | Effect |
|---|---|
| `opt-level = 3` | Maximum LLVM optimization |
| `lto = "fat"` | Link-time optimization across all crates |
| `codegen-units = 1` | Single code generation unit for the whole program (enables inlining across crate boundaries) |
| `panic = 'abort'` | No unwinding; smaller binary, no panic-handler code |
| `strip = true` | Strip debug symbols from the binary |
| `overflow-checks = true` | Enable integer overflow checks even in release mode (correctness > speed) |

The `overflow-checks` setting is intentional: the search engine uses `saturating_*` arithmetic extensively, but the runtime checks serve as a safety net for any future code that might use plain `+`/`-`/`*`.

## Logging configuration

The `tracing-subscriber` is initialized in [`src/main.rs::init_tracing`](../src/main.rs) with:

- A daily-rolling file appender writing to `<log_dir>/find.log.YYYY-MM-DD`.
- A stderr layer that mirrors the same events to the terminal.
- `EnvFilter` initialized from `RUST_LOG` with a default of `info`.

The non-blocking file writer (`tracing_appender::non_blocking`) decouples log I/O from the CPU-bound sweep. Buffered events are flushed when the returned `WorkerGuard` is dropped at process exit.

See [observability.md](observability.md) for the full logging model.

## Input validation

The orchestrator validates the configuration before starting the search:

| Validation | Source | Failure mode |
|---|---|---|
| `Config::pubkey` is non-empty | `src/orchestrator.rs::Config::validate` | `FindError::InvalidPublicKey("Public key cannot be empty")` |
| `Config::pubkey` parses as SEC1 | `src/ecc.rs::parse_pubkey` | `FindError::InvalidPublicKey(...)` or `FindError::HexError(...)` |

`Config::output_dir` is not validated; the directory is created on first write via `std::fs::create_dir_all`. The `data/` and `checkpoints/` subdirectories are created as needed.

## Resource budgets

The tool does not impose explicit CPU, memory, or disk quotas. Recommended resource budgets for a single search session are documented in [operations.md#resource-budgets](operations.md#resource-budgets) and [overview.md#compatibility-matrix](overview.md#compatibility-matrix).
