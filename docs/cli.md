# CLI Reference

The `find` binary is the primary user interface. It accepts a target SEC1 public key and runs a multi-variant range-splitting search.

## Synopsis

```bash
find [OPTIONS] --pubkey <HEX_SEC1>
```

## Flags

| Flag | Short | Type | Default | Description |
|---|---|---|---|---|
| `--pubkey` | `-p` | `String` (required) | — | HEX-encoded SEC1 public key (compressed or uncompressed) |
| `--output-dir` | `-o` | `String` | `data` | Data and checkpoint root directory |
| `--log-dir` | `-l` | `String` | `logs` | Rolling log directory |
| `--cache-points` | `-c` | `bool` | `false` | Persist `j·G` X-coordinates to binary caches for multi-pubkey reuse |
| `--help` | `-h` | — | — | Print help |
| `--version` | `-V` | — | — | Print version |

## Examples

### Basic search

```bash
find --pubkey 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
```

This runs a CPU-bound parallel sweep without writing any cache files.

### With binary caching

```bash
find --pubkey 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798 --cache-points
```

This precomputes a 32 GB cache file per billion scalars. Subsequent runs against any public key reuse the cache.

### Custom directories

```bash
find --pubkey 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798 \
     --output-dir /var/lib/find \
     --log-dir /var/log/find
```

### Resuming a checkpointed search

```bash
# First run (creates checkpoint)
find --pubkey 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798

# Interrupted, then resumed (verifies checkpoint integrity, continues)
find --pubkey 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
```

If a `checkpoint.json` exists in `--output-dir`, the tool:

1. Reads it.
2. Verifies the integrity anchor by recomputing `x(last_j · G)`.
3. If the pubkey matches and the anchor is valid → resumes from `last_j + 1`.
4. If the pubkey mismatches → starts a fresh search (and logs a warning).
5. If the anchor is invalid → refuses to proceed (`ResearchIntegrityError`).

See [architecture.md#persistence-layer](architecture.md#persistence-layer) and [ADR-0003](adr/0003-atomic-checkpointing.md) for the checkpoint lifecycle.

## Input format

The `--pubkey` value must be a valid hex-encoded SEC1 point:

| Format | Bytes | First byte | Example |
|---|---|---|---|
| Compressed | 33 | `0x02` or `0x03` (Y-parity) | `0279be66...` |
| Uncompressed | 65 | `0x04` | `0479be66...3c1f...` |

Hex digits may be upper- or lower-case. The string is passed directly to `k256::PublicKey::from_sec1_bytes` after hex decoding.

Empty or malformed input produces a [`FindError::InvalidPublicKey`](modules.md#error) or [`FindError::HexError`](modules.md#error) and the binary exits with a non-zero status.

## Output

### On success (match found)

```
============================================================
MATCH DISCOVERED (Variant: 2^10)
Shift scalar V: 1024
Search scalar j: 42
Target candidates (d = V +/- j):
  [1] 0x426
  [2] 0x3e2
Total Search Duration: 2.345s
============================================================
```

| Field | Meaning |
|---|---|
| `Variant` | The variant label that produced the match (e.g. `"2^10"`, `"sum(2^0..2^7)"`) |
| `Shift scalar V` | The original unreduced offset value (decimal) |
| `Search scalar j` | The small scalar that matched the X-coordinate |
| `Target candidates` | The two possible private keys, hex-encoded (V+j and V-j, both reduced mod n) |
| `Total Search Duration` | Wall-clock time of the entire search session |

The two candidates are emitted because X-coordinate matching cannot distinguish the Y-parity of `P - V·G`. The caller must verify each candidate externally (e.g. by checking `candidate·G = P`) to determine the correct one.

### On completion (no match)

```
Search completed. No match found.
```

This is printed if the search space is exhausted without finding a match. The exit status is `0`.

### On error

Any error from the toolchain is printed to stderr in the form:

```
Error: <message>
```

The exit status is non-zero. The specific [`FindError`](modules.md#error) variant determines the message prefix:

| Variant | Prefix |
|---|---|
| `EccError` | `ECC error: ...` |
| `ResearchIntegrityError` | `Research integrity violation: ...` |
| `InvalidPublicKey` | `Invalid public key format: ...` |
| `Io` | `I/O error: ...` |
| `HexError` | `Hex decoding error: ...` |
| `SerializationError` | `Serialization error: ...` |
| `CacheCorrupted` | `Cache file corrupted: ...` |

## Files written

The binary writes to two locations:

1. **Data directory** (default: `./data`) — contains:
   - `points.json` — variant metadata (X-coordinate → offset mapping) for auditability. Written once at the start of each session.
   - `checkpoint.json` — durable progress checkpoint. Written atomically at the end of every cache chunk.
   - `checkpoints/chunk_<start_j>.bin` — binary cache file (only when `--cache-points` is set or when an existing cache is reused).
2. **Log directory** (default: `./logs`) — contains:
   - `find.log.YYYY-MM-DD` — daily-rolling structured logs. See [observability.md](observability.md).

## See also

- [Configuration](configuration.md) — environment variables and runtime constants
- [Operations](operations.md) — backup, restore, monitoring
- [Troubleshooting](troubleshooting.md) — common error messages and resolutions
- [Observability](observability.md) — log levels, tracing, audit boundaries
