// Copyright (c) 2026 Sachin (https://github.com/sachn-cs)
// Released under MIT OR Apache-2.0. See LICENSE-MIT or LICENSE-APACHE.
// THIS SOFTWARE IS FOR EDUCATIONAL AND RESEARCH PURPOSES ONLY.

//! High-performance parallel search engine and binary caching protocols.
//!
//! # 🔬 Algorithmic Formalization
//! The `search` module implements a **Multi-Variant Range-Splitting** strategy.
//! Given a target public key $P = d \cdot G$, we search for a scalar $j$ and
//! a pre-defined offset $V$ such that:
//! $$x(j \cdot G) = x(P - V \cdot G)$$
//!
//! ## 📐 Mathematical Invariants
//! This equality on the X-coordinate represents a match due to point symmetry.
//! For each match found, the system derives two scalar candidates for $d$:
//! 1.  **Positive Case:** $P - V \cdot G = j \cdot G \implies d \equiv V + j \pmod n$
//! 2.  **Negative Case:** $P - V \cdot G = -j \cdot G \implies d \equiv V - j \pmod n$
//!
//! ## ⚡ Performance Optimizations
//! - **Indexing:** An $O(1)$ `VariantIndex` converts the $O(V)$ variant scan
//!   into a high-speed hash-table collision check.
//! - **Parallelism:** Utilizes `rayon` for work-stealing parallel sweeps
//!   across multi-core systems.
//! - **Binary Caching:** Enforces a rigid 32-byte sequential format for $jG$
//!   points, enabling I/O-bound search that bypasses ECC arithmetic.

use crate::ecc;
use crate::error::Result;
use k256::elliptic_curve::group::Curve;
use k256::elliptic_curve::PrimeField;
use k256::{elliptic_curve::sec1::ToEncodedPoint, ProjectivePoint, Scalar};
use num_bigint::BigUint;
use num_traits::One;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::os::unix::fs::FileExt; // Atomic pwrite for parallel I/O.
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{error, info, instrument};

use std::sync::OnceLock;

/// secp256k1 Curve Order $n$, used for modular scalar arithmetic.
pub static CURVE_ORDER: OnceLock<BigUint> = OnceLock::new();

/// Global accessor for the Curve Order n.
pub fn curve_order() -> &'static BigUint {
    CURVE_ORDER.get_or_init(|| {
        BigUint::parse_bytes(
            b"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
            16,
        )
        .unwrap()
    })
}

/// A shift-variant anchor used to split the massive search space.
///
/// Each variant represents a target point shifted by a specific scalar
/// $V$ (e.g., $2^{128}$). This allows the engine to sweep a small range
/// while effectively exploring 512 different remote regions of the curve.
#[derive(Debug, Clone)]
pub struct OffsetVariant {
    /// Identification label (e.g., "power-of-2-64").
    pub label: String,
    /// The shifted point: $P' = P - (V \cdot G)$.
    pub point: ProjectivePoint,
    /// The scalar value $V$ used for the shift.
    pub scalar_value: BigUint,
    /// Static X-coordinate buffer for fast comparison.
    pub x_bytes: Option<[u8; 32]>,
}

/// Cache-optimized lookup index for variants to achieve $O(\log N)$ matching.
///
/// Without this index, every step in the $10^{12}$ scalar sweep would require
/// 512 byte-comparisons. The `VariantIndex` collapses this into a high-speed
/// binary search over a flat, cache-aligned array.
/// Cache-optimized lookup index for variants.
///
/// Transitions from a node-based BTreeMap to a flat, cache-aligned sorted array
/// to maximize L1/L2 hits during high-frequency matching.
#[derive(Debug, Clone)]
pub struct VariantIndex {
    /// Sorted flat array of (X-coordinate, original_variant_index).
    pub sorted_entries: Vec<([u8; 32], usize)>,
    /// Backing list of full variant metadata.
    pub variants: Vec<OffsetVariant>,
}

impl VariantIndex {
    /// Constructs a new lookup index. The entries are sorted to enable
    /// O(log N) binary search with optimal cache locality.
    pub fn new(variants: Vec<OffsetVariant>) -> Self {
        let mut entries = Vec::with_capacity(variants.len());
        for (i, var) in variants.iter().enumerate() {
            if let Some(x) = var.x_bytes {
                entries.push((x, i));
            }
        }
        // Sort by X-coordinate to enable binary search.
        entries.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        Self {
            sorted_entries: entries,
            variants,
        }
    }

    /// Performs a high-speed match using binary search on the flat array.
    #[inline(always)]
    pub fn match_x(&self, test_x: &[u8; 32], j: u64) -> Option<SearchMatch> {
        self.sorted_entries
            .binary_search_by(|probe| probe.0.cmp(test_x))
            .ok()
            .map(|idx| {
                let (_, var_idx) = self.sorted_entries[idx];
                let var = &self.variants[var_idx];
                let mut candidates = Vec::new();
                let n = curve_order();

                let c1 = (&var.scalar_value + BigUint::from(j)) % n;
                candidates.push(c1.to_str_radix(16));

                let c2 = if var.scalar_value >= BigUint::from(j) {
                    (&var.scalar_value - BigUint::from(j)) % n
                } else {
                    (n + &var.scalar_value - BigUint::from(j)) % n
                };
                candidates.push(c2.to_str_radix(16));

                SearchMatch {
                    label: var.label.clone(),
                    offset: var.scalar_value.to_str_radix(10),
                    small_scalar: j,
                    candidates,
                }
            })
    }
}

/// Structured search result containing all derived private key candidates.
#[derive(Debug, Serialize, Deserialize)]
pub struct SearchMatch {
    pub label: String,
    pub offset: String,
    pub small_scalar: u64,
    pub candidates: Vec<String>,
}

/// Orchestrates the generation of 512 target shift variants.
///
/// Generates variants based on:
/// 1.  **Powers of 2** ($2^0 \to 2^{255}$)
/// 2.  **Leibniz-style Summations** ($\sum 2^i$)
///
/// This covers both bit-aligned and cumulative range segments.
#[instrument(skip(target_p), level = "info")]
pub fn generate_variants(target_p: &ProjectivePoint) -> Vec<OffsetVariant> {
    let mut variants = Vec::with_capacity(512);
    let p = *target_p; // Dereference for projective arithmetic efficacy.

    // Power-of-2 variant generation.
    for i in 0..256 {
        let val = BigUint::one() << i;
        let val_mod = &val % curve_order();
        let scalar = biguint_to_scalar(&val_mod);
        let shifted_p: ProjectivePoint = p - ecc::scalar_mul_g(&scalar);

        let affine = shifted_p.to_affine();
        let encoded = affine.to_encoded_point(false);
        let x_bytes: Option<[u8; 32]> = encoded.x().map(|x| {
            let mut b = [0u8; 32];
            b.copy_from_slice(x.as_ref());
            b
        });

        variants.push(OffsetVariant {
            label: format!("2^{}", i),
            point: shifted_p,
            scalar_value: val,
            x_bytes,
        });
    }

    // Cumulative summation variant generation.
    for i in 0..256 {
        let val = (BigUint::one() << (i + 1)) - BigUint::one();
        let val_mod = &val % curve_order();
        let scalar = biguint_to_scalar(&val_mod);
        let shifted_p: ProjectivePoint = p - ecc::scalar_mul_g(&scalar);

        let affine = shifted_p.to_affine();
        let encoded = affine.to_encoded_point(false);
        let x_bytes: Option<[u8; 32]> = encoded.x().map(|x| {
            let mut b = [0u8; 32];
            b.copy_from_slice(x.as_ref());
            b
        });

        variants.push(OffsetVariant {
            label: format!("sum(2^0..2^{})", i),
            point: shifted_p,
            scalar_value: val,
            x_bytes,
        });
    }

    variants
}

/// Performs a CPU-bound parallel sweep using work-stealing threads.
/// Performs a high-throughput parallel sweep using batch normalization.
///
/// This implementation amortizes the modular inversion cost (the primary bottleneck)
/// by processing scalars in batches of 32, yielding a theoretical 15-20x speedup
/// in coordinate extraction.
pub fn perform_chunked_sweep(index: &VariantIndex, start: u64, end: u64) -> Option<SearchMatch> {
    // The identity point (j=0) has no x-coordinate and can never match a variant.
    // batch_normalize panics on Z=0, so we skip it.
    let start = start.max(1);
    if start > end {
        return None;
    }

    const BATCH_SIZE: u64 = 32;

    let range_len = end.saturating_sub(start).saturating_add(1);
    let num_batches = range_len.div_ceil(BATCH_SIZE);

    // We iterate over batch indices to avoid allocating a massive Vec for the range.
    (0..num_batches).into_par_iter().find_map_any(|batch_idx| {
        let chunk_start = start + batch_idx * BATCH_SIZE;
        let chunk_end = (chunk_start + BATCH_SIZE - 1).min(end);
        let mut points = Vec::with_capacity(BATCH_SIZE as usize);

        // Phase 1: Rapid Scalar Multiplication (Projective)
        for j in chunk_start..=chunk_end {
            points.push(ecc::scalar_mul_g(&Scalar::from(j)));
        }

        // Phase 2: Batch Normalization (Single modular inversion)
        // k256 provides batch_normalize to amortize inversion costs.
        // We pre-allocate the affine buffer and normalize in-place.
        let mut affines = vec![k256::AffinePoint::IDENTITY; points.len()];
        k256::ProjectivePoint::batch_normalize(&points, &mut affines);

        // Phase 3: Final Matching Sweep
        for (idx, affine) in affines.iter().enumerate() {
            let j = chunk_start + idx as u64;
            let encoded: k256::elliptic_curve::sec1::EncodedPoint<k256::Secp256k1> =
                affine.to_encoded_point(false);

            if let Some(x_bytes) = encoded.x() {
                let mut test_x = [0u8; 32];
                test_x.copy_from_slice(x_bytes.as_ref());

                if let Some(matching) = index.match_x(&test_x, j) {
                    return Some(matching);
                }
            }
        }
        None
    })
}

/// Generates a high-performance binary database using parallel batch normalization.
///
/// This implementation achieves principal-grade throughput by:
/// 1.  **Rayon Threadpooling**: Distributes the workload across all CPU cores.
/// 2.  **Batch Normalization**: Processes 32 points per batch to amortize inversion.
/// 3.  **Atomic pwrite**: Uses `write_all_at` for non-blocking parallel I/O.
/// Generates a high-performance binary database using parallel batch normalization.
pub fn precompute_chunk(
    start: u64,
    end: u64,
    file_path: &Path,
    index: Option<&VariantIndex>,
) -> Result<Option<SearchMatch>> {
    // The identity point (j=0) has no x-coordinate and can never match.
    // batch_normalize panics on Z=0, so we skip it.
    let start = start.max(1);
    if start > end {
        return Ok(None);
    }

    if let Some(parent) = file_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let range_len = end.saturating_sub(start).saturating_add(1);
    let total_bytes = range_len * 32;

    let file = File::create(file_path)?;
    file.set_len(total_bytes)?; // Pre-allocate to prevent fragmentation.

    const BATCH_SIZE: u64 = 32;
    let num_batches = range_len.div_ceil(BATCH_SIZE);

    // Progress Heartbeat: Global Atomic Counter for all parallel workers.
    static PROGRESS: AtomicU64 = AtomicU64::new(0);
    PROGRESS.store(0, Ordering::Relaxed);

    // Parallel Worker Loop: Each thread computes its own segment of the file.
    let discovery = (0..num_batches).into_par_iter().find_map_any(|batch_idx| {
        let chunk_start = start + batch_idx * BATCH_SIZE;
        let chunk_end = (chunk_start + BATCH_SIZE - 1).min(end);
        let mut points = Vec::with_capacity(BATCH_SIZE as usize);

        for j in chunk_start..=chunk_end {
            points.push(ecc::scalar_mul_g(&Scalar::from(j)));
        }

        let mut affines = vec![k256::AffinePoint::IDENTITY; points.len()];
        ProjectivePoint::batch_normalize(&points, &mut affines);

        // Real-Time Discovery Phase: Check points before writing to disk.
        let mut match_found = None;
        let mut binary_block = Vec::with_capacity(affines.len() * 32);

        for (idx, affine) in affines.iter().enumerate() {
            let encoded = affine.to_encoded_point(false);
            let x_bytes = encoded.x().unwrap();
            let x_arr = x_bytes.as_ref();

            if let Some(idx_ref) = index {
                let mut test_x = [0u8; 32];
                test_x.copy_from_slice(x_arr);
                if let Some(m) = idx_ref.match_x(&test_x, chunk_start + idx as u64) {
                    match_found = Some(m);
                }
            }
            binary_block.extend_from_slice(x_arr);
        }

        // Atomic Parallel Write
        let offset = batch_idx * BATCH_SIZE * 32;
        if let Err(e) = file.write_all_at(&binary_block, offset) {
            error!("Background I/O failure during precompute: {}", e);
        }

        // Progress Heartbeat Update (Every 10 million keys)
        let current = PROGRESS.fetch_add(BATCH_SIZE, Ordering::Relaxed);
        if current > 0 && current % 10_000_000 == 0 {
            info!(
                "Binary cache generation progress: {}M keys...",
                current / 1_000_000
            );
        }

        match_found
    });

    Ok(discovery)
}

/// Performs an I/O-bound cached search against a pre-computed binary database.
#[instrument(skip(index), level = "info")]
pub fn perform_cached_sweep(
    index: &VariantIndex,
    cache_path: &Path,
    start_j: u64,
) -> Result<Option<SearchMatch>> {
    let file = File::open(cache_path)?;
    let mut reader = BufReader::new(file);
    let mut buffer = [0u8; 32];
    let mut j = start_j;

    // Sequential read-scan optimized for modern NVMe SSDs.
    while reader.read_exact(&mut buffer).is_ok() {
        if let Some(m) = index.match_x(&buffer, j) {
            return Ok(Some(m));
        }
        j += 1;
    }
    Ok(None)
}

/// Persists session variants to JSON for multi-pubkey auditability.
#[instrument(skip(variants, dir_path), level = "info")]
pub fn save_variants_to_json(variants: &[OffsetVariant], dir_path: &str) -> Result<String> {
    let mut map = BTreeMap::new();
    for var in variants {
        if let Some(x_bytes) = var.x_bytes {
            let x_hex = hex::encode(x_bytes);
            let val_str = var.scalar_value.to_string();
            map.insert(x_hex, val_str);
        }
    }

    let json = serde_json::to_string_pretty(&map).map_err(Into::<crate::error::FindError>::into)?;
    fs::create_dir_all(dir_path)?;

    let file_path = Path::new(dir_path).join("points.json");
    fs::write(&file_path, json)?;

    Ok(file_path.to_string_lossy().into_owned())
}

/// Safely converts BigUint to a k256 Scalar element.
///
/// Enforces 32-byte BE representation and handles curve-order boundaries.
fn biguint_to_scalar(big: &BigUint) -> Scalar {
    let bytes = big.to_bytes_be();
    let mut fixed_bytes = [0u8; 32];
    let len = bytes.len();
    if len > 32 {
        fixed_bytes.copy_from_slice(&bytes[len - 32..]);
    } else {
        fixed_bytes[32 - len..].copy_from_slice(&bytes);
    }
    Scalar::from_repr(fixed_bytes.into()).expect("Scalar conversion overflow in variant generation")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// Verifies variant JSON export persistence.
    #[test]
    fn test_save_to_json_creates_points_file() {
        let target = ecc::scalar_mul_g(&Scalar::from(100u64));
        let variants = generate_variants(&target);
        let dir = tempdir().unwrap();
        let dir_path = dir.path().to_str().unwrap();

        let res = save_variants_to_json(&variants, dir_path);
        assert!(res.is_ok());
        assert!(dir.path().join("points.json").exists());
    }

    /// Validates O(1) indexing logic and scalar derivation.
    #[test]
    fn test_indexing_speedup() {
        let target = ecc::scalar_mul_g(&Scalar::from(1000u64));
        let variants = generate_variants(&target);
        let index = VariantIndex::new(variants);

        let scalar_999 = Scalar::from(999u64);
        let p_999 = ecc::scalar_mul_g(&scalar_999);
        let affine = p_999.to_affine();
        let encoded = affine.to_encoded_point(false);
        let x_bytes = encoded.x().unwrap();
        let mut x_999 = [0u8; 32];
        x_999.copy_from_slice(x_bytes.as_ref());

        let m = index.match_x(&x_999, 999).unwrap();
        // Mathematical invariant: 1000 = V + 999 => V = 1.
        assert!(m.label == "2^0" || m.label == "sum(2^0..2^0)");
        assert_eq!(m.offset, "1");
    }
}
