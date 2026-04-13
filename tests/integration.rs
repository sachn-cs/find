use find::ecc;
use find::search::{self, VariantIndex};
use k256::elliptic_curve::PrimeField;
use k256::Scalar;
use num_bigint::BigUint;
use proptest::prelude::*;

/// Mathematical constant: secp256k1 Curve Order n.
const CURVE_ORDER_HEX: &str = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";

// --- MANDATORY RANDOMIZED TEST (6-8 DIGITS) ---

#[test]
fn test_mandatory_random_6_to_8_digits() {
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    let mut rng = ChaCha8Rng::seed_from_u64(42);
    let j: u64 = rng.gen_range(100_000..=99_999_999);

    // Set d = V + j where V = 2^64
    let v_scalar = BigUint::from(1u64) << 64;
    let n = BigUint::parse_bytes(CURVE_ORDER_HEX.as_bytes(), 16).unwrap();
    let d_biguint: BigUint = (&v_scalar + BigUint::from(j)) % &n;

    let target_scalar = biguint_to_scalar(&d_biguint);
    let target_p = ecc::scalar_mul_g(&target_scalar);

    let variants = search::generate_variants(&target_p);
    let index = VariantIndex::new(variants);

    let result = search::perform_chunked_sweep(&index, j, j);
    assert!(result.is_some(), "Match not found for 6-8 digit scalar");

    let m = result.unwrap();
    let expected_d_hex = d_biguint.to_str_radix(16);
    // Ensure both match (case insensitive if needed, but rad(16) is lower)
    assert!(m
        .candidates
        .iter()
        .any(|c| c.to_lowercase() == expected_d_hex.to_lowercase()));
}

// --- BOUNDARY & EDGE CASES ---

#[test]
fn test_boundary_min_6_digits() {
    run_controlled_test(100_000, 10, "Minimum 6-digit boundary");
}

#[test]
fn test_boundary_max_8_digits() {
    run_controlled_test(99_999_999, 20, "Maximum 8-digit boundary");
}

#[test]
fn test_edge_repeated_digits() {
    run_controlled_test(111_111, 30, "Repeated digits");
}

#[test]
fn test_edge_alternating_pattern() {
    run_controlled_test(121_212, 40, "Alternating pattern");
}

#[test]
fn test_edge_palindromic() {
    run_controlled_test(123_321, 50, "Palindromic scalar");
}

#[test]
fn test_edge_single_digit() {
    run_controlled_test(1, 1, "Single digit j");
}

// --- PROPERTY-BASED TESTING ---

proptest! {
    #![proptest_config(ProptestConfig::with_cases(20))]
    #[test]
    fn prop_search_finds_any_scalar_in_range(j in 1u64..100_000u64) {
        let v_val = BigUint::from(1u64) << 10;
        let n = BigUint::parse_bytes(CURVE_ORDER_HEX.as_bytes(), 16).unwrap();
        let d_val: BigUint = (&v_val + BigUint::from(j)) % &n;

        let target_scalar = biguint_to_scalar(&d_val);
        let target_p = ecc::scalar_mul_g(&target_scalar);
        let variants = search::generate_variants(&target_p);
        let index = VariantIndex::new(variants);

        let result = search::perform_chunked_sweep(&index, j, j);
        prop_assert!(result.is_some());
        let m = result.unwrap();
        let expected_hex = d_val.to_str_radix(16);
        prop_assert!(m.candidates.iter().any(|c| c.to_lowercase() == expected_hex.to_lowercase()));
    }
}

// --- FAILURE & INTEGRATION ---

#[test]
fn test_failure_malformed_hex() {
    let malformed = "not_hex_at_all";
    let res = ecc::parse_pubkey(malformed);
    assert!(res.is_err());
}

#[test]
fn test_idempotency_deterministic_output() {
    let j = 555_555u64;
    let v_val = BigUint::from(1u64) << 20;
    let d_val: BigUint = v_val + BigUint::from(j);

    let target_scalar = biguint_to_scalar(&d_val);
    let target_p = ecc::scalar_mul_g(&target_scalar);
    let variants = search::generate_variants(&target_p);
    let index = VariantIndex::new(variants);

    let res1 = search::perform_chunked_sweep(&index, j, j).unwrap();
    let res2 = search::perform_chunked_sweep(&index, j, j).unwrap();

    let expected_hex = d_val.to_str_radix(16);
    assert!(res1
        .candidates
        .iter()
        .any(|c| c.to_lowercase() == expected_hex.to_lowercase()));
    assert!(res2
        .candidates
        .iter()
        .any(|c| c.to_lowercase() == expected_hex.to_lowercase()));
}

// --- HELPER ---

fn run_controlled_test(j: u64, v_power: u32, label: &str) {
    let v_val = BigUint::from(1u64) << v_power;
    let n = BigUint::parse_bytes(CURVE_ORDER_HEX.as_bytes(), 16).unwrap();
    let d_val: BigUint = (&v_val + BigUint::from(j)) % &n;

    let target_scalar = biguint_to_scalar(&d_val);
    let target_p = ecc::scalar_mul_g(&target_scalar);
    let variants = search::generate_variants(&target_p);
    let index = VariantIndex::new(variants);

    let result = search::perform_chunked_sweep(&index, j, j);
    assert!(result.is_some(), "Failed boundary/edge test: {}", label);
}

fn biguint_to_scalar(big: &BigUint) -> Scalar {
    let bytes = big.to_bytes_be();
    let mut fixed_bytes = [0u8; 32];
    let len = bytes.len();
    if len > 32 {
        fixed_bytes.copy_from_slice(&bytes[len - 32..]);
    } else {
        fixed_bytes[32 - len..].copy_from_slice(&bytes);
    }
    Scalar::from_repr(fixed_bytes.into()).expect("Scalar overflow in test")
}
