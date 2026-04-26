use find::ecc;
use find::orchestrator::{run, Config};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use std::time::Instant;
use tempfile::tempdir;

/// Verifies that [`run`] discovers a match for a small known scalar.
///
/// The target scalar is d = 5, which implies a match in the very first
/// batch of the sweep (j = 2 or j = 4), so the test completes quickly.
#[test]
fn test_orchestrator_finds_small_scalar() {
    let d_hex = "05";
    let target_p = ecc::scalar_mul_g(&ecc::hex_to_scalar(d_hex).unwrap());
    let encoded = target_p.to_affine().to_encoded_point(true);
    let pubkey = hex::encode(encoded.as_bytes());

    let dir = tempdir().unwrap();
    let output_dir = dir.path().join("data");
    let log_dir = dir.path().join("logs");
    std::fs::create_dir_all(&log_dir).unwrap();

    let config = Config {
        pubkey,
        output_dir: output_dir.to_string_lossy().into_owned(),
        cache_points: false,
    };

    let start = Instant::now();
    let result = run(&config);
    let elapsed = start.elapsed();

    assert!(
        result.is_ok(),
        "Orchestrator must not error for small target: {:?}",
        result.err()
    );
    let m = result.unwrap();
    assert!(
        m.is_some(),
        "Orchestrator must find a match for d=5 within first chunk"
    );
    let m = m.unwrap();
    assert!(
        m.candidates.contains(&"5".to_string()),
        "Candidates must include d=5, got: {:?} (found via {} at j={} after {:?})",
        m.candidates,
        m.label,
        m.small_scalar,
        elapsed
    );
}

/// Verifies that [`run`] rejects a malformed public key.
#[test]
fn test_orchestrator_rejects_malformed_pubkey() {
    let dir = tempdir().unwrap();
    let config = Config {
        pubkey: "not_a_valid_key".to_string(),
        output_dir: dir.path().to_string_lossy().into_owned(),
        cache_points: false,
    };

    let result = run(&config);
    assert!(result.is_err(), "Malformed pubkey must be rejected");
}

/// Verifies that [`Config::validate`] rejects an empty public key.
#[test]
fn test_config_validate_rejects_empty_pubkey() {
    let config = Config {
        pubkey: "   ".to_string(),
        output_dir: "/tmp".to_string(),
        cache_points: false,
    };
    let result = config.validate();
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("cannot be empty"));
}

/// Verifies that [`run`] resumes from a valid checkpoint and still finds the match.
#[test]
fn test_orchestrator_resumes_from_checkpoint() {
    let d_hex = "05";
    let target_p = ecc::scalar_mul_g(&ecc::hex_to_scalar(d_hex).unwrap());
    let encoded = target_p.to_affine().to_encoded_point(true);
    let pubkey = hex::encode(encoded.as_bytes());

    let dir = tempdir().unwrap();
    let output_dir = dir.path().join("data");
    let log_dir = dir.path().join("logs");
    std::fs::create_dir_all(&log_dir).unwrap();

    // Seed a checkpoint with last_j=0 and a valid integrity anchor.
    let boundary_p = ecc::scalar_mul_g(&k256::Scalar::from(0u64));
    let boundary_x = ecc::to_hex_x(&boundary_p);
    let checkpoint = find::persistence::Checkpoint {
        last_j: 0,
        pubkey: pubkey.clone(),
        last_x: boundary_x,
    };
    let cp_path = output_dir.join("checkpoint.json");
    std::fs::create_dir_all(&output_dir).unwrap();
    checkpoint.save_atomic(&cp_path).unwrap();

    let config = Config {
        pubkey,
        output_dir: output_dir.to_string_lossy().into_owned(),
        cache_points: false,
    };

    let result = run(&config);
    assert!(result.is_ok(), "Orchestrator must resume and succeed");
    let m = result.unwrap();
    assert!(
        m.is_some(),
        "Orchestrator must find match after resuming from checkpoint"
    );
    let m = m.unwrap();
    assert!(
        m.candidates.contains(&"5".to_string()),
        "Candidates must include d=5 after resume"
    );
}

/// Verifies that [`run`] discovers a match using the cache-points path.
#[test]
fn test_orchestrator_finds_small_scalar_with_cache() {
    let d_hex = "05";
    let target_p = ecc::scalar_mul_g(&ecc::hex_to_scalar(d_hex).unwrap());
    let encoded = target_p.to_affine().to_encoded_point(true);
    let pubkey = hex::encode(encoded.as_bytes());

    let dir = tempdir().unwrap();
    let output_dir = dir.path().join("data");
    let log_dir = dir.path().join("logs");
    std::fs::create_dir_all(&log_dir).unwrap();

    let config = Config {
        pubkey,
        output_dir: output_dir.to_string_lossy().into_owned(),
        cache_points: true,
    };

    let result = run(&config);
    assert!(
        result.is_ok(),
        "Orchestrator with cache must not error: {:?}",
        result.err()
    );
    let m = result.unwrap();
    assert!(
        m.is_some(),
        "Orchestrator with cache must find a match for d=5"
    );
    let m = m.unwrap();
    assert!(
        m.candidates.contains(&"5".to_string()),
        "Candidates must include d=5 with cache, got: {:?}",
        m.candidates
    );

    // Verify that a cache file was actually written.
    let cache_dir = output_dir.join("checkpoints");
    assert!(cache_dir.exists(), "Cache directory should be created");
    let entries: Vec<_> = std::fs::read_dir(&cache_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    assert!(!entries.is_empty(), "At least one cache chunk should exist");
}
