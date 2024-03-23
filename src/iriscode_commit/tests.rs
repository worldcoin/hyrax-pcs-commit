use std::fs;
use std::io::{BufWriter, Read};

use halo2_base::utils::ScalarField;

use crate::curves::PrimeOrderCurve;
use crate::iriscode_commit::{
    deserialize_blinding_factors_from_bytes_compressed_concrete,
    deserialize_commitment_from_bytes_compressed_concrete,
};

/// Helper function for buffered writing to file.
fn write_bytes_to_file(filename: &str, bytes: &[u8]) {
    let file = fs::File::create(filename).unwrap();
    let bw = BufWriter::new(file);
    serde_json::to_writer(bw, &bytes).unwrap();
}

/// Helper function for buffered reading from file.
fn read_bytes_from_file(filename: &str) -> Vec<u8> {
    let mut file = std::fs::File::open(filename).unwrap();
    let initial_buffer_size = file.metadata().map(|m| m.len() as usize + 1).unwrap_or(0);
    let mut bufreader = Vec::with_capacity(initial_buffer_size);
    file.read_to_end(&mut bufreader).unwrap();
    serde_json::de::from_slice(&bufreader[..]).unwrap()
}

#[test]
fn test_serialize_end_to_end() {
    use crate::iriscode_commit::{
        compute_commitments, HyraxCommitmentOutput, LOG_NUM_COLS, PUBLIC_STRING,
    };
    use crate::pedersen::PedersenCommitter;
    use std::time::Instant;

    use halo2_base::halo2_proofs::halo2curves::bn256::G1 as Bn256Point;
    use itertools::Itertools;
    use rand::RngCore;
    use rand_core::OsRng;

    // image is 128 x 1024 = 2^17 in size
    const LOG_IMAGE_SIZE: usize = 17;
    const TEST_COMMITMENT_FILENAME: &str = "test-commitment-iris-image.json";
    const TEST_BLINDING_FACTORS_FILENAME: &str = "test-blinding-factors-iris-image.json";

    // --- Generate a random image to be committed to; this is a stand-in for the iris image ---
    let iris_image = (0..1 << LOG_IMAGE_SIZE)
        .map(|_| rand::random::<u8>())
        .collect_vec();

    let start_time = Instant::now();

    // --- Sample randomness for the generation of the blinding factors ---
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);

    // --- Compute generators ---
    let vector_committer: PedersenCommitter<Bn256Point> =
        PedersenCommitter::new(1 << LOG_NUM_COLS, PUBLIC_STRING);

    // --- Do commitment and output blinding factors ---
    let HyraxCommitmentOutput {
        commitment,
        blinding_factors,
    } = compute_commitments(&iris_image, &vector_committer, seed);

    println!("Computing commitment took: {:?}", start_time.elapsed());

    // --- Serialize into binary ---
    let commitment_serialized: Vec<u8> = commitment
        .iter()
        .flat_map(|element| element.to_bytes_compressed())
        .collect_vec();
    let blinding_factors_serialized: Vec<u8> = blinding_factors
        .iter()
        .flat_map(|element| element.to_bytes_le())
        .collect_vec();

    // --- Sample serialization to file (iris image, blinding factors) ---
    write_bytes_to_file(TEST_COMMITMENT_FILENAME, &commitment_serialized);
    write_bytes_to_file(TEST_BLINDING_FACTORS_FILENAME, &blinding_factors_serialized);

    // --- Sample serialization from file (iris image, blinding factors) ---
    let commitment_bytes_from_file = read_bytes_from_file(TEST_COMMITMENT_FILENAME);
    let blinding_factors_bytes_from_file = read_bytes_from_file(TEST_BLINDING_FACTORS_FILENAME);

    // --- Sanitycheck vs. bytes ---
    assert_eq!(commitment_serialized, commitment_bytes_from_file);
    assert_eq!(
        blinding_factors_bytes_from_file,
        blinding_factors_serialized
    );

    // --- Deserialize from bytes ---
    let deserialized_commitment =
        deserialize_commitment_from_bytes_compressed_concrete(&commitment_bytes_from_file);
    let deserialized_blinding_factors = deserialize_blinding_factors_from_bytes_compressed_concrete(
        &blinding_factors_bytes_from_file,
    );

    // --- Sanitycheck vs. original commitment/blinding factors ---
    assert_eq!(deserialized_commitment, commitment);
    assert_eq!(deserialized_blinding_factors, blinding_factors);
}
