/// Measure how long it takes to commit to the Worldcoin iris image.
/// Random u8 values are used as a stand in for the normalized iris image.
use halo2_base::halo2_proofs::halo2curves::bn256::G1 as Bn256;
use hyrax::iriscode_commit::{
    compute_commitments, compute_commitments_binary_outputs, HyraxCommitmentOutputSerialized,
};
use hyrax::pedersen::PedersenCommitter;
use hyrax::utils::{read_bytes_from_file, write_bytes_to_file};
use itertools::Itertools;
use rand::RngCore;
use rand_core::OsRng;
use std::time::Instant;

// image is 128 x 1024 = 2^17 in size
const LOG_IMAGE_SIZE: usize = 17;
const COMMITMENT_FILENAME: &str = "commitment-iris-image.json";
const BLINDING_FACTORS_FILENAME: &str = "blinding-factors-iris-image.json";

/// Usage: `cargo build --release && cargo run --release --bin hyrax_commit`
fn main() {
    // Generate a random image to be committed to; this is a stand-in for the iris image ---
    let iris_image = (0..1 << LOG_IMAGE_SIZE)
        .map(|_| rand::random::<u8>())
        .collect_vec();

    let start_time = Instant::now();

    // Sample randomness for the generation of the blinding factors (note that `OsRng` calls `/dev/urandom` under the hood)
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);

    // The actual commitment function, generating commitments and blinding factors
    let HyraxCommitmentOutputSerialized {
        commitment_serialized,
        blinding_factors_serialized,
    } = compute_commitments_binary_outputs(&iris_image, seed);

    println!("Computing commitment took: {:?}", start_time.elapsed());

    // Sample serialization to file (iris image, blinding factors)
    write_bytes_to_file(COMMITMENT_FILENAME, &commitment_serialized);
    write_bytes_to_file(BLINDING_FACTORS_FILENAME, &blinding_factors_serialized);

    // Sample serialization from file (iris image, blinding factors);
    let commitment_bytes_from_file = read_bytes_from_file(COMMITMENT_FILENAME);
    let blinding_factors_bytes_from_file = read_bytes_from_file(BLINDING_FACTORS_FILENAME);

    // Sanitycheck
    assert_eq!(commitment_serialized, commitment_bytes_from_file);
    assert_eq!(
        blinding_factors_bytes_from_file,
        blinding_factors_serialized
    );
}
