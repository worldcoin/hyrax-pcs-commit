/// Measure how long it takes to commit to the Worldcoin iris image.
/// Random u8 values are used as a stand in for the normalized iris image.
use hyrax::iriscode_commit::{compute_commitments_binary_outputs, HyraxCommitmentOutputSerialized};
use hyrax::utils::{read_bytes_from_file, write_bytes_to_file, INPUT_NORMALIZED_IMAGE_FILENAME, COMMITMENT_FILENAME, BLINDING_FACTORS_FILENAME};
use rand::RngCore;
use rand_core::OsRng;
use std::time::Instant;

/// Usage: `cargo run --release` from this directory (remainder-hyrax-tfh/hyrax/src/bin)
fn main() {
    // Read a dummy image from file
    let iris_image = read_bytes_from_file(INPUT_NORMALIZED_IMAGE_FILENAME);

    let start_time = Instant::now();

    // Sample randomness for the generation of the blinding factors (note that `OsRng` calls `/dev/urandom` under the hood)
    // (You will need to do this with what you determine is a good source of entropy!)
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
