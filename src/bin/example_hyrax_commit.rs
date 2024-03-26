/// Measure how long it takes to commit to the Worldcoin iris image.
/// Random u8 values are used as a stand in for the normalized iris image.
use hyrax::iriscode_commit::{compute_commitments_binary_outputs, HyraxCommitmentOutputSerialized};
use itertools::Itertools;
use rand::RngCore;
use rand_core::OsRng;
use std::fs;
use std::io::{BufWriter, Read};
use std::time::Instant;

// image is 128 x 1024 = 2^17 in size
const LOG_IMAGE_SIZE: usize = 17;
// this is the file that the image is stored in as an array of bytes. in the example
// function, we create a random "image" and just save this to file.
const INPUT_NORMALIZED_IMAGE_FILENAME: &str = "examples/e2etesting/image-example.json";
// this is the file that the serialized commitment to the iris image is stored in.
const COMMITMENT_FILENAME: &str = "examples/e2etesting/commit-test1.json";
// this is the file that the serialized blinding factors are stored in.
const BLINDING_FACTORS_FILENAME: &str = "examples/e2etesting/bf-test1.json";

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

/// Usage: `cargo run --release` from this directory (remainder-hyrax-tfh/hyrax/src/bin)
fn main() {
    // Generate a random image to be committed to; this is a stand-in for the iris image ---
    let iris_image = (0..1 << LOG_IMAGE_SIZE)
        .map(|_| rand::random::<u8>())
        .collect_vec();

    write_bytes_to_file(INPUT_NORMALIZED_IMAGE_FILENAME, &iris_image);

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
