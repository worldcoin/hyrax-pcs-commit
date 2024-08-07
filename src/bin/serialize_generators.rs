use ark_bn254::G1Projective as Bn256Point;
use hyrax::curves::PrimeOrderCurve;
use hyrax::iriscode_commit::{LOG_NUM_COLS, PUBLIC_STRING};
use hyrax::pedersen::PedersenCommitter;
use itertools::Itertools;
use std::fs;
use std::io::BufWriter;
// this is the file that the serialized generators are stored in.
const SERIALIZED_GENERATORS_FILENAME: &str = "examples/e2etesting/sample-generators.json";

/// Helper function for buffered writing to file.
fn write_bytes_to_file(filename: &str, bytes: &[u8]) {
    let file = fs::File::create(filename).unwrap();
    let bw = BufWriter::new(file);
    serde_json::to_writer(bw, &bytes).unwrap();
}

/// Usage: `cargo run --release` from this directory (remainder-hyrax-tfh/hyrax/src/bin)
fn main() {
    // Create committer, which auto-samples the generators using [PUBLIC_STRING]
    let vector_committer: PedersenCommitter<Bn256Point> =
        PedersenCommitter::new(1 << LOG_NUM_COLS, PUBLIC_STRING);

    // Serialize the generators
    let serialized_generators = vector_committer
        .generators
        .iter()
        .flat_map(|element| element.to_bytes_compressed())
        .collect_vec();

    // Sample serialization to file (iris image, blinding factors)
    write_bytes_to_file(SERIALIZED_GENERATORS_FILENAME, &serialized_generators);
}
