/// Measure how long it takes to commit to the Worldcoin iris image, arranged as a square matrix.
/// Random u8 values are used as a stand in for the normalized iris image.
use halo2curves::bn256::G1 as Bn256;
use hyrax::iriscode_commit::compute_matrix_commitments;
use hyrax::pedersen::PedersenCommitter;
use itertools::Itertools;
use rand::RngCore;
use rand_core::OsRng;
use std::fs;
use std::io::{BufWriter, Read};
use std::time::Instant;

const LOG_IMAGE_SIZE: usize = 17;
const LOG_SPLIT_POINT: usize = 9;
const FILENAME: &str = "commitment-iris-image.json";

// --- Public string used to derive the generators (arbitrary, but must not change) ---
const PUBLIC_STRING: &str = "accountable magic abcdefghijklmnopqrstuvwxyz";

/// Usage: `cargo run --release` from this directory (remainder-hyrax-tfh/hyrax/src/bin)
fn main() {
    // --- Generating random matrix to be committed to; this is a stand-in for the iris image ---
    let iris_image = (0..1 << LOG_IMAGE_SIZE)
        .map(|_| rand::random::<u8>())
        .collect_vec();

    let start_time = Instant::now();
    // generate a Pedersen Committer struct that includes all of the generators (`g_i`) needed in order
    // to commit to the message, along with the generator `h` that is needed in order to blind the message.
    // uses the default constructor which samples the generators deterministically using the Shake256 hash function.
    // public string is arbitrary for now.
    let vector_committer: PedersenCommitter<Bn256> = PedersenCommitter::new(
        1 << LOG_SPLIT_POINT,
        PUBLIC_STRING,
    );
    println!("Setup of the committer took: {:?}", start_time.elapsed());

    let start_time = Instant::now();
    // --- Randomness for blinding factors (note that `OsRng` calls `/dev/urandom` under the hood!) ---
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    // --- The actual commitment function which you will call ---
    let commitment = compute_matrix_commitments(&iris_image, &vector_committer, seed);
    println!("Computing commitment took: {:?}", start_time.elapsed());

    // --- Serialization ---
    let file = fs::File::create(FILENAME).unwrap();
    let bw = BufWriter::new(file);
    serde_json::to_writer(bw, &commitment).unwrap();

    // --- Deserialization ---
    let mut file = std::fs::File::open(FILENAME).unwrap();
    let initial_buffer_size = file.metadata().map(|m| m.len() as usize + 1).unwrap_or(0);
    let mut bufreader = Vec::with_capacity(initial_buffer_size);
    file.read_to_end(&mut bufreader).unwrap();
    let commitment_deserialized: Vec<Bn256> = serde_json::de::from_slice(&bufreader[..]).unwrap();

    assert_eq!(commitment, commitment_deserialized);
}
