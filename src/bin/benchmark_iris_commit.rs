/// Measure how long it takes to commit to the Worldcoin iris image.
/// Random u8 values are used as a stand in for the normalized iris image.
use halo2_base::halo2_proofs::halo2curves::bn256::G1 as Bn256;
use hyrax::iriscode_commit::compute_commitments;
use hyrax::pedersen::PedersenCommitter;
use itertools::Itertools;
use rand::RngCore;
use rand_core::OsRng;
use std::fs;
use std::io::{BufWriter, Read};
use std::time::Instant;

// image is 128 x 1024 = 2^17 in size
const LOG_IMAGE_SIZE: usize = 17;
// log of the number of columns in the re-arrangement of the image as a matrix
const LOG_NUM_COLS: usize = 9;
// public string used to derive the generators (arbitrary constant)
const PUBLIC_STRING: &str = "accountable magic abcdefghijklmnopqrstuvwxyz";
const FILENAME: &str = "commitment-iris-image.json";

/// Usage: `cargo run --release` from this directory (remainder-hyrax-tfh/hyrax/src/bin)
fn main() {
    // Generate a random image to be committed to; this is a stand-in for the iris image ---
    let iris_image = (0..1 << LOG_IMAGE_SIZE)
        .map(|_| rand::random::<u8>())
        .collect_vec();

    let start_time = Instant::now();
    // Create a Pedersen Committer struct that includes all of the generators (`g_i`) needed in order
    // to commit to the message, along with the generator `h` that is needed in order to blind the message.
    // Uses the default constructor which samples the generators deterministically using the Shake256 hash function.
    let vector_committer: PedersenCommitter<Bn256> = PedersenCommitter::new(
        1 << LOG_NUM_COLS,
        PUBLIC_STRING,
    );
    println!("Setup of the committer took: {:?}", start_time.elapsed());

    let start_time = Instant::now();
    // Sample randomness for the generation of the blinding factors (note that `OsRng` calls `/dev/urandom` under the hood)
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    // The actual commitment function which you will call
    let commitment = compute_commitments(&iris_image, &vector_committer, seed);
    println!("Computing commitment took: {:?}", start_time.elapsed());

    // Serialization
    let file = fs::File::create(FILENAME).unwrap();
    let bw = BufWriter::new(file);
    serde_json::to_writer(bw, &commitment).unwrap();

    // Deserialization
    let mut file = std::fs::File::open(FILENAME).unwrap();
    let initial_buffer_size = file.metadata().map(|m| m.len() as usize + 1).unwrap_or(0);
    let mut bufreader = Vec::with_capacity(initial_buffer_size);
    file.read_to_end(&mut bufreader).unwrap();
    let commitment_deserialized: Vec<Bn256> = serde_json::de::from_slice(&bufreader[..]).unwrap();

    assert_eq!(commitment, commitment_deserialized);
}
