/// Measure how long it takes to commit to the Worldcoin iris image, arranged as a square matrix.
/// Random u8 values are used.
use halo2curves::bn256::G1 as Bn256;
use hyrax::curves::PrimeOrderCurve;
use hyrax::iriscode_commit::compute_matrix_commitments;
use hyrax::pedersen::PedersenCommitter;
use itertools::Itertools;
use rand::RngCore;
use rand_core::OsRng;
use std::fs;
use std::io::{BufWriter, Read};
use std::time::Instant;

type Scalar = <Bn256 as PrimeOrderCurve>::Scalar;

const N_ROWS: usize = 1 << 8;
const N_COLS: usize = 1 << 9;

fn compute_commitment(
    filepath: &str,
    n_rows: usize,
    n_cols: usize,
    log_split_point: usize,
) -> Vec<Bn256> {
    // --- Generating random matrix to be committed to; same size as iris image ---
    let u8_matrix = (0..n_rows * n_cols)
        .map(|_| rand::random::<u8>())
        .collect_vec();
    let vector_committer: PedersenCommitter<Bn256> = PedersenCommitter::new(
        N_COLS,
        "accountable magic abcdefghijklmnopqrstuvwxyz",
        Some(8),
    );

    // --- Randomness for blinding factors (note that `OsRng` calls `/dev/urandom` under the hood!) ---
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);

    // --- The actual commitment function which you will call ---
    let commitment =
        compute_matrix_commitments(log_split_point, &u8_matrix, &vector_committer, seed);

    // --- Serialization ---
    let file = fs::File::create(filepath).unwrap();
    let bw = BufWriter::new(file);
    serde_json::to_writer(bw, &commitment).unwrap();

    // --- Return commitment ---
    commitment
}

/// Usage: `cargo run --release` from this directory (remainder-hyrax-tfh/hyrax/src/bin)
fn main() {
    let start_time = Instant::now();
    let log_split_point = 9;
    let commit = compute_commitment("test5.json", N_ROWS, N_COLS, log_split_point);
    println!(
        "Computing {} vector commitments, each of length {}, took: {:?}",
        N_ROWS,
        N_COLS,
        start_time.elapsed()
    );

    // testing deserialization
    let mut file = std::fs::File::open("test5.json").unwrap();
    let initial_buffer_size = file.metadata().map(|m| m.len() as usize + 1).unwrap_or(0);
    let mut bufreader = Vec::with_capacity(initial_buffer_size);
    file.read_to_end(&mut bufreader).unwrap();
    let commit_deserialized: Vec<Bn256> = serde_json::de::from_slice(&bufreader[..]).unwrap();

    assert_eq!(commit, commit_deserialized);
}
