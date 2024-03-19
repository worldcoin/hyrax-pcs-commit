use hyrax::curves::PrimeOrderCurve;
use hyrax::pedersen::PedersenCommitter;
/// Measure how long it takes to commit to the Worldcoin iris image, arranged as a square matrix.
/// Random u8 values are used.
use halo2curves::bn256::G1 as Bn256;
use std::time::Instant;

type Scalar = <Bn256 as PrimeOrderCurve>::Scalar;

const N_ROWS: usize = 1 << 9;
const N_COLS: usize = 1 << 9;


fn main() {
    let start_time = Instant::now();
    let u8_matrix: Vec<Vec<u8>> = (0..N_ROWS)
        .map(|_| (0..N_COLS).map(|_| rand::random::<u8>()).collect())
        .collect();
    let blinding_factor = Scalar::from(4u64);
    let u8_committer: PedersenCommitter<Bn256> =
        PedersenCommitter::random(N_COLS, &mut rand::thread_rng(), Some(8));

    for row in u8_matrix {
        let _commitment = u8_committer.u8_vector_commit(&row, &blinding_factor);
    }
    println!("Computing {} vector commitments, each of length {}, took: {:?}", N_ROWS, N_COLS, start_time.elapsed());
}