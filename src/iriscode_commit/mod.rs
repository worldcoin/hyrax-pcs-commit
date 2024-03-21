use super::curves::PrimeOrderCurve;
use crate::pedersen::PedersenCommitter;
use halo2_base::halo2_proofs::arithmetic::Field;
use itertools::Itertools;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// this function computes the commitments to the rows of the matrix. essentially, this is the vector of
/// commitments that the prover should be sending over to the verifier.
pub fn compute_matrix_commitments<C: PrimeOrderCurve>(
    input_layer_mle: &[u8],
    vector_committer: &PedersenCommitter<C>,
    blinding_factor_seed: [u8; 32],
) -> Vec<C> {
    assert!(input_layer_mle.len().is_power_of_two());
    // calculate the number of blinding factors needed, which is exactly the number of rows in the matrix
    let n_cols = vector_committer.message_generators.len();
    let n_rows = input_layer_mle.len() / n_cols;

    let mut prng = ChaCha20Rng::from_seed(blinding_factor_seed);
    let blinding_factors = (0..n_rows)
        .map(|_idx| C::Scalar::random(&mut prng))
        .collect_vec();

    // we are using the vector_commit to commit to each of the rows of the matrix
    let row_chunks = input_layer_mle.chunks(n_cols);
    row_chunks
        .zip(blinding_factors.iter())
        .map(|(chunk, blind)| vector_committer.vector_commit(&chunk, blind))
        .collect_vec()
}
