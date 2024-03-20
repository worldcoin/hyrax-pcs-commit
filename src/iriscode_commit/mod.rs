use super::curves::PrimeOrderCurve;
use crate::pedersen::PedersenCommitter;
use halo2_base::halo2_proofs::arithmetic::Field;
use itertools::Itertools;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// this function computes the commitments to the rows of the matrix. essentially, this is the vector of
/// commitments that the prover should be sending over to the verifier.
pub fn compute_matrix_commitments<C: PrimeOrderCurve>(
    // the log-size of the matrix rows. both the row size and the column size need to be powers of 2
    // for hyrax to work!
    log_split_point: usize,
    input_layer_mle: &[u8],
    vector_committer: &PedersenCommitter<C>,
    blinding_factor_seed: [u8; 32],
    // blinding_factors: &Vec<C::Scalar>,
) -> Vec<C> {
    // the number of blidning factors needed, which is exactly the number of rows in the matrix
    let num_blinding_factors_needed = input_layer_mle.len() / (1 << log_split_point);
    // checking that the matrix row size and the matrix column size are both powers of two! otherwise hyrax does not work
    assert!(input_layer_mle.len().is_power_of_two());
    let mut prng = ChaCha20Rng::from_seed(blinding_factor_seed);

    let blinding_factors = (0..num_blinding_factors_needed)
        .map(|_idx| C::Scalar::random(&mut prng))
        .collect_vec();

    // we are using the u8_vector_commit to commit to each of the rows of the matrix, which are determined by
    // the log_split_point!
    let row_chunks = input_layer_mle.chunks(1 << log_split_point);
    // we need to make sure that the number of blinding factors we have computed is equal to the number of rows
    assert_eq!(row_chunks.len(), num_blinding_factors_needed);
    row_chunks
        .zip(blinding_factors.iter())
        .map(|(chunk, blind)| vector_committer.u8_vector_commit(&chunk.to_vec(), blind))
        .collect_vec()
}
