use super::curves::PrimeOrderCurve;
use crate::pedersen::PedersenCommitter;
use halo2_base::halo2_proofs::arithmetic::Field;
use halo2_base::halo2_proofs::halo2curves::{bn256::G1 as Bn256Point, CurveExt};
use itertools::Itertools;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

// this function computes the commitments to the rows of the matrix. essentially, this is the vector of
// commitments that the prover should be sending over to the verifier.

/// Compute the commitments to the data using the PedersenCommitter.
/// Returns a vector of commitments, one for each chunk of the data
/// (i.e. each row of the data when arranged as a matrix).
/// Blinding factors are generated using the provided seed and the ChaCha20Rng.
/// Pre: data.len().is_power_of_two()
/// Post: result.len() == data.len() / vector_committer.generators.len()
pub fn compute_commitments<C: PrimeOrderCurve>(
    data: &[u8],
    vector_committer: &PedersenCommitter<C>,
    blinding_factor_seed: [u8; 32],
) -> Vec<C> {
    assert!(data.len().is_power_of_two());
    // calculate the number of blinding factors needed (=the number of rows in the matrix)
    let n_cols = vector_committer.generators.len();
    let n_rows = data.len() / n_cols;

    let mut prng = ChaCha20Rng::from_seed(blinding_factor_seed);
    let blinding_factors = (0..n_rows)
        .map(|_idx| C::Scalar::random(&mut prng))
        .collect_vec();

    // we are using the vector_commit to commit to each of the rows of the matrix
    let row_chunks = data.chunks(n_cols);
    row_chunks
        .zip(blinding_factors.iter())
        .map(|(chunk, blind)| vector_committer.vector_commit(&chunk, blind))
        .collect_vec()
}

/// Wrapper function around `compute_commitments` instantiated with the
/// appropriate implementation of the BN254 curve.
///
/// TODO!(benwilson): Update the function signature here to reflect the
/// new return type
pub fn compute_commitments_concrete(
    data: &[u8],
    vector_committer: &PedersenCommitter<Bn256Point>,
    blinding_factor_seed: [u8; 32],
) -> Vec<Bn256Point> {
    compute_commitments(data, vector_committer, blinding_factor_seed)
}
