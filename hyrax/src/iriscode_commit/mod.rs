use super::curves::PrimeOrderCurve;
use crate::pedersen::PedersenCommitter;
use itertools::Itertools;

/// an enum representing how the user can specify their MLE coefficients. at least for our pedersen
/// commitments, the distinction matters between u8, i8, and scalar field elements because of the
/// precomputations.
pub enum MleCoefficientsVector<C: PrimeOrderCurve> {
    U8Vector(Vec<u8>),
    I8Vector(Vec<i8>),
    ScalarFieldVector(Vec<C::Scalar>),
}

impl<C: PrimeOrderCurve> MleCoefficientsVector<C> {
    fn len(&self) -> usize {
        match &self {
            MleCoefficientsVector::U8Vector(vec) => vec.len(),
            MleCoefficientsVector::I8Vector(vec) => vec.len(),
            MleCoefficientsVector::ScalarFieldVector(vec) => vec.len(),
        }
    }
}

/// this function computes the commitments to the rows of the matrix. essentially, this is the vector of
/// commitments that the prover should be sending over to the verifier.
pub fn compute_matrix_commitments<C: PrimeOrderCurve>(
    // the log-size of the matrix rows. both the row size and the column size need to be powers of 2
    // for hyrax to work!
    log_split_point: usize,
    input_layer_mle: &MleCoefficientsVector<C>,
    vector_committer: &PedersenCommitter<C>,
    blinding_factors: &Vec<C::Scalar>,
) -> Vec<C> {
    // checking that the matrix row size and the matrix column size are both powers of two! otherwise hyrax does not work
    assert!(input_layer_mle.len().is_power_of_two());

    // this appropriately computes the commitments to the coefficients matrix based on its internal type. if it is a u8
    // or an i8, we can use precomputed bit decompositions in order to speed up the pedersen commitments!!
    let commits: Vec<C> = match input_layer_mle {
        MleCoefficientsVector::U8Vector(coeff_vector_u8) => {
            let u8committer: PedersenCommitter<C> = PedersenCommitter::new(
                vector_committer.message_generators.clone(),
                vector_committer.blinding_generator,
                Some(8),
            );
            // we are using the u8_vector_commit to commit to each of the rows of the matrix, which are determined by
            // the log_split_point!
            coeff_vector_u8
                .chunks(1 << log_split_point)
                .zip(blinding_factors.iter())
                .map(|(chunk, blind)| u8committer.u8_vector_commit(&chunk.to_vec(), blind))
                .collect_vec()
        }
        MleCoefficientsVector::I8Vector(coeff_vector_i8) => {
            let i8committer: PedersenCommitter<C> = PedersenCommitter::new(
                vector_committer.message_generators.clone(),
                vector_committer.blinding_generator,
                Some(8),
            );
            // we are using the i8_vector_commit to commit to each of the rows of the matrix
            coeff_vector_i8
                .chunks(1 << log_split_point)
                .zip(blinding_factors.iter())
                .map(|(chunk, blind)| i8committer.i8_vector_commit(&chunk.to_vec(), blind))
                .collect_vec()
        }
        MleCoefficientsVector::ScalarFieldVector(coeff_vector_scalar_field) => {
            // we are using the regular vector_commit to commit to the rows of the matrix
            coeff_vector_scalar_field
                .chunks(1 << log_split_point)
                .zip(blinding_factors.iter())
                .map(|(chunk, blind)| vector_committer.vector_commit(&chunk.to_vec(), blind))
                .collect_vec()
        }
    };
    commits
}
