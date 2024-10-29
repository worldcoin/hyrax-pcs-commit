pub mod tests;

use super::curves::PrimeOrderCurve;
use crate::pedersen::PedersenCommitter;
use ark_bn254::Fr as Bn256Scalar;
use ark_bn254::G1Projective as Bn256Point;
use ark_ff::BigInteger;
use ark_ff::PrimeField;
use ark_ff::UniformRand;
use itertools::Itertools;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
// log of the number of columns in the re-arrangement of the image as a matrix
pub const LOG_NUM_COLS: usize = 9;
// public string used to derive the generators (arbitrary constant)
pub const PUBLIC_STRING: &str = "Modulus <3 Worldcoin: ZKML Self-Custody Edition";

/// The Hyrax polynomial commitment scheme returns two things:
/// * The `commitment` itself, to be signed by the Orb and sent to Worldcoin's
///     backend (i.e. the verifier), and
/// * The `blinding_factors`, to be sent in the clear to ONLY the user's device
///     (leaking these to anyone else will cause the commitment to leak information
///     about the user's iris scan)
pub struct HyraxCommitmentOutput<C: PrimeOrderCurve> {
    pub commitment: Vec<C>,
    pub blinding_factors: Vec<C::Scalar>,
}

/// The concrete serialized version of `HyraxCommitmentOutput` to be used by
/// the Orb!
#[derive(Serialize, Deserialize)]
pub struct HyraxCommitmentOutputSerialized {
    pub commitment_serialized: Vec<u8>,
    pub blinding_factors_serialized: Vec<u8>,
}

/// Wrapper function around `compute_commitments` instantiated
/// with the appropriate implementation of the BN254 curve. Additionally,
/// serializes the commitment and the generated blinding factors for ease
/// of communication.
///
/// This is the function which should be called over both the iris scan
/// and the mask as `data` from the Orb!
pub fn compute_commitments_binary_outputs(
    data: &[u8],
    blinding_factor_seed: [u8; 32],
) -> HyraxCommitmentOutputSerialized {
    // --- Compute the generators from the given `PUBLIC_STRING` ---
    let vector_committer: PedersenCommitter<Bn256Point> =
        PedersenCommitter::new(1 << LOG_NUM_COLS, PUBLIC_STRING);

    // --- Compute the commitment and blinding factors ---
    let HyraxCommitmentOutput {
        commitment,
        blinding_factors,
    } = compute_commitments(data, &vector_committer, blinding_factor_seed);

    // --- Serialize into bytes ---
    let commitment_serialized: Vec<u8> = commitment
        .iter()
        .flat_map(|element| element.to_bytes_compressed())
        .collect_vec();
    let blinding_factors_serialized: Vec<u8> = blinding_factors
        .iter()
        .flat_map(|element| element.into_bigint().to_bytes_le())
        .collect_vec();

    HyraxCommitmentOutputSerialized {
        commitment_serialized,
        blinding_factors_serialized,
    }
}

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
) -> HyraxCommitmentOutput<C> {
    // pad the data to the nearest power of 2 by appending 0s
    let nearest_power_of_2_len = data.len().next_power_of_two();
    let padding_amount = nearest_power_of_2_len - data.len();
    let mut data_vec = data.to_vec();
    let padding_vec = vec![0; padding_amount];
    data_vec.extend(padding_vec.iter());

    // calculate the number of blinding factors needed (=the number of rows in the matrix)
    let n_cols = vector_committer.generators.len();
    let n_rows = data_vec.len() / n_cols;

    let mut prng = ChaCha20Rng::from_seed(blinding_factor_seed);
    let blinding_factors = (0..n_rows)
        .map(|_idx| C::Scalar::rand(&mut prng))
        .collect_vec();

    // we are using the vector_commit to commit to each of the rows of the matrix
    let row_chunks = data_vec.chunks(n_cols);
    let commitment = row_chunks
        .zip(blinding_factors.iter())
        .map(|(chunk, blind)| vector_committer.vector_commit(chunk, blind))
        .collect_vec();

    HyraxCommitmentOutput {
        commitment,
        blinding_factors,
    }
}

/// Helper functions for deserializing commitments/blinding factors from byte array
pub fn deserialize_commitment_from_bytes_compressed<C: PrimeOrderCurve>(bytes: &[u8]) -> Vec<C> {
    let commitment = bytes
        .chunks(C::COMPRESSED_CURVE_POINT_BYTEWIDTH)
        .map(|byte_repr| C::from_bytes_compressed(byte_repr))
        .collect_vec();
    commitment
}

pub fn deserialize_blinding_factors_from_bytes_compressed<C: PrimeOrderCurve>(
    bytes: &[u8],
) -> Vec<C::Scalar> {
    let blinding_factors: Vec<<C as PrimeOrderCurve>::Scalar> = bytes
        .chunks(C::SCALAR_ELEM_BYTEWIDTH)
        .map(C::Scalar::from_le_bytes_mod_order)
        .collect_vec();
    blinding_factors
}

pub fn deserialize_commitment_from_bytes_compressed_concrete(bytes: &[u8]) -> Vec<Bn256Point> {
    deserialize_commitment_from_bytes_compressed(bytes)
}

pub fn deserialize_blinding_factors_from_bytes_compressed_concrete(
    bytes: &[u8],
) -> Vec<Bn256Scalar> {
    deserialize_blinding_factors_from_bytes_compressed::<Bn256Point>(bytes)
}
