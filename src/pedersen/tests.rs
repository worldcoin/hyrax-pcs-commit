use crate::iriscode_commit::{LOG_NUM_COLS, PUBLIC_STRING};

/// Tests for the Pedersen commitment scheme using the BN254 (aka BN256) curve and its scalar field (Fr).
use super::super::curves::PrimeOrderCurve;
use super::*;
use ark_bn254::Fr as Bn256Scalar;
use ark_bn254::G1Projective as Bn256Point;

#[test]
/// tests whether when we run the generator sampling twice we still get the same generators
fn test_public_sampling() {
    let vector_committer: PedersenCommitter<Bn256Point> =
        PedersenCommitter::new(1 << LOG_NUM_COLS, PUBLIC_STRING);
    let vector_committer_2: PedersenCommitter<Bn256Point> =
        PedersenCommitter::new(1 << LOG_NUM_COLS, PUBLIC_STRING);

    assert_eq!(vector_committer.generators, vector_committer_2.generators);
    assert_eq!(
        vector_committer.blinding_generator,
        vector_committer_2.blinding_generator
    );
}

#[test]
fn test_commitment_with_random_generators_isnt_identity() {
    let zero: Bn256Scalar = Bn256Scalar::from(0_u64);
    let identity = Bn256Point::generator() * zero;
    let committer: PedersenCommitter<Bn256Point> =
        PedersenCommitter::new(2, "accountable magic something something");
    let message: Vec<u8> = vec![5, 7];
    let commit = committer.vector_commit(&message, &Bn256Scalar::from(4u64));
    assert!(commit != identity);
}

#[test]
fn test_blinding_factor_dependence() {
    let committer: PedersenCommitter<Bn256Point> =
        PedersenCommitter::new(2, "accountable magic something something");
    let message: Vec<u8> = vec![5, 7];
    let commit1 = committer.vector_commit(&message, &Bn256Scalar::from(4u64));
    let commit2 = committer.vector_commit(&message, &Bn256Scalar::from(5u64));
    assert!(commit1 != commit2);
}

#[test]
#[should_panic]
fn test_too_long_messages_fail() {
    let committer: PedersenCommitter<Bn256Point> =
        PedersenCommitter::new(1, "accountable magic something something");
    let blinding_factor: Bn256Scalar = Bn256Scalar::from(4u64);
    let message: Vec<u8> = vec![5, 7];
    let _commit = committer.vector_commit(&message, &blinding_factor);
}

#[test]
fn test_permutation() {
    let committer: PedersenCommitter<Bn256Point> =
        PedersenCommitter::new(2, "accountable magic something something");
    // test that permuting the message changes the commitment
    let message: Vec<u8> = vec![5, 7];
    let permuted_message: Vec<u8> = vec![7, 5];
    let blinding_factor: Bn256Scalar = Bn256Scalar::from(4u64);
    let commit = committer.vector_commit(&message, &blinding_factor);
    let permuted_message_commit = committer.vector_commit(&permuted_message, &blinding_factor);
    assert!(commit != permuted_message_commit);
}

#[test]
fn test_build_powers() {
    let g = Bn256Point::generator();
    let powers = precompute_doublings(g, 3);
    assert_eq!(powers.len(), 3);
    assert_eq!(powers[0], g);
    assert_eq!(powers[1], g.double());
    assert_eq!(powers[2], g.double().double());
}

#[test]
fn test_bit_decomposition_lsb() {
    let uint: u8 = 5;
    let bits = binary_decomposition_le(uint);
    assert_eq!(
        bits,
        vec![true, false, true, false, false, false, false, false]
    );
}
