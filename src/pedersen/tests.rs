use super::*;
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
/// Tests for the Pedersen commitment scheme using the BN254 (aka BN256) curve and its scalar field (Fr).
use halo2_base::halo2_proofs::halo2curves::bn256::G1 as Bn256;
use super::super::curves::PrimeOrderCurve;

type Scalar = <Bn256 as PrimeOrderCurve>::Scalar;

#[test]
fn test_commitment_with_random_generators_isnt_identity() {
    let zero: Scalar = Fr::zero();
    let identity = Bn256::generator() * zero;
    let committer: PedersenCommitter<Bn256> =
        PedersenCommitter::new(2, "accountable magic something something");
    let message: Vec<u8> = vec![5, 7];
    let commit = committer.vector_commit(&message, &Fr::from(4u64));
    assert!(commit != identity);
}

#[test]
fn test_blinding_factor_dependence() {
    let committer: PedersenCommitter<Bn256> =
        PedersenCommitter::new(2, "accountable magic something something");
    let message: Vec<u8> = vec![5, 7];
    let commit1 = committer.vector_commit(&message, &Fr::from(4u64));
    let commit2 = committer.vector_commit(&message, &Fr::from(5u64));
    assert!(commit1 != commit2);
}

#[test]
#[should_panic]
fn test_too_long_messages_fail() {
    let committer: PedersenCommitter<Bn256> =
        PedersenCommitter::new(1, "accountable magic something something");
    let blinding_factor: Scalar = Fr::from(4u64);
    let message: Vec<u8> = vec![5, 7];
    let _commit = committer.vector_commit(&message, &blinding_factor);
}

#[test]
fn test_permutation() {
    let committer: PedersenCommitter<Bn256> =
        PedersenCommitter::new(2, "accountable magic something something");
    // test that permuting the message changes the commitment
    let message: Vec<u8> = vec![5, 7];
    let permuted_message: Vec<u8> = vec![7, 5];
    let blinding_factor: Scalar = Fr::from(4u64);
    let commit = committer.vector_commit(&message, &blinding_factor);
    let permuted_message_commit = committer.vector_commit(&permuted_message, &blinding_factor);
    assert!(commit != permuted_message_commit);
}

#[test]
fn test_build_powers() {
    let g = Bn256::generator();
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