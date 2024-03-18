use super::super::curves::PrimeOrderCurve;
use super::*;
use remainder_shared_types::halo2curves::bn256::Fr;
/// Tests for the Pedersen commitment scheme using the BN254 (aka BN256) curve and its scalar field (Fr).
use remainder_shared_types::halo2curves::bn256::G1 as Bn256;

type Scalar = <Bn256 as PrimeOrderCurve>::Scalar;

#[test]
fn test_commitment_with_random_generators_isnt_identity() {
    let zero: Scalar = Fr::zero();
    let identity = Bn256::generator() * zero;
    let committer: PedersenCommitter<Bn256> =
        PedersenCommitter::random(2, &mut rand::thread_rng(), None);
    let message: Vec<Scalar> = vec![Fr::from(5u64), Fr::from(7u64)];
    let commit = committer.vector_commit(&message, &Fr::from(4u64));
    assert!(commit != identity);
    let scalar: Scalar = Fr::from(5u64);
    let commit = committer.scalar_commit(&scalar, &Fr::from(4u64));
    assert!(commit != identity);
}

#[test]
fn test_blinding_generator_dependence() {
    let g0 = Bn256::generator();
    let g1 = Bn256::generator() * Fr::from(3u64);

    // test that if blinding generator is identity then no blinding
    let zero: Scalar = Fr::zero();
    let identity = Bn256::generator() * zero;
    let committer = PedersenCommitter::new(vec![g0, g1], identity, None);
    let blinding_factor: Scalar = Fr::from(4u64);
    // for scalars
    let scalar: Scalar = Fr::from(5u64);
    let scalar_commit_not_blinded = committer.scalar_commit(&scalar, &blinding_factor);
    assert_eq!(scalar_commit_not_blinded, g0 * scalar);
    // for vectors
    let message: Vec<Scalar> = vec![Fr::from(5u64), Fr::from(7u64)];
    let vector_commit_not_blinded = committer.vector_commit(&message, &blinding_factor);
    assert_eq!(vector_commit_not_blinded, g0 * message[0] + g1 * message[1]);

    // test that non-identity blinding generator means blinding!
    let committer = PedersenCommitter::new(vec![g0, g1], g1, None);
    // for scalars
    let scalar: Scalar = Fr::from(5u64);
    let scalar_commit_blinded = committer.scalar_commit(&scalar, &blinding_factor);
    assert!(scalar_commit_blinded != scalar_commit_not_blinded);
    // for vectors
    let message: Vec<Scalar> = vec![Fr::from(5u64), Fr::from(7u64)];
    let vector_commit_blinded = committer.vector_commit(&message, &blinding_factor);
    assert!(vector_commit_blinded != vector_commit_not_blinded);
}

#[test]
fn test_blinding_factor_dependence() {
    let g0 = Bn256::generator();
    let g1 = Bn256::generator() * Fr::from(3u64);
    let h = Bn256::generator() * Fr::from(13u64);
    let committer = PedersenCommitter::new(vec![g0, g1], h, None);
    // check for scalar commitments
    let scalar: Scalar = Fr::from(5u64);
    let commit1 = committer.scalar_commit(&scalar, &Fr::from(4u64));
    let commit2 = committer.scalar_commit(&scalar, &Fr::from(5u64));
    assert!(commit1 != commit2);
    // check for vector commitments
    let message: Vec<Scalar> = vec![Fr::from(5u64), Fr::from(7u64)];
    let commit1 = committer.vector_commit(&message, &Fr::from(4u64));
    let commit2 = committer.vector_commit(&message, &Fr::from(5u64));
    assert!(commit1 != commit2);
}

#[test]
fn test_short_messages() {
    let g0 = Bn256::generator();
    let g1 = Bn256::generator() * Fr::from(3u64);
    let blinding_factor: Scalar = Fr::from(4u64);

    // test message can be shorter than the generators
    let committer = PedersenCommitter::new(vec![g0, g1], g0, None);
    let _commit = committer.vector_commit(&vec![Fr::from(5u64)], &blinding_factor);
    // worked!

    // test degenerate case of message length 0
    let committer = PedersenCommitter::new(vec![], g0, None);
    let commit = committer.vector_commit(&vec![], &blinding_factor);
    assert_eq!(commit, g0 * blinding_factor);
}

#[test]
#[should_panic]
fn test_too_long_messages_fail() {
    let committer: PedersenCommitter<Bn256> =
        PedersenCommitter::random(1, &mut rand::thread_rng(), None);
    let blinding_factor: Scalar = Fr::from(4u64);
    let message = vec![Fr::from(5u64), Fr::from(7u64)];
    let _commit = committer.vector_commit(&message, &blinding_factor);
}

#[test]
fn test_permutation() {
    let g0 = Bn256::generator();
    let g1 = Bn256::generator() * Fr::from(3u64);
    let h = Bn256::generator() * Fr::from(7u64);
    let blinding_factor: Scalar = Fr::from(4u64);

    // test that permuting the message changes the commitment
    let committer = PedersenCommitter::new(vec![g0, g1], h, None);
    let message = vec![Fr::from(5u64), Fr::from(7u64)];
    let permuted_message = message.iter().rev().cloned().collect();
    let commit = committer.vector_commit(&message, &blinding_factor);
    let permuted_message_commit = committer.vector_commit(&permuted_message, &blinding_factor);
    assert!(commit != permuted_message_commit);

    // test that simultaneously permuting the message and the generators doesn't change the commitment
    let permuted_committer = PedersenCommitter::new(vec![g1, g0], h, None);
    let simul_permuted_commit =
        permuted_committer.vector_commit(&permuted_message, &blinding_factor);
    assert_eq!(commit, simul_permuted_commit);
}

#[test]
fn test_generator_extraction() {
    let g0 = Bn256::generator();
    let g1 = Bn256::generator() * Fr::from(3u64);
    let h = Bn256::generator() * Fr::from(7u64);

    // test that a one-hot message returns the corresponding generator (when blinding factor is zero)
    let committer = PedersenCommitter::new(vec![g0, g1], h, None);
    // for vectors
    let commit = committer.vector_commit(&vec![Fr::zero(), Fr::one()], &Fr::zero());
    assert_eq!(commit, g1);
    // for scalars
    let commit = committer.scalar_commit(&Fr::one(), &Fr::zero());
    assert_eq!(commit, g0);

    // test that zero message with blinding factor one returns the blinding generator
    // for vectors
    let commit = committer.vector_commit(&vec![Fr::zero(), Fr::zero()], &Fr::one());
    assert_eq!(commit, h);
    // for scalars
    let commit = committer.scalar_commit(&Fr::zero(), &Fr::one());
    assert_eq!(commit, h);
}

#[test]
fn test_uint_vector_commit() {
    // check that we get the same commit using the precomputed generator powers and the binary decomposition as we do using the scalar field elements.
    let uint_message: Vec<u8> = vec![5, 1, 2, 255];
    let blinding_factor: Scalar = Fr::from(4u64);
    let committer: PedersenCommitter<Bn256> =
        PedersenCommitter::random(uint_message.len(), &mut rand::thread_rng(), Some(8usize));
    let uint_vec_commit = committer.u8_vector_commit(&uint_message, &blinding_factor);
    let message: Vec<_> = uint_message.iter().map(|x| Fr::from(*x as u64)).collect();
    let vec_commit = committer.vector_commit(&message, &blinding_factor);
    assert_eq!(uint_vec_commit, vec_commit);
}

#[test]
fn test_signed_int_vector_commit() {
    // check that we get the same commit using the precomputed generator powers and the binary decomposition as we do using the scalar field elements.
    let int_message: Vec<i8> = vec![-5, 7, -128, 127];
    let committer: PedersenCommitter<Bn256> =
        PedersenCommitter::random(int_message.len(), &mut rand::thread_rng(), Some(8usize));
    let blinding_factor: Scalar = Fr::from(4u64);
    let int_vec_commit = committer.i8_vector_commit(&int_message, &blinding_factor);
    let message = vec![
        Fr::from(5u64).neg(),
        Fr::from(7u64),
        Fr::from(128u64).neg(),
        Fr::from(127u64),
    ];
    let vec_commit = committer.vector_commit(&message, &blinding_factor);
    assert_eq!(int_vec_commit, vec_commit);
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

#[test]
fn test_split_at() {
    let g0 = Bn256::generator();
    let g1 = Bn256::generator() * Fr::from(3u64);
    let g2 = Bn256::generator() * Fr::from(6u64);
    let h = Bn256::generator() * Fr::from(7u64);
    let committer = PedersenCommitter::new(vec![g0, g1, g2], h, Some(8));
    let (first, second) = committer.split_at(1);
    assert_eq!(first.message_generators.len(), 1);
    assert_eq!(second.message_generators.len(), 2);
    assert_eq!(first.message_generators[0], committer.message_generators[0]);
    assert_eq!(
        second.message_generators[1],
        committer.message_generators[2]
    );
    assert_eq!(first.blinding_generator, h);
    assert_eq!(second.blinding_generator, h);
    assert_eq!(first.int_abs_val_bitwidth, 8);
    assert_eq!(second.int_abs_val_bitwidth, 8);
    assert_eq!(first.message_generator_doublings.len(), 1);
    assert_eq!(second.message_generator_doublings.len(), 2);
    assert_eq!(
        first.message_generator_doublings[0],
        committer.message_generator_doublings[0]
    );
    assert_eq!(
        second.message_generator_doublings[1],
        committer.message_generator_doublings[2]
    );
    // check split at 0
    let (first, second) = committer.split_at(0);
    assert_eq!(first.message_generators.len(), 0);
    assert_eq!(second.message_generators.len(), 3);
    // check split at len()
    let (first, second) = committer.split_at(3);
    assert_eq!(first.message_generators.len(), 3);
    assert_eq!(second.message_generators.len(), 0);
}
