#[test]
fn test_serialize_end_to_end() {
    use crate::iriscode_commit::{
        compute_commitments, deserialize_blinding_factors_from_bytes_compressed_concrete,
        deserialize_commitment_from_bytes_compressed_concrete, HyraxCommitmentOutput, LOG_NUM_COLS,
        PUBLIC_STRING,
    };
    use crate::pedersen::PedersenCommitter;
    use crate::utils::{
        read_bytes_from_file, write_bytes_to_file, BLINDING_FACTORS_FILENAME, COMMITMENT_FILENAME,
        INPUT_NORMALIZED_IMAGE_FILENAME,
    };
    use std::time::Instant;

    use crate::curves::PrimeOrderCurve;
    use ark_bn254::G1Projective as Bn256Point;
    use ark_ff::BigInteger;
    use ark_ff::PrimeField;
    use itertools::Itertools;
    use rand::RngCore;
    use rand_core::OsRng;

    // Read a dummy image from file
    let iris_image = read_bytes_from_file(INPUT_NORMALIZED_IMAGE_FILENAME);

    let start_time = Instant::now();

    // --- Sample randomness for the generation of the blinding factors ---
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);

    // --- Compute generators ---
    let vector_committer: PedersenCommitter<Bn256Point> =
        PedersenCommitter::new(1 << LOG_NUM_COLS, PUBLIC_STRING);

    // --- Do commitment and output blinding factors ---
    let HyraxCommitmentOutput {
        commitment,
        blinding_factors,
    } = compute_commitments(&iris_image, &vector_committer, seed);

    println!("Computing commitment took: {:?}", start_time.elapsed());

    // --- Serialize into binary ---
    let commitment_serialized: Vec<u8> = commitment
        .iter()
        .flat_map(|element| element.to_bytes_compressed())
        .collect_vec();
    let blinding_factors_serialized: Vec<u8> = blinding_factors
        .iter()
        .flat_map(|element| element.into_bigint().to_bytes_le())
        .collect_vec();

    // --- Sample serialization to file (iris image, blinding factors) ---
    write_bytes_to_file(COMMITMENT_FILENAME, &commitment_serialized);
    write_bytes_to_file(BLINDING_FACTORS_FILENAME, &blinding_factors_serialized);

    // --- Sample serialization from file (iris image, blinding factors) ---
    let commitment_bytes_from_file = read_bytes_from_file(COMMITMENT_FILENAME);
    let blinding_factors_bytes_from_file = read_bytes_from_file(BLINDING_FACTORS_FILENAME);

    // --- Sanitycheck vs. bytes ---
    assert_eq!(commitment_serialized, commitment_bytes_from_file);
    assert_eq!(
        blinding_factors_bytes_from_file,
        blinding_factors_serialized
    );

    // --- Deserialize from bytes ---
    let deserialized_commitment =
        deserialize_commitment_from_bytes_compressed_concrete(&commitment_bytes_from_file);
    let deserialized_blinding_factors = deserialize_blinding_factors_from_bytes_compressed_concrete(
        &blinding_factors_bytes_from_file,
    );

    // --- Sanitycheck vs. original commitment/blinding factors ---
    assert_eq!(deserialized_commitment, commitment);
    assert_eq!(deserialized_blinding_factors, blinding_factors);
}
