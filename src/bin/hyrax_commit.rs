use clap::Parser;
/// Measure how long it takes to commit to the Worldcoin iris image.
/// Random u8 values are used as a stand in for the normalized iris image.
use hyrax::iriscode_commit::{compute_commitments_binary_outputs, HyraxCommitmentOutputSerialized};
use hyrax::utils::{read_bytes_from_file, write_bytes_to_file};
use rand::RngCore;
use rand_core::OsRng;

// image is 128 x 1024 = 2^17 in size
const LOG_IMAGE_SIZE: usize = 17;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// this is the filepath which contains the array of bytes representing the normalized iris image.
    #[arg(long)]
    input_image_filepath: String,

    /// this is the filepath to which the commitment to the iris image provided will be written.
    /// NOTE: contents can be decryptable by the backend servers and by the phone
    #[arg(long)]
    output_commitment_filepath: String,

    /// this is the filepath to which the blinding factors used to produce the commitment will be written.
    /// NOTE: contents should only be able to be decrypted by the phone
    #[arg(long)]
    output_blinding_factors_filepath: String,
}

/// Usage: `cargo build --release && cargo run --release --bin hyrax_commit`
fn main() {
    let args = Args::parse();
    // Generate a random image to be committed to; this is a stand-in for the iris image ---
    let iris_image = read_bytes_from_file(&args.input_image_filepath);
    // Sanity check on expected image dimensions
    assert_eq!(iris_image.len(), 1 << LOG_IMAGE_SIZE);

    // Sample randomness for the generation of the blinding factors (note that `OsRng` calls `/dev/urandom` under the hood)
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);

    // The actual commitment function, generating commitments and blinding factors
    let HyraxCommitmentOutputSerialized {
        commitment_serialized,
        blinding_factors_serialized,
    } = compute_commitments_binary_outputs(&iris_image, seed);

    // Sample serialization to file (iris image, blinding factors)
    write_bytes_to_file(&args.output_commitment_filepath, &commitment_serialized);
    write_bytes_to_file(
        &args.output_blinding_factors_filepath,
        &blinding_factors_serialized,
    );

    // Sample serialization from file (iris image, blinding factors);
    let commitment_bytes_from_file = read_bytes_from_file(&args.output_commitment_filepath);
    let blinding_factors_bytes_from_file =
        read_bytes_from_file(&args.output_blinding_factors_filepath);

    // Sanity check
    assert_eq!(commitment_serialized, commitment_bytes_from_file);
    assert_eq!(
        blinding_factors_bytes_from_file,
        blinding_factors_serialized
    );
}
