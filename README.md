# Hyrax Polynomial Commitment Scheme (PCS)

## Overview
This repository contains an implementation of the [Hyrax](https://eprint.iacr.org/2017/1132) polynomial commitment scheme. In particular, it allows one to generate a zero-knowledge commitment to an array of bytes' (`&[u8]`) worth of data which can be used in the verification of a zero-knowledge proof over computation involving such data. 

Note that this repository contains _only_ the code needed to generate a commitment, and does not provide the implementation necessary to generate a proof-of-evaluation against any such committed polynomial, nor the verification of such an evaluation proof.

## Building
### Building using our binary
To execute our binary, you can run the following command:
```
cargo build --release
cargo run --release --bin hyrax_commit -- \
    --input-normalized-iris-image-filepath {filepath to iris image} \
    --output-commitment-filepath {filepath to write the commitment to} \
    --output-blinding-factors-filepath {filepath to write blinding factors to} \
```
The binary is found in `./src/bin/hyrax_commit.rs`. 

### Building using our library
This implementation of the Hyrax polynomial commitment requires Rust nightly (version found in `rust-toolchain` file). To compile using our library, run
`cargo build --release`.

## Example Usage
### Example binary usage 
In `./scripts`, we've included a shell script `run_hyrax_commit` which will execute our binary using a random iris image found in `./scripts/e2etesting/normalized-iris-image.json`. You can generate the commitment
and blinding factors for this commitment and write them to file by running `./run_hyrax_commit` within the
`./scripts` directory. The commitment will get written to `./scripts/e2etesting/commitment-iris-image-example.json` and the blinding factors will get written to `e2etesting/blinding-factors-iris-image-example.json`.

### Example library usage
To run the built-in example through our library, run `cargo run --release --bin example_hyrax_commit`. The `main` function computes the commitment to a mock iris image of size 2^17 (=128 x 1024). It also demonstrates binary serialization/deserialization, and writes/reads the byte stream to/from file.

## Production Usage
The primary user-friendly function can be found in `./src/iriscode_commit/mod.rs` as the `compute_commitments_binary_outputs` function. The function takes in as input
* A `data: &[u8]` parameter, corresponding to the iris image (and/or mask!) to be committed to, and
* A `blinding_factor_seed: [u8; 32]` parameter, corresponding to 32 bytes' worth of entropy to be sampled externally and used as the seed for the CSPRNG generating the blinding factors for zero-knowledge.

The function outputs
```
pub struct HyraxCommitmentOutputSerialized {
    pub commitment_serialized: Vec<u8>,
    pub blinding_factors_serialized: Vec<u8>,
}
```
where
* `commitment_serialized` is a bytestring representation of the polynomial commitment, *to be signed by the Orb and included as part of the payload to the backend servers/verifier*, and
* `blinding_factors_serialized` is a bytestring representation of the blinding factors generated during the commitment process, *to be sent from the Orb to the user's self-custody device (as part of the self-custody payload) through a secure channel and deleted immediately afterward*.

---

# Additional Notes

## Blinding Factor Generation
We generate blinding factors by taking as input a random seed of 32 bytes (e.g., by using Rust's `OsRng` which derives entropy from `/dev/urandom`). We then use this to seed a CSPRNG, `ChaCha20`, which is then used to generate random scalar field elements which are our blinding factors.

## Public Generator Setup
We sample the generators for the Pedersen commitment deterministically using the Shake256 hash function which uses a public string as an initializer. This can be found under the `sample_generators` function in `./src/pedersen/mod.rs`. The public string (once used, this _must_ be fixed) can be found as the constant `PUBLIC_STRING` within `src/iriscode_commit/mod.rs`. 
