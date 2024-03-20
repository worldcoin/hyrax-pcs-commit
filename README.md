# Hyrax Commitment Implementation 
## Usage 
In order to run a test/example, run `cargo run --release --bin benchmark_iriscode_commit`. The function models what an iris image commit would look like (assuming we have an image of size 2^17). Check the `compute_commitment` function for an example usage. This additionally serializes the commitment and saves it to a file specified by the constant `FILENAME` in the binary. Then, it
deserializes the commitment and asserts that the original commitment is equal to the deserialized version.

## Commitment function
Can be found under the `./src/iriscode_commit/mod.rs` as the `compute_matrix_commitments` function.

## Public Generator Setup
We sample the generators for the Pedersen commitment deterministically using the Shake256 hash function which uses a public string as an initializer. This can be found under the `sample_generators` function in `./src/pedersen/mod.rs`. 

## Blinding Factor Generation
We generate blinding factors by sampling a random seed of 32 bytes using Rust's `OsRng` which derives entropy from `/dev/urandom`. We then use this to seed a CSPRNG, `ChaCha20`, which is then used to generate random scalar field elements which are our blinding factors.
