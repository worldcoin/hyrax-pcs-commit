# Hyrax Commitment Implementation 
## Usage 
In order to run a test/example, run `cargo run --release --bin benchmark_iriscode_commit`. The `main` function computes the commitment to a mock iris image of size 2^17 (=128 x 1024). It also demonstrates serialization and deserialization of the commitment.

## Commitment function
Can be found under the `./src/iriscode_commit/mod.rs` as the `compute_commitments` function.

## Public Generator Setup
We sample the generators for the Pedersen commitment deterministically using the Shake256 hash function which uses a public string as an initializer. This can be found under the `sample_generators` function in `./src/pedersen/mod.rs`. 

## Blinding Factor Generation
We generate blinding factors by sampling a random seed of 32 bytes using Rust's `OsRng` which derives entropy from `/dev/urandom`. We then use this to seed a CSPRNG, `ChaCha20`, which is then used to generate random scalar field elements which are our blinding factors.
