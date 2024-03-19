# Hyrax Commitment Implementation 
## Usage 
In order to run a test/example, run `cargo run --release` under the `./hyrax/src/bin` directory. The function models what an iris image commit would look like (assuming we have an image of size 2^17). Check the `compute_commitment` function for an example usage.

## Commitment function
Can be found under the `./hyrax/src/iriscode_commit/mod.rs` as the `compute_matrix_commitments` function.
