# Hyrax Commitment Implementation 
## Usage 
In order to run a test/example, run `cargo run --release --bin benchmark_iriscode_commit`. The function models what an iris image commit would look like (assuming we have an image of size 2^17). Check the `compute_commitment` function for an example usage. This additionally serializes the commitment and saves it to a file specified by the constant `FILENAME` in the binary. Then, it
deserializes the commitment and asserts that the original commitment is equal to the deserialized version.

## Commitment function
Can be found under the `./src/iriscode_commit/mod.rs` as the `compute_matrix_commitments` function.
