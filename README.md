# Hyrax Polynomial Commitment Scheme (PCS)

## Overview
This repository contains an implementation of the [Hyrax](https://eprint.iacr.org/2017/1132) polynomial commitment scheme. In particular, it allows one to generate a zero-knowledge commitment to an array of bytes' (`&[u8]`) worth of data which can be used in the verification of a zero-knowledge proof over computation involving such data. 

Note that this repository contains _only_ the code needed to generate a commitment, and does not provide the implementation necessary to generate a proof-of-evaluation against any such committed polynomial, nor the verification of such an evaluation proof.

## Example Usage
### Example library usage
To run the built-in example through our library, run `cargo run --release --bin example_hyrax_commit`. The `main` function computes the commitment to a mock iris image of size 2^17 (=128 x 1024). It also demonstrates binary serialization/deserialization, and writes/reads the byte stream to/from file.

### Example binary usage 
In `./examples`, we've included a shell script `run_hyrax_commit` which will execute our binary using a dummy image found in `./examples/dummy-data/left_normalized_image.bin`. You can generate the commitment
and blinding factors for this commitment and write them to file by running `./run_hyrax_commit` within the
`./examples` directory. The commitment will get written to `./examples/dummy-data/left_normalized_image_commitment.bin` and the blinding factors will get written to `dummy-data/left_normalized_image_blinding_factors.bin`.

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

## Contributing

We plan to accept contributions at a later date, but do not have
bandwidth to review PRs currently.

Likewise, we are providing this source code for the benefit of the community,
but cannot commit to any SemVer or API stability guarantees. Be warned: we may
change things in a backwards-incompatible way at any time!

## License
Unless otherwise specified, all code in this repository is dual-licensed under
either:

- MIT License ([LICENSE-MIT](LICENSE-MIT))
- Apache License, Version 2.0, with LLVM Exceptions ([LICENSE-APACHE](LICENSE-APACHE))

at your option. This means you may select the license you prefer to use.

Any contribution intentionally submitted for inclusion in the work by you, as
defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
