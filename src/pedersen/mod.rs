use crate::curves::Sha3XofReaderWrapper;

use super::curves::PrimeOrderCurve;
use num_traits::PrimInt;
use sha3::digest::ExtendableOutput;
use sha3::digest::Input;
use sha3::Shake256;

/// For committing to vectors of integers and scalars using the Pedersen commitment scheme.
pub struct PedersenCommitter<C: PrimeOrderCurve> {
    /// vector of "g" generators, i.e. the generators that are exponentiated by the message elements themselves (length > 0)
    // TODO(vishady): "generators" rather than message_generators
    pub message_generators: Vec<C>,
    /// the "h" generator which is exponentiated by the blinding factor
    pub blinding_generator: C,
    // TODO(vishady): "generators" rather than message_generators
    message_generator_doublings: Vec<Vec<C>>,
}

const U8_BITWIDTH: usize = 8;
impl<C: PrimeOrderCurve> PedersenCommitter<C> {
    /// Creates a new PedersenCommitter with random generators.  See also [PedersenCommitter].
    /// Post: self.message_generators.len() == max_message_length
    /// TODO(vishady): look at the halo2curves C::random
    /// TODO(vishady): benchmarks on the hash function for rng
    pub fn new(
        num_generators: usize,
        public_string: &str,
    ) -> Self {
        let all_generators = Self::sample_generators(num_generators + 1, public_string);
        let blinding_generator_h = all_generators[0];
        let message_generators_g_i = all_generators[1..].to_vec();

        let message_generator_doublings: Vec<Vec<C>> = message_generators_g_i
            .clone()
            .into_iter()
            .map(|gen| precompute_doublings(gen, U8_BITWIDTH))
            .collect();

        Self {
            message_generators: message_generators_g_i,
            blinding_generator: blinding_generator_h,
            message_generator_doublings,
        }
    }

    // FIXME docstring
    fn sample_generators(num_generators: usize, public_string: &str) -> Vec<C> {
        assert!(public_string.len() >= 32);
        let mut public_string_array: [u8; 32] = [0; 32];
        public_string_array.copy_from_slice(&public_string.as_bytes()[..32]);
        let mut shake = Shake256::default();
        shake.input(public_string_array);

        let reader = shake.xof_result();
        let mut reader_wrapper = Sha3XofReaderWrapper::new(reader);
        let generators: Vec<_> = (0..num_generators)
            .map(|_| C::random(&mut reader_wrapper))
            .collect();
        generators
    }

    /// Commits to the vector of u8s using the specified blinding factor.
    /// Uses the precomputed generator powers and the binary decomposition.
    /// Pre: message.len() <= self.message_generators.len()
    /// Post: same result as vector_commit, assuming uints are smaller than scalar field order.
    pub fn vector_commit(&self, message: &[u8], blinding: &C::Scalar) -> C {
        assert!(message.len() <= self.message_generators.len());
        let unblinded_commit = message
            .iter()
            .zip(self.message_generator_doublings.iter())
            .map(|(input, generator_doublings)| {
                let bits = binary_decomposition_le(*input);
                let mut acc = C::zero();
                bits.into_iter().enumerate().for_each(|(i, bit)| {
                    if bit {
                        acc += generator_doublings[i];
                    }
                });
                acc
            })
            .fold(C::zero(), |acc, value| acc + value);

        unblinded_commit + self.blinding_generator * *blinding
    }
}

// Compute the little endian binary decomposition of the provided integer value.
// Pre: value is non-negative.
// Post: result.len() is std::mem::size_of::<T>() * 8;
fn binary_decomposition_le<T: PrimInt>(value: T) -> Vec<bool> {
    debug_assert!(value >= T::zero());
    let bit_size = std::mem::size_of::<T>() * 8;
    (0..bit_size)
        .map(|i| value & (T::one() << i) != T::zero())
        .collect()
}

// Returns the vector [2^i * base for i in 0..bitwidth]
// Post: powers.len() == bitwidth
fn precompute_doublings<G: PrimeOrderCurve>(base: G, bitwidth: usize) -> Vec<G> {
    let mut powers = vec![];
    let mut last = base;
    for _exponent in 0..bitwidth {
        powers.push(last);
        last = last.double();
    }
    powers
}
