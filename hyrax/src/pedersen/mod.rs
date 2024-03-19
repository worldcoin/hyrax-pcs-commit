use super::curves::PrimeOrderCurve;
use blake2::{Blake2s256, Digest};
use itertools::Itertools;
use num_traits::PrimInt;
use rand::Rng;
use rayon::iter::{IntoParallelIterator, ParallelIterator};

/// For committing to vectors of integers and scalars using the Pedersen commitment scheme.
pub struct PedersenCommitter<C: PrimeOrderCurve> {
    /// vector of "g" generators, i.e. the generators that are exponentiated by the message elements themselves (length > 0)
    // TODO(vishady): "generators" rather than message_generators
    pub message_generators: Vec<C>,
    /// the "h" generator which is exponentiated by the blinding factor
    pub blinding_generator: C,
    /// The bitwidth of the absolute values of the integers that can be committed to using integral vector commit methods (has no bearing on scalar_commit and vector_commit).
    pub int_abs_val_bitwidth: usize,
    // TODO(vishady): "generators" rather than message_generators
    message_generator_doublings: Vec<Vec<C>>,
}

impl<C: PrimeOrderCurve> PedersenCommitter<C> {
    const DEFAULT_INT_ABS_VAL_BITWIDTH: usize = 8;

    /// Creates a new PedersenCommitter with random generators.  See also [PedersenCommitter].
    /// DEFAULT_INT_ABS_VAL_BITWIDTH is used for `int_abs_val_bitwidth` if None is provided.
    /// Post: self.message_generators.len() == max_message_length
    /// TODO(vishady): look at the halo2curves C::random
    /// TODO(vishady): benchmarks on the hash function for rng
    pub fn new(
        num_generators: usize,
        public_string: &str,
        int_abs_val_bitwidth: Option<usize>,
    ) -> Self {
        let all_generators = Self::sample_generators(num_generators + 1, public_string);
        let blinding_generator_h = all_generators[0];
        let message_generators_g_i = all_generators[1..].to_vec();

        let int_abs_val_bitwidth =
            int_abs_val_bitwidth.unwrap_or(Self::DEFAULT_INT_ABS_VAL_BITWIDTH);
        let message_generator_doublings: Vec<Vec<C>> = message_generators_g_i
            .clone()
            .into_iter()
            .map(|gen| precompute_doublings(gen, int_abs_val_bitwidth))
            .collect();

        Self {
            message_generators: message_generators_g_i,
            blinding_generator: blinding_generator_h,
            int_abs_val_bitwidth,
            message_generator_doublings,
        }
    }

    fn sample_generators(num_generators: usize, public_string: &str) -> Vec<C> {
        let generators: Vec<_> = ark_std::cfg_into_iter!(0..num_generators)
            .map(|i| {
                let i = i as u64;
                let public_string_as_bytes = public_string.as_bytes();
                let hash = &Blake2s256::digest(
                    [public_string_as_bytes, &i.to_le_bytes()]
                        .concat()
                        .as_slice(),
                )[..68];
                let mut g = C::from_random_bytes(&hash);
                let mut j = 0u64;
                while g.is_none() {
                    // PROTOCOL NAME, i, j
                    let mut bytes = public_string_as_bytes.to_vec();
                    bytes.extend(i.to_le_bytes());
                    bytes.extend(j.to_le_bytes());
                    let hash = &Blake2s256::digest(bytes.as_slice())[..68];
                    g = C::from_random_bytes(&hash);
                    j += 1;
                }
                let generator = g.unwrap();
                generator
            })
            .collect();

        generators
    }

    /// Commits to the vector of u8s using the specified blinding factor.
    /// Uses the precomputed generator powers and the binary decomposition.
    /// Convient wrapper of integer_vector_commit.
    /// Pre: self.int_abs_val_bitwidth >= 8.
    /// Post: same result as vector_commit, assuming uints are smaller than scalar field order.
    pub fn u8_vector_commit(&self, message: &[u8], blinding: &C::Scalar) -> C {
        debug_assert!(self.int_abs_val_bitwidth >= 8);
        let message_is_negative_bits = vec![false; message.len()];
        self.integer_vector_commit(&message, &message_is_negative_bits, blinding)
    }

    /// Commits to the vector of integers using the specified blinding factor.
    /// Integers are provided as a vector of UNSIGNED ints and a vector of bits indicating whether the integer is negative.
    /// Pre: values in message are non-negative.
    /// Pre: values have unsigned binary expressions using at most (self.highest_generator_power + 1) bits.
    /// Pre: message.len() <= self.message_generators.len()
    pub fn integer_vector_commit<T: PrimInt>(
        &self,
        message: &[T],
        message_is_negative_bits: &Vec<bool>,
        blinding: &C::Scalar,
    ) -> C {
        assert!(message.len() <= self.message_generators.len());
        let unblinded_commit = message
            .iter()
            .zip(self.message_generator_doublings.iter())
            .map(|(input, generator_doublings)| {
                debug_assert!(*input >= T::zero());
                let bits = binary_decomposition_le(*input);
                let mut acc = C::zero();
                bits.into_iter().enumerate().for_each(|(i, bit)| {
                    if bit {
                        debug_assert!(i < self.int_abs_val_bitwidth); // ensure bit decomp is not longer than our precomputed generator powers
                        acc += generator_doublings[i];
                    }
                });
                acc
            })
            .zip(message_is_negative_bits.iter())
            .map(
                |(gen_power, is_negative)| {
                    if *is_negative {
                        -gen_power
                    } else {
                        gen_power
                    }
                },
            )
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
