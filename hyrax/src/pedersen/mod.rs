use super::curves::PrimeOrderCurve;
use itertools::Itertools;
use rand::Rng;

pub mod tests;
use num_traits::PrimInt;

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
    pub fn random(
        max_message_length: usize,
        mut rng: &mut impl Rng,
        int_abs_val_bitwidth: Option<usize>,
    ) -> Self {
        let message_generators: Vec<C> = (0..max_message_length)
            .map(|_| C::random(&mut rng))
            .collect_vec();
        let blinding_generator = C::random(&mut rng);
        Self::new(message_generators, blinding_generator, int_abs_val_bitwidth)
    }

    /// Create a new PedersenCommitter with the provided generators.
    /// See [PedersenCommitter].
    /// DEFAULT_INT_ABS_VAL_BITWIDTH is used for `int_abs_val_bitwidth` if None is provided.
    pub fn new(
        message_generators: Vec<C>,
        blinding_generator: C,
        int_abs_val_bitwidth: Option<usize>,
    ) -> Self {
        let int_abs_val_bitwidth =
            int_abs_val_bitwidth.unwrap_or(Self::DEFAULT_INT_ABS_VAL_BITWIDTH);
        let message_generator_doublings: Vec<Vec<C>> = message_generators
            .clone()
            .into_iter()
            .map(|gen| precompute_doublings(gen, int_abs_val_bitwidth))
            .collect();
        Self {
            message_generators,
            blinding_generator,
            int_abs_val_bitwidth,
            message_generator_doublings,
        }
    }

    /// Create a pair of new PedersenCommitters that share the same (original) blinding generator
    /// but that split the message generators between them.
    /// Split is such that first gets generators 0..split_index and second gets generators split_index..end.
    /// Useful in proof of dot product where we need to use the same h to commit to \vec{x} and y.
    /// Pre: 0 <= split_index <= self.message_generators.len()
    /// Post: self.message_generators == first.message_generators concat second_commit.message_generators
    /// Post: self, first and second have the same blinding_generator and int_abs_val_bitwidth
    pub fn split_at(&self, split_index: usize) -> (Self, Self) {
        let mut message_generators_first = self.message_generators.clone();
        let message_generators_second = message_generators_first.split_off(split_index);
        let mut message_doublings_first = self.message_generator_doublings.clone();
        let message_doublings_second = message_doublings_first.split_off(split_index);

        let first_commit = Self {
            message_generators: message_generators_first,
            blinding_generator: self.blinding_generator,
            int_abs_val_bitwidth: self.int_abs_val_bitwidth,
            message_generator_doublings: message_doublings_first,
        };
        let second_commit = Self {
            message_generators: message_generators_second,
            blinding_generator: self.blinding_generator,
            int_abs_val_bitwidth: self.int_abs_val_bitwidth,
            message_generator_doublings: message_doublings_second,
        };
        (first_commit, second_commit)
    }

    /// Commits to the vector of u8s using the specified blinding factor.
    /// Uses the precomputed generator powers and the binary decomposition.
    /// Convient wrapper of integer_vector_commit.
    /// Pre: self.int_abs_val_bitwidth >= 8.
    /// Post: same result as vector_commit, assuming uints are smaller than scalar field order.
    pub fn u8_vector_commit(&self, message: &Vec<u8>, blinding: &C::Scalar) -> C {
        debug_assert!(self.int_abs_val_bitwidth >= 8);
        let message_is_negative_bits = vec![false; message.len()];
        self.integer_vector_commit(&message, &message_is_negative_bits, blinding)
    }

    /// Commits to the vector of i8s using the specified blinding factor.
    /// Uses the precomputed generator powers and the binary decomposition.
    /// Convient wrapper of integer_vector_commit.
    /// Pre: self.int_abs_val_bitwidth >= 8.
    /// Post: same result as vector_commit, assuming ints are smaller than scalar field order.
    pub fn i8_vector_commit(&self, message: &Vec<i8>, blinding: &C::Scalar) -> C {
        debug_assert!(self.int_abs_val_bitwidth >= 8);
        let message_is_negative_bits = message.into_iter().map(|x| *x < 0i8).collect();
        let message: Vec<u8> = message.iter().map(|x| (*x as i16).abs() as u8).collect(); // convert i8 to i16 first so that .abs() doesn't fail for i8::MIN
        self.integer_vector_commit(&message, &message_is_negative_bits, blinding)
    }

    /// Commits to the vector of integers using the specified blinding factor.
    /// Integers are provided as a vector of UNSIGNED ints and a vector of bits indicating whether the integer is negative.
    /// Pre: values in message are non-negative.
    /// Pre: values have unsigned binary expressions using at most (self.highest_generator_power + 1) bits.
    /// Pre: message.len() <= self.message_generators.len()
    pub fn integer_vector_commit<T: PrimInt>(
        &self,
        message: &Vec<T>,
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

    /// Commit to the provided vector using the specified blinding factor.
    /// The first message.len() generators are used to commit to the message.
    /// Note that self.int_abs_val_bitwidth is not relevant here.
    /// Pre: message.len() <= self.message_generators.len()
    pub fn vector_commit(&self, message: &Vec<C::Scalar>, blinding: &C::Scalar) -> C {
        assert!(message.len() <= self.message_generators.len());
        let unblinded_commit = self
            .message_generators
            .iter()
            .zip(message.iter())
            .fold(C::zero(), |acc, (gen, input)| acc + (*gen * *input));
        unblinded_commit + self.blinding_generator * *blinding
    }

    /// Commit to the provided scalar using the specified blinding factor.
    /// Note that self.int_abs_val_bitwidth is not relevant here.
    /// Pre: self.message_generators.len() >= 1
    pub fn scalar_commit(&self, message: &C::Scalar, blinding: &C::Scalar) -> C {
        self.message_generators[0] * *message + self.blinding_generator * *blinding
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
