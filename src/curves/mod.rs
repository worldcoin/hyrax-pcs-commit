use ark_bn254::G1Affine as Bn256;
use ark_bn254::G1Projective as Bn256Point;
use ark_bn254::{Fq as Bn256Base, Fr as Bn256Scalar};
use ark_ec::AffineRepr;
use ark_ff::BigInteger;
use ark_ff::{Field, PrimeField};
use itertools::Itertools;
use rand_core::RngCore;
// use serde::{Deserialize, Serialize};
use ark_ec::CurveGroup;
use ark_ec::Group;
use num_traits::One;
use num_traits::Zero;

#[cfg(test)]
pub mod tests;

/// Traits and implementations for elliptic curves of prime order.
///
/// Justification for creating own elliptic curve trait:
/// + The trait in the halo2curves library that is closest to what is wanted is `CurveExt`.  However, the field trait they use for the base and scalar fields, viz. `WithSmallOrderMulGroup<3>` is not appropriate, however, as it restricts to finite fields for which p - 1 is divisible by 3.  This is an arbitrarily restriction from our POV (though it is satisfied by Bn254).  (Further, we found the halo2curves traits are very difficult to parse).
/// + The `AffineCurve` trait from `ark-ec` is precisely as specific as required and are beautifully written, but we'd need to implement the arkworks field traits for the fields we use from halo2.
use std::{
    fmt,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};
/// Minimal interface for an elliptic curve of prime order.
pub trait PrimeOrderCurve:
    Copy
    + Clone
    + Sized
    + Send
    + Sync
    + fmt::Debug
    + Eq
    + 'static
    + Neg<Output = Self>
    + Mul<Self::Scalar, Output = Self>
    + Add<Self, Output = Self>
    + Sub<Self, Output = Self>
    + AddAssign<Self>
    + SubAssign<Self>
    + MulAssign<Self::Scalar>
{
    type Scalar: PrimeField + Into<<Self::Scalar as PrimeField>::BigInt>;
    /// The finite field over which this curve is defined.
    type Base: Field;

    /// The byte sizes for the serialized representations.
    const UNCOMPRESSED_CURVE_POINT_BYTEWIDTH: usize;
    const COMPRESSED_CURVE_POINT_BYTEWIDTH: usize;
    const SCALAR_ELEM_BYTEWIDTH: usize;

    /// Return the additive identity of the curve.
    fn zero() -> Self;

    /// Return the "a" coordinate of the curve where y^2 = x^3 + ax + b
    fn a() -> Self::Base;

    /// Return the "b" coordinate of the curve where y^2 = x^3 + ax + b
    fn b() -> Self::Base;

    /// Return the chosen generator of the curve.
    fn generator() -> Self;

    /// Returns a bool determining whether the point is on the curve or not
    fn is_on_curve(&self) -> bool;

    /// Returns an element chosen uniformly at random.
    fn random(rng: impl RngCore) -> Self;

    /// Return the point doubled.
    fn double(&self) -> Self;

    /// Return the projective coordinates of the point.
    fn projective_coordinates(&self) -> (Self::Base, Self::Base, Self::Base);

    /// Return the affine coordinates of the point, if it is not at the identity (in which case, return None).
    fn affine_coordinates(&self) -> Option<(Self::Base, Self::Base)>;

    /// Returns an uncompressed byte representation of a curve element.
    fn to_bytes_uncompressed(&self) -> Vec<u8>;

    /// Returns a compressed byte representation of a curve element.
    fn to_bytes_compressed(&self) -> Vec<u8>;

    /// Returns the unique curve element represented by the uncompressed bytestring.
    fn from_bytes_uncompressed(bytes: &[u8]) -> Self;

    /// Returns the unique curve element represented by the compressed bytestring.
    fn from_bytes_compressed(bytes: &[u8]) -> Self;
}

impl PrimeOrderCurve for Bn256Point {
    type Scalar = Bn256Scalar;
    type Base = Bn256Base;

    const UNCOMPRESSED_CURVE_POINT_BYTEWIDTH: usize = 65;
    const COMPRESSED_CURVE_POINT_BYTEWIDTH: usize = 34;
    const SCALAR_ELEM_BYTEWIDTH: usize = 32;

    fn zero() -> Self {
        Bn256Point::default()
    }

    fn a() -> Self::Base {
        Bn256Base::zero()
    }

    fn b() -> Self::Base {
        Bn256Base::from(3_u64)
    }

    fn is_on_curve(&self) -> bool {
        if self.is_zero() {
            true
        } else {
            let (x, y) = self.affine_coordinates().unwrap();
            if ((x * x + Bn256Point::a()) * x + Bn256Point::b()) == y {
                true
            } else {
                false
            }
        }
    }

    fn generator() -> Self {
        Bn256::generator().into()
    }

    fn random(mut rng: impl RngCore) -> Self {
        // loop until we have a point that is not at infinity
        loop {
            let mut random_bytes = [0; 64];
            rng.fill_bytes(&mut random_bytes[..]);
            // use the first 512 bytes from the rng in order to sample a base field element reduced by mod
            let x_coord = Bn256Base::from_le_bytes_mod_order(&random_bytes);
            // grab the parity we want for the y coordinate in order to determine the unique square root
            let yparity_wanted = (rng.next_u32() % 2) as u8;

            // if the point is not at infinity, we can continue
            if let Some((y_option_1, y_option_2)) = Bn256::get_ys_from_x_unchecked(x_coord) {
                // return the correct parity y-coordinate
                let y_option_1_parity = y_option_1.into_bigint().to_bytes_le()[0] & 1;
                let y_coord = if yparity_wanted ^ y_option_1_parity == 0 {
                    y_option_1
                } else {
                    y_option_2
                };
                return Self {
                    x: x_coord,
                    y: y_coord,
                    z: Self::Base::one(),
                };
            }
        }
    }

    fn double(&self) -> Self {
        Group::double(&self)
    }

    fn projective_coordinates(&self) -> (Self::Base, Self::Base, Self::Base) {
        // See NB in affine_coordinates
        if let Some((x, y)) = self.affine_coordinates() {
            let z = Self::Base::one();
            (x, y, z)
        } else {
            // it's the identity element
            (Self::Base::zero(), Self::Base::one(), Self::Base::zero())
        }
    }

    fn affine_coordinates(&self) -> Option<(Self::Base, Self::Base)> {
        // NB: In version v2023_04_06 of halo2curves that Remainder is currently using,
        // the x,y,z members of the Bn256 struct are JACOBIAN coordinates, c.f.
        // [formulae for Jacobian coords](https://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html).
        // In more recent versions, the x,y,z are PROJECTIVE coordinates.  So when we upgrade to a more
        // recent version of halo2curves, we will need to change this implementation.
        if self.is_zero() {
            None
        } else {
            let coord = self.into_affine();
            let (x, y) = (coord.x, coord.y);
            Some((x, y))
        }
    }

    /// The bytestring representation of the BN256 curve is a `[u8; 65]` with
    /// the following semantic representation:
    /// * The first `u8` byte represents whether the point is a point at
    /// infinity (in affine coordinates). 1 if it is at infinity, 0 otherwise.
    /// * The next 32 `u8` bytes represent the x-coordinate of the point in little endian.
    /// * The next 32 `u8` bytes represent the y-coordinate of the point in little endian.
    fn to_bytes_uncompressed(&self) -> Vec<u8> {
        // --- First get the affine coordinates. If `None`, we have a point at infinity. ---
        let affine_coords = self.affine_coordinates();

        if let Some((x, y)) = affine_coords {
            let x_bytes = x.into_bigint().to_bytes_le();
            let y_bytes = y.into_bigint().to_bytes_le();
            let all_bytes = std::iter::once(0_u8)
                .chain(x_bytes.into_iter())
                .chain(y_bytes.into_iter())
                .collect_vec();
            assert_eq!(all_bytes.len(), Self::UNCOMPRESSED_CURVE_POINT_BYTEWIDTH);
            all_bytes
        } else {
            // --- Point at infinity ---
            return [1_u8; 65].to_vec();
        }
    }

    /// The bytestring representation of the BN256 curve is a `[u8; 34]` with
    /// the following semantic representation:
    /// * The first `u8` byte represents whether the point is a point at
    /// infinity (in affine coordinates).
    /// * The next 32 `u8` bytes represent the x-coordinate of the point in little endian.
    /// * The final `u8` byte represents the sign of the y-coordinate of the
    /// point.
    fn to_bytes_compressed(&self) -> Vec<u8> {
        // --- First get the affine coordinates. If `None`, we have a point at infinity. ---
        let affine_coords = self.affine_coordinates();

        if let Some((x, y)) = affine_coords {
            let x_bytes = x.into_bigint().to_bytes_le();
            // 0 when the square root is even, 1 when the square root is odd. we grab
            // the parity from the most significant byte and taking the & with 1. the
            // two square roots of y in the field always have opposite parity because
            // the field modulus is odd.
            let y_parity = y.into_bigint().to_bytes_le()[0] & 1;
            let all_bytes = std::iter::once(0_u8)
                .chain(x_bytes.into_iter())
                .chain(std::iter::once(y_parity))
                .collect_vec();
            assert_eq!(all_bytes.len(), Self::COMPRESSED_CURVE_POINT_BYTEWIDTH);
            all_bytes
        } else {
            // --- Point at infinity ---
            return [1_u8; 34].to_vec();
        }
    }

    /// will return the elliptic curve point corresponding to an array of bytes that represent an uncompressed point.
    /// we represent it as a a normalized projective curve point (ie, the x and y coordinates are directly the affine coordinates)
    /// so the z coordinate is always 1.
    fn from_bytes_uncompressed(bytes: &[u8]) -> Self {
        // assert that this is a 65 byte representation since it's uncompressed
        assert_eq!(bytes.len(), Self::UNCOMPRESSED_CURVE_POINT_BYTEWIDTH);
        // first check if it is a point at infinity
        if bytes[0] == 1_u8 {
            return Self {
                x: Self::Base::zero(),
                y: Self::Base::one(),
                z: Self::Base::zero(),
            };
        } else {
            let mut x_bytes_alloc = [0_u8; 32];
            let x_bytes = &bytes[1..33];
            x_bytes_alloc.copy_from_slice(x_bytes);

            let mut y_bytes_alloc = [0_u8; 32];
            let y_bytes = &bytes[33..];
            y_bytes_alloc.copy_from_slice(y_bytes);

            let x_coord = Self::Base::from_le_bytes_mod_order(&x_bytes_alloc);
            let y_coord = Self::Base::from_le_bytes_mod_order(&y_bytes_alloc);
            let point = Self {
                x: x_coord,
                y: y_coord,
                z: Self::Base::one(),
            };

            assert!(point.is_on_curve());

            point
        }
    }

    /// will return the elliptic curve point corresponding to an array of bytes that represent a compressed point.
    /// we represent it as a a normalized projective curve point (ie, the x and y coordinates are directly the affine coordinates)
    /// so the z coordinate is always 1.
    fn from_bytes_compressed(bytes: &[u8]) -> Self {
        // assert that this is a 34 byte representation since it's compressed
        assert_eq!(bytes.len(), Self::COMPRESSED_CURVE_POINT_BYTEWIDTH);
        // first check if it is a point at infinity
        if bytes[0] == 1_u8 {
            return Self {
                x: Self::Base::zero(),
                y: Self::Base::one(),
                z: Self::Base::zero(),
            };
        } else {
            let y_sign_byte: u8 = bytes[33];

            // y^2 = x^3 + ax + b
            let x_coord = Self::Base::from_le_bytes_mod_order(&bytes[1..33]);
            let (y_option_1, y_option_2) = Bn256::get_ys_from_x_unchecked(x_coord).unwrap();

            // --- Flip y-sign if needed ---
            let y_coord = if (y_option_1.into_bigint().to_bytes_le()[0] % 2) ^ y_sign_byte == 0 {
                y_option_1
            } else {
                y_option_2
            };

            let point = Self {
                x: x_coord,
                y: y_coord,
                z: Self::Base::one(),
            };

            point
        }
    }
}
