use halo2_base::utils::ScalarField as Halo2Field;
use halo2curves::{bn256::G1 as Bn256, group::ff::Field, CurveExt};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
/// Traits and implementations for elliptic curves of prime order.
///
/// Justification for creating own elliptic curve trait:
/// + The trait in the halo2curves library that is closest to what is wanted is `CurveExt`.  However, the field trait they use for the base and scalar fields, viz. `WithSmallOrderMulGroup<3>` is not appropriate, however, as it restricts to finite fields for which p - 1 is divisible by 3.  This is an arbitrarily restriction from our POV (though it is satisfied by Bn254).  (Further, we found the halo2curves traits are very difficult to parse).
/// + The `AffineCurve` trait from `ark-ec` is precisely as specific as required and are beautifully written, but we'd need to implement the arkworks field traits for the fields we use from halo2.
use std::{
    fmt,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};
// Implementation note: do not confuse the following with the very similarly named remainder_shared_types::halo2curves::Group
use halo2curves::group::Group;

pub mod tests;

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
    + Serialize
    + for<'de> Deserialize<'de>
{
    /// The scalar field of the curve.
    type Scalar: Halo2Field;

    /// The base field of the curve.
    type Base: Halo2Field;

    /// Return the additive identity of the curve.
    fn zero() -> Self;

    /// Return the chosen generator of the curve.
    fn generator() -> Self;

    /// Returns an element chosen uniformly at random.
    fn random(rng: impl RngCore) -> Self;

    /// Return the point doubled.
    fn double(&self) -> Self;

    /// Return the projective coordinates of the point.
    fn projective_coordinates(&self) -> (Self::Base, Self::Base, Self::Base);

    /// Return the affine coordinates of the point, if it is not at the identity (in which case, return None).
    fn affine_coordinates(&self) -> Option<(Self::Base, Self::Base)>;

    fn from_random_bytes(bytes: &[u8]) -> Option<Self>;
}

impl PrimeOrderCurve for Bn256 {
    type Scalar = <Bn256 as CurveExt>::ScalarExt;
    type Base = <Bn256 as CurveExt>::Base;

    fn zero() -> Self {
        Bn256::identity()
    }

    fn generator() -> Self {
        Bn256::generator()
    }

    fn random(rng: impl RngCore) -> Self {
        <Bn256 as Group>::random(rng)
    }

    fn from_random_bytes(bytes: &[u8]) -> Option<Self> {
        dbg!(bytes.len());
        if bytes.len() != 68 {
            return None;
        }
        let x_bytes = &bytes[..64];
        dbg!(x_bytes.len());
        let mut thingy = [0_u8; 32];
        // thingy.copy_from_slice(&x_bytes[..31]);
        dbg!(&thingy);
        let x = Self::Base::from_bytes(&thingy).unwrap();
        dbg!("hi");

        let sliced_sign_bytes = &bytes[64..68];
        dbg!("hi1");

        let mut sign_bytes = [0_u8; 4];
        sign_bytes.copy_from_slice(sliced_sign_bytes);
        let lastu32 = u32::from_le_bytes(sign_bytes);
        dbg!("hi2");

        let y_sign = (lastu32 % 2) as u8;
        let y2 = x.square() * x + Self::Base::from(3);

        if let Some(y_arb_sign) = Option::<Self::Base>::from(y2.sqrt()) {
            let arb_sign = y_arb_sign.to_bytes()[0] & 1;
            let y = if y_sign ^ arb_sign == 0 {
                y_arb_sign
            } else {
                -y_arb_sign
            };
            let rand_point = Bn256 {
                x,
                y,
                z: Self::Base::one(),
            };
            Some(rand_point)
        } else {
            None
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
        if self.z == Self::Base::zero() {
            None
        } else {
            let z_inv = self.z.invert().unwrap();
            Some((self.x * z_inv.square(), self.y * z_inv.cube()))
        }
    }
}
