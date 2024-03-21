use halo2_base::halo2_proofs::arithmetic::Field;
use halo2_base::utils::ScalarField as Halo2Field;
use halo2_base::halo2_proofs::halo2curves::{bn256::G1 as Bn256, CurveExt};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use sha3::digest::XofReader;
use sha3::Sha3XofReader;

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
// Implementation note: do not confuse the following with the very similarly named remainder_shared_types::halo2curves::Group
use halo2_base::halo2_proofs::halo2curves::group::Group;
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

    fn from_random_bytes(bytes: &[u8]) -> Self;
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

    fn from_random_bytes(bytes: &[u8]) -> Self {
        let curve_hasher = Bn256::hash_to_curve("hello");
        curve_hasher(&bytes)
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

pub struct Sha3XofReaderWrapper {
    item: Sha3XofReader,
}

impl Sha3XofReaderWrapper {
    pub fn new(item: Sha3XofReader) -> Self {
        Self { item }
    }
}

impl RngCore for Sha3XofReaderWrapper {
    fn next_u32(&mut self) -> u32 {
        let mut buffer: [u8; 4] = [0; 4];
        self.item.read(&mut buffer);
        u32::from_le_bytes(buffer)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buffer: [u8; 8] = [0; 8];
        self.item.read(&mut buffer);
        u64::from_le_bytes(buffer)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.item.read(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.item.read(dest);
        Ok(())
    }
}
