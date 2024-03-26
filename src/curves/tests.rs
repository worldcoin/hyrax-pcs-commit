use super::*;
use ark_bn254::G1Projective as Bn256;

fn test_curve_ops<C: PrimeOrderCurve>() {
    let zero = C::zero();
    let g = C::generator();
    // check that doubling works
    assert_eq!(g.double(), g + g);

    // generator better not be equal to twice itself!
    assert_ne!(g, g.double());

    // check that equality behaves as expected (i.e. it's not just comparing projective coordinates - this test isn't guaranteed to catch it out, of course)
    assert_eq!(g.double() - g, g);

    // check scalar multiplication
    let scalar = C::Scalar::from(4u64);
    assert_eq!(g * scalar, g + g + g + g);
    // also by negative scalars
    assert_eq!(g * scalar.neg(), -(g + g + g + g));

    // check the affine coords of the identity
    // NB if these fail, you've likely upgraded halo2curves, see note in the implementation of PrimeOrderCurve.
    assert_eq!(None, zero.affine_coordinates());
    // .. of the generator
    let (x, y) = g.affine_coordinates().unwrap(); // should not panic (since generator is not the identity!)
    assert_eq!(x, C::Base::from(1u64));
    assert_eq!(y, C::Base::from(2u64));

    // check the projective coordinates
    // .. of the identity
    let (x, y, z) = zero.projective_coordinates();
    assert_eq!(x, C::Base::zero());
    assert!(y != C::Base::zero());
    assert_eq!(z, C::Base::zero());
    // .. of the generator
    let (_x, _y, z) = g.projective_coordinates();
    assert!(z != C::Base::zero()); // only the identity has z=0

    // check that e.g. AddAssign works
    let mut acc = zero;
    acc += g;
    acc += g;
    assert_eq!(acc, g.double());

    // check that -= works
    let mut acc = zero;
    acc -= g;
    assert_eq!(acc, -g);

    // check that *= works
    let mut acc = g;
    acc *= scalar;
    assert_eq!(acc, g * scalar);

    // check that random works
    let r = C::random(&mut rand::thread_rng());
    assert_ne!(r, g); // improbable that they are equal, for large groups!
}

#[test]
fn test_bn256_implementation() {
    test_curve_ops::<Bn256>();
}
