pub mod transcript;

use halo2_base::utils::ScalarField;
use serde::{Deserialize, Serialize};

pub use halo2curves;
pub use halo2curves::bn256::Fr;
pub use poseidon::Poseidon;

///External definition of Field element trait, will remain an Alias for now
pub trait FieldExt: ScalarField + Serialize + for<'de> Deserialize<'de> {}

impl<F: ScalarField + Serialize + for<'de> Deserialize<'de>> FieldExt for F {}
