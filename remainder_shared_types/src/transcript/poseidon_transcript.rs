//! A transcript that uses the Poseidon hash function; Useful for recursive proving
use std::marker::PhantomData;

use crate::Poseidon;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use tracing::trace;

use crate::FieldExt;

use super::{Transcript, TranscriptError};

fn default_sponge<F: FieldExt>() -> Poseidon<F, 3, 2> {
    Poseidon::new(8, 57)
}

/// A transcript that uses the Poseidon hash function; Useful for recursive proving
#[derive(Serialize, Deserialize, Clone)]
#[serde(bound = "F: FieldExt")]
pub struct PoseidonTranscript<F: FieldExt> {
    #[serde(skip)]
    #[serde(default = "default_sponge")]
    sponge: Poseidon<F, 3, 2>,
    counter: usize,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Transcript<F> for PoseidonTranscript<F> {
    fn new(label: &'static str) -> Self {
        trace!(module = "Transcript", label);
        //TODO!(This sucks, generating them anew every time is slow, stupid, and likely to lead to problems integrating with Marcin. Need to read these from somewhere. Touch base with Marcin on these constants)
        // let (ark, mds) = find_poseidon_ark_and_mds::<F>(F::MODULUS_BIT_SIZE as u64, 2, 8, 60, 0);

        // let params = PoseidonConfig::new(8, 60, 5, mds, ark, 2, 1);
        Self {
            sponge: default_sponge(),
            counter: 1,
            _marker: PhantomData,
        }
    }

    fn append_field_element(
        &mut self,
        label: &'static str,
        element: F,
    ) -> Result<(), TranscriptError> {
        trace!(module = "Transcript", "Absorbing: {}, {:?}", label, element);
        self.sponge.update(&[element]);
        Ok(())
    }

    fn append_field_elements(
        &mut self,
        label: &'static str,
        elements: &[F],
    ) -> Result<(), TranscriptError> {
        trace!(
            module = "Transcript",
            "Absorbing: {}, {:?}",
            label,
            elements
        );
        // dbg!(&elements);
        self.sponge.update(elements);
        Ok(())
    }

    fn get_challenge(&mut self, label: &'static str) -> Result<F, TranscriptError> {
        let output = self.sponge.squeeze();
        trace!(module = "Transcript", "Squeezing: {}, {:?}", label, output);

        self.counter += 1;
        Ok(output)
    }

    fn get_challenges(
        &mut self,
        label: &'static str,
        len: usize,
    ) -> Result<Vec<F>, TranscriptError> {
        let output = (0..len).map(|_| self.sponge.squeeze()).collect_vec();
        trace!(module = "Transcript", "Squeezing: {}, {:?}", label, output);
        Ok(output)
    }
}

#[cfg(test)]
mod tests {}
