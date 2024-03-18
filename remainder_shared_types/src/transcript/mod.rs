//!A type that is responsible for FS over the interative version of the protocol

use thiserror::Error;
pub mod poseidon_transcript;

///An error representing the things that can go wrong when working with a Transcript
#[derive(Error, Debug, Clone)]
pub enum TranscriptError {
    #[error("The challenges generated don't match challenges given!")]
    TranscriptMatchError,
}

///A type that is responsible for FS over the interative version of the protocol
pub trait Transcript<F>: Clone {
    ///Create an empty transcript
    fn new(label: &'static str) -> Self;

    ///Append a single field element to the transcript
    fn append_field_element(
        &mut self,
        label: &'static str,
        element: F,
    ) -> Result<(), TranscriptError>;

    ///Append a list of field elements to the transcript
    fn append_field_elements(
        &mut self,
        label: &'static str,
        elements: &[F],
    ) -> Result<(), TranscriptError>;

    ///Generate a random challenge and add it to the transcript
    fn get_challenge(&mut self, label: &'static str) -> Result<F, TranscriptError>;

    ///Generate a list of random challenges and add it to the transcript
    fn get_challenges(
        &mut self,
        label: &'static str,
        len: usize,
    ) -> Result<Vec<F>, TranscriptError>;
}
