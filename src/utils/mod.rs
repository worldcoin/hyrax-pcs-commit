use std::{
    fs,
    io::{BufWriter, Read, Write},
};

/// The file that the image is stored in as an array of bytes.
pub const INPUT_NORMALIZED_IMAGE_FILENAME: &str = "examples/dummy-data/left_normalized_image.bin";
/// The file that the serialized commitment to the iris image is stored in.
pub const COMMITMENT_FILENAME: &str = "examples/dummy-data/left_normalized_image_commitment.bin";
/// The file that the serialized blinding factors are stored in.
pub const BLINDING_FACTORS_FILENAME: &str = "examples/dummy-data/left_normalized_image_blinding_factors.bin";

use rand::RngCore;
use sha3::digest::XofReader;
use sha3::Sha3XofReader;

/// Helper function for buffered writing to file.  Writes raw binary data.
pub fn write_bytes_to_file(filename: &str, bytes: &[u8]) {
    let file = fs::File::create(filename).unwrap();
    let mut bw = BufWriter::new(file);
    bw.write_all(bytes).unwrap();
}

/// Helper function to read (raw binary) bytes from a file, preallocating the required space.
pub fn read_bytes_from_file(filename: &str) -> Vec<u8> {
    let mut file = std::fs::File::open(filename).unwrap();
    let initial_buffer_size = file.metadata().map(|m| m.len() as usize + 1).unwrap_or(0);
    let mut bufreader = Vec::with_capacity(initial_buffer_size);
    file.read_to_end(&mut bufreader).unwrap();
    bufreader
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
