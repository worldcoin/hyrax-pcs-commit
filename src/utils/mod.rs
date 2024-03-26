use std::{
    fs,
    io::{BufWriter, Read},
};

use rand::RngCore;
use sha3::digest::XofReader;
use sha3::Sha3XofReader;

/// Helper function for buffered writing to file.
pub fn write_bytes_to_file(filename: &str, bytes: &[u8]) {
    let file = fs::File::create(filename).unwrap();
    let bw = BufWriter::new(file);
    serde_json::to_writer(bw, &bytes).unwrap();
}

/// Helper function for buffered reading from file.
pub fn read_bytes_from_file(filename: &str) -> Vec<u8> {
    let mut file = std::fs::File::open(filename).unwrap();
    let initial_buffer_size = file.metadata().map(|m| m.len() as usize + 1).unwrap_or(0);
    let mut bufreader = Vec::with_capacity(initial_buffer_size);
    file.read_to_end(&mut bufreader).unwrap();
    serde_json::de::from_slice(&bufreader[..]).unwrap()
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
