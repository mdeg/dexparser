#[macro_use] extern crate nom;
extern crate leb128;
extern crate byteorder;
extern crate failure;

mod parser;
mod error;
mod result_types;

pub use error::DexParserError;
pub use result_types::*;
pub use nom::Endianness;

pub fn parse(buf: &[u8]) -> Result<DexFile, DexParserError> {
    parser::parse(buf)
}

// TODO (improvement): validate checksum/signature