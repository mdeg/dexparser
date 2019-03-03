#[macro_use] extern crate nom;
extern crate leb128;
extern crate byteorder;

mod parser;
mod error;
mod result_types;

pub use error::ParserErr;
pub use result_types::*;
pub use nom::Endianness;

pub fn parse(buf: &[u8]) -> Result<DexFile, ParserErr> {
    parser::parse(buf)
}