#[macro_use] extern crate nom;
extern crate leb128;
extern crate byteorder;

mod parser;
mod error;
mod result_types;

pub use error::ParserErr;
pub use result_types::*;

use std::io::Read;

pub fn parse(buf: &[u8]) -> Result<DexFile, ParserErr> {
    parser::parse(buf)
}

pub fn parse_file(file: &mut std::fs::File) -> Result<DexFile, ParserErr> {
    let mut bytes = Vec::new();
    // TODO: map error to ParserErr and return
    file.read_to_end(&mut bytes);
    parser::parse(&bytes)
}