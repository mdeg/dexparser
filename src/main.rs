#[macro_use] extern crate nom;
extern crate leb128;
extern crate byteorder;

mod parser;

use std::fs::File;
use std::io::Read;

fn main() {

    let mut file = File::open("/home/michael/devel/dexparser/classes2.dex").unwrap();

    let mut dex_file = Vec::new();

    file.read_to_end(&mut dex_file);

//    match parser::parse(&dex_file) {
//        Ok(res) => {},
//        Err(e) => {}
//    }

    match parser::parse(&dex_file) {
        Ok(res) => println!("Result: {:#?}", res),
        Err(e) => println!("ERROR!: {:#?}", e)
    }
}