use ::std::fmt;

#[derive(Debug)]
pub struct ParserErr;

impl std::error::Error for ParserErr {}

impl<E: fmt::Debug + Clone> From<nom::Err<E>> for ParserErr {
    fn from(e: nom::Err<E>) -> Self {
        // TODO
        println!("error! {:?}", e);
        ParserErr
    }
}

impl From<&'static str> for ParserErr {
    fn from(e: &'static str) -> Self {
        // TODO
        println!("error! {:?}", e);
        ParserErr
    }
}

impl From<String> for ParserErr {
    fn from(e: String) -> Self {
        // TODO
        println!("error! {:?}", e);
        ParserErr
    }
}

impl From<ParserErr> for nom::Err<&[u8]> {
    fn from(e: ParserErr) -> Self {
        nom::Err::Failure(nom::Context::Code(b"TODO", nom::ErrorKind::Custom(0)))
//        unimplemented!()
    }
}

impl fmt::Display for ParserErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "TODO")
    }
}