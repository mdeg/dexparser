use ::std::fmt;

#[derive(Debug, Clone)]
pub enum ParserErr {
    EndedEarly(usize),
    ParsingFailed(String),
    EncodingError
}

impl std::error::Error for ParserErr {}

impl<E: fmt::Debug + Clone> From<nom::Err<E>> for ParserErr {
    fn from(e: nom::Err<E>) -> Self {

        match e {
            nom::Err::Incomplete(ref needed) => {
                match needed {
                    nom::Needed::Unknown => ParserErr::ParsingFailed(String::from("file ended early")),
                    nom::Needed::Size(size) => ParserErr::EndedEarly(*size)
                }
            },
            nom::Err::Error(ctx) => {
                match ctx {
                    nom::Context::Code(pos, kind) => {
//                        std::dbg!(position);
                        std::dbg!(kind);
                    },
                    // TODO: cfg flag this
                    nom::Context::List(errors) => {
                        for error in errors {
                            std::dbg!(error.1);
                        }
                    }
                }
                ParserErr::ParsingFailed(String::from("parsing failed"))
            },
            nom::Err::Failure(ctx) => ParserErr::ParsingFailed(String::from("parsing failed"))
        }
    }
}

impl From<&'static str> for ParserErr {
    fn from(e: &'static str) -> Self {
        ParserErr::ParsingFailed(e.to_string())
    }
}

impl From<String> for ParserErr {
    fn from(e: String) -> Self {
        ParserErr::ParsingFailed(e)
    }
}

impl From<::std::string::FromUtf8Error> for ParserErr {
    fn from(_e: ::std::string::FromUtf8Error) -> Self {
        ParserErr::ParsingFailed("could not parse string as UTF8".to_string())
    }
}

impl From<ParserErr> for nom::Err<&[u8]> {
    fn from(e: ParserErr) -> Self {
        nom::Err::Failure(nom::Context::Code(b"TODO", nom::ErrorKind::Custom(0)))
    }
}

impl fmt::Display for ParserErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            ParserErr::EndedEarly(size) => write!(f, "file ended early"),
            ParserErr::ParsingFailed(text) => write!(f, "{}", text),
            ParserErr::EncodingError => write!(f, "UTF8 string encoding error")
        }
    }
}