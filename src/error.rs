use failure::Fail;

#[derive(Debug, Fail, Clone)]
pub enum DexParserError {
    #[fail(display = "file unexpectedly ended early: expected {} bytes", needed)]
    EndedEarly {
        needed: usize
    },
    #[fail(display = "could not parse file: {}", reason)]
    ParsingFailed {
        reason: String
    },
    #[fail(display = "could not decode string to UTF8: may be malformed")]
    EncodingError
}

impl<E: std::fmt::Debug + Clone> From<nom::Err<E>> for DexParserError {
    fn from(e: nom::Err<E>) -> Self {
        match e {
            nom::Err::Incomplete(ref needed) => {
                match needed {
                    nom::Needed::Unknown => DexParserError::ParsingFailed { reason: "file ended early".to_string() },
                    nom::Needed::Size(size) => DexParserError::EndedEarly { needed: *size }
                }
            },
            nom::Err::Error(ctx) => {
                match ctx {
                    nom::Context::Code(pos, kind) => {
                        DexParserError::ParsingFailed { reason: format!("parsing failed at byte {:?}: parser {:?}", pos, kind) }
                    },
                    nom::Context::List(errors) => {
                        let reason = errors.iter()
                            .map(|(pos, kind)| format!("parsing failed at byte {:?}: parser {:?}", pos, kind))
                            .collect::<Vec<String>>()
                            .join(": ");

                        DexParserError::ParsingFailed { reason }
                    }
                }
            },
            nom::Err::Failure(ctx) => {
                match ctx {
                    nom::Context::Code(pos, kind) => {
                        DexParserError::ParsingFailed { reason: format!("parsing failed at byte {:?}: parser {:?}", pos, kind) }
                    },
                    nom::Context::List(errors) => {
                        let reason = errors.iter()
                            .map(|(pos, kind)| format!("parsing failed at byte {:?}: parser {:?}", pos, kind))
                            .collect::<Vec<String>>()
                            .join(": ");

                        DexParserError::ParsingFailed { reason }
                    }
                }
            }
        }
    }
}

impl From<&'static str> for DexParserError {
    fn from(e: &'static str) -> Self {
        DexParserError::ParsingFailed { reason: e.to_string() }
    }
}

impl From<String> for DexParserError {
    fn from(e: String) -> Self {
        DexParserError::ParsingFailed { reason: e }
    }
}

impl From<::std::string::FromUtf8Error> for DexParserError {
    fn from(_e: ::std::string::FromUtf8Error) -> Self {
        DexParserError::ParsingFailed { reason: "could not parse string as UTF8".to_string() }
    }
}

impl From<DexParserError> for nom::Err<&[u8]> {
    fn from(e: DexParserError) -> Self {
        // TODO (release) - work out how to build a proper error here, or avoid converting back and forth
        nom::Err::Failure(nom::Context::Code(b"TODO", nom::ErrorKind::Custom(0)))
    }
}