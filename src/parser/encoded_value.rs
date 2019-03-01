use super::{parse_uleb128, take_one, Uleb128};
use crate::error::*;
use super::parse_data::parse_annotation_element_item;
use super::raw_types::*;
use byteorder::ByteOrder;
use std::fmt;

// note that this does NOT peek! that's the responsibility of the calling parser
named!(pub parse_encoded_value_item<&[u8], EncodedValue>,
    do_parse!(
        value_type: call!(take_one) >>
        value: call!(parse_value, value_type) >>
        (value)
    )
);

fn parse_value(value: &[u8], value_type: u8) -> Result<(&[u8], EncodedValue), nom::Err<&[u8]>> {
    // The high order 3 bits of the value type may contain useful size information or data
    let value_arg = ((value_type & 0xE0) >> 5) as i8;

    Ok(match EncodedValueType::parse(value_type & 0x1F)? {
        EncodedValueType::Byte => map!(value, take!(1), |x| { EncodedValue::Byte(x[0]) })?,
        EncodedValueType::Short => map!(value, map!(take!(value_arg + 1), |x| { byteorder::LittleEndian::read_int(x, x.len()) as i16}), EncodedValue::Short)?,
        EncodedValueType::Char => map!(value, map!(take!(value_arg + 1), |x| { byteorder::LittleEndian::read_uint(x, x.len()) as u16 }), EncodedValue::Char)?,
        EncodedValueType::Int => map!(value, map!(take!(value_arg + 1), |x| { byteorder::LittleEndian::read_int(x, x.len()) as i32 }), EncodedValue::Int)?,
        EncodedValueType::Long => map!(value, map!(take!(value_arg + 1), |x| { byteorder::LittleEndian::read_int(x, x.len()) as i64 }), EncodedValue::Long)?,
        // Floats and Doubles below the maximum byte width should be 0-extended to the right
        EncodedValueType::Float => map!(value, map!(take!(value_arg + 1), |x| {
            if x.len() < 4 {
                let mut v = x.to_vec();
                v.extend(vec![0; 4 - x.len()]);
                byteorder::LittleEndian::read_f32(&v)
            } else {
                byteorder::LittleEndian::read_f32(x)
            }
        }), EncodedValue::Float)?,
        EncodedValueType::Double => map!(value, map!(take!(value_arg + 1), |x| {
            if x.len() < 8 {
                let mut v = x.to_vec();
                v.extend(vec![0; 8 - x.len()]);
                byteorder::LittleEndian::read_f64(&v)
            } else {
                byteorder::LittleEndian::read_f64(x)
            }
        }), EncodedValue::Double)?,
        EncodedValueType::MethodType => map!(value, call!(convert_variable_u32, value_arg + 1), EncodedValue::MethodType)?,
        EncodedValueType::MethodHandle => map!(value, call!(convert_variable_u32, value_arg + 1), EncodedValue::MethodHandle)?,
        EncodedValueType::String => map!(value, call!(convert_variable_u32, value_arg + 1), EncodedValue::String)?,
        EncodedValueType::Type => map!(value, call!(convert_variable_u32, value_arg + 1), EncodedValue::Type)?,
        EncodedValueType::Field => map!(value, call!(convert_variable_u32, value_arg + 1), EncodedValue::Field)?,
        EncodedValueType::Method => map!(value, call!(convert_variable_u32, value_arg + 1), EncodedValue::Method)?,
        EncodedValueType::Enum => map!(value, call!(convert_variable_u32, value_arg + 1), EncodedValue::Enum)?,
        EncodedValueType::Array => map!(value, parse_encoded_array_item, EncodedValue::Array)?,
        EncodedValueType::Annotation => map!(value, parse_encoded_annotation_item, EncodedValue::Annotation)?,
        EncodedValueType::Null => (value, EncodedValue::Null),
        // The value for boolean types is the last bit of the value arg
        EncodedValueType::Boolean => (value, EncodedValue::Boolean(value_arg != 0)),
    })
}

named_args!(convert_variable_u32(size: i8)<&[u8], u32>,
    map!(take!(size), |x| { byteorder::LittleEndian::read_uint(x, x.len()) as u32 })
);

named!(pub parse_encoded_annotation_item<&[u8], RawEncodedAnnotationItem>,
    do_parse!(
        type_idx: call!(parse_uleb128) >>
        size: call!(parse_uleb128) >>
        elements: count!(call!(parse_annotation_element_item), size as usize) >>
        (RawEncodedAnnotationItem { type_idx, size, elements })
    )
);

named!(pub parse_encoded_array_item<&[u8], EncodedArrayItem>,
    do_parse!(
        size: call!(parse_uleb128)   >>
        values: count!(call!(parse_encoded_value_item), size as usize)  >>
        (EncodedArrayItem { size, values })
    )
);

// TODO (release): this should be raw encoded value, and everything destructured out
// Specifically the method types and handles which are indexes into the string/prototype/etc stuff!!!
#[derive(Debug, PartialEq, Clone)]
pub enum EncodedValue {
    Byte(u8),
    Short(i16),
    Char(u16),
    Int(i32),
    Long(i64),
    Float(f32),
    Double(f64),
    MethodType(u32),
    MethodHandle(u32),
    String(u32),
    Type(u32),
    Field(u32),
    Method(u32),
    Enum(u32),
    Array(EncodedArrayItem),
    Annotation(RawEncodedAnnotationItem),
    Null,
    Boolean(bool)
}

impl fmt::Display for EncodedValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            EncodedValue::Byte(ref i) => write!(f, "{}", i),
            EncodedValue::Short(ref i) => write!(f, "{}", i),
            EncodedValue::Char(ref i) => write!(f, "{}", i),
            EncodedValue::Int(ref i) => write!(f, "{}", i),
            EncodedValue::Long(ref i) => write!(f, "{}", i),
            EncodedValue::Float(ref i) => write!(f, "{}", i),
            EncodedValue::Double(ref i) => write!(f, "{}", i),
            EncodedValue::MethodType(ref i) => write!(f, "{}", i),
            EncodedValue::MethodHandle(ref i) => write!(f, "{}", i),
            EncodedValue::String(ref i) => write!(f, "{}", i),
            EncodedValue::Type(ref i) => write!(f, "{}", i),
            EncodedValue::Field(ref i) => write!(f, "{}", i),
            EncodedValue::Method(ref i) => write!(f, "{}", i),
            EncodedValue::Enum(ref i) => write!(f, "{}", i),
            EncodedValue::Array(ref i) => write!(f, "{}", i),
            // indicates coding error - raw values should never reach output
            // TODO (release): should this panic?
            EncodedValue::Annotation(_) => write!(f, "TODO"),
//            EncodedValue::Annotation(_) => panic!("attempted to display raw annotation value"),
            EncodedValue::Null => write!(f, "null"),
            EncodedValue::Boolean(ref i) => write!(f, "{}", i)
        }
    }
}

impl ::std::fmt::Display for EncodedArrayItem {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "[{}]", &self.values.iter()
            .map(ToString::to_string)
            .collect::<Vec<String>>()
            .join(", "))
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct EncodedArrayItem {
    pub size: Uleb128,
    pub values: Vec<EncodedValue>
}

#[derive(Debug)]
enum EncodedValueType {
    Byte,
    Short,
    Char,
    Int,
    Long,
    Float,
    Double,
    MethodType,
    MethodHandle,
    String,
    Type,
    Field,
    Method,
    Enum,
    Array,
    Annotation,
    Null,
    Boolean
}

impl EncodedValueType {
    fn parse(value: u8) -> Result<Self, ParserErr> {
        match value {
            0x00 => Ok(EncodedValueType::Byte),
            0x02 => Ok(EncodedValueType::Short),
            0x03 => Ok(EncodedValueType::Char),
            0x04 => Ok(EncodedValueType::Int),
            0x06 => Ok(EncodedValueType::Long),
            0x10 => Ok(EncodedValueType::Float),
            0x11 => Ok(EncodedValueType::Double),
            0x15 => Ok(EncodedValueType::MethodType),
            0x16 => Ok(EncodedValueType::MethodHandle),
            0x17 => Ok(EncodedValueType::String),
            0x18 => Ok(EncodedValueType::Type),
            0x19 => Ok(EncodedValueType::Field),
            0x1A => Ok(EncodedValueType::Method),
            0x1B => Ok(EncodedValueType::Enum),
            0x1C => Ok(EncodedValueType::Array),
            0x1D => Ok(EncodedValueType::Annotation),
            0x1E => Ok(EncodedValueType::Null),
            0x1F => Ok(EncodedValueType::Boolean),
            _ => Err(ParserErr::from(format!("Could not find encoded value type for 0x{:02X}", value)))
        }
    }
}


#[cfg(test)]
mod tests {

    use super::*;
    use byteorder::*;

    #[test]
    fn test_empty_encoded_value_item() {
        let writer = vec!();
        let err = parse_encoded_value_item(&writer);
        assert!(err.is_err());
        assert_eq!(err.err().unwrap(), nom::Err::Incomplete(nom::Needed::Size(1)));
    }

    #[test]
    fn test_invalid_encoded_value_item_type() {
        let mut writer = vec!();
        writer.write_u8(0x01).unwrap();
        let err = parse_encoded_value_item(&writer);
        assert!(err.is_err());
    }

    #[test]
    fn test_parse_byte_value() {
        let mut writer = vec!();
        // value type
        writer.write_u8(0b00000000).unwrap();

        // with no following byte value
        let err = parse_encoded_value_item(&writer);
        assert!(err.is_err());

        // add in a value
        writer.write_u8(0x01).unwrap();

        let res = parse_encoded_value_item(&writer).unwrap();

        assert_eq!(res.1, EncodedValue::Byte(0x01));
    }

    #[test]
    fn test_parse_short_value_single_byte() {
        let mut writer = vec!();
        // value type
        writer.write_u8(0b00000010).unwrap();
        // value
        writer.write_u8(1 as u8).unwrap();

        let res = parse_encoded_value_item(&writer).unwrap();

        assert_eq!(res.1, EncodedValue::Short(1))
    }

    #[test]
    fn test_parse_short_value_multiple_bytes() {
        let mut writer = vec!();
        // value type
        writer.write_u8(0b00100010).unwrap();
        // value
        writer.write_i16::<LittleEndian>(::std::i16::MAX).unwrap();

        let res = parse_encoded_value_item(&writer).unwrap();

        assert_eq!(res.1, EncodedValue::Short(::std::i16::MAX))
    }

    #[test]
    fn test_parse_char_value_single_byte() {
        let mut writer = vec!();
        // value type
        writer.write_u8(0b00000011).unwrap();
        // single byte char value
        writer.write_u8('A' as u8).unwrap();

        let res = parse_encoded_value_item(&writer).unwrap();

        assert_eq!(res.1, EncodedValue::Char('A' as u16))
    }

    #[test]
    fn test_parse_char_value_multiple_byte() {
        let mut writer = vec!();
        // value type
        writer.write_u8(0b00100011).unwrap();
        // two byte unicode value
        writer.write_u16::<LittleEndian>('ß' as u16).unwrap();

        let res = parse_encoded_value_item(&writer).unwrap();

        assert_eq!(res.1, EncodedValue::Char('ß' as u16))
    }

    #[test]
    fn test_parse_int_value_single_byte() {
        let mut writer = vec!();
        // value type (int, single byte)
        writer.write_u8(0b00000100).unwrap();
        // value
        writer.write_u8(1_i32 as u8).unwrap();

        let res = parse_encoded_value_item(&writer).unwrap();

        assert_eq!(res.1, EncodedValue::Int(1_i32))
    }

    #[test]
    fn test_parse_int_value_multiple_bytes() {
        let mut writer = vec!();
        // value type (int, 4 bytes)
        writer.write_u8(0b01100100).unwrap();
        // value
        writer.write_i32::<LittleEndian>(::std::i32::MAX).unwrap();

        let res = parse_encoded_value_item(&writer).unwrap();

        assert_eq!(res.1, EncodedValue::Int(::std::i32::MAX))
    }

    #[test]
    fn test_parse_long_value_single_byte() {
        let mut writer = vec!();
        // value type (long, 1 byte)
        writer.write_u8(0b00000110).unwrap();
        // value
        writer.write_u8(1_i64 as u8).unwrap();

        let res = parse_encoded_value_item(&writer).unwrap();

        assert_eq!(res.1, EncodedValue::Long(1_i64))
    }

    #[test]
    fn test_parse_long_value_multiple_bytes() {
        let mut writer = vec!();
        // value type (long, 8 bytes)
        writer.write_u8(0b11100110).unwrap();
        // value
        writer.write_i64::<LittleEndian>(::std::i64::MAX).unwrap();

        let res = parse_encoded_value_item(&writer).unwrap();

        assert_eq!(res.1, EncodedValue::Long(::std::i64::MAX))
    }

    #[test]
    fn test_parse_float_value_single_byte() {
        // spec says a float may be encoded as a single byte
        // TODO (release): is 0 the only IEEE754 float value that can be encoded with a single byte?
        let mut writer = vec!();
        // value type (float, 1 byte)
        writer.write_u8(0b00010000).unwrap();
        // value
        writer.write_u8(0b00000000).unwrap();

        let res = parse_encoded_value_item(&writer).unwrap();

        match res.1 {
            EncodedValue::Float(x) => assert_eq!(x, 0_f32),
            _ => panic!()
        }
    }

    // TODO (release): work out how exactly the spec encodes floats
//    #[test]
//    fn test_parse_float_value_two_bytes() {
//        // a two byte value
//        // tests that we are sign extending correctly
//
//        let mut writer = vec!();
//        // value type (float, 2 byte)
//        writer.write_u8(0b00110000).unwrap();
//        // value
//        // write sign and exponent (2 decimal places)
//        writer.write_u8(0b00000010).unwrap();
//        // then value (255)
//        writer.write_u8(0b11111111).unwrap();
//
//        let res = parse_encoded_value_item(&writer).unwrap();
//
//        match res.1 {
//            EncodedValue::Float(x) => assert_eq!(x, 2.55_f32),
//            _ => panic!()
//        }
//    }

    #[test]
    fn test_parse_float_value_multiple_byte() {
        let mut writer = vec!();
        // value type (float, 4 bytes)
        writer.write_u8(0b01110000).unwrap();
        // value
        writer.write_f32::<LittleEndian>(::std::f32::MAX).unwrap();

        let res = parse_encoded_value_item(&writer).unwrap();

        assert_eq!(res.1, EncodedValue::Float(::std::f32::MAX))
    }

    #[test]
    fn test_parse_double_value() {
        let mut writer = vec!();
        // value type (8-byte length)
        writer.write_u8(0b11110001).unwrap();
        // value
        writer.write_f64::<LittleEndian>(123_f64).unwrap();

        let res = parse_encoded_value_item(&writer).unwrap();

        assert_eq!(res.1, EncodedValue::Double(123_f64))
    }

    // TODO (release): write more tests for double values

    // TODO (release): write multi/single byte tests for method types

    #[test]
    fn test_parse_method_type() {
        let mut writer = vec!();
        // value type
        writer.write_u8(0x15).unwrap();
        // value
        writer.write_u32::<LittleEndian>(123_u32).unwrap();

        let res = parse_encoded_value_item(&writer).unwrap();

        assert_eq!(res.1, EncodedValue::MethodType(123_u32))
    }

    #[test]
    fn test_parse_method_handle() {
        let mut writer = vec!();
        // value type
        writer.write_u8(0x16).unwrap();
        // value
        writer.write_u32::<LittleEndian>(123_u32).unwrap();

        let res = parse_encoded_value_item(&writer).unwrap();

        assert_eq!(res.1, EncodedValue::MethodHandle(123_u32))
    }

    #[test]
    fn test_parse_string() {
        let mut writer = vec!();
        // value type
        writer.write_u8(0x17).unwrap();
        // value
        writer.write_u32::<LittleEndian>(123_u32).unwrap();

        let res = parse_encoded_value_item(&writer).unwrap();

        assert_eq!(res.1, EncodedValue::String(123_u32))
    }

    #[test]
    fn test_parse_type() {
        let mut writer = vec!();
        // value type
        writer.write_u8(0x18).unwrap();
        // value
        writer.write_u32::<LittleEndian>(123_u32).unwrap();

        let res = parse_encoded_value_item(&writer).unwrap();

        assert_eq!(res.1, EncodedValue::Type(123_u32))
    }

    #[test]
    fn test_parse_field() {
        let mut writer = vec!();
        // value type
        writer.write_u8(0x19).unwrap();
        // value
        writer.write_u32::<LittleEndian>(123_u32).unwrap();

        let res = parse_encoded_value_item(&writer).unwrap();

        assert_eq!(res.1, EncodedValue::Field(123_u32))
    }

    #[test]
    fn test_parse_method() {
        let mut writer = vec!();
        // value type
        writer.write_u8(0x1A).unwrap();
        // value
        writer.write_u32::<LittleEndian>(123_u32).unwrap();

        let res = parse_encoded_value_item(&writer).unwrap();

        assert_eq!(res.1, EncodedValue::Method(123_u32))
    }

    #[test]
    fn test_parse_enum() {
        let mut writer = vec!();
        // value type
        writer.write_u8(0x1B).unwrap();
        // value
        writer.write_u32::<LittleEndian>(123_u32).unwrap();

        let res = parse_encoded_value_item(&writer).unwrap();

        assert_eq!(res.1, EncodedValue::Enum(123_u32))
    }

    #[test]
    fn test_parse_array_simple() {
        // simple test of two byte values
        let mut writer = vec!();

        // value type for the array itself
        writer.write_u8(0x1C).unwrap();
        // size - a ULEB value
        leb128::write::unsigned(&mut writer, 2).unwrap();
        // encoded elements - let's say two byte values
        writer.write_u8(0x00).unwrap();
        writer.write_u8(0x05).unwrap();
        // second byte value
        writer.write_u8(0x00).unwrap();
        writer.write_u8(0x06).unwrap();

        let res = parse_encoded_value_item(&writer).unwrap();

        assert_eq!(res.1, EncodedValue::Array(EncodedArrayItem {
            size: 2,
            values: vec!(EncodedValue::Byte(0x05), EncodedValue::Byte(0x06))
        }));
    }

    #[test]
    fn test_parse_array_complex() {
        // test some variable length ints, a boolean and a null
        let mut writer = vec!();

        // value type (array)
        writer.write_u8(0b00011100).unwrap();
        // size - a ULEB value
        leb128::write::unsigned(&mut writer, 4).unwrap();
        // value arg indicates an integer of 1 byte length (size - 1 = 0)
        writer.write_u8(0b00000100).unwrap();
        writer.write_u8(0x01).unwrap();
        // indicates a 4 byte integer (size - 1 = 3)
        writer.write_u8(0b01100100).unwrap();
        writer.write_i32::<LittleEndian>(::std::i32::MAX).unwrap();
        // throw in a boolean and a null value, to see if we handle 0-byte elements
        writer.write_u8(0b00111111).unwrap();
        writer.write_u8(0b00111110).unwrap();

        let res = parse_encoded_value_item(&writer).unwrap();

        assert_eq!(res.1, EncodedValue::Array(EncodedArrayItem {
            size: 4,
            values: vec!(
                EncodedValue::Int(1),
                EncodedValue::Int(::std::i32::MAX),
                EncodedValue::Boolean(true),
                EncodedValue::Null)
        }));
    }

    #[test]
    fn test_parse_array_recursive() {
        // test nested recursive arrays
        let mut writer = vec!();

        // value type (array)
        writer.write_u8(0b00011100).unwrap();
        // size - a ULEB value
        leb128::write::unsigned(&mut writer, 4).unwrap();
        // value arg indicates an integer of 1 byte length (size - 1 = 0)
        writer.write_u8(0b00000100).unwrap();
        writer.write_u8(0x01).unwrap();

        // let's put another array in
        writer.write_u8(0b00011100).unwrap();
        leb128::write::unsigned(&mut writer, 1).unwrap();
        // and an integer inside that
        writer.write_u8(0b00000100).unwrap();
        writer.write_u8(0x01).unwrap();

        // now boolean & null values - these should be outside the 2nd array and in the 1st array
        writer.write_u8(0b00111111).unwrap();
        writer.write_u8(0b00111110).unwrap();

        let res = parse_encoded_value_item(&writer).unwrap();

        assert_eq!(res.1, EncodedValue::Array(EncodedArrayItem {
            size: 4,
            values: vec!(
                EncodedValue::Int(1),
                EncodedValue::Array(EncodedArrayItem {
                    size: 1,
                    values: vec!(EncodedValue::Int(1))
                }),
                EncodedValue::Boolean(true),
                EncodedValue::Null
            )
        }))
    }

    #[test]
    fn test_parse_annotation() {
        let mut writer = vec!();
        // value type
        writer.write_u8(0x1D).unwrap();
        // value
        leb128::write::unsigned(&mut writer, 1).unwrap();
        leb128::write::unsigned(&mut writer, 2).unwrap();

        // Elem 1
        leb128::write::unsigned(&mut writer, 2).unwrap();
        writer.write_u8(0x00).unwrap();
        writer.write_u8(0x05).unwrap();

        // Elem 2
        leb128::write::unsigned(&mut writer, 3).unwrap();
        writer.write_u8(0x00).unwrap();
        writer.write_u8(0x06).unwrap();

        let res = parse_encoded_value_item(&writer).unwrap();

        assert_eq!(res.1, EncodedValue::Annotation(RawEncodedAnnotationItem {
            type_idx: 1,
            size: 2,
            elements: vec!(
                RawAnnotationElementItem {
                    name_idx: 2,
                    value: EncodedValue::Byte(0x05)
                },
                RawAnnotationElementItem {
                    name_idx: 3,
                    value: EncodedValue::Byte(0x06)
                },
            )
        }))
    }

    #[test]
    fn test_parse_null() {
        let mut writer = vec!();
        // value type (byte)
        writer.write_u8(0x1E).unwrap();
        // dud value
        writer.write_u8(0x01).unwrap();

        let res = parse_encoded_value_item(&writer).unwrap();

        assert_eq!(res.1, EncodedValue::Null)
    }

    #[test]
    fn test_parse_boolean_true() {
        let mut writer = vec!();
        // value type plus an extra bit for the boolean value
        writer.write_u8(0b00111111).unwrap();

        let res = parse_encoded_value_item(&writer).unwrap();

        assert_eq!(res.1, EncodedValue::Boolean(true))
    }

    #[test]
    fn test_parse_boolean_false() {
        let mut writer = vec!();
        // value type plus an extra bit for the boolean value
        writer.write_u8(0b00011111).unwrap();

        let res = parse_encoded_value_item(&writer).unwrap();

        assert_eq!(res.1, EncodedValue::Boolean(false))
    }
}