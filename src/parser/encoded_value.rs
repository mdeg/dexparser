use super::{parse_uleb128, take_one, Uleb128};
use super::error::*;
use super::parse_data::parse_annotation_element_item;
use super::raw_types::*;
use byteorder::ByteOrder;

named!(pub parse_encoded_value_item<&[u8], EncodedValue>,
    do_parse!(
        value_type: call!(take_one) >>
        value: call!(parse_value, value_type) >>
        (value)
    )
);

fn parse_value(mut value: &[u8], value_type: u8) -> Result<(&[u8], EncodedValue), nom::Err<&[u8]>> {
    // The high order 3 bits of the value type may contain useful size information or data
    let value_arg = (value_type & 0xE0) >> 5;

    Ok(match EncodedValueType::parse(value_type & 0x1F)? {
        EncodedValueType::Byte => map!(value, take!(1), |x| { EncodedValue::Byte(x[0]) })?,
        EncodedValueType::Short => map!(value, nom::le_i16, EncodedValue::Short)?,
        EncodedValueType::Char => map!(value, nom::le_u16, EncodedValue::Char)?,
        EncodedValueType::Int => map!(value, nom::le_i32, EncodedValue::Int)?,
        EncodedValueType::Long => map!(value, nom::le_i64, EncodedValue::Long)?,
        EncodedValueType::Float => map!(value, map!(take!(4), byteorder::LittleEndian::read_f32), EncodedValue::Float)?,
        EncodedValueType::Double => map!(value, map!(take!(8), byteorder::LittleEndian::read_f64), EncodedValue::Double)?,
        EncodedValueType::MethodType => map!(value, nom::le_u32, EncodedValue::MethodType)?,
        EncodedValueType::MethodHandle => map!(value, nom::le_u32, EncodedValue::MethodHandle)?,
        EncodedValueType::String => map!(value, nom::le_u32, EncodedValue::String)?,
        EncodedValueType::Type => map!(value, nom::le_u32, EncodedValue::Type)?,
        EncodedValueType::Field => map!(value, nom::le_u32, EncodedValue::Field)?,
        EncodedValueType::Method => map!(value, nom::le_u32, EncodedValue::Method)?,
        EncodedValueType::Enum => map!(value, nom::le_u32, EncodedValue::Enum)?,
        EncodedValueType::Array => map!(value, parse_encoded_array_item, EncodedValue::Array)?,
        EncodedValueType::Annotation => map!(value, parse_encoded_annotation_item, EncodedValue::Annotation)?,
        EncodedValueType::Null => (value, EncodedValue::Null),
        // The value for boolean types is the last bit of the value arg
        EncodedValueType::Boolean => (value, EncodedValue::Boolean(value_arg != 0)),
    })
}

named!(pub parse_encoded_annotation_item<&[u8], RawEncodedAnnotationItem>,
    do_parse!(
        type_idx: call!(parse_uleb128) >>
        size: call!(parse_uleb128) >>
        elements: count!(call!(parse_annotation_element_item), size as usize) >>
        (RawEncodedAnnotationItem { type_idx, size, elements })
    )
);

// parse value type, then get length and parse value based on that
#[derive(Debug, PartialEq)]
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

// TODO: dont call directly to this?
named!(pub parse_encoded_array_item<&[u8], EncodedArrayItem>,
    do_parse!(
        size: call!(parse_uleb128)   >>
        values: count!(call!(parse_encoded_value_item), size as usize)  >>
        (EncodedArrayItem { size, values })
    )
);

#[derive(Debug, PartialEq)]
pub struct EncodedArrayItem {
    size: Uleb128,
    values: Vec<EncodedValue>
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
        // TODO
//        assert_eq!(err.err().unwrap(), nom::Err::Failure);
    }

    #[test]
    fn test_parse_byte_value() {
        let mut writer = vec!();
        // value type (byte)
        writer.write_u8(0x00).unwrap();

        // with no following byte value
        let err = parse_encoded_value_item(&writer);
        assert!(err.is_err());

        // add in a value
        writer.write_u8(0x01).unwrap();

        let res = parse_encoded_value_item(&writer).unwrap();

        assert_eq!(res.1, EncodedValue::Byte(0x01));
    }

    #[test]
    fn test_parse_short_value() {
        let mut writer = vec!();
        // value type (byte)
        writer.write_u8(0x02).unwrap();
        // value
        writer.write_i16::<LittleEndian>(123_i16).unwrap();

        let res = parse_encoded_value_item(&writer).unwrap();

        assert_eq!(res.1, EncodedValue::Short(123_i16))
    }

    #[test]
    fn test_parse_char_value() {
        let mut writer = vec!();
        // value type (byte)
        writer.write_u8(0x03).unwrap();
        // value
        writer.write_u16::<LittleEndian>('a' as u16).unwrap();

        let res = parse_encoded_value_item(&writer).unwrap();

        assert_eq!(res.1, EncodedValue::Char('a' as u16))
    }

    #[test]
    fn test_parse_int_value() {
        let mut writer = vec!();
        // value type (byte)
        writer.write_u8(0x04).unwrap();
        // value
        writer.write_i32::<LittleEndian>(123_i32).unwrap();

        let res = parse_encoded_value_item(&writer).unwrap();

        assert_eq!(res.1, EncodedValue::Int(123_i32))
    }

    #[test]
    fn test_parse_long_value() {
        let mut writer = vec!();
        // value type (byte)
        writer.write_u8(0x06).unwrap();
        // value
        writer.write_i64::<LittleEndian>(123_i64).unwrap();

        let res = parse_encoded_value_item(&writer).unwrap();

        assert_eq!(res.1, EncodedValue::Long(123_i64))
    }

    #[test]
    fn test_parse_float_value() {
        let mut writer = vec!();
        // value type (byte)
        writer.write_u8(0x10).unwrap();
        // value
        writer.write_f32::<LittleEndian>(123_f32).unwrap();

        let res = parse_encoded_value_item(&writer).unwrap();

        assert_eq!(res.1, EncodedValue::Float(123_f32))
    }

    #[test]
    fn test_parse_double_value() {
        let mut writer = vec!();
        // value type (byte)
        writer.write_u8(0x11).unwrap();
        // value
        writer.write_f64::<LittleEndian>(123_f64).unwrap();

        let res = parse_encoded_value_item(&writer).unwrap();

        assert_eq!(res.1, EncodedValue::Double(123_f64))
    }

    #[test]
    fn test_parse_method_type() {
        let mut writer = vec!();
        // value type (byte)
        writer.write_u8(0x15).unwrap();
        // value
        writer.write_u32::<LittleEndian>(123_u32).unwrap();

        let res = parse_encoded_value_item(&writer).unwrap();

        assert_eq!(res.1, EncodedValue::MethodType(123_u32))
    }

    #[test]
    fn test_parse_method_handle() {
        let mut writer = vec!();
        // value type (byte)
        writer.write_u8(0x16).unwrap();
        // value
        writer.write_u32::<LittleEndian>(123_u32).unwrap();

        let res = parse_encoded_value_item(&writer).unwrap();

        assert_eq!(res.1, EncodedValue::MethodHandle(123_u32))
    }

    #[test]
    fn test_parse_string() {
        let mut writer = vec!();
        // value type (byte)
        writer.write_u8(0x17).unwrap();
        // value
        writer.write_u32::<LittleEndian>(123_u32).unwrap();

        let res = parse_encoded_value_item(&writer).unwrap();

        assert_eq!(res.1, EncodedValue::String(123_u32))
    }

    #[test]
    fn test_parse_type() {
        let mut writer = vec!();
        // value type (byte)
        writer.write_u8(0x18).unwrap();
        // value
        writer.write_u32::<LittleEndian>(123_u32).unwrap();

        let res = parse_encoded_value_item(&writer).unwrap();

        assert_eq!(res.1, EncodedValue::Type(123_u32))
    }

    #[test]
    fn test_parse_field() {
        let mut writer = vec!();
        // value type (byte)
        writer.write_u8(0x19).unwrap();
        // value
        writer.write_u32::<LittleEndian>(123_u32).unwrap();

        let res = parse_encoded_value_item(&writer).unwrap();

        assert_eq!(res.1, EncodedValue::Field(123_u32))
    }

    #[test]
    fn test_parse_method() {
        let mut writer = vec!();
        // value type (byte)
        writer.write_u8(0x1A).unwrap();
        // value
        writer.write_u32::<LittleEndian>(123_u32).unwrap();

        let res = parse_encoded_value_item(&writer).unwrap();

        assert_eq!(res.1, EncodedValue::Method(123_u32))
    }

    #[test]
    fn test_parse_enum() {
        let mut writer = vec!();
        // value type (byte)
        writer.write_u8(0x1B).unwrap();
        // value
        writer.write_u32::<LittleEndian>(123_u32).unwrap();

        let res = parse_encoded_value_item(&writer).unwrap();

        assert_eq!(res.1, EncodedValue::Enum(123_u32))
    }

    #[test]
    fn test_parse_array() {
        let mut writer = vec!();
        // value type (byte) for the array itself
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

//    #[test]
//    fn test_parse_annotation() {
//        let mut writer = vec!();
//        // value type (byte)
//        writer.write_u8(0x1D).unwrap();
//        // value
//        writer.write_u8(0x01).unwrap();
//
//        let res = parse_encoded_value_item(&writer).unwrap();
//
//        assert_eq!(res.1, EncodedValue::Anno)
//    }

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
    fn test_parse_boolean() {
        // true value
        {
            let mut writer = vec!();
            // value type (byte) plus an extra bit for the boolean value
            writer.write_u8(0b00111111).unwrap();

            let res = parse_encoded_value_item(&writer).unwrap();

            assert_eq!(res.1, EncodedValue::Boolean(true))
        }
        // false value
        {
            let mut writer = vec!();
            // value type (byte) plus an extra bit for the boolean value
            writer.write_u8(0b00011111).unwrap();

            println!("={:#b} {:#b}=", 0b00011111 & 0xE0, (0b00011111 & 0xE0) >> 5);

            let res = parse_encoded_value_item(&writer).unwrap();

            assert_eq!(res.1, EncodedValue::Boolean(false))
        }
    }
}