use super::{parse_uleb128, take_one};
use super::error::*;
use super::parse_data::parse_annotation_element_item;
use super::raw_types::*;
use byteorder::ByteOrder;

named!(pub parse_encoded_value_item<&[u8], EncodedValue>,
    peek!(
        do_parse!(
            value_type: call!(take_one) >>
            value: call!(parse_value, value_type) >>
            (value)
        )
    )
);

fn parse_value(value: &[u8], value_type: u8) -> Result<((), EncodedValue), nom::Err<&[u8]>> {
    // The high order 3 bits of the value type may contain useful size information or data
    let value_arg = value_type << 5;

    let value = match EncodedValueType::parse(value_type & 0x1F)? {
        EncodedValueType::Byte => EncodedValue::Byte(take!(value, 1)?.1[0]),
        EncodedValueType::Short => EncodedValue::Short(nom::le_i16(value)?.1),
        EncodedValueType::Char => EncodedValue::Char(nom::le_u16(value)?.1),
        EncodedValueType::Int => EncodedValue::Int(nom::le_i32(value)?.1),
        EncodedValueType::Long => EncodedValue::Long(nom::le_i64(value)?.1),
        EncodedValueType::Float => EncodedValue::Float(byteorder::LittleEndian::read_f32(&take!(value, 4)?.1)),
        EncodedValueType::Double => EncodedValue::Double(byteorder::LittleEndian::read_f64(&take!(value, 8)?.1)),
        EncodedValueType::MethodType => EncodedValue::MethodType(nom::le_u32(value)?.1),
        EncodedValueType::MethodHandle => EncodedValue::MethodHandle(nom::le_u32(value)?.1),
        EncodedValueType::String => EncodedValue::String(nom::le_u32(value)?.1),
        EncodedValueType::Type => EncodedValue::Type(nom::le_u32(value)?.1),
        EncodedValueType::Field => EncodedValue::Field(nom::le_u32(value)?.1),
        EncodedValueType::Method => EncodedValue::Method(nom::le_u32(value)?.1),
        EncodedValueType::Enum => EncodedValue::Enum(nom::le_u32(value)?.1),
        EncodedValueType::Array => EncodedValue::Array(parse_encoded_array_item(value)?.1),
        EncodedValueType::Annotation => EncodedValue::Annotation(parse_encoded_annotation_item(value)?.1),
        EncodedValueType::Null => EncodedValue::Null,
        // The value for boolean types is the last bit of the value arg
        EncodedValueType::Boolean => EncodedValue::Boolean((value_arg & 0x01) == 1)
    };

    Ok(((), value))
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

named!(pub parse_encoded_array_item<&[u8], EncodedArrayItem>,
    do_parse!(
        size: call!(parse_uleb128)   >>
        values: count!(call!(parse_encoded_value_item), size as usize)  >>
        (EncodedArrayItem { size, values })
    )
);

#[derive(Debug, PartialEq)]
pub struct EncodedArrayItem {
    size: u32,
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

        // ensure nonconsumption
        assert_eq!(res.0.len(), writer.len());
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

        // ensure nonconsumption
        assert_eq!(res.0.len(), writer.len());
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

        // ensure nonconsumption
        assert_eq!(res.0.len(), writer.len());
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

        // ensure nonconsumption
        assert_eq!(res.0.len(), writer.len());
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

        // ensure nonconsumption
        assert_eq!(res.0.len(), writer.len());
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

        // ensure nonconsumption
        assert_eq!(res.0.len(), writer.len());
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

        // ensure nonconsumption
        assert_eq!(res.0.len(), writer.len());
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

        // ensure nonconsumption
        assert_eq!(res.0.len(), writer.len());
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

        // ensure nonconsumption
        assert_eq!(res.0.len(), writer.len());
        assert_eq!(res.1, EncodedValue::MethodHandle(123_u32))
    }
}