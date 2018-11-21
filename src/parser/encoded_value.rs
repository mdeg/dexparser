use super::{parse_uleb128, take_one};
use super::error::*;
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
    let value_arg = value_type >> 5;

    let value = match EncodedValueType::parse(value_arg & 0x1F)? {
        EncodedValueType::Byte => EncodedValue::Byte(take!(value, 1)?.1[0]),
        EncodedValueType::Short => EncodedValue::Short(nom::le_i16(value)?.1),
        EncodedValueType::Char => EncodedValue::Char(nom::le_u16(value)?.1),
        EncodedValueType::Int => EncodedValue::Int(nom::le_i32(value)?.1),
        EncodedValueType::Long => EncodedValue::Long(nom::le_i64(value)?.1),
        EncodedValueType::Float => EncodedValue::Float(byteorder::LittleEndian::read_f32(&take!(value, 4)?.1)),
        EncodedValueType::Double => EncodedValue::Double(byteorder::LittleEndian::read_f64(&take!(value, 4)?.1)),
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

#[derive(Debug)]
pub struct EncodedAnnotationItem {
    pub type_idx: u64,
    size: u64,
    pub elements: Vec<AnnotationElementItem>
}

#[derive(Debug)]
pub struct AnnotationElementItem {
    pub name_idx: u64,
    pub value: EncodedValue
}

named!(pub parse_encoded_annotation_item<&[u8], EncodedAnnotationItem>,
    do_parse!(
        type_idx: call!(parse_uleb128) >>
        size: call!(parse_uleb128) >>
        elements: count!(call!(parse_annotation_element_item), size as usize) >>
        (EncodedAnnotationItem { type_idx, size, elements })
    )
);

named!(parse_annotation_element_item<&[u8], AnnotationElementItem>,
    do_parse!(
        name_idx: call!(parse_uleb128)   >>
        value: call!(parse_encoded_value_item)   >>
        (AnnotationElementItem { name_idx, value })
    )
);

// parse value type, then get length and parse value based on that
#[derive(Debug)]
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
    Annotation(EncodedAnnotationItem),
    Null,
    Boolean(bool)
}

named!(parse_encoded_array_item<&[u8], EncodedArrayItem>,
    do_parse!(
        size: call!(parse_uleb128)   >>
        values: count!(call!(parse_encoded_value_item), size as usize)  >>
        (EncodedArrayItem { size, values })
    )
);

#[derive(Debug)]
pub struct EncodedArrayItem {
    size: u64,
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
            _ => Err(ParserErr::from(format!("Could not find encoded value type for 0x{:0X}", value)))
        }
    }
}