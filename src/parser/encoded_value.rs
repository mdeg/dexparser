use super::parse_uleb128;

named_args!(pub parse_encoded_value_item(e: nom::Endianness)<&[u8], EncodedValue>,
    peek!(
        do_parse!(
            value_type: map!(take!(1), |x| {x[0]}) >>
            value: apply!(parse_value, value_type, e) >>
            (value)
        )
    )
);

// TODO: this is always little endian?
// has to be, if the right shift will work...
fn parse_value(value: &[u8], value_type: u8, e: nom::Endianness) -> Result<((), EncodedValue), nom::Err<&[u8]>> {
    // The high order 3 bits of the value type may contain useful size information or data
    let value_arg = value_type >> 5;

    let value = match EncodedValueType::parse(value_arg & 0x1F) {
        EncodedValueType::Byte => EncodedValue::Byte(take!(value, 1)?.1[0]),
        EncodedValueType::Short => EncodedValue::Short(i16!(value, e)?.1),
        EncodedValueType::Char => EncodedValue::Char(u16!(value, e)?.1),
        EncodedValueType::Int => EncodedValue::Int(i32!(value, e)?.1),
        EncodedValueType::Long => EncodedValue::Long(i64!(value, e)?.1),
        EncodedValueType::Float => unimplemented!(),
        EncodedValueType::Double => unimplemented!(),
        EncodedValueType::MethodType => EncodedValue::MethodType(u32!(value, e)?.1),
        EncodedValueType::MethodHandle => EncodedValue::MethodHandle(u32!(value, e)?.1),
        EncodedValueType::String => EncodedValue::String(u32!(value, e)?.1),
        EncodedValueType::Type => EncodedValue::Type(u32!(value, e)?.1),
        EncodedValueType::Field => EncodedValue::Field(u32!(value, e)?.1),
        EncodedValueType::Method => EncodedValue::Method(u32!(value, e)?.1),
        EncodedValueType::Enum => EncodedValue::Enum(u32!(value, e)?.1),
        EncodedValueType::Array => unimplemented!(),
        EncodedValueType::Annotation => EncodedValue::Annotation(parse_encoded_annotation_item(value, e)?.1),
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

named_args!(pub parse_encoded_annotation_item(e: nom::Endianness) <&[u8], EncodedAnnotationItem>,
    do_parse!(
        type_idx: call!(parse_uleb128, e) >>
        size: call!(parse_uleb128, e) >>
        elements: count!(call!(parse_annotation_element_item, e), size as usize) >>
        (EncodedAnnotationItem { type_idx, size, elements })
    )
);

named_args!(parse_annotation_element_item(e: nom::Endianness)<&[u8], AnnotationElementItem>,
    do_parse!(
        name_idx: call!(parse_uleb128, e)   >>
        value: call!(parse_encoded_value_item, e)   >>
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

#[derive(Debug)]
pub struct EncodedArrayItem {

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
    fn parse(value: u8) -> Self {
        match value {
            0x00 => EncodedValueType::Byte,
            0x02 => EncodedValueType::Short,
            0x03 => EncodedValueType::Char,
            0x04 => EncodedValueType::Int,
            0x06 => EncodedValueType::Long,
            0x10 => EncodedValueType::Float,
            0x11 => EncodedValueType::Double,
            0x15 => EncodedValueType::MethodType,
            0x16 => EncodedValueType::MethodHandle,
            0x17 => EncodedValueType::String,
            0x18 => EncodedValueType::Type,
            0x19 => EncodedValueType::Field,
            0x1A => EncodedValueType::Method,
            0x1B => EncodedValueType::Enum,
            0x1C => EncodedValueType::Array,
            0x1D => EncodedValueType::Annotation,
            0x1E => EncodedValueType::Null,
            0x1F => EncodedValueType::Boolean,
            // TODO: return result
            _ => panic!("Could not find encoded value type 0x{:02X}", value)
        }
    }
}