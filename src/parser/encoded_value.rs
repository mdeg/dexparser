use super::{parse_uleb128, take_one, Uleb128};
use crate::error::*;
use crate::result_types::*;
use byteorder::ByteOrder;

// note that this does NOT peek! that's the responsibility of the calling parser
pub fn parse_encoded_value_item<'a>(data: &'a[u8], fd: &DexFileData) -> nom::IResult<&'a[u8], EncodedValue> {
    do_parse!(data,
        value_type: call!(take_one) >>
        value: call!(parse_value, value_type, fd) >>
        (value)
    )
}

pub fn parse_encoded_annotation_item<'a>(data: &'a[u8], fd: &DexFileData) -> nom::IResult<&'a[u8], EncodedAnnotationItem> {
    let res = do_parse!(data,
        type_idx: call!(parse_uleb128) >>
        size: call!(parse_uleb128) >>
        elements: count!(call!(parse_annotation_element_item, fd), size as usize) >>
        (RawEncodedAnnotationItem { type_idx, size, elements })
    )?;

    Ok((res.0, EncodedAnnotationItem {
        type_: fd.type_identifiers[res.1.type_idx as usize].clone(),
        values: res.1.elements.into_iter().map(|item| AnnotationElement {
            name: fd.string_data[item.name_idx as usize].clone(),
            value: item.value
        }).collect()
    }))
}

// Docs: annotation_element_item
#[derive(Debug, PartialEq, Clone)]
pub struct RawAnnotationElementItem {
    pub name_idx: Uleb128,
    pub value: EncodedValue
}

#[derive(Debug, PartialEq, Clone)]
pub struct RawEncodedAnnotationItem {
    pub type_idx: Uleb128,
    pub size: Uleb128,
    pub elements: Vec<RawAnnotationElementItem>
}

pub fn parse_encoded_array_item<'a>(data: &'a[u8], fd: &DexFileData) -> nom::IResult<&'a[u8], Vec<EncodedValue>> {
    do_parse!(data,
        size: call!(parse_uleb128)   >>
        values: count!(call!(parse_encoded_value_item, fd), size as usize)  >>
        (values)
    )
}

fn parse_value<'a>(value: &'a[u8], value_type: u8, fd: &DexFileData) -> nom::IResult<&'a[u8], EncodedValue> {
    // The high order 3 bits of the value type may contain useful size information or data
    let value_arg = ((value_type & 0xE0) >> 5) as i8;

    Ok(match EncodedValueType::parse(value_type & 0x1F)? {
        EncodedValueType::Byte => {
            map!(value, take!(1), |x| { EncodedValue::Byte(x[0]) })?
        },
        EncodedValueType::Short => {
            map!(value, map!(take!(value_arg + 1), |x| { byteorder::LittleEndian::read_int(x, x.len()) as i16}), EncodedValue::Short)?
        },
        EncodedValueType::Char => {
            map!(value, map!(take!(value_arg + 1), |x| { byteorder::LittleEndian::read_uint(x, x.len()) as u16 }), EncodedValue::Char)?
        },
        EncodedValueType::Int => {
            map!(value, map!(take!(value_arg + 1), |x| { byteorder::LittleEndian::read_int(x, x.len()) as i32 }), EncodedValue::Int)?
        },
        EncodedValueType::Long => {
            map!(value, map!(take!(value_arg + 1), |x| { byteorder::LittleEndian::read_int(x, x.len()) as i64 }), EncodedValue::Long)?
        },
        // Floats and Doubles below the maximum byte width should be 0-extended to the right
        EncodedValueType::Float => map!(value, map!(take!(value_arg + 1), |x| {
            let mut v = x.to_vec();
            v.extend(vec![0; 4 - x.len()]);
            byteorder::LittleEndian::read_f32(&v)
        }), EncodedValue::Float)?,
        EncodedValueType::Double => map!(value, map!(take!(value_arg + 1), |x| {
            let mut v = x.to_vec();
            v.extend(vec![0; 8 - x.len()]);
            byteorder::LittleEndian::read_f64(&v)
        }), EncodedValue::Double)?,
        EncodedValueType::MethodType => {
            let res = call!(value, convert_variable_u32, value_arg + 1)?;
            (res.0, EncodedValue::MethodType(fd.prototypes[res.1 as usize].clone()))
        },
        EncodedValueType::MethodHandle => {
            let res = call!(value, convert_variable_u32, value_arg + 1)?;
            (res.0, EncodedValue::MethodHandle(fd.methods[res.1 as usize].clone()))
        },
        EncodedValueType::String => {
            let res = call!(value, convert_variable_u32, value_arg + 1)?;
            (res.0, EncodedValue::String(fd.string_data[res.1 as usize].clone()))
        },
        EncodedValueType::Type => {
            let res = call!(value, convert_variable_u32, value_arg + 1)?;
            (res.0, EncodedValue::Type(fd.type_identifiers[res.1 as usize].clone()))
        },
        EncodedValueType::Field => {
            let res = call!(value, convert_variable_u32, value_arg + 1)?;
            (res.0, EncodedValue::Field(fd.fields[res.1 as usize].clone()))
        }
        EncodedValueType::Method => {
            let res = call!(value, convert_variable_u32, value_arg + 1)?;
            (res.0, EncodedValue::Method(fd.methods[res.1 as usize].clone()))
        },
        EncodedValueType::Enum => {
            let res = call!(value, convert_variable_u32, value_arg + 1)?;
            (res.0, EncodedValue::Enum(fd.fields[res.1 as usize].clone()))
        },
        EncodedValueType::Array => {
            map!(value, call!(parse_encoded_array_item, fd), EncodedValue::Array)?
        },
        EncodedValueType::Annotation => {
            map!(value, call!(parse_encoded_annotation_item, fd), EncodedValue::Annotation)?
        },
        EncodedValueType::Null => (value, EncodedValue::Null),
        // The value for boolean types is the last bit of the value arg
        EncodedValueType::Boolean => (value, EncodedValue::Boolean(value_arg != 0)),
    })
}

// Docs: annotation_element_item
fn parse_annotation_element_item<'a>(data: &'a[u8], fd: &DexFileData) -> nom::IResult<&'a[u8], RawAnnotationElementItem> {
    do_parse!(data,
        name_idx: call!(parse_uleb128)   >>
        value: call!(parse_encoded_value_item, fd)   >>
        (RawAnnotationElementItem { name_idx, value })
    )
}

named_args!(convert_variable_u32(size: i8)<&[u8], u32>,
    map!(take!(size), |x| { byteorder::LittleEndian::read_uint(x, x.len()) as u32 })
);

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
    fn parse(value: u8) -> Result<Self, DexParserError> {
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
            _ => Err(DexParserError::from(format!("Could not find encoded value type for 0x{:02X}", value)))
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use byteorder::*;
    use std::rc::Rc;

    #[test]
    fn test_empty_encoded_value_item() {
        let fd = generate_file_data();
        let writer = vec!();

        let err = parse_encoded_value_item(&writer, &fd);

        assert!(err.is_err());
        assert_eq!(err.err().unwrap(), nom::Err::Incomplete(nom::Needed::Size(1)));
    }

    #[test]
    fn test_invalid_encoded_value_item_type() {
        let fd = generate_file_data();
        let mut writer = vec!();

        writer.write_u8(0x01).unwrap();
        let err = parse_encoded_value_item(&writer, &fd);

        assert!(err.is_err());
    }

    #[test]
    fn test_parse_byte_value() {
        let fd = generate_file_data();

        let mut writer = vec!();
        // value type
        writer.write_u8(0b00000000).unwrap();

        // with no following byte value
        let err = parse_encoded_value_item(&writer, &fd);
        assert!(err.is_err());

        // add in a value
        writer.write_u8(0x01).unwrap();

        let res = parse_encoded_value_item(&writer, &fd).unwrap();

        assert_eq!(res.1, EncodedValue::Byte(0x01));
    }

    #[test]
    fn test_parse_short_value_single_byte() {
        let fd = generate_file_data();

        let mut writer = vec!();
        // value type
        writer.write_u8(0b00000010).unwrap();
        // value
        writer.write_u8(1 as u8).unwrap();

        let res = parse_encoded_value_item(&writer, &fd).unwrap();

        assert_eq!(res.1, EncodedValue::Short(1))
    }

    #[test]
    fn test_parse_short_value_multiple_bytes() {
        let fd = generate_file_data();
        let mut writer = vec!();
        // value type
        writer.write_u8(0b00100010).unwrap();
        // value
        writer.write_i16::<LittleEndian>(::std::i16::MAX).unwrap();

        let res = parse_encoded_value_item(&writer, &fd).unwrap();

        assert_eq!(res.1, EncodedValue::Short(::std::i16::MAX))
    }

    #[test]
    fn test_parse_char_value_single_byte() {
        let fd = generate_file_data();
        let mut writer = vec!();
        // value type
        writer.write_u8(0b00000011).unwrap();
        // single byte char value
        writer.write_u8('A' as u8).unwrap();

        let res = parse_encoded_value_item(&writer, &fd).unwrap();

        assert_eq!(res.1, EncodedValue::Char('A' as u16))
    }

    #[test]
    fn test_parse_char_value_multiple_byte() {
        let fd = generate_file_data();
        let mut writer = vec!();
        // value type
        writer.write_u8(0b00100011).unwrap();
        // two byte unicode value
        writer.write_u16::<LittleEndian>('ß' as u16).unwrap();

        let res = parse_encoded_value_item(&writer, &fd).unwrap();

        assert_eq!(res.1, EncodedValue::Char('ß' as u16))
    }

    #[test]
    fn test_parse_int_value_single_byte() {
        let fd = generate_file_data();
        let mut writer = vec!();
        // value type (int, single byte)
        writer.write_u8(0b00000100).unwrap();
        // value
        writer.write_u8(1_i32 as u8).unwrap();

        let res = parse_encoded_value_item(&writer, &fd).unwrap();

        assert_eq!(res.1, EncodedValue::Int(1_i32))
    }

    #[test]
    fn test_parse_int_value_multiple_bytes() {
        let fd = generate_file_data();
        let mut writer = vec!();
        // value type (int, 4 bytes)
        writer.write_u8(0b01100100).unwrap();
        // value
        writer.write_i32::<LittleEndian>(::std::i32::MAX).unwrap();

        let res = parse_encoded_value_item(&writer, &fd).unwrap();

        assert_eq!(res.1, EncodedValue::Int(::std::i32::MAX))
    }

    #[test]
    fn test_parse_long_value_single_byte() {
        let fd = generate_file_data();
        let mut writer = vec!();
        // value type (long, 1 byte)
        writer.write_u8(0b00000110).unwrap();
        // value
        writer.write_u8(1_i64 as u8).unwrap();

        let res = parse_encoded_value_item(&writer, &fd).unwrap();

        assert_eq!(res.1, EncodedValue::Long(1_i64))
    }

    #[test]
    fn test_parse_long_value_multiple_bytes() {
        let fd = generate_file_data();
        let mut writer = vec!();
        // value type (long, 8 bytes)
        writer.write_u8(0b11100110).unwrap();
        // value
        writer.write_i64::<LittleEndian>(::std::i64::MAX).unwrap();

        let res = parse_encoded_value_item(&writer, &fd).unwrap();

        assert_eq!(res.1, EncodedValue::Long(::std::i64::MAX))
    }

    #[test]
    fn test_parse_float_value_single_byte() {
        let fd = generate_file_data();
        // spec says a float may be encoded as a single byte
        let mut writer = vec!();
        // value type (float, 1 byte)
        writer.write_u8(0b00010000).unwrap();
        // value
        writer.write_u8(0b00000000).unwrap();

        let res = parse_encoded_value_item(&writer, &fd).unwrap();

        match res.1 {
            EncodedValue::Float(x) => assert_eq!(x, 0_f32),
            _ => panic!()
        }
    }

    #[test]
    fn test_parse_float_value_two_bytes() {
        // a two byte value (which will be tiny, as it has no exponent)
        // tests that we are sign extending correctly
        let fd = generate_file_data();
        let mut writer = vec!();
        // value type (float, 2 byte)
        writer.write_u8(0b00110000).unwrap();
        // value
        writer.write_u8(0b00110011).unwrap();
        writer.write_u8(0b00110011).unwrap();

        let res = parse_encoded_value_item(&writer, &fd).unwrap();

        match res.1 {
            EncodedValue::Float(x) => {
                assert_eq!(x, 0.000000000000000000000000000000000000000018367_f32)
            },
            _ => panic!()
        }
    }

    #[test]
    fn test_parse_float_value_multiple_byte() {
        let fd = generate_file_data();
        let mut writer = vec!();
        // value type (float, 4 bytes)
        writer.write_u8(0b01110000).unwrap();
        // value
        writer.write_f32::<LittleEndian>(::std::f32::MAX).unwrap();

        let res = parse_encoded_value_item(&writer, &fd).unwrap();

        assert_eq!(res.1, EncodedValue::Float(::std::f32::MAX))
    }

    #[test]
    fn test_parse_double_value() {
        let fd = generate_file_data();
        let mut writer = vec!();
        // value type (8-byte length)
        writer.write_u8(0b11110001).unwrap();
        // value
        writer.write_f64::<LittleEndian>(123_f64).unwrap();

        let res = parse_encoded_value_item(&writer, &fd).unwrap();

        assert_eq!(res.1, EncodedValue::Double(123_f64))
    }

    // TODO: write more tests for double values

    // TODO: write multi/single byte tests for method types

    #[test]
    fn test_parse_method_type() {
        let fd = generate_file_data();
        let mut writer = vec!();
        // value type
        writer.write_u8(0x15).unwrap();
        // value
        writer.write_u32::<LittleEndian>(1_u32).unwrap();

        let res = parse_encoded_value_item(&writer, &fd).unwrap();

        assert_eq!(res.1, EncodedValue::MethodType(fd.prototypes[1].clone()))
    }

    #[test]
    fn test_parse_method_handle() {
        let fd = generate_file_data();
        let mut writer = vec!();
        // value type
        writer.write_u8(0x16).unwrap();
        // value
        writer.write_u32::<LittleEndian>(1_u32).unwrap();

        let res = parse_encoded_value_item(&writer, &fd).unwrap();

        assert_eq!(res.1, EncodedValue::MethodHandle(fd.methods[1].clone()))
    }

    #[test]
    fn test_parse_string() {
        let fd = generate_file_data();
        let mut writer = vec!();
        // value type
        writer.write_u8(0x17).unwrap();
        // value
        writer.write_u32::<LittleEndian>(0).unwrap();

        let res = parse_encoded_value_item(&writer, &fd).unwrap();

        assert_eq!(res.1, EncodedValue::String(fd.string_data[0].clone()))
    }

    #[test]
    fn test_parse_type() {
        let fd = generate_file_data();
        let mut writer = vec!();
        // value type
        writer.write_u8(0x18).unwrap();
        // value
        writer.write_u32::<LittleEndian>(1_u32).unwrap();

        let res = parse_encoded_value_item(&writer, &fd).unwrap();

        assert_eq!(res.1, EncodedValue::Type(fd.string_data[1].clone()))
    }

    #[test]
    fn test_parse_field() {
        let fd = generate_file_data();
        let mut writer = vec!();
        // value type
        writer.write_u8(0x19).unwrap();
        // value
        writer.write_u32::<LittleEndian>(1_u32).unwrap();

        let res = parse_encoded_value_item(&writer, &fd).unwrap();

        assert_eq!(res.1, EncodedValue::Field(fd.fields[1].clone()))
    }

    #[test]
    fn test_parse_method() {
        let fd = generate_file_data();
        let mut writer = vec!();
        // value type
        writer.write_u8(0x1A).unwrap();
        // value
        writer.write_u32::<LittleEndian>(0_u32).unwrap();

        let res = parse_encoded_value_item(&writer, &fd).unwrap();

        assert_eq!(res.1, EncodedValue::Method(fd.methods[0].clone()))
    }

    #[test]
    fn test_parse_enum() {
        let fd = generate_file_data();
        let mut writer = vec!();
        // value type
        writer.write_u8(0x1B).unwrap();
        // value
        writer.write_u32::<LittleEndian>(1_u32).unwrap();

        let res = parse_encoded_value_item(&writer, &fd).unwrap();

        assert_eq!(res.1, EncodedValue::Enum(fd.fields[1].clone()))
    }

    #[test]
    fn test_parse_array_simple() {
        let fd = generate_file_data();
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

        let res = parse_encoded_value_item(&writer, &fd).unwrap();

        assert_eq!(res.1, EncodedValue::Array(vec!(
            EncodedValue::Byte(0x05), EncodedValue::Byte(0x06))
        ));
    }

    #[test]
    fn test_parse_array_complex() {
        let fd = generate_file_data();
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

        let res = parse_encoded_value_item(&writer, &fd).unwrap();

        assert_eq!(res.1, EncodedValue::Array(vec!(
            EncodedValue::Int(1),
            EncodedValue::Int(::std::i32::MAX),
            EncodedValue::Boolean(true),
            EncodedValue::Null)
        ));
    }

    #[test]
    fn test_parse_array_recursive() {
        let fd = generate_file_data();
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

        let res = parse_encoded_value_item(&writer, &fd).unwrap();

        assert_eq!(res.1, EncodedValue::Array(vec!(
                EncodedValue::Int(1),
                EncodedValue::Array(vec!(EncodedValue::Int(1))),
                EncodedValue::Boolean(true),
                EncodedValue::Null
            )
        ))
    }

    #[test]
    fn test_parse_annotation() {
        let fd = generate_file_data();
        let mut writer = vec!();
        // value type
        writer.write_u8(0x1D).unwrap();
        // value
        leb128::write::unsigned(&mut writer, 1).unwrap();
        leb128::write::unsigned(&mut writer, 2).unwrap();

        // Elem 1
        leb128::write::unsigned(&mut writer, 0).unwrap();
        writer.write_u8(0x00).unwrap();
        writer.write_u8(0x05).unwrap();

        // Elem 2
        leb128::write::unsigned(&mut writer, 1).unwrap();
        writer.write_u8(0x00).unwrap();
        writer.write_u8(0x06).unwrap();

        let res = parse_encoded_value_item(&writer, &fd).unwrap();

        assert_eq!(res.1, EncodedValue::Annotation(EncodedAnnotationItem {
            type_: fd.string_data[1].clone(),
            values: vec!(
                AnnotationElement {
                    name: fd.string_data[0].clone(),
                    value: EncodedValue::Byte(0x05)
                },
                AnnotationElement {
                    name: fd.string_data[1].clone(),
                    value: EncodedValue::Byte(0x06)
                },
            )
        }))
    }

    #[test]
    fn test_parse_null() {
        let fd = generate_file_data();
        let mut writer = vec!();
        // value type (byte)
        writer.write_u8(0x1E).unwrap();
        // dud value
        writer.write_u8(0x01).unwrap();

        let res = parse_encoded_value_item(&writer, &fd).unwrap();

        assert_eq!(res.1, EncodedValue::Null)
    }

    #[test]
    fn test_parse_boolean_true() {
        let fd = generate_file_data();
        let mut writer = vec!();
        // value type plus an extra bit for the boolean value
        writer.write_u8(0b00111111).unwrap();

        let res = parse_encoded_value_item(&writer, &fd).unwrap();

        assert_eq!(res.1, EncodedValue::Boolean(true))
    }

    #[test]
    fn test_parse_boolean_false() {
        let fd = generate_file_data();
        let mut writer = vec!();
        // value type plus an extra bit for the boolean value
        writer.write_u8(0b00011111).unwrap();

        let res = parse_encoded_value_item(&writer, &fd).unwrap();

        assert_eq!(res.1, EncodedValue::Boolean(false))
    }

    #[test]
    fn test_parse_annotation_element_item() {
        let fd = generate_file_data();
        let mut writer = vec!();

        // name_idx
        leb128::write::unsigned(&mut writer, 1).unwrap();

        // insert an encoded_value_item (byte)
        writer.write_u8(0x00).unwrap();
        writer.write_u8(0x01).unwrap();

        let res = parse_annotation_element_item(&writer, &fd).unwrap();

        assert_eq!(res.1, RawAnnotationElementItem {
            name_idx: 1,
            value: EncodedValue::Byte(0x01)
        })
    }

    // helpers
    fn generate_file_data() -> DexFileData {
        let (mut string_data, mut type_identifiers, mut prototypes, mut fields, mut methods) =
            (vec!(), vec!(), vec!(), vec!(), vec!());

        for i in 0..2 {
            let data = Rc::new(i.to_string());

            string_data.push(data.clone());

            type_identifiers.push(data.clone());

            let prototype = Rc::new(Prototype {
                shorty: data.clone(),
                return_type: data.clone(),
                parameters: vec!(data.clone(), data.clone())
            });
            prototypes.push(prototype.clone());

            fields.push(Rc::new(Field {
                definer: data.clone(),
                type_: data.clone(),
                name: data.clone()
            }));

            methods.push(Rc::new(Method {
                definer: data.clone(),
                prototype,
                name: data.clone()
            }))
        }

        DexFileData {
            string_data,
            type_identifiers,
            prototypes,
            fields,
            methods
        }
    }
}