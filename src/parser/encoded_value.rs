pub struct EncodedValueItem {
    value_type: EncodedValueType,
    value: Vec<u8>
}

pub struct EncodedValueDataItem<T> {
    value_type: EncodedValueType,
    value: T
}


named_args!(pub parse_encoded_value_item(e: nom::Endianness)<&[u8], EncodedValueItem>,
    do_parse!(
        value_type: map!(take!(1), |x| { EncodedValueType::parse(x[0]) }) >>
        value: map!(take!(value_type.len()), Vec::from) >>
        (EncodedValueItem { value_type, value })
    )
);

//
//struct EncodedAnnotationItem {
//    type_idx: u64,
//    size: u64,
//    elements: Vec<AnnotationElementItem>
//}



//Value formats
//Type Name 	value_type 	value_arg Format 	value Format 	Description
//VALUE_BYTE 	0x00 	(none; must be 0) 	ubyte[1] 	signed one-byte integer value
//VALUE_SHORT 	0x02 	size - 1 (0…1) 	ubyte[size] 	signed two-byte integer value, sign-extended
//VALUE_CHAR 	0x03 	size - 1 (0…1) 	ubyte[size] 	unsigned two-byte integer value, zero-extended
//VALUE_INT 	0x04 	size - 1 (0…3) 	ubyte[size] 	signed four-byte integer value, sign-extended
//VALUE_LONG 	0x06 	size - 1 (0…7) 	ubyte[size] 	signed eight-byte integer value, sign-extended
//VALUE_FLOAT 	0x10 	size - 1 (0…3) 	ubyte[size] 	four-byte bit pattern, zero-extended to the right, and interpreted as an IEEE754 32-bit floating point value
//VALUE_DOUBLE 	0x11 	size - 1 (0…7) 	ubyte[size] 	eight-byte bit pattern, zero-extended to the right, and interpreted as an IEEE754 64-bit floating point value
//VALUE_METHOD_TYPE 	0x15 	size - 1 (0…3) 	ubyte[size] 	unsigned (zero-extended) four-byte integer value, interpreted as an index into the proto_ids section and representing a method type value
//VALUE_METHOD_HANDLE 	0x16 	size - 1 (0…3) 	ubyte[size] 	unsigned (zero-extended) four-byte integer value, interpreted as an index into the method_handles section and representing a method handle value
//VALUE_STRING 	0x17 	size - 1 (0…3) 	ubyte[size] 	unsigned (zero-extended) four-byte integer value, interpreted as an index into the string_ids section and representing a string value
//VALUE_TYPE 	0x18 	size - 1 (0…3) 	ubyte[size] 	unsigned (zero-extended) four-byte integer value, interpreted as an index into the type_ids section and representing a reflective type/class value
//VALUE_FIELD 	0x19 	size - 1 (0…3) 	ubyte[size] 	unsigned (zero-extended) four-byte integer value, interpreted as an index into the field_ids section and representing a reflective field value
//VALUE_METHOD 	0x1a 	size - 1 (0…3) 	ubyte[size] 	unsigned (zero-extended) four-byte integer value, interpreted as an index into the method_ids section and representing a reflective method value
//VALUE_ENUM 	0x1b 	size - 1 (0…3) 	ubyte[size] 	unsigned (zero-extended) four-byte integer value, interpreted as an index into the field_ids section and representing the value of an enumerated type constant
//VALUE_ARRAY 	0x1c 	(none; must be 0) 	encoded_array 	an array of values, in the format specified by "encoded_array format" below. The size of the value is implicit in the encoding.
//VALUE_ANNOTATION 	0x1d 	(none; must be 0) 	encoded_annotation 	a sub-annotation, in the format specified by "encoded_annotation format" below. The size of the value is implicit in the encoding.
//VALUE_NULL 	0x1e 	(none; must be 0) 	(none) 	null reference value
//VALUE_BOOLEAN 	0x1f 	boolean (0…1) 	(none) 	one-bit value; 0 for false and 1 for true. The bit is represented in the value_arg.

// parse value type, then get length and parse value based on that

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
            0x1a => EncodedValueType::Method,
            0x1b => EncodedValueType::Enum,
            0x1c => EncodedValueType::Array,
            0x1d => EncodedValueType::Annotation,
            0x1e => EncodedValueType::Null,
            0x1f => EncodedValueType::Boolean,
            _ => panic!("Could not find encoded value type for {}", value)
        }
    }

    fn len(&self) -> usize {
        match self {
            EncodedValueType::Byte => 1,
            _ => unimplemented!()
        }
    }
}
