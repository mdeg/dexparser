mod encoded_value;
mod error;
mod result_types;
mod raw_types;
mod parse_data;

use self::result_types::*;
use self::raw_types::*;
use self::error::*;
use nom::*;
use std::str;

// The magic that starts a DEX file
const DEX_FILE_MAGIC: [u8; 4] = [0x64, 0x65, 0x78, 0x0A];
// Indicates standard (little-endian) encoding
const ENDIAN_CONSTANT: [u8; 4] = [0x12, 0x34, 0x56, 0x78];
// Indicates modified non-standard (big-endian) encoding
const REVERSE_ENDIAN_CONSTANT: [u8; 4] = [0x78, 0x56, 0x34, 0x12];

const NO_INDEX: u32 = 0xffffffff;

type Uleb128 = u32;
type Sleb128 = i32;

pub fn parse(buffer: &[u8]) -> Result<DexFile, ParserErr> {

    // Peek ahead to determine endianness
    let endianness = {
        if buffer[40 .. 44] == ENDIAN_CONSTANT {
            nom::Endianness::Big
        } else if buffer[40 .. 44] == REVERSE_ENDIAN_CONSTANT {
            nom::Endianness::Little
        } else {
            return Err(ParserErr);
        }
    };

    let raw = parse_dex_file(buffer, endianness)?.1;
    let res = parse_data::transform_dex_file(raw, endianness);

    match res {
        Ok(dexf) => Ok(dexf),
        Err(e) => {
//            println!("ERROR: {}", e);
            Err(ParserErr)
        }
    }
}

// TODO: conds for string id, type id, etc
fn parse_dex_file(input: &[u8], e: nom::Endianness) -> Result<(&[u8], RawDexFile), nom::Err<&[u8]>> {
    do_parse!(input,
        header: call!(parse_header, e) >>
        // Version 038 adds some new index pools with sizes not indicated in the header
        // For this version and higher, we'll need to peek at the map list to know their size for parsing
        // TODO: versioning
        map_list: cond!(true, peek!(call!(parse_map_list, &input[header.map_off as usize - (header.file_size as usize - input.len()) ..], e)))    >>
        string_id_items: call!(parse_string_id_items, header.string_ids_size as usize, e) >>
        type_id_items: call!(parse_u32_list, header.type_ids_size as usize, e)  >>
        proto_id_items: call!(parse_proto_id_items, header.proto_ids_size as usize, e) >>
        field_id_items: call!(parse_field_id_items, header.field_ids_size as usize, e)   >>
        method_id_items: call!(parse_method_id_items, header.method_ids_size as usize, e)  >>
        class_def_items: call!(parse_class_def_items, header.class_defs_size as usize, e) >>
        call_site_idxs: cond!(map_list.is_some(), call!(parse_u32_list, map_list.as_ref().unwrap().list.iter().filter(|item| item.type_ == MapListItemType::CALL_SITE_ID_ITEM).count(), e)) >>
        method_handle_idxs: cond!(map_list.is_some(), call!(parse_method_handle_items, map_list.as_ref().unwrap().list.iter().filter(|item| item.type_  == MapListItemType::METHOD_HANDLE_ITEM).count(), e))   >>
        data: map!(take!(header.data_size), |d| { d.to_vec() })  >>
        link_data: cond!(header.link_off > 0, map!(eof!(), |ld| { ld.to_vec() }))   >>
        (RawDexFile { header, string_id_items, type_id_items, proto_id_items, field_id_items,
            method_id_items, class_def_items, call_site_idxs, method_handle_idxs, data, link_data })
    )
}

named!(take_one<&[u8], u8>, map!(take!(1), |x| { x[0] }));

pub fn determine_leb128_length(input: &[u8]) -> usize {
    input.iter()
        .take_while(|byte| (*byte & 0x80) != 0)
        .count()
        + 1
}

named!(parse_uleb128<&[u8], Uleb128>,
    do_parse!(
        len: peek!(map!(alt_complete!(take!(5) | rest), determine_leb128_length))    >>
        value: map_res!(take!(len), read_uleb128)          >>
        (value)
    )
);

named!(parse_sleb128<&[u8], Sleb128>,
    do_parse!(
        len: peek!(map!(alt_complete!(take!(5) | rest), determine_leb128_length))    >>
        value: map_res!(take!(len), read_sleb128)          >>
        (value)
    )
);

// uleb128p1 is uleb128 plus one - so subtract one from uleb128
named!(parse_uleb128p1<&[u8], Uleb128>,
    map!(call!(parse_uleb128), |i| { i - 1 })
);

// LEB128 only ever encodes 32-bit values in a .dex file
pub fn read_uleb128(input: &[u8]) -> Result<Uleb128, leb128::read::Error> {
    leb128::read::unsigned(&mut (input.clone())).map(|i| i as u32)
}

pub fn read_sleb128(input: &[u8]) -> Result<Sleb128, leb128::read::Error> {
    leb128::read::signed(&mut (input.clone())).map(|i| i as i32)
}

named_args!(parse_string_id_items(size: usize, e: nom::Endianness)<&[u8], Vec<u32>>,
    call!(parse_u32_list, size, e)
);

named_args!(parse_u32_list(size: usize, e: nom::Endianness)<&[u8], Vec<u32>>, count!(u32!(e), size));

// Docs: map_list
fn parse_map_list<'a>(_: &[u8], data: &'a[u8], e: nom::Endianness) -> nom::IResult<&'a[u8], RawMapList> {
    do_parse!(data,
        size: u32!(e)                                           >>
        list: count!(do_parse!(
                type_: map_res!(u16!(e), MapListItemType::parse)    >>
                unused: u16!(e)                                 >>
                size: u32!(e)                                   >>
                offset: u32!(e)                                 >>
                (RawMapListItem { type_, unused, size, offset })
            ), size as usize)                                   >>

        (RawMapList { size, list })
    )
}

// Docs: type_list
named_args!(parse_type_list(e: nom::Endianness)<&[u8], RawTypeList>,
    peek!(
        do_parse!(
            size: u32!(e)                                       >>
            list: count!(u16!(e), size as usize)                >>
            (RawTypeList { size, list })
    )
));

// Docs: proto_id_item
named_args!(parse_proto_id_items(size: usize, e: nom::Endianness)<&[u8], Vec<RawPrototype>>,
    count!(
        do_parse!(
            shorty_idx: u32!(e)         >>
            return_type_idx: u32!(e)    >>
            parameters_off: u32!(e)     >>
            (RawPrototype { shorty_idx, return_type_idx, parameters_off })
        ), size)
);

// Docs: field_id_item
named_args!(parse_field_id_items(size: usize, e: nom::Endianness)<&[u8], Vec<RawField>>,
    count!(
        do_parse!(
            class_idx: u16!(e)                                  >>
            type_idx: u16!(e)                                   >>
            name_idx: u32!(e)                                   >>
            (RawField { class_idx, type_idx, name_idx })
        ), size)
);

// Docs: method_id_item
named_args!(parse_method_id_items(size: usize, e: nom::Endianness)<&[u8], Vec<RawMethod>>,
    count!(
        do_parse!(
            class_idx: u16!(e)                                  >>
            proto_idx: u16!(e)                                  >>
            name_idx: u32!(e)                                   >>
            (RawMethod { class_idx, proto_idx, name_idx })
        ), size)
);

named_args!(parse_class_def_items(size: usize, e: nom::Endianness)<&[u8], Vec<RawClassDefinition>>,
    count!(
        do_parse!(
            class_idx: u32!(e)                  >>
            access_flags: u32!(e)               >>
            superclass_idx: u32!(e)             >>
            interfaces_off: u32!(e)             >>
            source_file_idx: u32!(e)            >>
            annotations_off: u32!(e)            >>
            class_data_off: u32!(e)             >>
            static_values_off: u32!(e)          >>

            (RawClassDefinition { class_idx, access_flags, superclass_idx, interfaces_off,
            source_file_idx, annotations_off, class_data_off, static_values_off})
        ), size)
);

named_args!(parse_header(e: nom::Endianness)<&[u8], RawHeader>,
    do_parse!(
        // Little bit of magic at the start
        tag!(DEX_FILE_MAGIC)                >>
        // Followed by the version (0380 for example)
        // TODO: convert these to digits and stringify them
        // TODO: just take(4)
        version: count_fixed!(u8, call!(take_one), 4) >>
        // adler32 checksum of the rest of this DEX file
        // TODO: validate this later
        checksum: u32!(e)                   >>
        // SHA1 signature of the rest of the file
        // TODO: verify this later
        signature: count_fixed!(u8, call!(take_one), 20)                >>
        file_size: u32!(e)                  >>
        header_size: u32!(e)                >>
        endian_tag: u32!(e)                 >>
        link_size: u32!(e)                  >>
        link_off: u32!(e)                   >>
        map_off: u32!(e)                    >>
        // Count of strings in the string identifier list
        string_ids_size: u32!(e)            >>
        string_ids_off: u32!(e)             >>
        type_ids_size: u32!(e)              >>
        type_ids_off: u32!(e)               >>
        proto_ids_size: u32!(e)             >>
        proto_ids_off: u32!(e)              >>
        field_ids_size: u32!(e)             >>
        field_ids_off: u32!(e)              >>
        method_ids_size: u32!(e)            >>
        method_ids_off: u32!(e)             >>
        class_defs_size: u32!(e)            >>
        class_defs_off: u32!(e)             >>
        data_size: u32!(e)                  >>
        data_off: u32!(e)                   >>

        (RawHeader { version, checksum, signature, file_size, header_size, endian_tag, link_size, link_off,
         map_off, string_ids_size, string_ids_off, type_ids_size, type_ids_off, proto_ids_size,
         proto_ids_off, field_ids_size, field_ids_off, method_ids_size, method_ids_off, class_defs_size,
         class_defs_off, data_size, data_off })
    )
);

// Docs: method_handle_item
named_args!(parse_method_handle_items(size: usize, e: nom::Endianness)<&[u8], Vec<RawMethodHandleItem>>,
    count!(
        do_parse!(
            type_: u16!(e) >>
            unused_1: u16!(e) >>
            field_or_method_id: u16!(e) >>
            unused_2: u16!(e)   >>
            (RawMethodHandleItem { type_, unused_1, field_or_method_id, unused_2 })
    ), size)
);
//=============================
#[derive(Debug, PartialEq)]
enum AnnotationType {
    Class,
    Field,
    Method
}

impl Visibility {
    pub fn parse(value: u8) -> Result<Self, ParserErr> {
        match value {
            0x00 => Ok(Visibility::BUILD),
            0x01 => Ok(Visibility::RUNTIME),
            0x02 => Ok(Visibility::SYSTEM),
            _ => Err(ParserErr::from(format!("Could not find visibility for value 0x{:0X}", value)))
        }
    }
}

impl MapListItemType {
    fn parse(value: u16) -> Result<Self, ParserErr> {
        match value {
            0x0000 => Ok(MapListItemType::HEADER_ITEM),
            0x0001 => Ok(MapListItemType::STRING_ID_ITEM),
            0x0002 => Ok(MapListItemType::TYPE_ID_ITEM),
            0x0003 => Ok(MapListItemType::PROTO_ID_ITEM),
            0x0004 => Ok(MapListItemType::FIELD_ID_ITEM),
            0x0005 => Ok(MapListItemType::METHOD_ID_ITEM),
            0x0006 => Ok(MapListItemType::CLASS_DEF_ITEM),
            0x0007 => Ok(MapListItemType::CALL_SITE_ID_ITEM),
            0x0008 => Ok(MapListItemType::METHOD_HANDLE_ITEM),
            0x1000 => Ok(MapListItemType::MAP_LIST),
            0x1001 => Ok(MapListItemType::TYPE_LIST),
            0x1002 => Ok(MapListItemType::ANNOTATION_SET_REF_LIST),
            0x1003 => Ok(MapListItemType::ANNOTATION_SET_ITEM),
            0x2000 => Ok(MapListItemType::CLASS_DATA_ITEM),
            0x2001 => Ok(MapListItemType::CODE_ITEM),
            0x2002 => Ok(MapListItemType::STRING_DATA_ITEM),
            0x2003 => Ok(MapListItemType::DEBUG_INFO_ITEM),
            0x2004 => Ok(MapListItemType::ANNOTATION_ITEM),
            0x2005 => Ok(MapListItemType::ENCODED_ARRAY_ITEM),
            0x2006 => Ok(MapListItemType::ANNOTATIONS_DIRECTORY_ITEM),
            _ => Err(ParserErr::from(format!("No type code found for map list item 0x{:0X}", value)))
        }
    }
}

impl AccessFlag {
    fn parse(value: u32, type_: AnnotationType) -> Vec<Self> {
        let mut v = vec!();

        if value & 0x01 != 0 { v.push(AccessFlag::ACC_PUBLIC); }
        if value & 0x02 != 0 { v.push(AccessFlag::ACC_PRIVATE); }
        if value & 0x04 != 0 { v.push(AccessFlag::ACC_PROTECTED); }
        if value & 0x08 != 0 { v.push(AccessFlag::ACC_STATIC); }
        if value & 0x10 != 0 { v.push(AccessFlag::ACC_FINAL); }
        if value & 0x20 != 0 { v.push(AccessFlag::ACC_SYNCHRONIZED); }
        if value & 0x40 != 0 {
            if type_ == AnnotationType::Field {
                v.push(AccessFlag::ACC_VOLATILE);
            } else if type_ == AnnotationType::Method {
                v.push(AccessFlag::ACC_BRIDGE);
            }
        }
        if value & 0x80 != 0 {
            if type_ == AnnotationType::Field {
                v.push(AccessFlag::ACC_TRANSIENT);
            } else if type_ == AnnotationType::Method {
                v.push(AccessFlag::ACC_VARARGS);
            }
        }
        if value & 0x100 != 0 { v.push(AccessFlag::ACC_NATIVE); }
        if value & 0x200 != 0 { v.push(AccessFlag::ACC_INTERFACE); }
        if value & 0x400 != 0 { v.push(AccessFlag::ACC_ABSTRACT); }
        if value & 0x800 != 0 { v.push(AccessFlag::ACC_STRICT); }
        if value & 0x1000 != 0 { v.push(AccessFlag::ACC_SYNTHETIC); }
        if value & 0x2000 != 0 { v.push(AccessFlag::ACC_ANNOTATION); }
        if value & 0x4000 != 0 { v.push(AccessFlag::ACC_ENUM); }
        if value & 0x8000 != 0 { v.push(AccessFlag::UNUSED); }
        if value & 0x10000 != 0 { v.push(AccessFlag::ACC_CONSTRUCTOR); }
        if value & 0x20000 != 0 { v.push(AccessFlag::ACC_DECLARED_SYNCHRONIZED); }

        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use byteorder::*;

    #[allow(non_upper_case_globals)]
    const e: nom::Endianness = nom::Endianness::Little;

    #[test]
    // TODO: test endianness
    fn test_access_flag_bitmasking() {
        // Christmas tree
        assert_eq!(AccessFlag::parse(std::u32::MAX, AnnotationType::Method).len(), 18);
        // No flags
        assert_eq!(AccessFlag::parse(std::u32::MIN, AnnotationType::Method).len(), 0);
    }

    #[test]
    fn test_parse_method_handle_item() {
        // two method handle items
        let mut writer = vec!();
        for d in &[1_u16, 2_u16, 3_u16, 4_u16, 5_u16, 6_u16, 7_u16, 8_u16] {
            writer.write_u16::<LittleEndian>(*d).unwrap();
        }

        let res = parse_method_handle_items(&writer, 2, e).unwrap();

        assert_eq!(res.0.len(), 0);
        assert_eq!(res.1.len(), 2);
        assert_eq!(res.1[0], RawMethodHandleItem { type_: 1, unused_1: 2, field_or_method_id: 3, unused_2: 4 } );
        assert_eq!(res.1[1], RawMethodHandleItem { type_: 5, unused_1: 6, field_or_method_id: 7, unused_2: 8 } );
    }

    #[test]
    fn test_parse_class_def_items() {
        let mut writer = vec!();
        // two class def items
        for d in &[1_u32, 1_u32, 1_u32, 1_u32, 1_u32, 1_u32, 1_u32, 1_u32,
            2_u32, 2_u32, 2_u32, 2_u32, 2_u32, 2_u32, 2_u32, 2_u32] {

            writer.write_u32::<LittleEndian>(*d).unwrap();
        }

        let res = parse_class_def_items(&writer, 2, e).unwrap();

        assert_eq!(res.0.len(), 0);
        assert_eq!(res.1, vec!(
            RawClassDefinition {
                class_idx: 1,
                access_flags: 1,
                superclass_idx: 1,
                interfaces_off: 1,
                source_file_idx: 1,
                annotations_off: 1,
                class_data_off: 1,
                static_values_off: 1
            },
            RawClassDefinition {
                class_idx: 2,
                access_flags: 2,
                superclass_idx: 2,
                interfaces_off: 2,
                source_file_idx: 2,
                annotations_off: 2,
                class_data_off: 2,
                static_values_off: 2
            }
        ))
    }

    #[test]
    fn test_parse_method_id_items() {
        let mut writer = vec!();
        // two method id items
        writer.write_u16::<LittleEndian>(1).unwrap();
        writer.write_u16::<LittleEndian>(1).unwrap();
        writer.write_u32::<LittleEndian>(1).unwrap();

        writer.write_u16::<LittleEndian>(2).unwrap();
        writer.write_u16::<LittleEndian>(2).unwrap();
        writer.write_u32::<LittleEndian>(2).unwrap();

        let res = parse_method_id_items(&writer, 2, e).unwrap();

        assert_eq!(res.0.len(), 0);
        assert_eq!(res.1, vec!(
            RawMethod {
                class_idx: 1,
                proto_idx: 1,
                name_idx: 1
            },
            RawMethod {
                class_idx: 2,
                proto_idx: 2,
                name_idx: 2
            }
        ));
    }

    #[test]
    fn test_parse_field_id_items() {
        let mut writer = vec!();
        // two field id items
        writer.write_u16::<LittleEndian>(1).unwrap();
        writer.write_u16::<LittleEndian>(1).unwrap();
        writer.write_u32::<LittleEndian>(1).unwrap();

        writer.write_u16::<LittleEndian>(2).unwrap();
        writer.write_u16::<LittleEndian>(2).unwrap();
        writer.write_u32::<LittleEndian>(2).unwrap();

        let res = parse_field_id_items(&writer, 2, e).unwrap();

        assert_eq!(res.0.len(), 0);
        assert_eq!(res.1, vec!(
            RawField {
                class_idx: 1,
                type_idx: 1,
                name_idx: 1
            },
            RawField {
                class_idx: 2,
                type_idx: 2,
                name_idx: 2
            }
        ));
    }

    #[test]
    fn test_parse_proto_id_items() {
        let mut writer = vec!();
        // two proto id items
        writer.write_u32::<LittleEndian>(1).unwrap();
        writer.write_u32::<LittleEndian>(1).unwrap();
        writer.write_u32::<LittleEndian>(1).unwrap();

        writer.write_u32::<LittleEndian>(2).unwrap();
        writer.write_u32::<LittleEndian>(2).unwrap();
        writer.write_u32::<LittleEndian>(2).unwrap();

        let res = parse_proto_id_items(&writer, 2, e).unwrap();

        assert_eq!(res.0.len(), 0);
        assert_eq!(res.1, vec!(
            RawPrototype {
                shorty_idx: 1,
                return_type_idx: 1,
                parameters_off: 1
            },
            RawPrototype {
                shorty_idx: 2,
                return_type_idx: 2,
                parameters_off: 2
            }
        ));
    }

    #[test]
    fn test_parse_type_list() {
        let mut writer = vec!();
        writer.write_u32::<LittleEndian>(2).unwrap();
        writer.write_u16::<LittleEndian>(1).unwrap();
        writer.write_u16::<LittleEndian>(1).unwrap();

        let res = parse_type_list(&writer, e).unwrap();

        assert_eq!(res.0.len(), writer.len());
        assert_eq!(res.1, RawTypeList {
            size: 2,
            list: vec!(1, 1)
        });
    }

    #[test]
    fn test_parse_map_list() {
        let mut writer = vec!();
        writer.write_u32::<LittleEndian>(2).unwrap();

        // First list item
        writer.write_u16::<LittleEndian>(0x0000).unwrap();
        writer.write_u16::<LittleEndian>(1).unwrap();
        writer.write_u32::<LittleEndian>(1).unwrap();
        writer.write_u32::<LittleEndian>(1).unwrap();

        // Second list item
        writer.write_u16::<LittleEndian>(0x0001).unwrap();
        writer.write_u16::<LittleEndian>(2).unwrap();
        writer.write_u32::<LittleEndian>(2).unwrap();
        writer.write_u32::<LittleEndian>(2).unwrap();

        let res = parse_map_list(&[], &writer, e).unwrap();

        assert_eq!(res.0.len(), 0);
        assert_eq!(res.1, RawMapList {
            size: 2,
            list: vec!(RawMapListItem {
                type_: MapListItemType::HEADER_ITEM,
                unused: 1,
                size: 1,
                offset: 1
            }, RawMapListItem {
                type_: MapListItemType::STRING_ID_ITEM,
                unused: 2,
                size: 2,
                offset: 2
            })
        });
    }

    #[test]
    fn test_parse_string_id_items() {
        let mut writer = vec!();
        writer.write_u32::<LittleEndian>(1).unwrap();
        writer.write_u32::<LittleEndian>(2).unwrap();

        let res = parse_string_id_items(&writer, 2, e).unwrap();

        assert_eq!(res.0.len(), 0);
        assert_eq!(res.1, vec!(1, 2));
    }

    // TODO: redo this using writer
    #[test]
    fn test_determine_leb128_length() {
        assert_eq!(determine_leb128_length(&[0b00000001]), 1);
        assert_eq!(determine_leb128_length(&[0b10000000, 0b00000001]), 2);
        assert_eq!(determine_leb128_length(&[0b10000000, 0b11111111, 0b11111111, 0b11111111, 0b00000001]), 5);
    }

    #[test]
    fn test_parse_uleb128() {
        let mut res = parse_uleb128(&[0b00000001]).unwrap();
        assert_eq!(res.1, 1);

        res = parse_uleb128(&[0b10000000, 0b00000001]).unwrap();
        assert_eq!(res.1, 128);

        res = parse_uleb128(&[0b11111111, 0b11111111, 0b11111111, 0b11111111, 0b01111111]).unwrap();
        assert_eq!(res.1, std::u32::MAX);
    }

    #[test]
    fn test_parse_uleb128p1() {
        let mut res = parse_uleb128p1(&[0b00000001]).unwrap();
        assert_eq!(res.1, 0);

        res = parse_uleb128p1(&[0b10000000, 0b00000001]).unwrap();
        assert_eq!(res.1, 127);

        res = parse_uleb128p1(&[0b11111111, 0b11111111, 0b11111111, 0b11111111, 0b01111111]).unwrap();
        assert_eq!(res.1, std::u32::MAX - 1);
    }

    #[test]
    fn test_parse_sleb128() {
        let mut res = parse_sleb128(&[0b00000001]).unwrap();
        assert_eq!(res.1, 1);

        res = parse_sleb128(&[0b10000000, 0b00000001]).unwrap();
        assert_eq!(res.1, 128);

        res = parse_sleb128(&[0b11111111, 0b11111111, 0b11111111, 0b11111111, 0b00000111]).unwrap();
        assert_eq!(res.1, std::i32::MAX);

        res = parse_sleb128(&[0b11111111, 0b11111111, 0b11111111, 0b11111111, 0b01111111]).unwrap();
        assert_eq!(res.1, -1);
    }

    // TODO: test parse_header

    // TODO: test parse_dex_file
}