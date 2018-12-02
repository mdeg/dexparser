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
const DEX_FILE_MAGIC: [u8; 4] = [0x64, 0x65, 0x78, 0x0a];
// Indicates standard (little-endian) encoding
const ENDIAN_CONSTANT: [u8; 4] = [0x12, 0x34, 0x56, 0x78];
// Indicates modified non-standard (big-endian) encoding
const REVERSE_ENDIAN_CONSTANT: [u8; 4] = [0x78, 0x56, 0x34, 0x12];

const NO_INDEX: u32 = 0xffffffff;

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

named_args!(parse_string_id_items(size: usize, e: nom::Endianness)<&[u8], Vec<u32>>,
    call!(parse_u32_list, size, e)
);

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

// TODO: write this in nom
pub fn determine_leb128_length(input: &[u8]) -> usize {
    input.iter()
        .take_while(|byte| (*byte & 0x80) != 0)
        .count()
        + 1
}

named!(parse_uleb128<&[u8], u64>,
    do_parse!(
        len: peek!(map!(take!(5), determine_leb128_length))    >>
        value: map_res!(take!(len), read_uleb128)          >>
        (value)
    )
);

named!(parse_sleb128<&[u8], i64>,
    do_parse!(
        len: peek!(map!(take!(5), determine_leb128_length))    >>
        value: map_res!(take!(len), read_sleb128)          >>
        (value)
    )
);

// uleb128p1 is uleb128 plus one - so subtract one from uleb128
named!(parse_uleb128p1<&[u8], u64>,
    call!(parse_uleb128)
);

// nom gives us immutable byte slices, but the leb128 library requires mutable slices
// No syntactically valid way to convert the two inside the macro so we'll make a wrapper function
pub fn read_uleb128(input: &[u8]) -> Result<u64, leb128::read::Error> {
    leb128::read::unsigned(&mut (input.clone()))
}

pub fn read_sleb128(input: &[u8]) -> Result<i64, leb128::read::Error> {
    leb128::read::signed(&mut (input.clone()))
}

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

// Docs: annotation_directory_item
named_args!(parse_annotations_directory_item(e:nom::Endianness)<&[u8], RawAnnotations>,
    peek!(do_parse!(
        class_annotations_off: u32!(e)                                                          >>
        fld_size: u32!(e)                                                                    >>
        mtd_size: u32!(e)                                                         >>
        prm_size: u32!(e)                                                      >>
        fld_annot: cond!(fld_size > 0, count!(apply!(parse_field_annotation_item, e), fld_size as usize)) >>
        mtd_annot: cond!(mtd_size > 0, count!(apply!(parse_method_annotation_item, e), mtd_size as usize)) >>
        prm_annot: cond!(prm_size > 0, count!(apply!(parse_parameter_annotation_item, e), prm_size as usize)) >>
        (RawAnnotations { class_annotations_off, fld_annot, mtd_annot, prm_annot })
    ))
);

// Docs: field_annotation_item
named_args!(parse_field_annotation_item(e: nom::Endianness)<&[u8], RawFieldAnnotation>,
    do_parse!(
        field_idx: u32!(e) >>
        annotations_offset: u32!(e) >>
        (RawFieldAnnotation { field_idx, annotations_offset })
    )
);

// Docs: method_annotation_item
named_args!(parse_method_annotation_item(e: nom::Endianness)<&[u8], RawMethodAnnotation>,
    do_parse!(
        method_idx: u32!(e) >>
        annotations_offset: u32!(e) >>
        (RawMethodAnnotation { method_idx, annotations_offset })
    )
);

// Docs: parameter_annotation_item
named_args!(parse_parameter_annotation_item(e: nom::Endianness)<&[u8], RawParameterAnnotation>,
    do_parse!(
        method_idx: u32!(e) >>
        annotations_offset: u32!(e) >>
        (RawParameterAnnotation { method_idx, annotations_offset })
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

    #[test]
    // TODO: test endianness
    fn test_access_flag_bitmasking() {
        // Christmas tree
        assert_eq!(AccessFlag::parse(std::u32::MAX, AnnotationType::Method).len(), 18);
        // No flags
        assert_eq!(AccessFlag::parse(std::u32::MIN, AnnotationType::Method).len(), 0);
    }
}