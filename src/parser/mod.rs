use nom::*;
use std::str;
use std::rc::Rc;

// The magic that starts a DEX file
const DEX_FILE_MAGIC: [u8; 4] = [0x64, 0x65, 0x78, 0x0a];
// Indicates standard (little-endian) encoding
const ENDIAN_CONSTANT: [u8; 4] = [0x12, 0x34, 0x56, 0x78];
// Indicates modified non-standard (big-endian) encoding
const REVERSE_ENDIAN_CONSTANT: [u8; 4] = [0x78, 0x56, 0x34, 0x12];

const NO_INDEX: u32 = 0xffffffff;

#[derive(Debug)]
pub struct DexFile<'a> {
    header: Header<'a>,
    string_data_items: Vec<StringDataItem>,
    type_id_data_items: Vec<TypeIdentifierDataItem>,
    proto_id_data_items: Vec<PrototypeDataItem>
}

#[derive(Debug)]
pub struct Header<'a> {
    pub version: [u8; 4],
    pub checksum: u32,
    pub signature: &'a[u8],
    pub file_size: u32,
    pub header_size: u32,
    pub endian_tag: u32,
    pub link_size: u32,
    pub link_off: u32,
    pub map_off: u32,
    pub string_ids_size: u32,
    pub string_ids_off: u32,
    pub type_ids_size: u32,
    pub type_ids_off: u32,
    pub proto_ids_size: u32,
    pub proto_ids_off: u32,
    pub field_ids_size: u32,
    pub field_ids_off: u32,
    pub method_ids_size: u32,
    pub method_ids_off: u32,
    pub class_defs_size: u32,
    pub class_defs_off: u32,
    pub data_size: u32,
    pub data_off: u32
}

#[derive(Debug)]
pub struct ParserErr;

pub fn parse(buffer: &[u8]) -> Result<DexFile, ParserErr> {

    // Peek ahead to determine endianness
    let endianness = {
        // TODO: remove this
        println!("{:X?}", &buffer[40 .. 44]);

        if buffer[40 .. 44] == ENDIAN_CONSTANT {
            nom::Endianness::Big
        } else if buffer[40 .. 44] == REVERSE_ENDIAN_CONSTANT {
            nom::Endianness::Little
        } else {
            return Err(ParserErr);
        }
    };

    println!("Endianness is {:?}", endianness);

    // TODO: proper error
//    parse_dex_file(buffer, endianness)
//        .map(|(_, res)| res)
//        .map_err(|e| ParserErr )


    let res = parse_dex_file(buffer, endianness);

    match res {
        Ok(dexf) => Ok(dexf),
        Err(e) => {
//            println!("ERROR: {}", e);
            Err(ParserErr)
        }
    }
}

impl From<nom::Err<&[u8]>> for ParserErr {
    fn from(e: nom::Err<&[u8]>) -> Self {
        println!("error! {:?}", e);
        ParserErr
    }
}

fn parse_dex_file(buffer: &[u8], e: nom::Endianness) -> Result<DexFile, ParserErr> {
    let (buffer, header) = parse_header(buffer, e)?;

    // Version 038 adds some new index pools with sizes not indicated in the header
    // Need to peek at this a bit early so we know how big some of the index pools are
    // Very inconvenient!
    let map_list = parse_map_list(&buffer[(header.map_off - header.header_size) as usize ..], e)?.1;

    // Peek ahead and pull out the data segment
    let (_, data) = take!(&buffer[header.data_off as usize - header.header_size as usize .. ], header.data_size)?;

    // Pull out string data objects
    let (buffer, string_data_items) = parse_string_data(&buffer[..], &header, &data, e)?;

    let (buffer, (type_id_idxs, proto_id_idxs, field_id_idxs, method_id_idxs, class_def_idxs))
    = parse_id_idxs(&buffer, e, &header).unwrap();

    let call_site_idxs = parse_u32_list(buffer, e,
                                        map_list.list.iter().filter(|item| item.type_ == MapListItemType::CallSiteIdItem).count());

    let method_handle_items_idxs = parse_u32_list(buffer, e,
                                        map_list.list.iter().filter(|item| item.type_  == MapListItemType::MethodHandleItem).count());

    let type_id_data_items: Vec<TypeIdentifierDataItem> = type_id_idxs.into_iter().map(|idx| {
        // Type ID indexes are indexes into the string IDs list, which we have pulled out above
        TypeIdentifierDataItem { descriptor: string_data_items[idx as usize].data.clone() }
    }).collect();

    let proto_id_data_items = proto_id_idxs.into_iter().map(|item| {
        let shorty = string_data_items[item.shorty_idx as usize].data.clone();
        let return_type = type_id_data_items[item.return_type_idx as usize].descriptor.clone();

        let parameters = if item.parameters_off == 0 {
            None
        } else {
            match parse_type_list(&data[item.parameters_off as usize - header.data_off as usize..], e) {
                Ok((_, res)) => {
                    // We now have a list of indexes into the type IDs list
                    Some(res.list.into_iter()
                        .map(|idx| type_id_data_items[idx as usize].descriptor.clone())
                        .collect())
                },
                Err(e) => panic!("TODO")
            }
        };

        PrototypeDataItem {
            shorty,
            return_type,
            parameters
        }
    }).collect();

    Ok(DexFile {
        header,
        string_data_items,
        type_id_data_items,
        proto_id_data_items
    })
}

fn parse_string_data<'a>(input: &'a[u8], header: &Header, data: &'a[u8], e: nom::Endianness)
    -> Result<(&'a[u8], Vec<StringDataItem>), nom::Err<&'a[u8]>> {
    let mut v = Vec::with_capacity(header.string_ids_size as usize);
    // Pull out the list of offsets into data block
    println!("size: [{}]", header.string_ids_size);
    println!("input size: {}", input.len());

    let (buffer, offsets) = parse_u32_list(input, e, header.string_ids_size as usize)?;

    for offset in offsets {
        // Offsets are given as offset from start of file, not start of data
        // This should not consume data - offsets must be preserved
        v.push(parse_string_data_item(&data[offset as usize - header.data_off as usize..])?.1);
    }
    Ok((buffer, v))
}

named_args!(parse_type_list (e: nom::Endianness) <&[u8], TypeListItem>,
    peek!(do_parse!(
            size: u32!(e) >>
            list: count!(u16!(e), size as usize) >>
            (TypeListItem { size, list })
)));

struct TypeListItem {
    // Size of the following list
    size: u32,
    list: Vec<u16>
}

#[derive(Debug)]
struct PrototypeDataItem {
    shorty: Rc<String>,
    return_type: Rc<String>,
    parameters: Option<Vec<Rc<String>>>
}

#[derive(Debug)]
struct TypeIdentifierDataItem {
    descriptor: Rc<String>
}

// Length of uleb128 value is determined by the
fn determine_uleb128_length(input: &[u8]) -> usize {
    // TODO: work out what this is actually doing
    input.iter().take_while(|byte| *byte & (0 << 0) != 0).count() + 1
}

named!(parse_string_data_item <&[u8], StringDataItem> ,
    peek!(
        do_parse!(
            // uleb128 values are 1-5 bytes long - determine how long it is so we can parse the item
            uleb_len: peek!(map!(take!(5), determine_uleb128_length))           >>
            utf16_size: map_res!(take!(uleb_len), read_uleb128)                >>
            data: map!(map!(map_res!(take_until_and_consume!("\0"), str::from_utf8), str::to_string), Rc::new) >>
            (StringDataItem { utf16_size, data })
    ))
);

// nom gives us immutable byte slices, but the leb128 library requires mutable slices
// No syntactically valid way to convert the two inside the macro so we'll make a wrapper function
fn read_uleb128(input: &[u8]) -> Result<u64, leb128::read::Error> {
    leb128::read::unsigned(&mut (input.clone()))
}

#[derive(Debug)]
struct StringDataItem {
    // Need to convert this from a uleb128 value
    utf16_size: u64,
    data: Rc<String>
}

named_args!(parse_id_idxs <'a> ( e: nom::Endianness, header: &Header ) <&'a[u8], ( Vec<u32>,
Vec<ProtoIdItem>, Vec<FieldIdItem>, Vec<MethodIdItem>, Vec<ClassDefItem> ) >,
        do_parse!(
            typ: apply!(parse_u32_list, e, header.type_ids_size as usize)           >>
            pro: apply!(proto_id_items, e, header.proto_ids_size as usize)          >>
            fld: apply!(field_id_items, e, header.field_ids_size as usize)          >>
            mtd: apply!(method_id_items, e, header.method_ids_size as usize)        >>
            cls: apply!(class_def_items, e, header.class_defs_size as usize)        >>
            (typ, pro, fld, mtd, cls)
        )
);

named_args!(parse_u32_list ( e: nom::Endianness, size: usize ) <&[u8], Vec<u32> >,
    count!(u32!(e), size));

struct MapList {
    size: u32,
    list: Vec<MapListItem>
}

struct MapListItem {
    type_: MapListItemType,
    unused: u16,
    size: u32,
    offset: u32
}

#[derive(PartialEq)]
enum MapListItemType {
    HeaderItem,
    StringIdItem,
    TypeIdItem,
    ProtoIdItem,
    FieldIdItem,
    MethodIdItem,
    ClassDefItem,
    CallSiteIdItem,
    MethodHandleItem,
    MapList,
    TypeList,
    AnnotationSetRefList,
    AnnotationSetItem,
    ClassDataItem,
    CodeItem,
    StringDataItem,
    DebugInfoItem,
    AnnotationItem,
    EncodedArrayItem,
    AnnotationsDirectoryItem
}

impl MapListItemType {
    fn parse(value: u16) -> Self {
        match value {
            0x0000 => MapListItemType::HeaderItem,
            0x0001 => MapListItemType::StringIdItem,
            0x0002 => MapListItemType::TypeIdItem,
            0x0003 => MapListItemType::ProtoIdItem,
            0x0004 => MapListItemType::FieldIdItem,
            0x0005 => MapListItemType::MethodIdItem,
            0x0006 => MapListItemType::ClassDefItem,
            0x0007 => MapListItemType::CallSiteIdItem,
            0x0008 => MapListItemType::MethodHandleItem,
            0x1000 => MapListItemType::MapList,
            0x1001 => MapListItemType::TypeList,
            0x1002 => MapListItemType::AnnotationSetRefList,
            0x1003 => MapListItemType::AnnotationSetItem,
            0x2000 => MapListItemType::ClassDataItem,
            0x2001 => MapListItemType::CodeItem,
            0x2002 => MapListItemType::StringDataItem,
            0x2003 => MapListItemType::DebugInfoItem,
            0x2004 => MapListItemType::AnnotationItem,
            0x2005 => MapListItemType::EncodedArrayItem,
            0x2006 => MapListItemType::AnnotationsDirectoryItem,
            _ => panic!("No type code found for map list item {}", value)
        }
    }
}

named_args!(parse_map_list ( e: nom::Endianness) <&[u8], MapList>,
peek!(
    do_parse!(
        size: u32!(e)                                           >>
        list: count!(do_parse!(
                type_: map!(u16!(e), MapListItemType::parse)    >>
                unused: u16!(e)                                 >>
                size: u32!(e)                                   >>
                offset: u32!(e)                                 >>
                (MapListItem { type_, unused, size, offset })
            ), size as usize)                                   >>

        (MapList { size, list })
    )
    )
);

named_args!(proto_id_items ( e: nom::Endianness, s: usize ) <&[u8], Vec<ProtoIdItem> >,
    count!(
        do_parse!(
            shorty_idx: u32!(e)         >>
            return_type_idx: u32!(e)    >>
            parameters_off: u32!(e)     >>
            (ProtoIdItem { shorty_idx, return_type_idx, parameters_off })
        ), s)
);

struct ProtoIdItem {
    // Index into the string IDs list for the descriptor string of this prototype
    shorty_idx: u32,
    // Index into the type_ids list for the return type of this prototype
    return_type_idx: u32,
    parameters_off: u32
}

named_args!(field_id_items ( e: nom::Endianness, s: usize ) <&[u8], Vec<FieldIdItem> >,
    count!(
        do_parse!(
            class_idx: u16!(e)  >>
            type_idx: u16!(e)   >>
            name_idx: u32!(e)   >>
            (FieldIdItem { class_idx, type_idx, name_idx })
        ), s)
);

struct FieldIdItem {
    class_idx: u16,
    type_idx: u16,
    name_idx: u32
}

named_args!(method_id_items ( e: nom::Endianness, s: usize ) <&[u8], Vec<MethodIdItem> >,
    count!(
        do_parse!(
            class_idx: u16!(e)  >>
            proto_idx: u16!(e)   >>
            name_idx: u32!(e)   >>
            (MethodIdItem { class_idx, proto_idx, name_idx })
        ), s)
);

struct MethodIdItem {
    class_idx: u16,
    proto_idx: u16,
    name_idx: u32
}

named_args!(class_def_items ( e: nom::Endianness, s: usize ) <&[u8], Vec<ClassDefItem> >,
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

            (ClassDefItem { class_idx, access_flags, superclass_idx, interfaces_off,
            source_file_idx, annotations_off, class_data_off, static_values_off})
        ), s)
);

struct ClassDefItem {
    class_idx: u32,
    access_flags: u32,
    superclass_idx: u32,
    interfaces_off: u32,
    source_file_idx: u32,
    annotations_off: u32,
    class_data_off: u32,
    static_values_off: u32
}

named_args!(parse_header ( e: nom::Endianness ) <&[u8], Header>,
    do_parse!(
        // Little bit of magic at the start
        tag!(DEX_FILE_MAGIC)                >>
        // Followed by the version (0380 for example)
        // TODO: convert these to digits and stringify them
        version: dbg!(count_fixed!(u8, map!(take!(1), |x| { x[0] } ), 4)) >>
        // adler32 checksum of the rest of this DEX file
        // TODO: validate this later
        checksum: u32!(e)                   >>
        // SHA1 signature of the rest of the file
        // TODO: verify this later
        signature: take!(20)                >>
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

        (Header { version, checksum, signature, file_size, header_size, endian_tag, link_size, link_off,
         map_off, string_ids_size, string_ids_off, type_ids_size, type_ids_off, proto_ids_size,
         proto_ids_off, field_ids_size, field_ids_off, method_ids_size, method_ids_off, class_defs_size,
         class_defs_off, data_size, data_off })
    )
);
