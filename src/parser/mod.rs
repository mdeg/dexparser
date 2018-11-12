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
    string_data_items: Vec<Rc<StringDataItem>>,
    type_id_data_items: Vec<Rc<TypeIdentifierDataItem>>,
    proto_id_data_items: Vec<Rc<PrototypeDataItem>>,
    field_data_items: Vec<FieldDataItem>,
    method_data_items: Vec<MethodDataItem>,
    class_def_items: Vec<ClassDefDataItem>
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
    let (_, map_list) = parse_map_list(&buffer[(header.map_off - header.header_size) as usize ..], e)?;

    // Peek ahead and pull out the data segment
    let (_, data) = take!(&buffer[header.data_off as usize - header.header_size as usize .. ], header.data_size)?;

    // Pull out string data objects
    let (buffer, string_data_items) = parse_string_data(&buffer[..], &header, &data, e)?;

    let (buffer, type_id_data_items) = parse_type_data(&buffer, e, header.type_ids_size as usize, &string_data_items)?;

    let (buffer, proto_id_data_items) = parse_prototype_data(&buffer, &data, &string_data_items, &type_id_data_items,
                                                             header.proto_ids_size as usize, header.data_off as usize, e)?;

    let (buffer, field_data_items) = parse_field_data(&buffer, &string_data_items, &type_id_data_items, header.field_ids_size as usize, e)?;

    let (buffer, method_data_items) = parse_method_data(&buffer, &string_data_items, &type_id_data_items, &proto_id_data_items, header.method_ids_size as usize, e)?;

    let (buffer, class_def_items) = parse_class_defs(&buffer, &type_id_data_items, &string_data_items, &data, header.data_off as usize, header.class_defs_size as usize, e)?;

    let call_site_idxs = parse_u32_list(buffer, e,
                                        map_list.list.iter().filter(|item| item.type_ == MapListItemType::CallSiteIdItem).count());

    let method_handle_items_idxs = parse_u32_list(buffer, e,
                                        map_list.list.iter().filter(|item| item.type_  == MapListItemType::MethodHandleItem).count());

    Ok(DexFile {
        header,
        string_data_items,
        type_id_data_items,
        proto_id_data_items,
        field_data_items,
        method_data_items,
        class_def_items
    })
}

//class_idx 	uint 	index into the type_ids list for this class. This must be a class type, and not an array or primitive type.
//access_flags 	uint 	access flags for the class (public, final, etc.). See "access_flags Definitions" for details.
//superclass_idx 	uint 	index into the type_ids list for the superclass, or the constant value NO_INDEX if this class has no superclass (i.e., it is a root class such as Object). If present, this must be a class type, and not an array or primitive type.
//interfaces_off 	uint 	offset from the start of the file to the list of interfaces, or 0 if there are none. This offset should be in the data section, and the data there should be in the format specified by "type_list" below. Each of the elements of the list must be a class type (not an array or primitive type), and there must not be any duplicates.
//source_file_idx 	uint 	index into the string_ids list for the name of the file containing the original source for (at least most of) this class, or the special value NO_INDEX to represent a lack of this information. The debug_info_item of any given method may override this source file, but the expectation is that most classes will only come from one source file.
//annotations_off 	uint 	offset from the start of the file to the annotations structure for this class, or 0 if there are no annotations on this class. This offset, if non-zero, should be in the data section, and the data there should be in the format specified by "annotations_directory_item" below, with all items referring to this class as the definer.
//class_data_off 	uint 	offset from the start of the file to the associated class data for this item, or 0 if there is no class data for this class. (This may be the case, for example, if this class is a marker interface.) The offset, if non-zero, should be in the data section, and the data there should be in the format specified by "class_data_item" below, with all items referring to this class as the definer.
//static_values_off 	uint 	offset from the start of the file to the list of initial values for static fields, or 0 if there are none (and all static fields are to be initialized with 0 or null). This offset should be in the data section, and the data there should be in the format specified by "encoded_array_item" below. The size of the array must be no larger than the number of static fields declared by this class, and the elements correspond to the static fields in the same order as declared in the corresponding field_list. The type of each array element must match the declared type of its corresponding field. If there are fewer elements in the array than there are static fields, then the leftover fields are initialized with a type-appropriate 0 or null.

#[derive(Debug)]
struct ClassDefDataItem {
    class_type: Rc<TypeIdentifierDataItem>,
    access_flags: Vec<AccessFlag>,
    superclass: Option<Rc<TypeIdentifierDataItem>>,
    interfaces: Option<Vec<Rc<TypeIdentifierDataItem>>>,
    source_file_name: Option<Rc<StringDataItem>>
}

fn parse_class_defs<'a>(input: &'a[u8], tidi: &[Rc<TypeIdentifierDataItem>], sdi: &[Rc<StringDataItem>],
                        data: &'a[u8], data_offset: usize,
                        size: usize, e: nom::Endianness) -> Result<(&'a[u8], Vec<ClassDefDataItem>), nom::Err<&'a[u8]>> {
    let mut v = Vec::with_capacity(size);
    let (buffer, class_def_items) = parse_class_def_items(&input, e, size)?;
    for class_def_item in class_def_items {
        let class_type = tidi[class_def_item.class_idx as usize].clone();

        // TODO
        let access_flags = vec!();

        let superclass = if class_def_item.superclass_idx == NO_INDEX {
            None
        } else {
            Some(tidi[class_def_item.superclass_idx as usize].clone())
        };

        let interfaces = if class_def_item.interfaces_off == 0 {
            None
        } else {
            Some(parse_type_list(&data[class_def_item.interfaces_off as usize - data_offset..], e)?
                .1
                .list
                .into_iter()
                .map(|idx| tidi[idx as usize].clone())
                .collect())
        };

        let source_file_name = if class_def_item.source_file_idx == NO_INDEX {
            None
        } else {
            Some(sdi[class_def_item.source_file_idx as usize].clone())
        };

        v.push(ClassDefDataItem { class_type, access_flags, superclass, interfaces, source_file_name });
    }

    Ok((buffer, v))
}

fn parse_prototype_data<'a>(input: &'a[u8], data: &'a[u8], sdi: &[Rc<StringDataItem>], tidi: &[Rc<TypeIdentifierDataItem>],
                            size: usize, data_offset: usize, e: nom::Endianness) -> Result<(&'a[u8], Vec<Rc<PrototypeDataItem>>), nom::Err<&'a[u8]>> {

    let mut v = Vec::with_capacity(size);
    let (buffer, id_items) = parse_proto_id_items(&input, e, size)?;
    for id_item in id_items {
        let shorty = sdi[id_item.shorty_idx as usize].clone();
        let return_type = tidi[id_item.return_type_idx as usize].clone();

        let parameters = if id_item.parameters_off == 0 {
            None
        } else {
            Some(parse_type_list(&data[id_item.parameters_off as usize - data_offset..], e)?
                .1
                .list
                .into_iter()
                .map(|idx| tidi[idx as usize].clone())
                .collect())
        };

        v.push(Rc::new(PrototypeDataItem {shorty, return_type, parameters}));
    }

    Ok((buffer, v))
}

fn parse_method_data<'a>(input: &'a[u8], sdi: &[Rc<StringDataItem>], tidi: &[Rc<TypeIdentifierDataItem>],
                        pdi: &[Rc<PrototypeDataItem>], size: usize, e: nom::Endianness) -> Result<(&'a[u8], Vec<MethodDataItem>), nom::Err<&'a[u8]>> {
    let (input, items) = parse_method_id_items(&input, e, size)?;

    Ok((input,
        items.into_iter().map(|item| {
            MethodDataItem {
                definer: tidi[item.class_idx as usize].clone(),
                prototype: pdi[item.proto_idx as usize].clone(),
                name: sdi[item.name_idx as usize].clone()
            }
        }).collect())
    )
}

#[derive(Debug)]
struct MethodDataItem {
    definer: Rc<TypeIdentifierDataItem>,
    prototype: Rc<PrototypeDataItem>,
    name: Rc<StringDataItem>
}

fn parse_field_data<'a>(input: &'a[u8], sdi: &[Rc<StringDataItem>], tidi: &[Rc<TypeIdentifierDataItem>],
                        size: usize, e: nom::Endianness) -> Result<(&'a[u8], Vec<FieldDataItem>), nom::Err<&'a[u8]>> {
    let (input, items) = parse_field_id_items(&input, e, size)?;

    Ok((input,
        items.into_iter().map(|item| {
            FieldDataItem {
                definer: tidi[item.class_idx as usize].clone(),
                type_: tidi[item.type_idx as usize].clone(),
                name: sdi[item.name_idx as usize].clone()
            }
        }).collect())
    )
}

#[derive(Debug)]
struct FieldDataItem {
    definer: Rc<TypeIdentifierDataItem>,
    type_: Rc<TypeIdentifierDataItem>,
    name: Rc<StringDataItem>
}

fn parse_type_data<'a>(input: &'a[u8], e: nom::Endianness, size: usize, sdi: &[Rc<StringDataItem>]) -> Result<(&'a[u8], Vec<Rc<TypeIdentifierDataItem>>), nom::Err<&'a[u8]>> {
    let (buffer, idxs) = parse_u32_list(&input, e, size)?;
    Ok((buffer, idxs.into_iter()
        .map(|idx| Rc::new(TypeIdentifierDataItem { descriptor: sdi[idx as usize].clone() }))
        .collect()
    ))
}

fn parse_string_data<'a>(input: &'a[u8], header: &Header, data: &'a[u8], e: nom::Endianness)
    -> Result<(&'a[u8], Vec<Rc<StringDataItem>>), nom::Err<&'a[u8]>> {
    let mut v = Vec::with_capacity(header.string_ids_size as usize);
    // Pull out the list of offsets into data block
    let (buffer, offsets) = parse_u32_list(input, e, header.string_ids_size as usize)?;

    for offset in offsets {
        // Offsets are given as offset from start of file, not start of data
        // This should not consume data - offsets must be preserved
        v.push(Rc::new(parse_string_data_item(&data[offset as usize - header.data_off as usize..])?.1));
    }
    Ok((buffer, v))
}

#[derive(Debug)]
struct PrototypeDataItem {
    shorty: Rc<StringDataItem>,
    return_type: Rc<TypeIdentifierDataItem>,
    parameters: Option<Vec<Rc<TypeIdentifierDataItem>>>
}

#[derive(Debug)]
struct TypeIdentifierDataItem {
    descriptor: Rc<StringDataItem>
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
            uleb_len: peek!(map!(take!(5), determine_uleb128_length))               >>
            utf16_size: map_res!(take!(uleb_len), read_uleb128)                     >>
            data: map!(
                    map_res!(
                        take_until_and_consume!("\0"), str::from_utf8),
                    str::to_string)                                                 >>
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
    data: String
}

named_args!(parse_u32_list(e: nom::Endianness, size: usize)<&[u8], Vec<u32>>, count!(u32!(e), size));

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

//noinspection RsEnumVariantNaming
#[derive(PartialEq, Debug)]
enum AccessFlag {
    ACC_PUBLIC,
    ACC_PRIVATE,
    ACC_PROTECTED,
    ACC_STATIC,
    ACC_FINAL,
    ACC_SYNCHRONIZED,
    ACC_VOLATILE,
    ACC_BRIDGE,
    ACC_TRANSIENT,
    ACC_VARARGS,
    ACC_NATIVE,
    ACC_INTERFACE,
    ACC_ABSTRACT,
    ACC_STRICT,
    ACC_SYNTHETIC,
    ACC_ANNOTATION,
    ACC_ENUM,
    UNUSED,
    ACC_CONSTRUCTOR,
    ACC_DECLARED_SYNCHRONIZED
}

//impl AccessFlag {
//    fn parse(value: u32) -> Self {
//        match value {
//            0x1 => AccessFlag::ACC_PUBLIC,
//            0x2 => AccessFlag::ACC_PRIVATE,
//            0x4 => AccessFlag::ACC_PROTECTED,
//            0x8 => AccessFlag::ACC_STATIC,
//            0x10 => AccessFlag::ACC_FINAL,
//            0x20 => AccessFlag::ACC_SYNCHRONIZED,
//            0x40 => AccessFlag::ACC_VOLATILE,
//            0x40 => AccessFlag::ACC_BRIDGE,
//            0x80 => AccessFlag::ACC_TRANSIENT,
//            0x80 => AccessFlag::ACC_VARARGS,
//            0x100 => AccessFlag::ACC_NATIVE,
//            0x200 => AccessFlag::ACC_INTERFACE,
//            0x400 => AccessFlag::ACC_ABSTRACT,
//            0x800 => AccessFlag::ACC_STRICT,
//            0x1000 => AccessFlag::ACC_SYNTHETIC,
//            0x2000 => AccessFlag::ACC_ANNOTATION,
//            0x4000 => AccessFlag::ACC_ENUM,
//            0x8000 => AccessFlag::UNUSED,
//            0x10000 => AccessFlag::ACC_CONSTRUCTOR,
//            0x20000 => AccessFlag::ACC_DECLARED_SYNCHRONIZED,
//            _ => panic!("No type code found for access flag {}", value)
//        }
//    }
//}

named_args!(parse_map_list(e: nom::Endianness)<&[u8], MapList>,
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

named_args!(parse_type_list(e: nom::Endianness)<&[u8], TypeListItem>,
    peek!(
        do_parse!(
            size: u32!(e)                                       >>
            list: count!(u16!(e), size as usize)                >>
            (TypeListItem { size, list })
    )
));

struct TypeListItem {
    // Size of the following list
    size: u32,
    list: Vec<u16>
}

named_args!(parse_proto_id_items(e: nom::Endianness, size: usize)<&[u8], Vec<ProtoIdItem>>,
    count!(
        do_parse!(
            shorty_idx: u32!(e)         >>
            return_type_idx: u32!(e)    >>
            parameters_off: u32!(e)     >>
            (ProtoIdItem { shorty_idx, return_type_idx, parameters_off })
        ), size)
);

struct ProtoIdItem {
    // Index into the string IDs list for the descriptor string of this prototype
    shorty_idx: u32,
    // Index into the type_ids list for the return type of this prototype
    return_type_idx: u32,
    parameters_off: u32
}

named_args!(parse_field_id_items(e: nom::Endianness, size: usize)<&[u8], Vec<FieldIdItem>>,
    count!(
        do_parse!(
            class_idx: u16!(e)                                  >>
            type_idx: u16!(e)                                   >>
            name_idx: u32!(e)                                   >>
            (FieldIdItem { class_idx, type_idx, name_idx })
        ), size)
);

struct FieldIdItem {
    class_idx: u16,
    type_idx: u16,
    name_idx: u32
}

named_args!(parse_method_id_items(e: nom::Endianness, size: usize)<&[u8], Vec<MethodIdItem>>,
    count!(
        do_parse!(
            class_idx: u16!(e)                                  >>
            proto_idx: u16!(e)                                  >>
            name_idx: u32!(e)                                   >>
            (MethodIdItem { class_idx, proto_idx, name_idx })
        ), size)
);

struct MethodIdItem {
    class_idx: u16,
    proto_idx: u16,
    name_idx: u32
}

named_args!(parse_class_def_items(e: nom::Endianness, size: usize)<&[u8], Vec<ClassDefItem>>,
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
        ), size)
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

named_args!(parse_header(e: nom::Endianness)<&[u8], Header>,
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
