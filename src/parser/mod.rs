mod encoded_value;
mod error;
mod result_types;
mod raw_types;

use self::result_types::*;
use self::raw_types::*;
use self::error::*;
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

    let (buffer, class_def_items) = parse_class_defs(&buffer, &type_id_data_items, &string_data_items, &field_data_items, &data, header.data_off as usize, header.class_defs_size as usize, e)?;

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

fn parse_class_defs<'a>(input: &'a[u8], tidi: &[Rc<TypeIdentifier>], sdi: &[Rc<StringData>],
                        fdi: &[Rc<Field>], data: &'a[u8], data_offset: usize, size: usize, e: nom::Endianness)
                        -> Result<(&'a[u8], Vec<ClassDefinition>), nom::Err<&'a[u8]>> {
    let mut v = Vec::with_capacity(size);
    let (buffer, class_def_items) = parse_class_def_item(&input, e, size)?;
    for class_def_item in class_def_items {
        let class_type = tidi[class_def_item.class_idx as usize].clone();

        let access_flags = AccessFlag::parse(class_def_item.access_flags, AnnotationType::Class);

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

        // class_def_item contains an offset to the start of the annotations structure
        let annotations = if class_def_item.annotations_off == 0 {
            None
        } else {
            let adi_offset = class_def_item.annotations_off as usize - data_offset;
            let (_, adi) = parse_annotations_directory_item(&data[adi_offset..], e)?;
            let class_annotations = if adi.class_annotations_off == 0 {
                None
            } else {
                let (_, set_item) = parse_annotation_set_item(
                    &data[adi.class_annotations_off as usize - data_offset..], e)?;

                let mut class_annotations = vec!();
                // Each entry here is an offset to an annotation_item in the data pool
                for annotation_offset in set_item.entries {
                    // Every annotation item contains a visibility, a type and an annotation
                    let (_, annotation_item) = parse_annotation_item(&data[annotation_offset as usize - data_offset..])?;

                    class_annotations.push(ClassAnnotation {
                        visibility: annotation_item.visibility,
                        type_: tidi[annotation_item.annotation.type_idx as usize].clone(),
                        elements: annotation_item.annotation.elements.into_iter().map(|item| {
                            AnnotationElement {
                                name: sdi[item.name_idx as usize].clone(),
                                value: item.value
                            }
                        }).collect()
                    });
                }

                Some(class_annotations)
            };

            let field_annotations = match adi.fld_annot {
                Some(raw_field_annotations) => {
                    let mut fa = vec!();
                    // convert raw field annotations to sensible ones
                    for rfa in raw_field_annotations {
                        let field_data = fdi[rfa.field_idx as usize].clone();

                        let (_, asi) = parse_annotation_set_item(&data[rfa.annotations_offset as usize - data_offset..], e)?;

                        let mut annotations = vec!();
                        for annot_offset in asi.entries {
                            let (_, ai) = parse_annotation_item(&data[annot_offset as usize - data_offset..])?;
                            annotations.push(ai);
                        }

                        fa.push(FieldAnnotation {
                            field_data,
                            annotations
                        })
                    }
                    Some(fa)
                },
                None => None
            } ;


            // todo: method, parameter annotations


            //TODO
            Some(Annotations {
                class_annotations,
                field_annotations
            })
        };

        let class_data = None;
//        if adi.class_data_off = 0 {
//            let (_, class_data) = parse_class_data_item(&data[- data_offset]);
//        }

        v.push(ClassDefinition {
            class_type, access_flags, superclass,
            interfaces, source_file_name, annotations,
            class_data });
    }

    Ok((buffer, v))
}

// Docs: annotation_item
named!(parse_annotation_item<&[u8], AnnotationItem>,
    peek!(
        do_parse!(
            visibility: map_res!(call!(take_one), Visibility::parse)    >>
            annotation: call!(encoded_value::parse_encoded_annotation_item)    >>
            (AnnotationItem { visibility, annotation })
        )
    )
);

named!(take_one<&[u8], u8>, map!(take!(1), |x| { x[0] }));

fn parse_prototype_data<'a>(input: &'a[u8], data: &'a[u8], sdi: &[Rc<StringData>], tidi: &[Rc<TypeIdentifier>],
                            size: usize, data_offset: usize, e: nom::Endianness) -> Result<(&'a[u8], Vec<Rc<Prototype>>), nom::Err<&'a[u8]>> {

    let mut v = Vec::with_capacity(size);
    let (buffer, id_items) = parse_proto_id_item(&input, e, size)?;
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

        v.push(Rc::new(Prototype {shorty, return_type, parameters}));
    }

    Ok((buffer, v))
}

fn parse_method_data<'a>(input: &'a[u8], sdi: &[Rc<StringData>], tidi: &[Rc<TypeIdentifier>],
                         pdi: &[Rc<Prototype>], size: usize, e: nom::Endianness) -> Result<(&'a[u8], Vec<Method>), nom::Err<&'a[u8]>> {
    let (input, items) = parse_method_id_item(&input, e, size)?;

    Ok((input,
        items.into_iter().map(|item| {
            Method {
                definer: tidi[item.class_idx as usize].clone(),
                prototype: pdi[item.proto_idx as usize].clone(),
                name: sdi[item.name_idx as usize].clone()
            }
        }).collect())
    )
}


fn parse_field_data<'a>(input: &'a[u8], sdi: &[Rc<StringData>], tidi: &[Rc<TypeIdentifier>],
                        size: usize, e: nom::Endianness) -> Result<(&'a[u8], Vec<Rc<Field>>), nom::Err<&'a[u8]>> {
    let (input, items) = parse_field_id_item(&input, e, size)?;

    Ok((input,
        items.into_iter().map(|item| {
            Rc::new(Field {
                definer: tidi[item.class_idx as usize].clone(),
                type_: tidi[item.type_idx as usize].clone(),
                name: sdi[item.name_idx as usize].clone()
            })
        }).collect())
    )
}

fn parse_type_data<'a>(input: &'a[u8], e: nom::Endianness, size: usize, sdi: &[Rc<StringData>]) -> Result<(&'a[u8], Vec<Rc<TypeIdentifier>>), nom::Err<&'a[u8]>> {
    let (buffer, idxs) = parse_u32_list(&input, e, size)?;
    Ok((buffer, idxs.into_iter()
        .map(|idx| Rc::new(TypeIdentifier { descriptor: sdi[idx as usize].clone() }))
        .collect()
    ))
}

fn parse_string_data<'a>(input: &'a[u8], header: &Header, data: &'a[u8], e: nom::Endianness)
                         -> Result<(&'a[u8], Vec<Rc<StringData>>), nom::Err<&'a[u8]>> {
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

// Length of uleb128 value is determined by the
pub fn determine_uleb128_length(input: &[u8]) -> usize {
    input.iter()
        .take_while(|byte| (*byte & 0x80) != 0)
        .count()
        + 1
}

named!(parse_string_data_item<&[u8], StringData>,
    peek!(
        do_parse!(
            // uleb128 values are 1-5 bytes long - determine how long it is so we can parse the item
            uleb_len: peek!(map!(take!(5), determine_uleb128_length))               >>
            utf16_size: map_res!(take!(uleb_len), read_uleb128)                     >>
            data: map!(
                    map_res!(
                        take_until_and_consume!("\0"), str::from_utf8),
                    str::to_string)                                                 >>
            (StringData { utf16_size, data })
    ))
);

named!(parse_uleb128<&[u8], u64>,
    do_parse!(
        len: peek!(map!(take!(5), determine_uleb128_length))    >>
        value: map_res!(take!(len), read_uleb128)          >>
        (value)
    )
);

// nom gives us immutable byte slices, but the leb128 library requires mutable slices
// No syntactically valid way to convert the two inside the macro so we'll make a wrapper function
fn read_uleb128(input: &[u8]) -> Result<u64, leb128::read::Error> {
    leb128::read::unsigned(&mut (input.clone()))
}

named_args!(parse_u32_list(e: nom::Endianness, size: usize)<&[u8], Vec<u32>>, count!(u32!(e), size));

// Docs: map_list
named_args!(parse_map_list(e: nom::Endianness)<&[u8], RawMapList>,
    peek!(
        do_parse!(
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
    )
);

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
named_args!(parse_proto_id_item(e: nom::Endianness, size: usize)<&[u8], Vec<RawPrototype>>,
    count!(
        do_parse!(
            shorty_idx: u32!(e)         >>
            return_type_idx: u32!(e)    >>
            parameters_off: u32!(e)     >>
            (RawPrototype { shorty_idx, return_type_idx, parameters_off })
        ), size)
);

// Docs: field_id_item
named_args!(parse_field_id_item(e: nom::Endianness, size: usize)<&[u8], Vec<RawField>>,
    count!(
        do_parse!(
            class_idx: u16!(e)                                  >>
            type_idx: u16!(e)                                   >>
            name_idx: u32!(e)                                   >>
            (RawField { class_idx, type_idx, name_idx })
        ), size)
);

// Docs: method_id_item
named_args!(parse_method_id_item(e: nom::Endianness, size: usize)<&[u8], Vec<RawMethod>>,
    count!(
        do_parse!(
            class_idx: u16!(e)                                  >>
            proto_idx: u16!(e)                                  >>
            name_idx: u32!(e)                                   >>
            (RawMethod { class_idx, proto_idx, name_idx })
        ), size)
);

named_args!(parse_class_def_item(e: nom::Endianness, size: usize)<&[u8], Vec<RawClassDefinition>>,
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

named_args!(parse_header(e: nom::Endianness)<&[u8], Header>,
    do_parse!(
        // Little bit of magic at the start
        tag!(DEX_FILE_MAGIC)                >>
        // Followed by the version (0380 for example)
        // TODO: convert these to digits and stringify them
        // TODO: just take(4)
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

// Docs: annotation_set_item
named_args!(parse_annotation_set_item(e: nom::Endianness)<&[u8], RawAnnotationSetItem>,
    peek!(
        do_parse!(
            size: u32!(e)                               >>
            entries: count!(call!(parse_annotation_offset_item, e), size as usize)     >>
            (RawAnnotationSetItem { size, entries })
        )
    )
);

// Docs: annotation_offset_item
named_args!(parse_annotation_offset_item(e: nom::Endianness)<&[u8], u32>, u32!(e));

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
            0x0000 => Ok(MapListItemType::HeaderItem),
            0x0001 => Ok(MapListItemType::StringIdItem),
            0x0002 => Ok(MapListItemType::TypeIdItem),
            0x0003 => Ok(MapListItemType::ProtoIdItem),
            0x0004 => Ok(MapListItemType::FieldIdItem),
            0x0005 => Ok(MapListItemType::MethodIdItem),
            0x0006 => Ok(MapListItemType::ClassDefItem),
            0x0007 => Ok(MapListItemType::CallSiteIdItem),
            0x0008 => Ok(MapListItemType::MethodHandleItem),
            0x1000 => Ok(MapListItemType::MapList),
            0x1001 => Ok(MapListItemType::TypeList),
            0x1002 => Ok(MapListItemType::AnnotationSetRefList),
            0x1003 => Ok(MapListItemType::AnnotationSetItem),
            0x2000 => Ok(MapListItemType::ClassDataItem),
            0x2001 => Ok(MapListItemType::CodeItem),
            0x2002 => Ok(MapListItemType::StringDataItem),
            0x2003 => Ok(MapListItemType::DebugInfoItem),
            0x2004 => Ok(MapListItemType::AnnotationItem),
            0x2005 => Ok(MapListItemType::EncodedArrayItem),
            0x2006 => Ok(MapListItemType::AnnotationsDirectoryItem),
            _ => Err(ParserErr::from(format!("No type code found for map list item 0x{:0X}", value)))
        }
    }
}

impl AccessFlag {
    fn parse(value: u32, type_: AnnotationType) -> Vec<Self> {
        let mut v = vec!();

        // Break the integer into component bytes
        let bytes = [
            ((value >> 24) & 0xFF) as u8,
            ((value >> 16) & 0xFF) as u8,
            ((value >> 8) & 0xFF) as u8,
            (value & 0xFF) as u8,
        ];

        let bits = bit_vec::BitVec::from_bytes(&bytes);
        // First byte
        if Some(true) == bits.get(0) {
            v.push(AccessFlag::ACC_PUBLIC);
        }
        if Some(true) == bits.get(1) {
            v.push(AccessFlag::ACC_PRIVATE);
        }
        if Some(true) == bits.get(2) {
            v.push(AccessFlag::ACC_PROTECTED);
        }
        if Some(true) == bits.get(3) {
            v.push(AccessFlag::ACC_STATIC);
        }
        if Some(true) == bits.get(4) {
            v.push(AccessFlag::ACC_FINAL);
        }
        if Some(true) == bits.get(5) {
            v.push(AccessFlag::ACC_SYNCHRONIZED);
        }
        if Some(true) == bits.get(6) {
            if type_ == AnnotationType::Field {
                v.push(AccessFlag::ACC_VOLATILE);
            } else if type_ == AnnotationType::Method {
                v.push(AccessFlag::ACC_BRIDGE);
            }
        }
        if Some(true) == bits.get(7) {
            if type_ == AnnotationType::Field {
                v.push(AccessFlag::ACC_TRANSIENT);
            } else if type_ == AnnotationType::Method {
                v.push(AccessFlag::ACC_VARARGS);
            }
        }

        // Second byte
        if Some(true) == bits.get(8) {
            v.push(AccessFlag::ACC_NATIVE);
        }
        if Some(true) == bits.get(9) {
            v.push(AccessFlag::ACC_INTERFACE);
        }
        if Some(true) == bits.get(10) {
            v.push(AccessFlag::ACC_ABSTRACT);
        }
        if Some(true) == bits.get(11) {
            v.push(AccessFlag::ACC_STRICT);
        }
        if Some(true) == bits.get(12) {
            v.push(AccessFlag::ACC_SYNTHETIC);
        }
        if Some(true) == bits.get(13) {
            v.push(AccessFlag::ACC_ANNOTATION);
        }
        if Some(true) == bits.get(14) {
            v.push(AccessFlag::ACC_ENUM);
        }
        if Some(true) == bits.get(15) {
            v.push(AccessFlag::UNUSED);
        }
        if Some(true) == bits.get(16) {
            v.push(AccessFlag::ACC_CONSTRUCTOR);
        }
        // Third byte
        if Some(true) == bits.get(17) {
            v.push(AccessFlag::ACC_DECLARED_SYNCHRONIZED);
        }

        // TODO: some kind of assert here

        v
    }
}