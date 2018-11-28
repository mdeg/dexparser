use ::std::rc::Rc;
use super::raw_types::*;
use super::result_types::*;
use super::*;

fn transform_string_id_items<'a>(data: &'a[u8], sdi: &[u32], off: usize) -> nom::IResult<&'a[u8], Vec<Rc<StringData>>> {
    let mut v = vec!();
    for offset in sdi {
        v.push(Rc::new(parse_string_data_item(&data[*offset as usize - off..])?.1));
    }
    Ok((data, v))
}

fn transform_header(raw: RawHeader, e: nom::Endianness) -> Result<Header, ParserErr> {
    Ok(Header {
        version: String::from_utf8(raw.version.to_vec())?,
        checksum: raw.checksum.to_string(),
        signature: raw.signature,
        file_size: raw.file_size,
        endianness: e
    })
}

fn transform_prototype_id_items<'a>(data: &'a[u8], proto_ids: &[RawPrototype], sd: &[Rc<StringData>],
                                    ti: &[Rc<TypeIdentifier>], off: usize, e: nom::Endianness) -> nom::IResult<&'a[u8], Vec<Rc<Prototype>>> {
    let mut v = vec!();
    for item in proto_ids {
        let shorty = sd[item.shorty_idx as usize].clone();
        let return_type = ti[item.return_type_idx as usize].clone();

        let parameters = if item.parameters_off == 0 {
            None
        } else {
            Some(parse_type_list(&data[item.parameters_off as usize - off..], e)?.1
                .list
                .into_iter()
                .map(|idx| ti[idx as usize].clone())
                .collect())
        };

        v.push(Rc::new(Prototype {shorty, return_type, parameters} ));
    }

    Ok((data, v))
}

pub fn transform_dex_file<'a>(raw: RawDexFile, e: nom::Endianness) -> Result<DexFile, ParserErr> {

    // Offsets are given, but we only have the data blob here, so we'll need to do some math
    let off = raw.header.data_off as usize;

    let header = transform_header(raw.header, e)?;

    let sd = transform_string_id_items(&raw.data, &raw.string_id_items, off)?.1;

    let ti = raw.type_id_items.into_iter()
        .map(|i| Rc::new(TypeIdentifier { descriptor: sd[i as usize].clone() })).collect::<Vec<_>>();

    let pro = transform_prototype_id_items(&raw.data, &raw.proto_id_items, &sd, &ti, off, header.endianness)?.1;

    let fields = raw.field_id_items.into_iter()
        .map(|i| Rc::new(Field {
            definer: ti[i.class_idx as usize].clone(),
            type_: ti[i.type_idx as usize].clone(),
            name: sd[i.name_idx as usize].clone()
        })).collect();

    let methods = raw.method_id_items.into_iter()
        .map(|i| Method {
            definer: ti[i.class_idx as usize].clone(),
            prototype: pro[i.proto_idx as usize].clone(),
            name: sd[i.name_idx as usize].clone()
        }).collect();

    Ok(DexFile {
        header,
        string_data: sd,
        type_identifiers: ti,
        prototypes: pro,
        fields,
        methods,
        class_def_items: vec!()
    })
}

//
//fn parse_class_defs<'a>(input: &'a[u8], tidi: &[Rc<TypeIdentifier>], sdi: &[Rc<StringData>],
//                        fdi: &[Rc<Field>], data: &'a[u8], data_offset: usize, size: usize, e: nom::Endianness)
//                        -> Result<(&'a[u8], Vec<ClassDefinition>), nom::Err<&'a[u8]>> {
//    let mut v = Vec::with_capacity(size);
//    let (buffer, class_def_items) = parse_class_def_item(&input, e, size)?;
//    for class_def_item in class_def_items {
//        let class_type = tidi[class_def_item.class_idx as usize].clone();
//
//        let access_flags = AccessFlag::parse(class_def_item.access_flags, AnnotationType::Class);
//
//        let superclass = if class_def_item.superclass_idx == NO_INDEX {
//            None
//        } else {
//            Some(tidi[class_def_item.superclass_idx as usize].clone())
//        };
//
//        let interfaces = if class_def_item.interfaces_off == 0 {
//            None
//        } else {
//            Some(parse_type_list(&data[class_def_item.interfaces_off as usize - data_offset..], e)?
//                .1
//                .list
//                .into_iter()
//                .map(|idx| tidi[idx as usize].clone())
//                .collect())
//        };
//
//        let source_file_name = if class_def_item.source_file_idx == NO_INDEX {
//            None
//        } else {
//            Some(sdi[class_def_item.source_file_idx as usize].clone())
//        };
//
//        // class_def_item contains an offset to the start of the annotations structure
//        let annotations = if class_def_item.annotations_off == 0 {
//            None
//        } else {
//            let adi_offset = class_def_item.annotations_off as usize - data_offset;
//            let (_, adi) = parse_annotations_directory_item(&data[adi_offset..], e)?;
//            let class_annotations = if adi.class_annotations_off == 0 {
//                None
//            } else {
//                let (_, set_item) = parse_annotation_set_item(
//                    &data[adi.class_annotations_off as usize - data_offset..], e)?;
//
//                let mut class_annotations = vec!();
//                // Each entry here is an offset to an annotation_item in the data pool
//                for annotation_offset in set_item.entries {
//                    // Every annotation item contains a visibility, a type and an annotation
//                    let (_, annotation_item) = parse_annotation_item(&data[annotation_offset as usize - data_offset..])?;
//
//                    class_annotations.push(ClassAnnotation {
//                        visibility: annotation_item.visibility,
//                        type_: tidi[annotation_item.annotation.type_idx as usize].clone(),
//                        elements: annotation_item.annotation.elements.into_iter().map(|item| {
//                            AnnotationElement {
//                                name: sdi[item.name_idx as usize].clone(),
//                                value: item.value
//                            }
//                        }).collect()
//                    });
//                }
//
//                Some(class_annotations)
//            };
//
//            let field_annotations = match adi.fld_annot {
//                Some(raw_field_annotations) => {
//                    let mut fa = vec!();
//                    // convert raw field annotations to sensible ones
//                    for rfa in raw_field_annotations {
//                        let field_data = fdi[rfa.field_idx as usize].clone();
//
//                        let (_, asi) = parse_annotation_set_item(&data[rfa.annotations_offset as usize - data_offset..], e)?;
//
//                        let mut annotations = vec!();
//                        for annot_offset in asi.entries {
//                            let (_, ai) = parse_annotation_item(&data[annot_offset as usize - data_offset..])?;
//                            annotations.push(ai);
//                        }
//
//                        fa.push(FieldAnnotation {
//                            field_data,
//                            annotations
//                        })
//                    }
//                    Some(fa)
//                },
//                None => None
//            } ;
//
//
//            // todo: method, parameter annotations
//
//
//            //TODO
//            Some(Annotations {
//                class_annotations,
//                field_annotations
//            })
//        };
//
//        let class_data = None;
////        if adi.class_data_off = 0 {
////            let (_, class_data) = parse_class_data_item(&data[- data_offset]);
////        }
//
//        v.push(ClassDefinition {
//            class_type, access_flags, superclass,
//            interfaces, source_file_name, annotations,
//            class_data });
//    }
//
//    Ok((buffer, v))
//}


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