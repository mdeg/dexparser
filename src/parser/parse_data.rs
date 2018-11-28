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
        })).collect::<Vec<_>>();

    let methods = raw.method_id_items.into_iter()
        .map(|i| Rc::new(Method {
            definer: ti[i.class_idx as usize].clone(),
            prototype: pro[i.proto_idx as usize].clone(),
            name: sd[i.name_idx as usize].clone()
        })).collect::<Vec<_>>();

    let class_def_items = transform_class_defs(&raw.data, off, &raw.class_def_items, &ti, &sd,
                                               &fields, &methods, header.endianness)?.1;

    Ok(DexFile {
        header,
        string_data: sd,
        type_identifiers: ti,
        prototypes: pro,
        fields,
        methods,
        class_def_items
    })
}

fn transform_annotations<'a>(data: &'a[u8], off: usize, data_off: usize, sd: &[Rc<StringData>],
                             ti: &[Rc<TypeIdentifier>], fi: &[Rc<Field>], mi: &[Rc<Method>],
                             e: nom::Endianness) -> nom::IResult<&'a[u8], Annotations> {

    let adi = parse_annotations_directory_item(&data[off - data_off..], e)?.1;

    let class_annotations = if adi.class_annotations_off == 0 {
        None
    } else {
        let set_item = parse_annotation_set_item(&data[adi.class_annotations_off as usize - data_off..], e)?.1;

        let mut class_annotations = vec!();
        // Each entry here is an offset to an annotation_item in the data pool
        for annotation_offset in set_item.entries {
            // Every annotation item contains a visibility, a type and an annotation
            let annotation_item = parse_annotation_item(&data[annotation_offset as usize - data_off..])?.1;

            class_annotations.push(ClassAnnotation {
                visibility: annotation_item.visibility,
                type_: ti[annotation_item.annotation.type_idx as usize].clone(),
                elements: annotation_item.annotation.elements.into_iter().map(|i| {
                    AnnotationElement {
                        name: sd[i.name_idx as usize].clone(),
                        value: i.value
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
                fa.push(FieldAnnotation {
                    field_data: fi[rfa.field_idx as usize].clone(),
                    annotations: parse_annotations(&data, rfa.annotations_offset as usize, data_off, e)?.1
                })
            }
            Some(fa)
        },
        None => None
    };

    let method_annotations = match adi.mtd_annot {
        Some(raw_method_annotations) => {
            let mut ma = vec!();
            for rma in raw_method_annotations {
                ma.push(MethodAnnotation {
                    method: mi[rma.method_idx as usize].clone(),
                    annotations: parse_annotations(&data, rma.annotations_offset as usize, data_off, e)?.1
                })
            }
            Some(ma)
        },
        None => None
    };

    let parameter_annotations = match adi.prm_annot {
        Some(raw_parameter_annotations) => {
            let mut pa = vec!();
            for rpa in raw_parameter_annotations {
                let asrl = parse_annotation_set_ref_list(&data[rpa.annotations_offset as usize - data_off..], e)?.1;

                for annot_set_offset in asrl.entries {
                    if annot_set_offset != 0 {
                        pa.push(Some(ParameterAnnotation {
                            method: mi[rpa.method_idx as usize].clone(),
                            annotations: parse_annotations(&data, annot_set_offset as usize, data_off, e)?.1
                        }))
                    }
                }
            }
            Some(pa)
        },
        None => None
    };

    Ok((data, Annotations {
        class_annotations,
        field_annotations,
        method_annotations,
        parameter_annotations
    }))
}

fn parse_annotations(data: &[u8], off: usize, data_off: usize, e: nom::Endianness) -> nom::IResult<&[u8], Vec<AnnotationItem>> {
    let mut annotations = vec!();
    let asi = parse_annotation_set_item(&data[off - data_off..], e)?.1;
    for annot_offset in asi.entries {
        annotations.push(parse_annotation_item(&data[annot_offset as usize - data_off..])?.1);
    }
    Ok((data, annotations))
}

fn transform_class_defs<'a>(data: &'a[u8], data_off: usize, cdis: &[RawClassDefinition], ti: &[Rc<TypeIdentifier>],
                            sd: &[Rc<StringData>], fi: &[Rc<Field>], mtd: &[Rc<Method>],
                            e: nom::Endianness) -> nom::IResult<&'a[u8], Vec<ClassDefinition>> {

    let mut v = Vec::with_capacity(cdis.len());

    for cdi in cdis {
        let class_type = ti[cdi.class_idx as usize].clone();

        let access_flags = AccessFlag::parse(cdi.access_flags, AnnotationType::Class);

        let superclass = if cdi.superclass_idx == NO_INDEX {
            None
        } else {
            Some(ti[cdi.superclass_idx as usize].clone())
        };

        let interfaces = if cdi.interfaces_off == 0 {
            None
        } else {
            Some(parse_type_list(&data[cdi.interfaces_off as usize ..], e)?
                .1
                .list
                .into_iter()
                .map(|idx| ti[idx as usize].clone())
                .collect())
        };

        let annotations = if cdi.annotations_off == 0 {
            None
        } else {
            Some(transform_annotations(&data, cdi.annotations_off as usize, data_off, &sd, &ti, &fi, &mtd, e)?.1)
        };

        let source_file_name = if cdi.source_file_idx == NO_INDEX {
            None
        } else {
            Some(sd[cdi.source_file_idx as usize].clone())
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

    Ok((data, v))
}

// Docs: string_data
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

// Docs: annotation_set_ref_list
named_args!(parse_annotation_set_ref_list(e: nom::Endianness)<&[u8], RawAnnotationSetRefList>,
    peek!(
        do_parse!(
            size: u32!(e)   >>
            entries: count!(call!(parse_annotation_set_ref_item, e), size as usize)     >>
            (RawAnnotationSetRefList { size, entries })
        )
    )
);

// Docs: annotation_set_ref_item
named_args!(parse_annotation_set_ref_item(e: nom::Endianness)<&[u8], u32>, peek!(u32!(e)));

// Docs: annotation_offset_item
named_args!(parse_annotation_offset_item(e: nom::Endianness)<&[u8], u32>, peek!(u32!(e)));

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