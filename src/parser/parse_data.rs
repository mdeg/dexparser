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
        signature: String::from_utf8(raw.signature.to_vec())?,
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
    let data = [0x11];
    // TODO: get data from raw
    // Offsets are given, but we only have the data blob here, so we'll need to do some math
    let off = raw.header.data_off as usize;

    let header = transform_header(raw.header, e)?;

    let sd = transform_string_id_items(&data, &raw.string_id_items, off)?.1;

    let ti = raw.type_id_items.into_iter()
        .map(|i| Rc::new(TypeIdentifier { descriptor: sd[i as usize].clone() })).collect::<Vec<_>>();

    let pro = transform_prototype_id_items(&data, &raw.proto_id_items, &sd, &ti, off, header.endianness)?.1;

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

//#[derive(Debug)]
//pub struct DexFile<'a> {
//    pub header: super::Header<'a>,
//    pub string_data_items: Vec<Rc<StringData>>,
//    pub type_id_data_items: Vec<Rc<TypeIdentifier>>,
//    pub proto_id_data_items: Vec<Rc<Prototype>>,
//    pub field_data_items: Vec<Rc<Field>>,
//    pub method_data_items: Vec<Method>,
//    pub class_def_items: Vec<ClassDefinition>
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