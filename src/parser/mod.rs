use nom::*;

const DEX_FILE_MAGIC: [u8; 4] = [0x64, 0x65, 0x78, 0x0a];

// Indicates standard (little-endian) encoding
const ENDIAN_CONSTANT: [u8; 4] = [0x12, 0x34, 0x56, 0x78];
// Indicates modified non-standard (big-endian) encoding
const REVERSE_ENDIAN_CONSTANT: [u8; 4] = [0x78, 0x56, 0x34, 0x12];

#[derive(Debug)]
pub struct DexFile<'a> {
    header: Header<'a>
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
        Ok(dexf) => Ok(dexf.1),
        Err(e) => {
//            println!("ERROR: {}", e);
            Err(ParserErr)
        }
    }
}

named_args!(parse_dex_file ( e: nom::Endianness ) <&[u8], DexFile>,
    do_parse!(
        header: apply!(parse_header, e)                     >>
        string_ids: apply!(string_identifier_list, e, header.string_ids_size)       >>

        (DexFile { header })
));

struct StringIdentifierOffsetList {
    // String data offsets
    string_data_offsets: Vec<u32>
}

named_args!(string_identifier_list ( e: nom::Endianness, num: u32 ) <&[u8], StringIdentifierOffsetList>,
    do_parse!(
        string_data_offsets: count!(u32!(e), num as usize) >>
    (StringIdentifierOffsetList { string_data_offsets })
));

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
