// Raw type of the DEX file
//
#[derive(Debug)]
pub struct RawDexFile {
    // Docs: header_item
    pub header: RawHeader,
    // Docs: string_id_item
    pub string_id_items: Vec<u32>,
    // Docs: type_id_item
    pub type_id_items: Vec<u32>,
    // Docs: proto_id_item
    pub proto_id_items: Vec<RawPrototype>,
    // Docs: field_id_item
    pub field_id_items: Vec<RawField>,
    // Docs: method_id_item
    pub method_id_items: Vec<RawMethod>,
    // Docs: class_def_item
    pub class_def_items: Vec<RawClassDefinition>,
    // Docs: call_site_item
    // New in version 03x
    pub call_site_idxs: Option<Vec<u32>>,
    // Docs: method_handle_item
    pub method_handle_idxs: Option<Vec<RawMethodHandleItem>>,
    // Docs: data
    pub data: Vec<u8>,
    // Docs: link_data
    pub link_data: Option<Vec<u8>>
}

#[derive(Debug)]
pub struct RawHeader {
    // DEX file version
    pub version: [u8; 4],
    // adler32 checksum of the rest of the file (everything except the magic, version, and this)
    pub checksum: u32,
    // SHA-1 hash of the rest of the file
    pub signature: [u8; 20],
    // Size of the entire file in bytes
    pub file_size: u32,
    // Size of the header in bytes
    pub header_size: u32,
    // Tag indicating little-endian or big-endian
    pub endian_tag: u32,
    // Size of the link section (or 0 if not linked)
    pub link_size: u32,
    // Offset into the link section (or 0 if not linked)
    pub link_off: u32,
    // Offset from the start of the file to the map item
    pub map_off: u32,
    // Number of string IDs
    pub string_ids_size: u32,
    // Offset string IDs begin at
    pub string_ids_off: u32,
    // Number of type IDs
    pub type_ids_size: u32,
    // Offset type IDs begin at
    pub type_ids_off: u32,
    // Number of prototypes
    pub proto_ids_size: u32,
    // Offset prototypes begin at
    pub proto_ids_off: u32,
    // Number of field identifiers
    pub field_ids_size: u32,
    // Offset field identifiers begin at
    pub field_ids_off: u32,
    // Number of method identifiers
    pub method_ids_size: u32,
    // Offset method identifiers begin at
    pub method_ids_off: u32,
    // Number of class defintions
    pub class_defs_size: u32,
    // Offset class definitions begin at
    pub class_defs_off: u32,
    // Size of the 'data' blob in bytes
    pub data_size: u32,
    // Offset the 'data' blob begins at
    pub data_off: u32
}

#[derive(Debug)]
pub struct RawClassDataItem {
    pub static_fields_size: u64,
    pub instance_fields_size: u64,
    pub direct_methods_size: u64,
    pub virtual_methods_size: u64,
    pub static_fields: Vec<RawEncodedField>,
    pub instance_fields: Vec<RawEncodedField>,
    pub direct_methods: Vec<RawEncodedMethod>,
    pub virtual_methods: Vec<RawEncodedMethod>
}

#[derive(Debug)]
pub struct RawEncodedField {
    pub field_idx_diff: u64,
    pub access_flags: u64
}

#[derive(Debug)]
pub struct RawEncodedMethod {
    pub method_idx_diff: u64,
    pub access_flags: u64,
    pub code_off: u64
}

#[derive(Debug)]
pub struct RawAnnotations {
    pub class_annotations_off: u32,
    pub fld_annot: Option<Vec<RawFieldAnnotation>>,
    pub mtd_annot: Option<Vec<RawMethodAnnotation>>,
    pub prm_annot: Option<Vec<RawParameterAnnotation>>
}

#[derive(Debug)]
pub struct RawFieldAnnotation {
    pub field_idx: u32,
    pub annotations_offset: u32
}

#[derive(Debug)]
pub struct RawMethodAnnotation {
    pub method_idx: u32,
    pub annotations_offset: u32
}

#[derive(Debug)]
pub struct RawParameterAnnotation {
    pub method_idx: u32,
    pub annotations_offset: u32
}

// Docs: type_list
#[derive(Debug)]
pub struct RawTypeList {
    // Size of the following list
    pub size: u32,
    // List of indexes into type_id list
    // Docs: type_item
    pub list: Vec<u16>
}

// Docs: annotation_set_item
#[derive(Debug)]
pub struct RawAnnotationSetItem {
    // Size of the following list
    pub size: u32,
    // List of offsets to annotations
    // Docs: annotation_off_item
    pub entries: Vec<u32>
}

// Docs: annotation_set_ref_list
#[derive(Debug)]
pub struct RawAnnotationSetRefList {
    // Size of the following list
    pub size: u32,
    // List of offsets to annotation items
    // Docs: annotation_set_ref_item
    pub entries: Vec<u32>
}

// Docs: method_id_item
#[derive(Debug)]
pub struct RawMethod {
    // Index in the classes list
    pub class_idx: u16,
    // Index in the prototypes list
    pub proto_idx: u16,
    // Index in the string data list
    pub name_idx: u32
}

// Docs: class_def_item
#[derive(Debug)]
pub struct RawClassDefinition {
    pub class_idx: u32,
    pub access_flags: u32,
    pub superclass_idx: u32,
    pub interfaces_off: u32,
    pub source_file_idx: u32,
    pub annotations_off: u32,
    pub class_data_off: u32,
    pub static_values_off: u32
}


#[derive(Debug)]
pub struct RawField {
    pub class_idx: u16,
    pub type_idx: u16,
    pub name_idx: u32
}

// Docs: proto_id_item
#[derive(Debug)]
pub struct RawPrototype {
    // Index into the string IDs list for the descriptor string of this prototype
    pub shorty_idx: u32,
    // Index into the type_ids list for the return type of this prototype
    pub return_type_idx: u32,
    // Offset from start of file into data section containing parameters
    pub parameters_off: u32
}

// Docs: map_list
#[derive(Debug)]
pub struct RawMapList {
    pub size: u32,
    pub list: Vec<RawMapListItem>
}

// Docs: map_list_item
#[derive(Debug)]
pub struct RawMapListItem {
    pub type_: MapListItemType,
    pub unused: u16,
    pub size: u32,
    pub offset: u32
}

// Docs: method_handle_item
#[derive(Debug)]
pub struct RawMethodHandleItem {
    pub type_: u16,
    pub unused_1: u16,
    pub field_or_method_id: u16,
    pub unused_2: u16
}


#[derive(Debug, PartialEq)]
pub enum MapListItemType {
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