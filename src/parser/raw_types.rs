
//static_fields_size 	uleb128 	the number of static fields defined in this item
//instance_fields_size 	uleb128 	the number of instance fields defined in this item
//direct_methods_size 	uleb128 	the number of direct methods defined in this item
//virtual_methods_size 	uleb128 	the number of virtual methods defined in this item
//static_fields 	encoded_field[static_fields_size] 	the defined static fields, represented as a sequence of encoded elements. The fields must be sorted by field_idx in increasing order.
//instance_fields 	encoded_field[instance_fields_size] 	the defined instance fields, represented as a sequence of encoded elements. The fields must be sorted by field_idx in increasing order.
//direct_methods 	encoded_method[direct_methods_size] 	the defined direct (any of static, private, or constructor) methods, represented as a sequence of encoded elements. The methods must be sorted by method_idx in increasing order.
//virtual_methods 	encoded_method[virtual_methods_size] 	the defined virtual (none of static, private, or constructor) methods, represented as a sequence of encoded elements. This list should not include inherited methods unless overridden by the class that this item represents. The methods must be sorted by method_idx in increasing order. The method_idx of a virtual method must not be the same as any direct method.

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


//field_idx_diff 	uleb128 	index into the field_ids list for the identity of this field (includes the name and descriptor), represented as a difference from the index of previous element in the list. The index of the first element in a list is represented directly.
//access_flags 	uleb128 	access flags for the field (public, final, etc.). See "access_flags Definitions" for details.

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

//method_idx_diff 	uleb128 	index into the method_ids list for the identity of this method (includes the name and descriptor), represented as a difference from the index of previous element in the list. The index of the first element in a list is represented directly.
//access_flags 	uleb128 	access flags for the method (public, final, etc.). See "access_flags Definitions" for details.
//code_off 	uleb128 	offset from the start of the file to the code structure for this method, or 0 if this method is either abstract or native. The offset should be to a location in the data section. The format of the data is specified by "code_item" below.

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