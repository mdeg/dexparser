use std::rc::Rc;

#[derive(Debug, PartialEq)]
pub struct DexFile {
    pub header: super::Header,
    pub file_data: DexFileData,
    pub classes: Vec<ClassDefinition>
    /* TODO: parse call site items
        pub call_site_items: Vec<CallSiteItem>
    */
}

#[derive(Debug, PartialEq)]
pub struct DexFileData {
    pub string_data: Vec<Rc<String>>,
    pub type_identifiers: Vec<Rc<String>>,
    pub prototypes: Vec<Rc<Prototype>>,
    pub fields: Vec<Rc<Field>>,
    pub methods: Vec<Rc<Method>>
}

#[derive(Debug, PartialEq)]
pub struct CallSiteItem {
    pub method_handle: Rc<Method>,
    pub method_name: Rc<String>,
    pub method_type: Rc<Prototype>,
    pub constant_values: Vec<EncodedValue>
}

#[derive(Debug, PartialEq)]
pub struct Header {
    pub version: i32,
    pub checksum: String,
    pub signature: [u8; 20],
    pub file_size: u32,
    pub endianness: nom::Endianness
}

#[derive(Debug, PartialEq)]
pub struct Prototype {
    pub shorty: Rc<String>,
    pub return_type: Rc<String>,
    pub parameters: Vec<Rc<String>>
}

#[derive(Debug, PartialEq)]
pub struct Field {
    pub definer: Rc<String>,
    pub type_: Rc<String>,
    pub name: Rc<String>
}

#[derive(Debug, PartialEq)]
pub struct Method {
    pub definer: Rc<String>,
    pub prototype: Rc<Prototype>,
    pub name: Rc<String>
}

#[derive(Debug, PartialEq)]
pub struct ClassAnnotation {
    pub visibility: Visibility,
    pub type_: Rc<String>,
    pub elements: Vec<AnnotationElement>
}

#[derive(Debug, PartialEq, Clone)]
pub struct AnnotationElement {
    pub name: Rc<String>,
    pub value: EncodedValue
}

#[derive(Debug, PartialEq)]
pub struct ClassDefinition {
    pub class_type: Rc<String>,
    pub access_flags: Vec<AccessFlag>,
    pub superclass: Option<Rc<String>>,
    pub interfaces: Vec<Rc<String>>,
    pub source_file_name: Option<Rc<String>>,
    pub annotations: Option<Annotations>,
    pub class_data: Option<ClassData>,
    pub static_values: Vec<EncodedValue>
}

#[derive(Debug, PartialEq)]
pub struct Annotations {
    pub class_annotations: Vec<ClassAnnotation>,
    pub field_annotations: Vec<FieldAnnotation>,
    pub method_annotations: Vec<MethodAnnotation>,
    pub parameter_annotations: Vec<ParameterAnnotation>
}

#[derive(Debug, PartialEq)]
pub struct ClassData {
    pub static_fields: Vec<EncodedField>,
    pub instance_fields: Vec<EncodedField>,
    pub direct_methods: Vec<EncodedMethod>,
    pub virtual_methods: Vec<EncodedMethod>
}

#[derive(Debug, PartialEq)]
pub struct EncodedField {
    pub field: Rc<Field>,
    pub access_flags: Vec<AccessFlag>
}

#[derive(Debug, PartialEq)]
pub struct EncodedMethod {
    pub method: Rc<Method>,
    pub access_flags: Vec<AccessFlag>,
    pub code: Option<Code>
}

#[derive(Debug, PartialEq)]
pub struct MethodAnnotation {
    pub method: Rc<Method>,
    pub annotations: Vec<AnnotationItem>
}

#[derive(Debug, PartialEq)]
pub struct ParameterAnnotation {
    pub method: Rc<Method>,
    pub annotations: Vec<AnnotationItem>
}

#[derive(Debug, PartialEq)]
pub struct FieldAnnotation {
    pub field_data: Rc<Field>,
    pub annotations: Vec<AnnotationItem>
}

#[derive(Debug, PartialEq, Clone)]
pub struct AnnotationItem {
    pub visibility: Visibility,
    pub type_: Rc<String>,
    pub annotations: Vec<AnnotationElement>
}

#[derive(Debug, PartialEq, Clone)]
pub enum Visibility {
    BUILD,
    RUNTIME,
    SYSTEM
}

// Docs: code_item
#[derive(Debug, PartialEq)]
pub struct Code {
    // number of registers used by this code
    pub registers_size: u16,
    // number of words of incoming arguments
    pub ins_size: u16,
    // number of words of outgoing argument space
    pub outs_size: u16,
    pub debug_info: Option<DebugInfo>,
    pub insns: Vec<u16>,
    pub tries: Vec<TryItem>,
    pub handlers: Vec<EncodedCatchHandler>
}

// Docs: try_item
#[derive(Debug, PartialEq)]
pub struct TryItem {
    pub code_units: Vec<u16>,
    pub handler: EncodedCatchHandler
}

// Docs: encoded_catch_handler
#[derive(Debug, PartialEq)]
pub struct EncodedCatchHandler {
    pub handlers: Vec<EncodedTypeAddrPair>,
    // bytecode
    // only present if size is non-positive
    pub catch_all_addr: Option<u32>
}

// Docs: encoded_type_addr_pair
#[derive(Debug, PartialEq)]
pub struct EncodedTypeAddrPair {
    // index into type_ids list for the type of exception to catch
    pub type_: Rc<String>,
    // bytecode address of associated exception handler
    pub addr: u32
}

// Docs: debug_info_item
#[derive(Debug, PartialEq)]
pub struct DebugInfo {
    pub line_start: u32,
    pub parameter_names: Vec<i32>,
    pub bytecode: Vec<DebugItemBytecodes>
}

#[derive(Debug, PartialEq, Clone)]
pub enum EncodedValue {
    Byte(u8),
    Short(i16),
    Char(u16),
    Int(i32),
    Long(i64),
    Float(f32),
    Double(f64),
    MethodType(Rc<Prototype>),
    MethodHandle(Rc<Method>),
    String(Rc<String>),
    Type(Rc<String>),
    Field(Rc<Field>),
    Method(Rc<Method>),
    Enum(Rc<Field>),
    Array(Vec<EncodedValue>),
    Annotation(EncodedAnnotationItem),
    Null,
    Boolean(bool)
}

#[derive(Debug, PartialEq, Clone)]
pub struct EncodedAnnotationItem {
    pub type_: Rc<String>,
    pub values: Vec<AnnotationElement>
}

//noinspection RsEnumVariantNaming
#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq)]
pub enum DebugItemBytecodes {
    DBG_END_SEQUENCE,
    DBG_ADVANCE_PC,
    DBG_ADVANCE_LINE,
    DBG_START_LOCAL,
    DBG_START_LOCAL_EXTENDED,
    DBG_END_LOCAL,
    DBG_RESTART_LOCAL,
    DBG_SET_PROLOGUE_END,
    DBG_SET_EPILOGUE_BEGIN,
    DBG_SET_FILE,
    SPECIAL_OPCODE(u8)
}

//noinspection RsEnumVariantNaming
#[allow(non_camel_case_types)]
#[derive(PartialEq, Debug)]
pub enum AccessFlag {
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