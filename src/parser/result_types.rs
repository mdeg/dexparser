use std::{fmt, rc::Rc};
use super::encoded_value;

#[derive(Debug, PartialEq)]
pub struct DexFile {
    pub header: super::Header,
    pub string_data: Vec<Rc<StringData>>,
    pub type_identifiers: Vec<Rc<TypeIdentifier>>,
    pub prototypes: Vec<Rc<Prototype>>,
    pub fields: Vec<Rc<Field>>,
    pub methods: Vec<Rc<Method>>,
    pub class_def_items: Vec<ClassDefinition>
}

#[derive(Debug, PartialEq)]
pub struct Header {
    pub version: String,
    pub checksum: String,
    pub signature: [u8; 20],
    pub file_size: u32,
    pub endianness: nom::Endianness
}

#[derive(Debug, PartialEq)]
pub struct StringData {
    pub utf16_size: u32,
    pub data: String
}

impl fmt::Display for StringData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.data)
    }
}

#[derive(Debug, PartialEq)]
pub struct TypeIdentifier {
    pub descriptor: Rc<StringData>
}

impl fmt::Display for TypeIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.descriptor)
    }
}

#[derive(Debug, PartialEq)]
pub struct Prototype {
    pub shorty: Rc<StringData>,
    pub return_type: Rc<TypeIdentifier>,
    pub parameters: Option<Vec<Rc<TypeIdentifier>>>
}

impl fmt::Display for Prototype {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(p) = &self.parameters {
            // TODO
            write!(f, "shorty: {}\nreturn type: {}\n parameters: {}", self.shorty, self.return_type, "TODO")
        } else {
            write!(f, "shorty: {}\nreturn type: {}\n parameters: -", self.shorty, self.return_type)
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct Field {
    pub definer: Rc<TypeIdentifier>,
    pub type_: Rc<TypeIdentifier>,
    pub name: Rc<StringData>
}

impl fmt::Display for Field {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "definer: {}\ntype: {}\nname: {}", self.definer, self.type_, self.name)
    }
}

#[derive(Debug, PartialEq)]
pub struct Method {
    pub definer: Rc<TypeIdentifier>,
    pub prototype: Rc<Prototype>,
    pub name: Rc<StringData>
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "definer: {}\nprototype: {}\nname: {}", self.definer, self.prototype, self.name)
    }
}

#[derive(Debug, PartialEq)]
pub struct ClassAnnotation {
    pub visibility: Visibility,
    pub type_: Rc<TypeIdentifier>,
    pub elements: Vec<AnnotationElement>
}

#[derive(Debug, PartialEq, Clone)]
pub struct AnnotationElement {
    pub name: Rc<StringData>,
    pub value: encoded_value::EncodedValue
}

#[derive(Debug, PartialEq)]
pub struct ClassDefinition {
    pub class_type: Rc<TypeIdentifier>,
    pub access_flags: Vec<AccessFlag>,
    pub superclass: Option<Rc<TypeIdentifier>>,
    pub interfaces: Option<Vec<Rc<TypeIdentifier>>>,
    pub source_file_name: Option<Rc<StringData>>,
    pub annotations: Option<Annotations>,
    pub class_data: Option<ClassData>,
    pub static_values: Option<encoded_value::EncodedArrayItem>
}

#[derive(Debug, PartialEq)]
pub struct Annotations {
    pub class_annotations: Option<Vec<ClassAnnotation>>,
    pub field_annotations: Option<Vec<FieldAnnotation>>,
    pub method_annotations: Option<Vec<MethodAnnotation>>,
    // TODO: ensure handling situations where this vec is empty
    pub parameter_annotations: Option<Vec<ParameterAnnotation>>
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

// TODO
//impl fmt::Display for FieldAnnotation {
//    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//        write!(f, "Field Data:{}\nAnnotations: {}",
//               self.field_data,
//               self.annotations.iter().fold(String::new(), |x, y| { format!("{}\n{}", x, y)}))
//    }
//}

#[derive(Debug, PartialEq, Clone)]
pub struct AnnotationItem {
    pub visibility: Visibility,
    pub type_: Rc<TypeIdentifier>,
    pub annotations: Vec<AnnotationElement>
}

// TODO
//impl fmt::Display for AnnotationItem {
//    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//        write!(f, "Visibility:{}\nAnnotation: {}", self.visibility, self.annotation)
//    }
//}

#[derive(Debug, PartialEq, Clone)]
pub enum Visibility {
    BUILD,
    RUNTIME,
    SYSTEM
}

impl fmt::Display for Visibility {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Visibility::BUILD => write!(f, "build"),
            Visibility::RUNTIME => write!(f, "runtime"),
            Visibility::SYSTEM => write!(f, "system")
        }
    }
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
    pub tries: Option<Vec<TryItem>>,
    pub handlers: Option<Vec<EncodedCatchHandler>>
}

// Docs: try_item
#[derive(Debug, PartialEq)]
pub struct TryItem {
    pub code_units: Vec<u16>,
    pub handler: Vec<EncodedCatchHandler>
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
    pub type_: Rc<TypeIdentifier>,
    // bytecode address of associated exception handler
    pub addr: u32
}

// Docs: debug_info_item
#[derive(Debug, PartialEq)]
pub struct DebugInfo {
    pub line_start: u32,
    pub parameter_names: Vec<u32>,
    pub bytecode: Vec<DebugItemBytecodes>
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