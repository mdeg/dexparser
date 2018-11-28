use std::{fmt, rc::Rc};
use super::encoded_value;

#[derive(Debug)]
pub struct DexFile {
    pub header: super::Header,
    pub string_data: Vec<Rc<StringData>>,
    pub type_identifiers: Vec<Rc<TypeIdentifier>>,
    pub prototypes: Vec<Rc<Prototype>>,
    pub fields: Vec<Rc<Field>>,
    pub methods: Vec<Rc<Method>>,
    pub class_def_items: Vec<ClassDefinition>
}

#[derive(Debug)]
pub struct Header {
    pub version: String,
    pub checksum: String,
    pub signature: [u8; 20],
    pub file_size: u32,
    pub endianness: nom::Endianness
}

#[derive(Debug)]
pub struct StringData {
    pub utf16_size: u64,
    pub data: String
}

impl fmt::Display for StringData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.data)
    }
}

#[derive(Debug)]
pub struct TypeIdentifier {
    pub descriptor: Rc<StringData>
}

impl fmt::Display for TypeIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.descriptor)
    }
}

#[derive(Debug)]
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

#[derive(Debug)]
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

#[derive(Debug)]
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

#[derive(Debug)]
pub struct ClassAnnotation {
    pub visibility: Visibility,
    pub type_: Rc<TypeIdentifier>,
    pub elements: Vec<AnnotationElement>
}

#[derive(Debug)]
pub struct AnnotationElement {
    pub name: Rc<StringData>,
    pub value: encoded_value::EncodedValue
}

#[derive(Debug)]
pub struct ClassDefinition {
    pub class_type: Rc<TypeIdentifier>,
    pub access_flags: Vec<AccessFlag>,
    pub superclass: Option<Rc<TypeIdentifier>>,
    pub interfaces: Option<Vec<Rc<TypeIdentifier>>>,
    pub source_file_name: Option<Rc<StringData>>,
    pub annotations: Option<Annotations>,
    pub class_data: Option<ClassData>
}

#[derive(Debug)]
pub struct Annotations {
    pub class_annotations: Option<Vec<ClassAnnotation>>,
    pub field_annotations: Option<Vec<FieldAnnotation>>,
    pub method_annotations: Option<Vec<MethodAnnotation>>,
    pub parameter_annotations: Option<Vec<Option<ParameterAnnotation>>>
}

#[derive(Debug)]
pub struct ClassData {
    pub static_fields: Vec<EncodedField>,
    pub instance_fields: Vec<EncodedField>,
    pub direct_methods: Vec<EncodedMethod>,
    pub virtual_methods: Vec<EncodedMethod>
}

#[derive(Debug)]
pub struct EncodedField {

}

#[derive(Debug)]
pub struct EncodedMethod {

}

#[derive(Debug)]
pub struct MethodAnnotation {
    pub method: Rc<Method>,
    pub annotations: Vec<AnnotationItem>
}

#[derive(Debug)]
pub struct ParameterAnnotation {
    pub method: Rc<Method>,
    pub annotations: Vec<AnnotationItem>
}

#[derive(Debug)]
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

#[derive(Debug)]
pub struct AnnotationItem {
    pub visibility: Visibility,
    // TODO
    pub annotation: encoded_value::RawEncodedAnnotationItem
}

// TODO
//impl fmt::Display for AnnotationItem {
//    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//        write!(f, "Visibility:{}\nAnnotation: {}", self.visibility, self.annotation)
//    }
//}

#[derive(Debug)]
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