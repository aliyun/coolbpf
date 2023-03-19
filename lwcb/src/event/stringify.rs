use byteorder::ByteOrder;

use crate::{
    types::{Type, TypeKind},
    *, builtin::UBuiltin,
};

pub enum ComplexString {
    Simple(String),
    Complex(Vec<ComplexString>),
}

impl ComplexString {

    fn __flatten(self, res: &mut Vec<String>) {
        match self {
            Self::Simple(s) => res.push(s),
            Self::Complex(c) => {
                for x in c {
                    x.__flatten(res);
                }
            }
        }
    }

    pub fn flatten(self) -> Vec<String> {
        let mut res = vec![];
        self.__flatten(&mut res);
        res
    }
}

impl From<String> for ComplexString {
    fn from(val: String) -> Self {
        ComplexString::Simple(val)
    }
}

pub fn stringify(typ: &Type, data: &[u8]) -> ComplexString {
    match &typ.kind {
        TypeKind::U8 => ComplexString::from(data[0].to_string()),
        TypeKind::I8 => ComplexString::from((data[0] as i8).to_string()),
        TypeKind::U16 => ComplexString::from(readu16!(data).to_string()),
        TypeKind::I16 => ComplexString::from(readi16!(data).to_string()),
        TypeKind::U32 => ComplexString::from(readu32!(data).to_string()),
        TypeKind::I32 => ComplexString::from(readi32!(data).to_string()),
        TypeKind::U64 | TypeKind::Ptr(_) => ComplexString::from(readu64!(data).to_string()),
        TypeKind::I64 => ComplexString::from(readi64!(data).to_string()),

        TypeKind::UBuiltin(ub, _) => ComplexString::from(ub.stringify(data)),

        TypeKind::Struct(types) => {
            let mut css = vec![];
            for typ in types {
                css.push(stringify(typ, &data[typ.offset()..]));
            }
            ComplexString::Complex(css)
        }
        _ => todo!("{}", typ),
    }
}
