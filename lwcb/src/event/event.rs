use std::ffi::CString;
use crate::types::Type;

use super::{
    printer::{parse_fmt, printer},
    stringify, ComplexString,
};

pub struct Event {
    typ: Type,
    fmts: Vec<CString>,
}

impl Event {
    pub fn new(fmt: Option<String>, typ: Type) -> Self {
        Self {
            typ,
            fmts: fmt.map_or_else(|| vec![], |fmt| parse_fmt(fmt)),
        }
    }

    pub fn print(&self, data: &[u8]) {
        printer(&self.fmts, &self.typ, data);
    }

    pub fn stringify(&self, data: &[u8]) -> ComplexString {
        stringify(&self.typ, data)
    }
}
