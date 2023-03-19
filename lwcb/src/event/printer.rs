use std::ffi::CString;

use crate::{
    types::{Type, TypeKind},
    *,
};
use byteorder::ByteOrder;

fn print<T>(fmt: &CString, val: T) {
    unsafe { libc::printf(fmt.as_ptr(), val) };
}

pub fn print_string(fmt: &CString, val: String) {
    let cstring = CString::new(val).unwrap();
    print(fmt, cstring.as_ptr());
}

pub fn print_number<T>(fmt: &CString, val: T) {
    print(fmt, val)
}

pub fn parse_fmt(fmt: String) -> Vec<CString> {
    let mut is_escape = false;
    let mut fmts = vec![];
    let mut pre = 0;
    for (i, c) in fmt.chars().enumerate() {
        if c == '\\' {
            is_escape = !is_escape;
            continue;
        }
        if !is_escape && c == '%' {
            if i == 0 {
                fmts.push(CString::new("").expect("Failed to create cstring"));
            } else {
                fmts.push(CString::new(&fmt[pre..i]).unwrap());
            }
            pre = i;
            continue;
        }
        is_escape = false;
    }

    fmts.push(CString::new(&fmt[pre..fmt.len()]).unwrap());
    fmts
}

fn __printer(fmt: &CString, typ: &Type, data: &[u8]) {
    log::debug!("fmt: {:?}, type: {}", fmt, typ);
    match &typ.kind {
        TypeKind::U8 => print_number(fmt, data[0]),
        TypeKind::I8 => print_number(fmt, data[0] as i8),
        TypeKind::U16 => print_number(fmt, readu16!(data)),
        TypeKind::I16 => print_number(fmt, readi16!(data)),
        TypeKind::U32 => print_number(fmt, readu32!(data)),
        TypeKind::I32 => print_number(fmt, readi32!(data)),
        TypeKind::U64 | TypeKind::Ptr(_) => print_number(fmt, readu64!(data)),
        TypeKind::I64 => print_number(fmt, readi64!(data)),
        TypeKind::UBuiltin(ub, _) => ub.print(fmt, data),
        _ => todo!("{}", typ),
    }
}

pub fn printer(fmts: &Vec<CString>, typ: &Type, data: &[u8]) {
    if let TypeKind::Struct(types) = &typ.kind {
        print_string(&fmts[0], "".to_owned());
        for (idx, typ) in types[1..].iter().enumerate() {
            __printer(&fmts[idx + 1], typ, &data[typ.offset()..])
        }
    }
}
