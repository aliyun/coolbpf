use anyhow::Result;
use btfparse::btf::{Btf, BtfType};
use btfparse::{btf_load, BtfKind, BtfMember, Func};
use libfirm_rs::Mode;
use once_cell::sync::Lazy;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Mutex;

use crate::types::Constant;
use crate::utils::btf::btf_locate_path;

pub struct BtfCache {
    btf: Btf,
    funcs: HashMap<String, u32>,
    char: u32,
    bool: u32,
    u8: u32,
    i8: u32,
    u16: u32,
    i16: u32,
    u32: u32,
    i32: u32,
    u64: u32,
    i64: u32,
}

impl BtfCache {
    pub fn new(path: &str) -> Result<Self> {
        let mut funcs = HashMap::new();
        let mut char = 0;
        let mut bool = 0;
        let mut u8 = 0;
        let mut i8 = 0;
        let mut u16 = 0;
        let mut i16 = 0;
        let mut u32 = 0;
        let mut i32 = 0;
        let mut u64 = 0;
        let mut i64 = 0;

        let btf = Btf::from_file(path)?;
        for (typeid, ty) in btf.types().iter().enumerate() {
            let id = typeid as u32;
            if let BtfType::Func(f) = ty {
                funcs.entry(f.name.clone()).or_insert(id);
            }

            if let BtfType::Int(i) = ty {
                if i.is_bool() {
                    bool = id;
                    log::debug!("found bool type, typeid: {}", id)
                }

                if i.is_char() {
                    char = id;
                }

                if i.is_u8() {
                    u8 = id;
                }

                if i.is_i8() {
                    i8 = id;
                }

                if i.is_u16() {
                    u16 = id;
                }

                if i.is_i16() {
                    i16 = id;
                }

                if i.is_u32() {
                    u32 = id;
                }

                if i.is_i32() {
                    i32 = id;
                }

                if i.is_u64() {
                    u64 = id;
                }

                if i.is_i64() {
                    i64 = id;
                }
            }
        }
        Ok(BtfCache {
            btf: Btf::from_file(path)?,
            funcs,
            char,
            bool,
            u8,
            i8,
            u16,
            i16,
            u32,
            i32,
            u64,
            i64,
        })
    }

    pub fn btf_type_constant(&self, constant: &Constant) -> u32 {
        match constant {
            Constant::Bool(_) => self.bool,
            Constant::Char(_) => self.char,
            Constant::I8(_) => self.i8,
            Constant::U8(_) => self.u8,
            Constant::I16(_) => self.i16,
            Constant::U16(_) => self.u16,
            Constant::I32(_) => self.i32,
            Constant::U32(_) => self.u32,
            Constant::I64(_) => self.i64,
            Constant::U64(_) => self.u64,
        }
    }
}

static GLOBAL_BTF: Lazy<Btf> = Lazy::new(|| btf_load(&btf_locate_path().unwrap()));

pub fn btf_typeid_of_arg(btf: &Btf, func_name: &String, arg_name: &String) -> Option<u32> {
    // for ty in btf.types() {
    //     match ty {
    //         BtfType::Func(f) => {
    //             if Ordering::Equal == f.name.cmp(func_name) {
    //                 match &btf.types()[f.type_id as usize] {
    //                     BtfType::FuncProto(fp) => {
    //                         for para in &fp.params {
    //                             if let Ordering::Equal = para.name.cmp(arg_name) {
    //                                 return Some(para.type_id);
    //                             }
    //                         }
    //                     }
    //                     _ => unimplemented!(),
    //                 }
    //             }
    //         }
    //         _ => continue,
    //     }
    // }

    // None
    todo!()
}

pub fn btf_type_kind(typeid: u32) -> BtfKind {
    (&get_btf!().types()[typeid as usize]).into()
}

pub fn btf_type_name(typeid: u32) -> &'static str {
    // get_btf!().types()[typeid as usize]
    todo!()
}

pub fn btf_get_struct_name(typeid: u32) -> String {
    if let BtfType::Struct(s) = &get_btf!().types()[typeid as usize] {
        return s.name.clone();
    }
    panic!("typeid is not Struct")
}

pub fn btf_get_struct_size(typeid: u32) -> u32 {
    if let BtfType::Struct(s) = &get_btf!().types()[typeid as usize] {
        return s.size;
    }
    panic!("typeid is not Struct")
}

pub fn btf_get_point_to(typeid: u32) -> u32 {
    if let BtfType::Ptr(p) = &get_btf!().types()[typeid as usize] {
        return p.type_id;
    }
    panic!("typeid is not Pointer")
}

pub fn btf_skip_typedef(typeid: u32) -> u32 {
    if let BtfType::Typedef(t) = &get_btf!().types()[typeid as usize] {
        return t.type_id;
    }
    panic!("typeid is not Typedef")
}

pub fn btf_skip_volatile(typeid: u32) -> u32 {
    if let BtfType::Volatile(v) = &get_btf!().types()[typeid as usize] {
        return v.type_id;
    }
    panic!("typeid is not volatile")
}

pub fn btf_skip_const(typeid: u32) -> u32 {
    if let BtfType::Const(c) = &get_btf!().types()[typeid as usize] {
        return c.type_id;
    }
    panic!("typeid is not volatile")
}

// translate constant type into btf type
pub fn btf_type_constant(constant: &Constant) -> u32 {
    // get_btfcache!().btf_type_constant(constant)
    todo!()
}

/// Get func typeid by function name
pub fn btf_find_func(name: &String) -> u32 {
    get_btf!().find_func(name).unwrap()
}

pub fn try_btf_find_func(name: &str) -> Option<u32> {
    get_btf!().find_func(name)
}

pub fn btf_find_funcs_by_typeid(typeid: u32, pos: usize) -> Vec<u32> {
    let mut funcs = vec![];
    for (id, ty) in GLOBAL_BTF.types().iter().enumerate() {
        if let BtfType::Func(f) = ty {
            // todo: resolve type, skip unuseless type
            if let BtfType::FuncProto(fp) = &GLOBAL_BTF.types()[f.type_id as usize] {
                if let Some(param) = fp.params.get(pos) {
                    if param.type_id == typeid {
                        funcs.push(id as u32);
                    }
                }
                continue;
            }
            panic!("wrong func proto")
        }
    }
    funcs
}

pub fn btf_find_funcs_by_typename(name: &str, pointer: usize, pos: usize) -> Vec<u32> {
    let mut typeid = btf_find_struct(name);
    let mut update = false;
    for _ in 0..pointer {
        update = false;
        for (id, ty) in GLOBAL_BTF.types().iter().enumerate() {
            if let BtfType::Ptr(p) = ty {
                if p.type_id == typeid {
                    typeid = id as u32;
                    update = true;
                    break;
                }
            }
        }

        if !update {
            panic!("Failed to target typeid")
        }
    }

    btf_find_funcs_by_typeid(typeid, pos)
}

/// Get all arguments of target function
///
/// return: (name, typeid)
pub fn btf_get_func_args(typeid: u32) -> Vec<(String, u32)> {
    let btf = get_btf!();
    if let BtfType::Func(f) = &btf.types()[typeid as usize] {
        let fpid = f.type_id;
        if let BtfType::FuncProto(fp) = &btf.types()[fpid as usize] {
            let mut ret = vec![];
            for param in &fp.params {
                ret.push((param.name.clone(), param.type_id));
            }
            return ret;
        }
    }
    panic!("typeid is not Func")
}

pub fn btf_get_func_returnty(typeid: u32) -> u32 {
    let btf = get_btf!();
    if let BtfType::Func(f) = &btf.types()[typeid as usize] {
        let fpid = f.type_id;
        if let BtfType::FuncProto(fp) = &btf.types()[fpid as usize] {
            return fp.return_type_id;
        }
    }
    panic!("typeid is not Func")
}

pub fn btf_get_func_argnum(typeid: u32) -> u32 {
    todo!()
}

/// Get function argument typeid by argument's name
///
pub fn btf_find_func_arg_by_name(typeid: u32, name: &String) -> Option<u32> {
    todo!()
}

pub fn btf_get_func_name(typeid: u32) -> String {
    if let BtfType::Func(f) = &get_btf!().types()[typeid as usize] {
        return f.name.clone();
    }
    panic!("typeid is not Func")
}

/// Get function argument typeid by argument's position
///
/// Position counts from 1
pub fn btf_find_func_arg_by_pos(typeid: u32, pos: usize) -> Option<u32> {
    todo!()
}

/// Get function argument typeid by type's name of that argument.
///
/// For example, type's name is sock
pub fn btf_find_func_arg_by_typename(typeid: u32, type_name: &String) -> Option<u32> {
    todo!()
}

pub fn btf_struct_has_bitfield(typeid: u32) -> bool {
    if let BtfType::Struct(s) = &get_btf!().types()[typeid as usize] {
        return s.has_bitfield();
    }
    log::warn!("Expect struct or union, found other type");
    panic!()
}

pub fn btf_find_union_or_struct_member(typeid: u32, name: &str) -> Option<BtfMember> {
    // need to get offset and check if it is bitfield
    if let BtfType::Union(u) = &get_btf!().types()[typeid as usize] {
        for mem in &u.members {
            if let Ordering::Equal = mem.name.as_str().cmp(name) {
                return Some(mem.clone());
            }

            if mem.name.is_empty() {
                // find embedded member
                if let Some(mut find_mem) = btf_find_union_or_struct_member(mem.type_id, name) {
                    find_mem.offset += mem.offset;
                    return Some(find_mem);
                }
            }
        }
    }

    if let BtfType::Struct(s) = &get_btf!().types()[typeid as usize] {
        for mem in &s.members {
            if let Ordering::Equal = mem.name.as_str().cmp(name) {
                return Some(mem.clone());
            }

            if mem.name.is_empty() {
                // find embedded member
                if let Some(mut find_mem) = btf_find_union_or_struct_member(mem.type_id, name) {
                    find_mem.offset += mem.offset;
                    return Some(find_mem);
                }
            }
        }
    }
    return None;
    panic!(
        "Expect struct or union, found other type: {:?}",
        btf_type_kind(typeid)
    );
}

/// Get field typeid from struct or union
pub fn btf_find_struct_member(typeid: u32, name: &str) -> Option<BtfMember> {
    // need to get offset and check if it is bitfield
    if let BtfType::Struct(s) = &get_btf!().types()[typeid as usize] {
        for mem in &s.members {
            if let Ordering::Equal = mem.name.as_str().cmp(name) {
                return Some(mem.clone());
            }

            if mem.name.is_empty() {
                // find embedded member
                if let Some(mut find_mem) = btf_find_union_or_struct_member(mem.type_id, name) {
                    find_mem.offset += mem.offset;
                    return Some(find_mem);
                }
            }
        }
    }
    panic!("Expect struct or union, found other type");
}

pub fn btf_struct_members(typeid: u32) -> Vec<BtfMember> {
    if let BtfType::Struct(s) = &get_btf!().types()[typeid as usize] {
        return s.members.clone();
    }

    panic!("typeid is not struct")
}

pub fn btf_struct_size(typeid: u32) -> u32 {
    if let BtfType::Struct(s) = &get_btf!().types()[typeid as usize] {
        return s.size;
    }
    panic!("{} is not struct", typeid)
}

pub fn btf_type_size(typeid: u32) -> u32 {
    match &get_btf!().types()[typeid as usize] {
        BtfType::Int(i) => {
            return i.size();
        }
        _ => {}
    }

    todo!()
}

pub fn btf_type_mode(typeid: u32) -> Mode {
    match &get_btf!().types()[typeid as usize] {
        BtfType::Int(i) => {
            if i.is_bool() || i.is_char() || i.is_i8() {
                return Mode::ModeBs();
            }

            if i.is_u8() {
                return Mode::ModeBu();
            }

            if i.is_i16() {
                return Mode::ModeHs();
            }

            if i.is_u16() {
                return Mode::ModeHu();
            }

            if i.is_i32() {
                return Mode::ModeIs();
            }

            if i.is_u32() {
                return Mode::ModeIu();
            }

            if i.is_i64() {
                return Mode::ModeLs();
            }

            if i.is_u64() {
                return Mode::ModeLu();
            }
        }
        _ => {}
    }

    todo!()
}

pub fn btf_find_struct(name: &str) -> u32 {
    try_btf_find_struct(name).unwrap()
}

pub fn try_btf_find_struct(name: &str) -> Option<u32> {
    for (typeid, ty) in get_btf!().types().iter().enumerate() {
        if let BtfType::Struct(s) = ty {
            if s.name.as_str().cmp(name) == Ordering::Equal {
                return Some(typeid as u32);
            }
        }
    }
    None
}

/// Get typeid of struct pointer by structure's name
pub fn btf_find_struct_pointer(typeid: u32, name: &String) -> Option<u32> {
    todo!()
}

pub fn btf_type_is_pointer(typeid: u32) -> bool {
    // get_btf!().types()[typeid as usize].is_pointer()
    todo!()
}

pub fn dump_by_typeid(typeid: u32) {
    println!("{:?}", get_btf!().types()[typeid as usize]);
}
// /// short lived
macro_rules! get_btf {
    () => {
        &GLOBAL_BTF
    };
}

// /// short lived
// macro_rules! get_btfcache {
//     () => {
//         GLOBAL_BTF_CACHE.lock().unwrap().as_ref().unwrap()
//     };
// }

pub(crate) use get_btf;
// pub(crate) use get_btfcache;

#[test]
fn test_btf_find_struct() {
    assert!(try_btf_find_struct("pt_regs").is_some());
}
