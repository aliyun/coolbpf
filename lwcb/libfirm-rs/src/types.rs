use crate::{mode::Mode, Ident};
use libfirm_sys::*;
use std::fmt;

#[derive(Clone, Copy, PartialEq)]
pub enum TypeKind {
    Uninitialized,
    Struct,
    Union,
    Class,
    Segment,
    Method,
    Array,
    Pointer,
    Primitive,
    Code,
    Unknown,
}

impl From<u32> for TypeKind {
    fn from(num: u32) -> Self {
        match num {
            0 => TypeKind::Uninitialized,
            1 => TypeKind::Struct,
            2 => TypeKind::Union,
            3 => TypeKind::Class,
            4 => TypeKind::Segment,
            5 => TypeKind::Method,
            6 => TypeKind::Array,
            7 => TypeKind::Pointer,
            8 => TypeKind::Primitive,
            9 => TypeKind::Code,
            _ => TypeKind::Unknown,
        }
    }
}

impl fmt::Display for TypeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TypeKind::Uninitialized => write!(f, "Uninitialized"),
            TypeKind::Struct => write!(f, "Struct"),
            TypeKind::Union => write!(f, "Union"),
            TypeKind::Class => write!(f, "Class"),
            TypeKind::Segment => write!(f, "Segment"),
            TypeKind::Method => write!(f, "Method"),
            TypeKind::Array => write!(f, "Array"),
            TypeKind::Pointer => write!(f, "Pointer"),
            TypeKind::Primitive => write!(f, "Primitive"),
            TypeKind::Code => write!(f, "Code"),
            TypeKind::Unknown => write!(f, "Unknown"),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Type(*mut ir_type);

unsafe impl Sync for Type {}

impl From<*mut ir_type> for Type {
    fn from(ptr: *mut ir_type) -> Self {
        Type(ptr)
    }
}

impl Type {
    pub fn global_type() -> Self {
        Type::new(unsafe { get_glob_type() })
    }

    pub fn kind(&self) -> TypeKind {
        unsafe { get_type_opcode(self.raw()).into() }
    }

    pub fn new(raw: *mut ir_type) -> Self {
        Type(raw)
    }

    pub fn raw(&self) -> *mut ir_type {
        self.0
    }

    pub fn mode(&self) -> Mode {
        unsafe { get_type_mode(self.raw()).into() }
    }

    /// new primitive type
    pub fn new_primitive(mode: &Mode) -> Self {
        Type::new(unsafe { new_type_primitive(mode.raw()) })
    }

    pub fn set_size(&mut self, size: u32) {
        unsafe { set_type_size(self.raw(), size) }
    }

    pub fn size(&self) -> u32 {
        unsafe { get_type_size(self.raw()) }
    }

    pub fn set_align(&mut self, align: u32) {
        unsafe { set_type_alignment(self.raw(), align) }
    }

    /// create pointer type
    pub fn new_pointer(points_to: &Type) -> Self {
        Type::new(unsafe { new_type_pointer(points_to.raw()) })
    }

    pub fn point_to(&self) -> Self {
        unsafe { get_pointer_points_to_type(self.raw()).into() }
    }

    /// create array type
    pub fn new_array(elem: &Type, length: u32) -> Self {
        Type::new(unsafe { new_type_array(elem.raw(), length) })
    }

    /// new method type
    pub fn new_method(args: &Vec<Type>, ret: Option<&Type>) -> Self {
        let method = Type::new(unsafe {
            new_type_method(
                args.len() as u64,
                if ret.is_none() { 0 } else { 1 },
                0,
                cc_cdecl_set,
                mtp_additional_properties_mtp_no_property,
            )
        });

        for (idx, arg) in args.iter().enumerate() {
            unsafe {
                set_method_param_type(method.raw(), idx as u64, arg.raw());
            }
        }

        if let Some(r) = ret {
            unsafe {
                set_method_res_type(method.raw(), 0, r.raw());
            }
        }
        method
    }

    pub fn method_n_res(&self) -> u64 {
        unsafe { get_method_n_ress(self.raw()) }
    }

    pub fn try_method_res(&self) -> Option<Self> {
        unsafe {
            let ty = get_method_res_type(self.raw(), 0);
            if ty.is_null() {
                return None;
            }
            return Some(ty.into());
        }
    }

    pub fn method_res(&self) -> Self {
        unsafe { get_method_res_type(self.raw(), 0).into() }
    }

    pub fn params_num(&self) -> u64 {
        unsafe { get_method_n_params(self.raw()) }
    }

    pub fn param(&self, pos: u64) -> Self {
        unsafe { get_method_param_type(self.raw(), pos).into() }
    }

    /// create structure's or union's type
    pub fn new_struct(ident: &Ident) -> Self {
        unsafe { new_type_struct(ident.raw()).into() }
    }

    pub fn is_struct(&self) -> bool {
        unsafe { is_Struct_type(self.raw()) != 0 }
    }

    pub fn is_pointer(&self) -> bool {
        unsafe { is_Pointer_type(self.raw()) != 0 }
    }

    pub fn set_layout_fixed(&self) {
        unsafe {
            set_type_state(self.raw(), ir_type_state_layout_fixed);
        }
    }

    /// set btf type id which use dbi(type_dbg_info) field in ir_type
    pub fn set_typeid(&mut self, typeid: u32) {
        unsafe { set_type_dbg_info(self.raw(), typeid as u64 as *mut type_dbg_info) }
    }

    pub fn typeid(&self) -> Option<u32> {
        let typeid = unsafe { get_type_dbg_info(self.raw()) } as u64;

        if typeid == 0 {
            None
        } else {
            Some(typeid as u32)
        }
    }
}

impl std::fmt::Display for Type {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = self.kind();
        write!(f, "{}", kind)?;
        match kind {
            TypeKind::Pointer => write!(f, "{}", self.point_to()),
            _ => write!(f, ""),
        }
    }
}
