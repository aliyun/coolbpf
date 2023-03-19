use std::ffi::{CString, CStr};

use libfirm_sys::*;

#[derive(Clone, Copy)]
pub struct Ident(*mut ident);

impl From<*mut ident> for Ident {
    fn from(ptr: *mut ident) -> Self {
        Ident(ptr)
    }
}

unsafe impl Sync for Ident {}

impl Ident {

    pub fn raw(&self) -> *mut ident {
        self.0
    }

    pub fn unique(name: &CString) -> Self {
        unsafe { id_unique(name.as_ptr()).into() }
    }

    pub fn new(name: &CString) -> Self {
        unsafe { new_id_from_str(name.as_ptr()).into() }
    }

    pub fn str(&self) -> &str {
        let str = unsafe {CStr::from_ptr(self.raw() as *const i8)};
        str.to_str().unwrap()
    }
}
