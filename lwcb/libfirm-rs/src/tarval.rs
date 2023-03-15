use libfirm_sys::*;

use crate::Mode;

#[derive(Clone, Copy)]
pub struct Tarval(*mut ir_tarval);

impl From<*mut ir_tarval> for Tarval {
    fn from(ptr: *mut ir_tarval) -> Self {
        Tarval(ptr)
    }
}

impl Tarval {
    /// return long integer
    pub fn long(&self) -> i64 {
        unsafe { get_tarval_long(self.0) }
    }

    pub fn new_long(val: i64, mode: &Mode) -> Self {
        unsafe { new_tarval_from_long(val, mode.raw()).into() }
    }

    pub fn raw(&self) -> *mut ir_tarval {
        self.0
    }

    pub fn mode(&self) -> Mode {
        unsafe { get_tarval_mode(self.raw()).into() }
    }
}
