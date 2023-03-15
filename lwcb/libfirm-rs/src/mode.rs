use libfirm_sys::*;
use paste::paste;
use std::ffi::CStr;

use crate::Type;

macro_rules! get_mode {
    ($($name: ident), *) => {
        paste! {
            $(
                pub fn [<Mode $name>]() -> Self {
                    Mode(unsafe {[<get_mode $name>]() } )
                }
            )*
        }
    };
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Mode(*mut ir_mode);

impl From<*mut ir_mode> for Mode {
    fn from(ptr: *mut ir_mode) -> Self {
        Mode(ptr)
    }
}

impl Mode {
    get_mode!(ANY, BAD, BB, Bs, Bu, D, F, Hs, Hu, Is, Iu, Ls, Lu, M, P, T, X, b);

    // pub fn name(&self) -> &CStr {
    //     unsafe { CStr::from_ptr(get_mode_name(self.0)) }
    // }

    pub fn offset_mode() -> Self {
        unsafe { get_reference_offset_mode(Mode::ModeP().raw()).into() }
    }

    pub fn raw(&self) -> *mut ir_mode {
        self.0
    }

    pub fn size(&self) -> u32 {
        unsafe { get_mode_size_bytes(self.0) }
    }

    pub fn type_(&self) -> Type {
        unsafe { get_type_for_mode(self.raw()).into() }
    }
}
