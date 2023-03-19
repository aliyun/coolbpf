

use cached::proc_macro::cached;
use crate::types::Type;

/// get Type of `struct pt_regs`
#[cached(size = 1)]
pub fn pt_regs_type() -> Type {
    Type::from_struct_name("pt_regs")
}




