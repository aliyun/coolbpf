mod be;

mod bblock;
mod cfg;
mod func;
mod module;
pub mod types;
mod value;

pub use bblock::BBlock;
pub use func::Func;
pub use func::FuncData;
pub use module::Module;
pub use types::Type;
pub use types::TypeKind;
pub use value::Value;
pub use value::ValueData;
pub use value::ValueKind;

use std::sync::atomic::{AtomicUsize, Ordering};
static GLOBAL_TMP_NAME_ID_COUNTER: AtomicUsize = AtomicUsize::new(0);
static GLOBAL_NAME_ID_COUNTER: AtomicUsize = AtomicUsize::new(0);

pub fn tmp_unique_name() -> String {
    format!(
        "TMP_{}",
        GLOBAL_TMP_NAME_ID_COUNTER.fetch_add(1, Ordering::SeqCst)
    )
}

pub fn unique_name(name: &str) -> String {
    format!(
        "{name}_{}",
        GLOBAL_TMP_NAME_ID_COUNTER.fetch_add(1, Ordering::SeqCst)
    )
}