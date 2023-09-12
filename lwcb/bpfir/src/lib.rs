pub(crate) mod be;
pub mod mir;
pub mod types;
pub use be::object::BPFObject;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
pub use types::Type;
pub use types::TypeKind;
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
